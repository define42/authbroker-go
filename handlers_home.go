package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"
)

func (b *Broker) handleStylesheet(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(authbrokerCSS))
}

func (b *Broker) handleScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(authbrokerJS))
}

func (b *Broker) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (b *Broker) handleLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (b *Broker) handleReady(w http.ResponseWriter, _ *http.Request) {
	if err := b.store.Ready(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (b *Broker) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.metrics.render()))
}

func (b *Broker) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	issuer := b.cfg.Issuer
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"userinfo_endpoint":                     issuer + "/oauth2/userinfo",
		"jwks_uri":                              issuer + "/oauth2/jwks",
		"revocation_endpoint":                   issuer + "/oauth2/revoke",
		"introspection_endpoint":                issuer + "/oauth2/introspect",
		"end_session_endpoint":                  issuer + "/oauth2/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups", "offline_access"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "preferred_username", "email", "name", "groups", "azp", "amr"},
		"code_challenge_methods_supported":      []string{"S256"},
		"response_modes_supported":              []string{"query"},
	})
}

func (b *Broker) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	writeJSON(w, http.StatusOK, map[string]any{"keys": b.publicJWKs})
}

func (b *Broker) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b.maybeExtendSession(w, r)
	data := b.homeData(r, nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = brokerHomeTemplate.Execute(w, data)
}

type appTokenView struct {
	ID              string
	DisplayName     string
	Audience        string
	ClientID        string
	Scope           string
	TokenTTLSeconds int
	TokenTTLLabel   string
	JWKSURL         string
}

type issuedAppTokenView struct {
	appTokenView

	Token string
}

func (b *Broker) homeData(r *http.Request, issued *issuedAppTokenView) map[string]any {
	data := map[string]any{
		"DisplayName": b.cfg.DisplayName,
		"Issuer":      b.cfg.Issuer,
		"AppTokens":   b.appTokenViews(),
	}
	if sess, ok := b.validSession(r); ok {
		data["Authenticated"] = true
		data["UserID"] = sess.UserID
		data["ExpiresAt"] = sess.ExpiresAt.Format(time.RFC1123)
		data["CSRFToken"] = sess.CSRFToken
		user, _ := b.store.GetUser(sess.UserID)
		data["IsAdmin"] = b.userIsAdmin(user)
	}
	if issued != nil {
		data["IssuedAppToken"] = issued
	}
	return data
}

func (b *Broker) appTokenViews() []appTokenView {
	merged := b.snapshotAppTokens()
	ids := make([]string, 0, len(merged))
	for id := range merged {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	views := make([]appTokenView, 0, len(merged))
	for _, id := range ids {
		views = append(views, b.appTokenView(merged[id]))
	}
	return views
}

func (b *Broker) appTokenView(cfg AppTokenConfig) appTokenView {
	return appTokenView{
		ID:              cfg.ID,
		DisplayName:     cfg.DisplayName,
		Audience:        cfg.Audience,
		ClientID:        cfg.ClientID,
		Scope:           cfg.Scope,
		TokenTTLSeconds: cfg.TokenTTLMinutes * 60,
		TokenTTLLabel:   formatTokenTTL(cfg.TokenTTLMinutes),
		JWKSURL:         b.cfg.Issuer + "/oauth2/jwks",
	}
}

func formatTokenTTL(minutes int) string {
	switch {
	case minutes%1440 == 0:
		days := minutes / 1440
		return pluralize(days, "day")
	case minutes%60 == 0:
		hours := minutes / 60
		return pluralize(hours, "hour")
	default:
		return pluralize(minutes, "minute")
	}
}

func pluralize(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func (b *Broker) handleAppToken(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAppTokenFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !verifySessionCSRF(r, sess) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	// Re-auth required: app tokens default to 8h TTL and ship user identity
	// claims (groups, email, name). A stolen session must not be able to
	// silently mint one.
	if !b.requireRecentReAuth(w, sess) {
		return
	}
	b.maybeExtendSession(w, r)
	tokenID := r.PathValue("id")
	tokenCfg, ok := b.lookupAppToken(tokenID)
	if !ok {
		b.auditEvent(r, auditEventAppTokenIssue, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("app_token_id", tokenID),
			slog.String("reason", "unknown_app_token"))
		http.NotFound(w, r)
		return
	}
	token, err := b.issueAppToken(sess, tokenCfg)
	if err != nil {
		b.auditEvent(r, auditEventAppTokenIssue, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("app_token_id", tokenCfg.ID),
			slog.String("reason", "signing_error"))
		http.Error(w, "could not issue app token", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventAppTokenIssue, auditOutcomeSuccess,
		slog.String("user_id", sess.UserID),
		slog.String("app_token_id", tokenCfg.ID),
		slog.String("audience", tokenCfg.Audience),
		slog.String("client_id", tokenCfg.ClientID))
	issued := &issuedAppTokenView{
		appTokenView: b.appTokenView(tokenCfg),
		Token:        token,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = brokerHomeTemplate.Execute(w, b.homeData(r, issued))
}
