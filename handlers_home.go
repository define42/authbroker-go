package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Strong ETags for the embedded static assets. Computed once at init from a
// SHA-256 of the body — any rebuild that mutates authbrokerCSS / authbrokerJS
// produces a new ETag, so the 1h Cache-Control window does not strand users
// on stale bytes after a deploy.
//
//nolint:gochecknoglobals // Asset bodies are static; their hashes are too.
var (
	authbrokerCSSETag = computeAssetETag(authbrokerCSS)
	authbrokerJSETag  = computeAssetETag(authbrokerJS)
)

func computeAssetETag(body string) string {
	sum := sha256.Sum256([]byte(body))
	return `"` + base64RawURL(sum[:]) + `"`
}

func (b *Broker) handleStylesheet(w http.ResponseWriter, r *http.Request) {
	serveStaticAsset(w, r, "text/css; charset=utf-8", authbrokerCSS, authbrokerCSSETag)
}

func (b *Broker) handleScript(w http.ResponseWriter, r *http.Request) {
	serveStaticAsset(w, r, "application/javascript; charset=utf-8", authbrokerJS, authbrokerJSETag)
}

// serveStaticAsset writes one of the embedded CSS/JS strings with a strong
// ETag (SHA-256 of the body, pre-computed at init time). The 3600s Cache-
// Control + ETag combination lets browsers reuse the bytes for an hour but
// pick up a new build the moment the operator rolls a binary update — the
// ETag changes because the embedded string changed, and the conditional
// If-None-Match path returns 304 only when the contents truly match.
func serveStaticAsset(w http.ResponseWriter, r *http.Request, contentType, body, etag string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write([]byte(body))
}

// etagMatches honors comma-separated If-None-Match values per RFC 7232 §3.2,
// tolerating optional W/ weak markers and surrounding whitespace.
func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == "*" || candidate == etag {
			return true
		}
	}
	return false
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

func (b *Broker) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !b.metricsRequestAuthorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(b.metrics.render()))
}

func (b *Broker) metricsRequestAuthorized(r *http.Request) bool {
	expectedHex := strings.TrimSpace(b.cfg.Metrics.BearerSHA256)
	if expectedHex == "" {
		return true
	}
	expected, err := hex.DecodeString(expectedHex)
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	bearer := bearerValue(r.Header.Get("Authorization"))
	if bearer == "" {
		return false
	}
	actual := sha256.Sum256([]byte(bearer))
	return subtle.ConstantTimeCompare(expected, actual[:]) == 1
}

func bearerValue(authz string) string {
	value := strings.TrimSpace(strings.TrimPrefix(authz, bearerPrefix))
	if value != "" && value != authz {
		return value
	}
	return ""
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
	sess, authenticated := b.maybeExtendSession(w, r)
	data := b.homeData(sess, authenticated, nil)
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

// homeData renders the template payload for the broker's home page. The
// session is supplied by the caller — handleHome obtains it from
// maybeExtendSession, and handleAppToken passes the already-validated session
// it used to authenticate the request. Threading the session through here
// (rather than calling validSession a second time inside this helper) avoids
// a race window where the background sweeper could delete the session
// between the load-and-extend and the home-page render.
func (b *Broker) homeData(sess Session, authenticated bool, issued *issuedAppTokenView) map[string]any {
	data := map[string]any{
		"DisplayName": b.cfg.DisplayName,
		"Issuer":      b.cfg.Issuer,
		"AppTokens":   b.appTokenViews(),
	}
	if authenticated {
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
	// Use the extended session's refreshed ExpiresAt for the home render when
	// available; if maybeExtendSession lost a race with the sweeper, fall back
	// to the session that was just validated and re-auth'd above so the page
	// still renders the user's identity correctly.
	if extended, extendOK := b.maybeExtendSession(w, r); extendOK {
		sess = extended
	}
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
	_ = brokerHomeTemplate.Execute(w, b.homeData(sess, true, issued))
}
