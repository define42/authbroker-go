package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const maxAdminFormBodyBytes = 16 << 10

// adminContext is the result of adminAuth — handlers should always run it
// first to short-circuit non-admin requests with a 403.
type adminContext struct {
	Session Session
	User    *StoredUser
}

// adminAuth validates that the request carries a session for a user with at
// least one configured admin group. Returns false (and writes a response)
// when the request is not authorized. Centralizes the redirect-to-login
// behavior so each admin handler stays small.
func (b *Broker) adminAuth(w http.ResponseWriter, r *http.Request) (adminContext, bool) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return adminContext{}, false
	}
	user, _ := b.store.GetUser(sess.UserID)
	if !b.userIsAdmin(user) {
		b.auditEvent(r, auditEventAdminMutation, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "not_admin"))
		http.Error(w, "forbidden: admin group required", http.StatusForbidden)
		return adminContext{}, false
	}
	b.maybeExtendSession(w, r)
	return adminContext{Session: sess, User: user}, true
}

func (b *Broker) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	ctx, ok := b.adminAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = adminHomeTemplate.Execute(w, map[string]any{
		"DisplayName": b.cfg.DisplayName,
		"UserID":      ctx.Session.UserID,
		"CSRFToken":   ctx.Session.CSRFToken,
		"Clients":     b.adminClientViews(),
		"AppTokens":   b.adminAppTokenViews(),
		"Flash":       r.URL.Query().Get("flash"),
	})
}

func (b *Broker) handleAdminClientsNew(w http.ResponseWriter, r *http.Request) {
	ctx, ok := b.adminAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = adminClientFormTemplate.Execute(w, map[string]any{
		"DisplayName": b.cfg.DisplayName,
		"UserID":      ctx.Session.UserID,
		"CSRFToken":   ctx.Session.CSRFToken,
		"Error":       r.URL.Query().Get("error"),
	})
}

//nolint:funlen // Form parsing, validation, and persistence flow read clearer end-to-end.
func (b *Broker) handleAdminClientsCreate(w http.ResponseWriter, r *http.Request) {
	ctx, ok := b.adminAuth(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !verifySessionCSRF(r, ctx.Session) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}

	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	if !validClientID(clientID) {
		b.adminClientsFormRedirect(w, r, "client_id must be 1-64 chars of letters, digits, dot, underscore, or hyphen")
		return
	}
	if _, exists := b.lookupClient(clientID); exists {
		b.adminClientsFormRedirect(w, r, "client_id already exists")
		return
	}
	redirectURIs := splitFormLines(r.Form.Get("redirect_uris"))
	if len(redirectURIs) == 0 {
		b.adminClientsFormRedirect(w, r, "at least one redirect_uri is required")
		return
	}
	postLogoutRedirectURIs := splitFormLines(r.Form.Get("post_logout_redirect_uris"))
	if err := b.validateAdminClientRedirects(clientID, redirectURIs, postLogoutRedirectURIs); err != nil {
		b.adminClientsFormRedirect(w, r, err.Error())
		return
	}
	if b.cfg.Production && r.Form.Get("require_pkce") != "on" {
		b.adminClientsFormRedirect(w, r, "production clients must require PKCE")
		return
	}
	allowedScopes := splitScopeForm(r.Form.Get("allowed_scopes"))
	clientCredentialsScopes := splitScopeForm(r.Form.Get("client_credentials_scopes"))

	client := Client{
		ClientID:                clientID,
		RedirectURIs:            redirectURIs,
		PostLogoutRedirectURIs:  postLogoutRedirectURIs,
		Public:                  r.Form.Get("public") == "on",
		RequirePKCE:             r.Form.Get("require_pkce") == "on",
		AllowedScopes:           allowedScopes,
		ClientCredentialsScopes: clientCredentialsScopes,
		AllowOfflineAccess:      r.Form.Get("allow_offline_access") == "on",
		RequireConsent:          r.Form.Get("require_consent") == "on",
		StoredAt:                time.Now(),
	}
	if err := normalizeClientScopePolicy(&client); err != nil {
		b.adminClientsFormRedirect(w, r, err.Error())
		return
	}
	var secretPlain string
	if !client.Public {
		secretPlain = randomB64(24)
		sum := sha256.Sum256([]byte(secretPlain))
		client.ClientSecretSHA256 = hex.EncodeToString(sum[:])
	}
	if err := b.store.PutStoredClient(client); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if err := b.reloadStoredRegistries(); err != nil {
		http.Error(w, "registry reload error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventAdminMutation, auditOutcomeSuccess,
		slog.String("user_id", ctx.Session.UserID),
		slog.String("entity", "client"),
		slog.String("action", "create"),
		slog.String("client_id", client.ClientID))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = adminClientCreatedTemplate.Execute(w, map[string]any{
		"DisplayName":  b.cfg.DisplayName,
		"UserID":       ctx.Session.UserID,
		"ClientID":     client.ClientID,
		"ClientSecret": secretPlain,
		"Public":       client.Public,
	})
}

func (b *Broker) validateAdminClientRedirects(clientID string, redirectURIs, postLogoutRedirectURIs []string) error {
	for _, u := range redirectURIs {
		if _, err := url.ParseRequestURI(u); err != nil {
			return fmt.Errorf("invalid redirect_uri: %s", u)
		}
	}
	if !b.cfg.Production {
		return nil
	}
	for _, u := range redirectURIs {
		if err := validateProductionRedirectURI(clientID, u); err != nil {
			return err
		}
	}
	for _, u := range postLogoutRedirectURIs {
		if err := validateProductionRedirectURI(clientID, u); err != nil {
			return err
		}
	}
	return nil
}

func (b *Broker) handleAdminClientsDelete(w http.ResponseWriter, r *http.Request) {
	ctx, ok := b.adminAuth(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !verifySessionCSRF(r, ctx.Session) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}
	if _, isConfig := b.clients[id]; isConfig {
		http.Error(w, "config-defined clients are read-only", http.StatusForbidden)
		return
	}
	if err := b.store.DeleteStoredClient(id); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if err := b.store.DeleteConsentsForClient(id); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if err := b.reloadStoredRegistries(); err != nil {
		http.Error(w, "registry reload error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventAdminMutation, auditOutcomeSuccess,
		slog.String("user_id", ctx.Session.UserID),
		slog.String("entity", "client"),
		slog.String("action", "delete"),
		slog.String("client_id", id))
	http.Redirect(w, r, "/admin?flash=client+deleted", http.StatusFound)
}

func (b *Broker) handleAdminAppTokensNew(w http.ResponseWriter, r *http.Request) {
	ctx, ok := b.adminAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = adminAppTokenFormTemplate.Execute(w, map[string]any{
		"DisplayName": b.cfg.DisplayName,
		"UserID":      ctx.Session.UserID,
		"CSRFToken":   ctx.Session.CSRFToken,
		"Error":       r.URL.Query().Get("error"),
	})
}

//nolint:funlen // App-token create validates id, ttl, scope, and audience together; splitting would obscure the form-to-store flow.
func (b *Broker) handleAdminAppTokensCreate(w http.ResponseWriter, r *http.Request) {
	ctx, ok := b.adminAuth(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !verifySessionCSRF(r, ctx.Session) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}

	id := strings.TrimSpace(r.Form.Get("id"))
	if !validAppTokenID(id) {
		b.adminAppTokensFormRedirect(w, r, fmt.Sprintf("id must be 1-%d chars of letters, digits, dot, underscore, or hyphen", maxAppTokenIDLen))
		return
	}
	if _, exists := b.lookupAppToken(id); exists {
		b.adminAppTokensFormRedirect(w, r, "id already exists")
		return
	}
	ttl, err := parseAdminTokenTTL(r.Form.Get("token_ttl_minutes"))
	if err != nil {
		b.adminAppTokensFormRedirect(w, r, err.Error())
		return
	}
	if b.cfg.Production && !within(ttl, 1, 1440) {
		b.adminAppTokensFormRedirect(w, r, "production app-token ttl must be between 1 and 1440 minutes")
		return
	}
	displayName := strings.TrimSpace(r.Form.Get("display_name"))
	if displayName == "" {
		displayName = id
	}
	audience := strings.TrimSpace(r.Form.Get("audience"))
	if audience == "" {
		audience = id
	}
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	if clientID == "" {
		clientID = audience
	}
	scope, err := parseAdminAppTokenScope(r.Form)
	if err != nil {
		b.adminAppTokensFormRedirect(w, r, err.Error())
		return
	}
	tok := AppTokenConfig{
		ID:              id,
		DisplayName:     displayName,
		Audience:        audience,
		ClientID:        clientID,
		Scope:           scope,
		TokenTTLMinutes: ttl,
		StoredAt:        time.Now(),
	}
	if err := b.store.PutStoredAppToken(tok); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if err := b.reloadStoredRegistries(); err != nil {
		http.Error(w, "registry reload error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventAdminMutation, auditOutcomeSuccess,
		slog.String("user_id", ctx.Session.UserID),
		slog.String("entity", "app_token"),
		slog.String("action", "create"),
		slog.String("app_token_id", tok.ID))
	http.Redirect(w, r, "/admin?flash=app+token+created", http.StatusFound)
}

func (b *Broker) handleAdminAppTokensDelete(w http.ResponseWriter, r *http.Request) {
	ctx, ok := b.adminAuth(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !verifySessionCSRF(r, ctx.Session) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "missing app_token_id", http.StatusBadRequest)
		return
	}
	if _, isConfig := b.appTokens[id]; isConfig {
		http.Error(w, "config-defined app tokens are read-only", http.StatusForbidden)
		return
	}
	if err := b.store.DeleteStoredAppToken(id); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if err := b.reloadStoredRegistries(); err != nil {
		http.Error(w, "registry reload error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventAdminMutation, auditOutcomeSuccess,
		slog.String("user_id", ctx.Session.UserID),
		slog.String("entity", "app_token"),
		slog.String("action", "delete"),
		slog.String("app_token_id", id))
	http.Redirect(w, r, "/admin?flash=app+token+deleted", http.StatusFound)
}

// adminClientView is what the list template renders for each client. The
// ReadOnly flag drives whether the delete button is shown.
type adminClientView struct {
	ClientID                string
	RedirectURIs            []string
	Public                  bool
	RequirePKCE             bool
	RequireConsent          bool
	AllowedScopes           []string
	ClientCredentialsScopes []string
	AllowOfflineAccess      bool
	ReadOnly                bool
}

func (b *Broker) adminClientViews() []adminClientView {
	merged := b.snapshotClients()
	ids := make([]string, 0, len(merged))
	for id := range merged {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	views := make([]adminClientView, 0, len(ids))
	for _, id := range ids {
		c := merged[id]
		_, configDefined := b.clients[id]
		views = append(views, adminClientView{
			ClientID:                c.ClientID,
			RedirectURIs:            c.RedirectURIs,
			Public:                  c.Public,
			RequirePKCE:             c.RequirePKCE,
			RequireConsent:          c.RequireConsent,
			AllowedScopes:           c.AllowedScopes,
			ClientCredentialsScopes: c.ClientCredentialsScopes,
			AllowOfflineAccess:      c.AllowOfflineAccess,
			ReadOnly:                configDefined,
		})
	}
	return views
}

type adminAppTokenView struct {
	ID          string
	DisplayName string
	Audience    string
	ClientID    string
	Scope       string
	TTLLabel    string
	ReadOnly    bool
}

func (b *Broker) adminAppTokenViews() []adminAppTokenView {
	merged := b.snapshotAppTokens()
	ids := make([]string, 0, len(merged))
	for id := range merged {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	views := make([]adminAppTokenView, 0, len(ids))
	for _, id := range ids {
		t := merged[id]
		_, configDefined := b.appTokens[id]
		views = append(views, adminAppTokenView{
			ID:          t.ID,
			DisplayName: t.DisplayName,
			Audience:    t.Audience,
			ClientID:    t.ClientID,
			Scope:       t.Scope,
			TTLLabel:    formatTokenTTL(t.TokenTTLMinutes),
			ReadOnly:    configDefined,
		})
	}
	return views
}

func (b *Broker) adminClientsFormRedirect(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/admin/clients/new?error="+url.QueryEscape(msg), http.StatusFound)
}

func (b *Broker) adminAppTokensFormRedirect(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/admin/app-tokens/new?error="+url.QueryEscape(msg), http.StatusFound)
}

// validClientID applies the same character/length rules used for app-token
// IDs. Reflected in URLs and JWT claims, so an explicit whitelist keeps the
// HTML/CSP/audit pipeline boring.
func validClientID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func splitFormLines(in string) []string {
	out := []string{}
	for _, line := range strings.Split(in, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func splitScopeForm(in string) []string {
	return strings.Fields(in)
}

func parseAdminAppTokenScope(form url.Values) (string, error) {
	scope := strings.TrimSpace(form.Get("scope"))
	if scope == "" {
		scope = strings.Join(defaultClientAllowedScopes, " ")
	}
	return normalizeAppTokenScope(scope)
}

func parseAdminTokenTTL(in string) (int, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return 480, nil
	}
	n := 0
	for _, r := range in {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("token_ttl_minutes must be a positive integer")
		}
		n = n*10 + int(r-'0')
		if n > 60*24*30 {
			return 0, fmt.Errorf("token_ttl_minutes too large (max 30 days)")
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("token_ttl_minutes must be greater than zero")
	}
	return n, nil
}
