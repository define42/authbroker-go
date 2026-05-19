package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (b *Broker) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	rid := r.URL.Query().Get("request_id")
	clientID := "authbroker"
	if rid != "" {
		// Cap unauthenticated bbolt lookups per IP. The request_id space is
		// 32 random bytes and effectively unguessable, but absent this cap a
		// hostile client can hammer GetAuthRequest with random IDs and keep
		// the read transaction loop busy. The limit is shared with the rest
		// of the preauth surface (authorize, webauthn login begin).
		if !b.allowPreAuthWrite(w, r, "login_get") {
			return
		}
		ar, ok, err := b.store.GetAuthRequest(rid)
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		if !ok || time.Now().After(ar.ExpiresAt) {
			http.Error(w, "login request expired", http.StatusBadRequest)
			return
		}
		clientID = ar.ClientID
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, map[string]any{
		"DisplayName": b.cfg.DisplayName,
		"RequestID":   rid,
		"ClientID":    clientID,
		"TOTPHint":    b.cfg.MFA.TOTPRequired,
		"CSRFToken":   b.anonymousCSRFToken(w, r, true),
	})
}

//nolint:gocognit,cyclop,nestif,funlen // Login keeps OAuth request restoration and TOTP handling in one flow.
func (b *Broker) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !verifyAnonymousCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}

	// Lowercase the username at the boundary so the rate-limit key, LDAP
	// bind, store key, and audit user_id agree on a single identifier.
	// AD/OpenLDAP are case-insensitive in practice; oscillating case used to
	// surface as different audit user_id strings for the same account.
	username := strings.ToLower(strings.TrimSpace(r.Form.Get("username")))
	if ok, retry := b.allowCredentialLoginAttempt(r, username); !ok {
		writeRetryAfter(w, retry)
		b.auditEvent(r, auditEventLogin, auditOutcomeFailure,
			slog.String("user_id", username),
			slog.String("reason", "rate_limited"))
		http.Error(w, "too many login attempts; try again later", http.StatusTooManyRequests)
		return
	}

	rid := r.Form.Get("request_id")
	oauthLogin := rid != ""
	var ar AuthorizationRequest
	if oauthLogin {
		var ok bool
		var persistErr error
		ar, ok, persistErr = b.store.ConsumeAuthRequest(rid)
		if persistErr != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		if !ok || time.Now().After(ar.ExpiresAt) {
			http.Error(w, "login request expired", http.StatusBadRequest)
			return
		}
	}

	password := r.Form.Get("password")
	profile, err := b.authn.Authenticate(r.Context(), username, password)
	if err != nil {
		b.recordCredentialLoginFailure(r, username)
		if oauthLogin {
			if err := b.putAuthRequest(ar); err != nil {
				log.Printf("restore auth request after login failure: %v", err)
			}
		}
		b.auditEvent(r, auditEventLogin, auditOutcomeFailure,
			slog.String("user_id", username),
			slog.String("client_id", loginAuditClientID(ar)),
			slog.String("reason", "invalid_credentials"))
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	user, err := b.store.UpsertProfile(profile)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}

	if b.needsTOTP(user) {
		otp := strings.TrimSpace(r.Form.Get("otp"))
		if user.TOTPSecretBase32 == "" {
			b.recordCredentialLoginFailure(r, user.Username)
			if oauthLogin {
				if err := b.putAuthRequest(ar); err != nil {
					log.Printf("restore auth request after missing totp enrollment: %v", err)
				}
			}
			b.auditEvent(r, auditEventLogin, auditOutcomeFailure,
				slog.String("user_id", user.Username),
				slog.String("client_id", loginAuditClientID(ar)),
				slog.String("reason", "totp_not_enrolled"))
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}
		if !verifyTOTP(user.TOTPSecretBase32, otp, time.Now(), 1) {
			b.recordCredentialLoginFailure(r, user.Username)
			if oauthLogin {
				if err := b.putAuthRequest(ar); err != nil {
					log.Printf("restore auth request after totp failure: %v", err)
				}
			}
			b.auditEvent(r, auditEventLogin, auditOutcomeFailure,
				slog.String("user_id", user.Username),
				slog.String("client_id", loginAuditClientID(ar)),
				slog.String("reason", "invalid_totp"))
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}
	}

	b.recordCredentialLoginSuccess(r, user.Username)
	amr := []string{amrPassword}
	if b.needsTOTP(user) {
		amr = append(amr, amrOTP, amrMFA)
	}
	sess, err := b.createSession(w, user.Username, true, amr)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventLogin, auditOutcomeSuccess,
		slog.String("user_id", user.Username),
		slog.String("client_id", ar.ClientID),
		slog.Bool("oauth_flow", oauthLogin),
		slog.Bool("totp_used", b.needsTOTP(user)))
	if oauthLogin {
		if err := b.proceedAfterAuthn(w, r, ar, sess); err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleReAuth re-confirms the current user's password and refreshes
// ReAuthAt so the session may immediately mutate second-factor material
// (TOTP enroll, WebAuthn register). Required when the existing session's
// ReAuthAt is older than reAuthValidity.
func (b *Broker) handleReAuth(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !verifySessionCSRF(r, sess) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	password := r.Form.Get("password")
	rateKey := b.loginRateKey(r, sess.UserID)
	if ok, retry := b.loginLimiter.allow(rateKey); !ok {
		writeRetryAfter(w, retry)
		b.auditEvent(r, auditEventReAuth, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "rate_limited"))
		http.Error(w, "too many login attempts; try again later", http.StatusTooManyRequests)
		return
	}
	if _, err := b.authn.Authenticate(r.Context(), sess.UserID, password); err != nil {
		b.loginLimiter.recordFailure(rateKey)
		b.auditEvent(r, auditEventReAuth, auditOutcomeFailure,
			slog.String("user_id", sess.UserID),
			slog.String("reason", "invalid_credentials"))
		http.Error(w, "invalid password", http.StatusUnauthorized)
		return
	}
	b.loginLimiter.recordSuccess(rateKey)
	if err := b.markSessionReAuth(r); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventReAuth, auditOutcomeSuccess,
		slog.String("user_id", sess.UserID))
	w.WriteHeader(http.StatusNoContent)
}

func (b *Broker) handleLocalLogoutGet(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = brokerLogoutTemplate.Execute(w, map[string]any{
		"DisplayName": b.cfg.DisplayName,
		"UserID":      sess.UserID,
		"CSRFToken":   sess.CSRFToken,
		"Action":      "/logout",
	})
}

func (b *Broker) handleLocalLogoutPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	sess, ok := b.validSession(r)
	if ok && !verifySessionCSRF(r, sess) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}
	if err := b.clearSession(w, r); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if ok {
		b.auditEvent(r, auditEventLogout, auditOutcomeSuccess,
			slog.String("user_id", sess.UserID),
			slog.String("source", "local"))
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (b *Broker) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Cap the request body for both methods. POST carries the form; GET
	// should be empty but a hostile client can still send megabytes at a GET
	// route, and Go would otherwise read them on r.Body access. ReadTimeout
	// on the server limits the worst case, but the explicit cap is cheap
	// defense in depth.
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBodyBytes)
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
	}

	idTokenHint := strings.TrimSpace(logoutParam(r, "id_token_hint"))
	clientID := strings.TrimSpace(logoutParam(r, "client_id"))
	clientID, ok := b.resolveLogoutClientID(w, clientID, idTokenHint)
	if !ok {
		return
	}

	postLogoutRedirectURI := strings.TrimSpace(logoutParam(r, "post_logout_redirect_uri"))
	state := logoutParam(r, "state")

	// Per OIDC RP-Initiated Logout 1.0 §3, the broker SHOULD confirm the
	// end-user's logout intent before clearing the SSO session. Render an
	// interstitial for GET requests carrying an active session so that
	// <a>/<img>/redirect-driven CSRF cannot drop the session in one round-trip.
	// RP-initiated POSTs proceed directly, as in spec-compliant flows.
	//
	// A GET without an active session AND without a valid id_token_hint is
	// refused below when a post_logout_redirect_uri is supplied — otherwise
	// the broker can be used as a low-friction redirector to any registered
	// post_logout_redirect_uri with attacker-controlled state. Spec-
	// compliant RP-initiated GETs always carry id_token_hint, so this only
	// blocks crafted phishing links.
	sess, hasSession := b.validSession(r)
	if r.Method == http.MethodGet && hasSession {
		b.renderRPLogoutConfirm(w, sess, idTokenHint, clientID, postLogoutRedirectURI, state)
		return
	}
	if r.Method == http.MethodGet && !hasSession && idTokenHint == "" && postLogoutRedirectURI != "" {
		http.Error(w, "logout requires id_token_hint or an active session", http.StatusBadRequest)
		return
	}

	if postLogoutRedirectURI != "" && !b.validPostLogoutRedirect(clientID, postLogoutRedirectURI) {
		http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}

	if postLogoutRedirectURI != "" {
		b.handlePostLogoutRedirect(w, r, clientID, postLogoutRedirectURI, state)
		return
	}

	priorSess, hadSession := b.validSession(r)
	if err := b.clearSession(w, r); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if hadSession {
		b.auditEvent(r, auditEventLogout, auditOutcomeSuccess,
			slog.String("user_id", priorSess.UserID),
			slog.String("client_id", clientID),
			slog.String("source", "rp_initiated"))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("logged out\n"))
}

// renderRPLogoutConfirm shows a confirmation page for RP-initiated logout
// when the request arrives as a GET. The form re-submits to /oauth2/logout
// via POST and carries the original id_token_hint / client_id /
// post_logout_redirect_uri / state so the resulting logout matches the
// caller's intent.
func (b *Broker) renderRPLogoutConfirm(w http.ResponseWriter, sess Session, idTokenHint, clientID, postLogoutRedirectURI, state string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = brokerLogoutTemplate.Execute(w, map[string]any{
		"DisplayName":           b.cfg.DisplayName,
		"UserID":                sess.UserID,
		"CSRFToken":             sess.CSRFToken,
		"Action":                "/oauth2/logout",
		"IDTokenHint":           idTokenHint,
		"ClientID":              clientID,
		"PostLogoutRedirectURI": postLogoutRedirectURI,
		"State":                 state,
	})
}

func (b *Broker) handlePostLogoutRedirect(w http.ResponseWriter, r *http.Request, clientID, redirectURI, state string) {
	if !b.validPostLogoutRedirect(clientID, redirectURI) {
		http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	priorSess, hadSession := b.validSession(r)
	if err := b.clearSession(w, r); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	if state != "" {
		q := u.Query()
		q.Set("state", state)
		u.RawQuery = q.Encode()
	}
	if hadSession {
		b.auditEvent(r, auditEventLogout, auditOutcomeSuccess,
			slog.String("user_id", priorSess.UserID),
			slog.String("client_id", clientID),
			slog.String("source", "rp_initiated"))
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (b *Broker) validPostLogoutRedirect(clientID, redirectURI string) bool {
	client, ok := b.lookupClient(clientID)
	return ok && clientAllowsPostLogoutRedirect(client, redirectURI)
}

func (b *Broker) resolveLogoutClientID(w http.ResponseWriter, clientID, idTokenHint string) (string, bool) {
	if idTokenHint == "" {
		return clientID, true
	}
	hintClientID, err := b.logoutClientIDFromIDTokenHint(idTokenHint)
	if err != nil && clientID == "" {
		http.Error(w, "invalid id_token_hint", http.StatusBadRequest)
		return "", false
	}
	if err != nil || hintClientID == "" {
		return clientID, true
	}
	if clientID != "" && clientID != hintClientID {
		http.Error(w, "client_id does not match id_token_hint", http.StatusBadRequest)
		return "", false
	}
	return hintClientID, true
}

func logoutParam(r *http.Request, name string) string {
	if r.Method == http.MethodPost {
		return r.Form.Get(name)
	}
	return r.URL.Query().Get(name)
}

func (b *Broker) logoutClientIDFromIDTokenHint(idTokenHint string) (string, error) {
	// Per OIDC RP-Initiated Logout 1.0 §3, id_token_hint is a HINT — the
	// broker should accept previously valid (signature + iss) ID tokens even
	// after exp has passed so that callers using long-lived stored tokens can
	// still initiate logout.
	//
	// Note that verifyJWTWithOptions still consults the revoked-JTI bucket,
	// so a token whose JTI has been explicitly revoked is unusable as a
	// logout hint. This is intentional — revocation is a stronger statement
	// than expiry, and treating a revoked token as a valid hint would
	// re-introduce a window of confused-deputy attacks the revocation was
	// meant to close. Callers without an id_token can omit the hint and
	// supply client_id directly.
	claims, err := b.verifyJWTWithOptions(idTokenHint, jwtVerifyOptions{ignoreExpiry: true})
	if err != nil {
		return "", err
	}
	return clientIDFromTokenClaims(claims), nil
}

func clientIDFromTokenClaims(claims map[string]any) string {
	// Per OIDC Core §3.1.3.7, azp (authorized party) is the authoritative
	// client identifier when an ID token has multiple audiences. Prefer it,
	// then the explicit client_id claim, then aud — accepting either a string
	// or a single-element list. Multi-audience aud without azp is ambiguous
	// and yields "" so logout falls through to the no-client path rather than
	// guessing.
	if azp, _ := claims["azp"].(string); azp != "" {
		return azp
	}
	if clientID, _ := claims["client_id"].(string); clientID != "" {
		return clientID
	}
	if aud, _ := claims["aud"].(string); aud != "" {
		return aud
	}
	if audList, ok := claims["aud"].([]any); ok && len(audList) == 1 {
		clientID, _ := audList[0].(string)
		return clientID
	}
	return ""
}

func (b *Broker) needsTOTP(user *StoredUser) bool {
	return b.cfg.MFA.TOTPRequired || (user != nil && user.TOTPSecretBase32 != "")
}

// anonymousCSRFToken issues (or reuses) the double-submit anonymous CSRF
// cookie used by the login form. Callers that render a login page should
// pass rotate=true so the cookie is replaced with a fresh value on every
// GET — otherwise a single token would be reused for the full 24h MaxAge
// and a passive observer of one form submission could replay it well past
// the lifetime of the page that issued it. Multi-tab logins must re-GET
// the form to pick up the latest cookie value.
func (b *Broker) anonymousCSRFToken(w http.ResponseWriter, r *http.Request, rotate bool) string {
	if !rotate {
		if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
			return c.Value
		}
	}
	token := randomB64(32)
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is controlled by issuer/config for local HTTP demos and HTTPS deployments.
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   b.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((24 * time.Hour).Seconds()),
	})
	return token
}

func verifyAnonymousCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil {
		return false
	}
	return csrfTokenMatches(r.Form.Get(csrfFormField), c.Value)
}

func verifySessionCSRF(r *http.Request, sess Session) bool {
	token := r.Form.Get(csrfFormField)
	if token == "" {
		token = r.Header.Get(csrfHeaderName)
	}
	return csrfTokenMatches(token, sess.CSRFToken)
}

func requireSessionCSRF(w http.ResponseWriter, r *http.Request, sess Session) bool {
	if verifySessionCSRF(r, sess) {
		return true
	}
	http.Error(w, "invalid csrf token", http.StatusForbidden)
	return false
}

func csrfTokenMatches(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// cookieSecure delegates to cookieSecureForConfig so the same logic governs
// runtime cookie issuance and config-time production validation. Earlier
// revisions kept two near-identical copies; deduping prevents the two from
// drifting if cookie semantics later grow new inputs (e.g. a runtime flag the
// broker has but config validation doesn't).
func (b *Broker) cookieSecure() bool {
	return cookieSecureForConfig(b.cfg)
}

func (b *Broker) validSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	s, ok, err := b.store.GetSession(c.Value)
	if err != nil {
		log.Printf("load session state: %v", err)
		return Session{}, false
	}
	if !ok {
		return Session{}, false
	}
	now := time.Now()
	if now.After(s.ExpiresAt) || (!s.AbsoluteExpiresAt.IsZero() && now.After(s.AbsoluteExpiresAt)) {
		if err := b.store.DeleteSession(c.Value); err != nil {
			log.Printf("delete expired session: %v", err)
		}
		return Session{}, false
	}
	if s.CSRFToken == "" {
		migrated, ok, err := b.store.EnsureSessionCSRF(c.Value, func() string { return randomB64(32) })
		if err != nil {
			log.Printf("persist session csrf: %v", err)
			return Session{}, false
		}
		if !ok {
			return Session{}, false
		}
		s = migrated
	}
	return s, true
}

// markSessionReAuth refreshes the current session's ReAuthAt timestamp after a
// successful password (or factor) re-confirmation.
func (b *Broker) markSessionReAuth(r *http.Request) error {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return fmt.Errorf("no session")
	}
	s, ok, err := b.store.GetSession(c.Value)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	s.ReAuthAt = time.Now()
	return b.store.PutSession(c.Value, s)
}

// sessionRecentlyReAuthenticated reports whether the session's ReAuthAt is
// within reAuthValidity of now. Returns false for sessions that have never
// completed a password (or factor) re-confirmation.
func sessionRecentlyReAuthenticated(sess Session) bool {
	if sess.ReAuthAt.IsZero() {
		return false
	}
	return time.Since(sess.ReAuthAt) <= reAuthValidity
}

// maybeExtendSession loads the current session, lazily backfills the CSRF
// token on legacy sessions, and refreshes the expiry on activity once more
// than half of the TTL has been consumed (re-setting the cookie so the
// browser does not drop it at the original expiration). It returns the
// resulting (Session, true) so callers that also need to read the session
// for rendering can use the same load — earlier revisions ran
// maybeExtendSession and then validSession separately, which raced with the
// background sweeper between the two reads. Expired sessions are cleared
// from the store and reported as (Session{}, false).
//
// CSRF backfill duplicates the path in validSession; both call sites are
// idempotent because EnsureSessionCSRF preserves the first writer's token,
// so a request that hits both still observes a stable value.
//
//nolint:gocognit,cyclop // Combined load + CSRF backfill + extend keeps the home page from racing the sweeper between separate reads.
func (b *Broker) maybeExtendSession(w http.ResponseWriter, r *http.Request) (Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	s, found, err := b.store.GetSession(c.Value)
	if err != nil {
		log.Printf("load session for extension: %v", err)
		return Session{}, false
	}
	if !found {
		return Session{}, false
	}
	now := time.Now()
	if now.After(s.ExpiresAt) || (!s.AbsoluteExpiresAt.IsZero() && now.After(s.AbsoluteExpiresAt)) {
		if err := b.store.DeleteSession(c.Value); err != nil {
			log.Printf("delete expired session: %v", err)
		}
		return Session{}, false
	}
	if s.CSRFToken == "" {
		migrated, ok, err := b.store.EnsureSessionCSRF(c.Value, func() string { return randomB64(32) })
		if err != nil {
			log.Printf("persist session csrf: %v", err)
			return Session{}, false
		}
		if !ok {
			return Session{}, false
		}
		s = migrated
	}
	ttl := time.Duration(b.cfg.SessionTTLHrs) * time.Hour
	if ttl <= 0 || s.ExpiresAt.Sub(now) > ttl/2 {
		return s, true
	}
	newExpiry := now.Add(ttl)
	// The absolute ceiling, when set, clamps the sliding renewal. The session
	// can be extended right up to the ceiling but not past it; once we reach
	// the ceiling validSession will refuse to honor the cookie.
	if !s.AbsoluteExpiresAt.IsZero() && newExpiry.After(s.AbsoluteExpiresAt) {
		newExpiry = s.AbsoluteExpiresAt
	}
	s.ExpiresAt = newExpiry
	if err := b.store.PutSession(c.Value, s); err != nil {
		log.Printf("persist extended session: %v", err)
		return s, true
	}

	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is controlled by issuer/config for local HTTP demos and HTTPS deployments.
		Name:     sessionCookieName,
		Value:    c.Value,
		Path:     "/",
		HttpOnly: true,
		Secure:   b.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
		Expires:  newExpiry,
	})
	return s, true
}

func (b *Broker) clearSession(w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		if err := b.store.DeleteSession(c.Value); err != nil {
			return err
		}
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is controlled by issuer/config for local HTTP demos and HTTPS deployments.
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   b.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	return nil
}

// createSession persists a new session, sets the cookie, and optionally marks
// the session as freshly re-authenticated. Direct password / passkey logins
// pass freshlyAuthenticated=true so the user can immediately enroll TOTP /
// register a passkey without an extra re-auth round-trip. The amr slice
// records the RFC 8176 authentication methods used at this login so the
// id_token may include the OIDC `amr` claim.
func (b *Broker) createSession(w http.ResponseWriter, userID string, freshlyAuthenticated bool, amr []string) (Session, error) {
	sid := randomB64(32)
	now := time.Now()
	sess := Session{UserID: userID, ExpiresAt: now.Add(time.Duration(b.cfg.SessionTTLHrs) * time.Hour), AuthTime: now, CSRFToken: randomB64(32), AMR: amr}
	if b.cfg.SessionAbsoluteTTLHrs > 0 {
		sess.AbsoluteExpiresAt = now.Add(time.Duration(b.cfg.SessionAbsoluteTTLHrs) * time.Hour)
	}
	if freshlyAuthenticated {
		sess.ReAuthAt = now
	}
	if err := b.store.PutSession(sid, sess); err != nil {
		return Session{}, err
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is controlled by issuer/config for local HTTP demos and HTTPS deployments.
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   b.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})
	return sess, nil
}

func (b *Broker) issueCodeRedirect(w http.ResponseWriter, r *http.Request, ar AuthorizationRequest, sess Session) error {
	code := randomB64(32)
	ac := AuthCode{
		UserID:              sess.UserID,
		ClientID:            ar.ClientID,
		RedirectURI:         ar.RedirectURI,
		Scope:               ar.Scope,
		Nonce:               ar.Nonce,
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
		AuthTime:            sess.AuthTime,
		ExpiresAt:           time.Now().Add(time.Duration(b.cfg.AuthCodeTTLSeconds) * time.Second),
		AMR:                 sess.AMR,
	}
	if err := b.store.PutAuthCode(hashSecret(code), ac); err != nil {
		return err
	}

	u, _ := url.Parse(ar.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if ar.State != "" {
		q.Set("state", ar.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return nil
}

// loginAuditClientID returns the client_id label used in login audit events.
// Falls back to "authbroker" for direct logins (no OAuth request_id) so audit
// consumers can filter consistently between OAuth and direct sign-in flows
// — matching the value handleLoginGet supplies to the login template.
func loginAuditClientID(ar AuthorizationRequest) string {
	if ar.ClientID != "" {
		return ar.ClientID
	}
	return "authbroker"
}

func (b *Broker) allowCredentialLoginAttempt(r *http.Request, username string) (bool, time.Duration) {
	for _, key := range b.credentialLoginRateKeys(r, username) {
		if ok, retry := b.loginLimiter.allow(key); !ok {
			return false, retry
		}
	}
	return true, 0
}

func (b *Broker) recordCredentialLoginFailure(r *http.Request, username string) {
	for _, key := range b.credentialLoginRateKeys(r, username) {
		b.loginLimiter.recordFailure(key)
	}
}

func (b *Broker) recordCredentialLoginSuccess(r *http.Request, username string) {
	// A successful login clears only the user-specific bucket. The IP bucket
	// intentionally keeps recent failures so one valid account cannot reset a
	// credential-stuffing spray against many other usernames.
	b.loginLimiter.recordSuccess(b.loginRateKey(r, username))
}

func (b *Broker) credentialLoginRateKeys(r *http.Request, username string) []string {
	ipKey := b.loginIPRateKey(r)
	userKey := b.loginRateKey(r, username)
	if userKey == ipKey {
		return []string{ipKey}
	}
	return []string{ipKey, userKey}
}

func (b *Broker) loginIPRateKey(r *http.Request) string {
	return "ip:" + b.clientIP(r)
}

// loginRateKey scopes the user-specific limiter by client IP and (when known)
// the username being attempted so a single hostile IP cannot brute one account
// by trying many other accounts in parallel. Credential login also records
// failures against loginIPRateKey so username spraying from one IP is capped.
func (b *Broker) loginRateKey(r *http.Request, username string) string {
	if username == "" {
		return b.loginIPRateKey(r)
	}
	return b.loginIPRateKey(r) + "/user:" + strings.ToLower(username)
}

func writeRetryAfter(w http.ResponseWriter, d time.Duration) {
	if d < time.Second {
		d = time.Second
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", int(d.Seconds())))
}

// requireRecentReAuth returns true if the session has a fresh ReAuthAt within
// reAuthValidity. Otherwise it writes a 403 with a hint to re-authenticate.
// Handlers that mutate second-factor material (TOTP, WebAuthn credentials)
// should gate on this.
func (b *Broker) requireRecentReAuth(w http.ResponseWriter, sess Session) bool {
	if sessionRecentlyReAuthenticated(sess) {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":             "re_auth_required",
		"error_description": "POST your current password to /reauth before enrolling a new factor",
		"reauth_endpoint":   "/reauth",
		"reauth_max_age":    int(reAuthValidity.Seconds()),
	})
	return false
}
