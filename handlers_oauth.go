package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// handleAuthorize trusts the request's Host header to be the canonical issuer
// hostname. The broker does NOT compare r.Host against cfg.Issuer — it relies
// on the upstream listener / reverse proxy to route only the configured
// hostname(s) to this process. If you front the broker with a proxy that
// terminates TLS and accepts arbitrary Host values, the cookie set on the
// resulting response is host-bound (no Domain attribute), so the worst case
// is cookies dropped on an unintended origin — but the OAuth code redirect
// itself is safe because redirect_uri is exact-match against the registered
// list. Production deployments MUST ensure the listener only answers for the
// issuer hostname (or domain wildcard in the ACME config).
//
//nolint:funlen // Authorize validates the request, dispatches prompt handling, and routes to login/consent — splitting would obscure the linear flow.
func (b *Broker) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	client, ok := b.lookupClient(q.Get("client_id"))
	if !ok {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !clientAllowsRedirect(client, redirectURI) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	scope, err := validateAuthorizationScope(client, q.Get("scope"))
	if err != nil {
		redirectOAuthError(w, r, redirectURI, q.Get("state"), "invalid_scope", err.Error())
		return
	}
	method := q.Get("code_challenge_method")
	challenge := q.Get("code_challenge")
	if method == "" && challenge != "" {
		method = "S256"
	}
	if msg := authorizePKCEError(client, challenge, method); msg != "" {
		redirectOAuthError(w, r, redirectURI, q.Get("state"), "invalid_request", msg)
		return
	}
	authReq := AuthorizationRequest{
		ID:                  randomB64(32),
		ClientID:            client.ClientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(time.Duration(b.cfg.AuthCodeTTLSeconds) * time.Second),
	}

	sess, hasSession := b.validSession(r)
	errCode, errDesc, forceLogin, err := b.checkPrompt(q.Get("prompt"), q.Get("max_age"), sess, hasSession, client, authReq.Scope)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if errCode != "" {
		redirectOAuthError(w, r, redirectURI, q.Get("state"), errCode, errDesc)
		return
	}

	if hasSession && !forceLogin {
		b.maybeExtendSession(w, r)
		if err := b.proceedAfterAuthn(w, r, authReq, sess); err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
		}
		return
	}

	if !b.allowPreAuthWrite(w, r, "authorize") {
		return
	}
	if err := b.putAuthRequest(authReq); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login?request_id="+url.QueryEscape(authReq.ID), http.StatusFound)
}

// allowPreAuthWrite caps per-IP creation of unauthenticated pre-login state
// (auth requests, WebAuthn login challenges, login GET lookups). These writes
// happen before any credential check and would otherwise let one client grow
// the bbolt store without bound; the limiter bumps on every attempt so the
// bucket fills under burst load even though the request itself never "fails"
// in the usual sense. Returns true to proceed, false when a 429 has already
// been written.
func (b *Broker) allowPreAuthWrite(w http.ResponseWriter, r *http.Request, scope string) bool {
	if b.preAuthLimiter == nil {
		return true
	}
	key := "preauth:" + scope + "/ip:" + b.clientIP(r)
	allowed, retry := b.preAuthLimiter.allowAndRecord(key)
	if !allowed {
		writeRetryAfter(w, retry)
		http.Error(w, "too many requests; try again later", http.StatusTooManyRequests)
		return false
	}
	return true
}

// checkPrompt implements OIDC Core §3.1.2.1 freshness handling for the
// /authorize endpoint. It parses the space-separated `prompt` parameter and
// the `max_age` parameter, rejects `none` combined with any other prompt
// value, applies the silent-auth pre-checks when `none` was requested, and
// signals (via forceLogin=true) that an existing SSO session must be
// bypassed in favor of a fresh login when `login` was requested or when
// `max_age` shows that the session's auth_time is too stale. The returned
// (errCode, errDesc) is the OIDC error to redirect to the client, or empty
// strings if the request may proceed.
func (b *Broker) checkPrompt(promptRaw, maxAgeRaw string, sess Session, hasSession bool, client Client, scope string) (errCode, errDesc string, forceLogin bool, err error) {
	prompts := map[string]bool{}
	for _, p := range strings.Fields(promptRaw) {
		prompts[p] = true
	}
	if prompts["none"] && len(prompts) > 1 {
		return "invalid_request", "prompt=none cannot be combined with other prompt values", false, nil
	}
	stale, parseErr := authTimeStale(sess, hasSession, maxAgeRaw)
	if parseErr != nil {
		return "invalid_request", parseErr.Error(), false, nil
	}
	if prompts["none"] {
		if !hasSession || stale {
			return "login_required", "prompt=none but the user is not authenticated within max_age", false, nil
		}
		needConsent, cerr := b.consentMissingForRequest(sess.UserID, client, scope)
		if cerr != nil {
			return "", "", false, cerr
		}
		if needConsent {
			return "consent_required", "prompt=none but consent has not been granted", false, nil
		}
		return "", "", false, nil
	}
	return "", "", prompts["login"] || stale, nil
}

// authTimeStale reports whether the active session's auth_time is older than
// the OIDC max_age window. When max_age is unset or malformed in a benign way
// (empty), returns false; when malformed (negative or non-numeric), returns
// an error so handleAuthorize can surface invalid_request.
func authTimeStale(sess Session, hasSession bool, maxAgeRaw string) (bool, error) {
	maxAgeRaw = strings.TrimSpace(maxAgeRaw)
	if maxAgeRaw == "" {
		return false, nil
	}
	maxAge, err := strconv.Atoi(maxAgeRaw)
	if err != nil || maxAge < 0 {
		return false, fmt.Errorf("max_age must be a non-negative integer")
	}
	if !hasSession {
		return false, nil
	}
	return time.Since(sess.AuthTime) > time.Duration(maxAge)*time.Second, nil
}

// consentMissingForRequest reports whether prompt=none must error with
// consent_required for the given user and requested scope: true when the
// client requires consent and the stored record does not cover every
// requested scope.
func (b *Broker) consentMissingForRequest(userID string, client Client, scope string) (bool, error) {
	if !client.RequireConsent {
		return false, nil
	}
	rec, found, err := b.store.GetConsent(userID, client.ClientID)
	if err != nil {
		return false, err
	}
	if !found {
		return true, nil
	}
	return !consentCovers(rec, requestedScopeList(scope)), nil
}

func authorizePKCEError(client Client, challenge, method string) string {
	if (client.RequirePKCE || client.Public) && (challenge == "" || method != "S256") {
		return "PKCE S256 is required"
	}
	if challenge != "" && method != "S256" {
		return "only PKCE S256 is accepted"
	}
	return ""
}

func (b *Broker) putAuthRequest(ar AuthorizationRequest) error {
	return b.store.PutAuthRequest(ar)
}

func (b *Broker) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBodyBytes)
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "bad form")
		return
	}
	client, retry, err := b.authenticateClientRateLimited(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		if errors.Is(err, errClientAuthRateLimited) {
			writeRetryAfter(w, retry)
			tokenErrorStatus(w, http.StatusTooManyRequests, "invalid_client", "too many client authentication attempts")
			return
		}
		tokenErrorStatus(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	switch r.Form.Get("grant_type") {
	case "authorization_code":
		b.tokenAuthorizationCode(w, r, client)
	case "refresh_token":
		b.tokenRefresh(w, r, client)
	case "client_credentials":
		b.tokenClientCredentials(w, r, client)
	default:
		tokenError(w, "unsupported_grant_type", "unsupported grant_type")
	}
}

var errClientAuthRateLimited = errors.New("client authentication rate limited")

func (b *Broker) authenticateClientRateLimited(r *http.Request) (Client, time.Duration, error) {
	id := clientIDFromRequest(r)
	key := b.clientAuthRateKey(r, id)
	if allowed, retry := b.tokenLimiter.allow(key); !allowed {
		return Client{}, retry, errClientAuthRateLimited
	}
	client, err := b.authenticateClient(r)
	if err != nil {
		b.tokenLimiter.recordFailure(key)
		return Client{}, 0, err
	}
	b.tokenLimiter.recordSuccess(key)
	return client, 0, nil
}

func clientIDFromRequest(r *http.Request) string {
	if id, _, ok := r.BasicAuth(); ok {
		return strings.TrimSpace(id)
	}
	return strings.TrimSpace(r.Form.Get("client_id"))
}

func (b *Broker) clientAuthRateKey(r *http.Request, clientID string) string {
	if clientID == "" {
		clientID = "unknown"
	}
	return "ip:" + b.clientIP(r) + "/client:" + strings.ToLower(clientID)
}

func (b *Broker) authenticateClient(r *http.Request) (Client, error) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	client, exists := b.lookupClient(id)
	if !exists || id == "" {
		return Client{}, fmt.Errorf("unknown client")
	}
	if client.Public {
		return client, nil
	}
	if !clientSecretMatches(client, secret) {
		return Client{}, fmt.Errorf("bad client credentials")
	}
	return client, nil
}

func clientSecretMatches(client Client, secret string) bool {
	if secret == "" {
		return false
	}
	expected, err := hex.DecodeString(strings.TrimSpace(client.ClientSecretSHA256))
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	actual := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(expected, actual[:]) == 1
}

//nolint:funlen // The audit attributes for the burned-but-mismatched code path inflate this past 60 lines but stay linear.
func (b *Broker) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request, client Client) {
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	codeKey := hashSecret(code)

	ac, ok, persistErr := b.store.ConsumeAuthCode(codeKey)
	if persistErr != nil {
		tokenServerError(w, "consume authorization code", persistErr)
		return
	}

	if !ok || time.Now().After(ac.ExpiresAt) {
		b.auditEvent(r, auditEventTokenIssue, auditOutcomeFailure,
			slog.String("client_id", client.ClientID),
			slog.String("grant_type", "authorization_code"),
			slog.String("reason", "invalid_or_expired_code"))
		tokenError(w, "invalid_grant", "invalid or expired code")
		return
	}
	if ac.ClientID != client.ClientID || ac.RedirectURI != redirectURI {
		// The code is consumed (RFC 6749 §4.1.2 — codes MUST be invalidated on
		// any redemption attempt) so a legitimate client that fat-fingers
		// redirect_uri will see this once per code. Surface the two distinct
		// mismatch dimensions so operators can debug a misconfigured client
		// without correlating across audit lines.
		mismatch := "redirect_uri"
		if ac.ClientID != client.ClientID {
			mismatch = "client_id"
			if ac.RedirectURI != redirectURI {
				mismatch = "client_id_and_redirect_uri"
			}
		}
		b.auditEvent(r, auditEventTokenIssue, auditOutcomeFailure,
			slog.String("client_id", client.ClientID),
			slog.String("user_id", ac.UserID),
			slog.String("grant_type", "authorization_code"),
			slog.String("reason", "client_or_redirect_mismatch"),
			slog.String("mismatch", mismatch),
			slog.String("expected_client_id", ac.ClientID),
			slog.String("expected_redirect_uri", ac.RedirectURI),
			slog.String("presented_redirect_uri", redirectURI))
		tokenError(w, "invalid_grant", "client or redirect_uri mismatch")
		return
	}
	if ac.CodeChallenge != "" {
		verifier := r.Form.Get("code_verifier")
		if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, verifier) {
			b.auditEvent(r, auditEventTokenIssue, auditOutcomeFailure,
				slog.String("client_id", client.ClientID),
				slog.String("user_id", ac.UserID),
				slog.String("grant_type", "authorization_code"),
				slog.String("reason", "pkce_failed"))
			tokenError(w, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	// Per OIDC core, refresh tokens are issued only when the grant has the
	// offline_access scope. Browsers can still re-establish tokens via a
	// silent /oauth2/authorize using the SSO session cookie.
	includeRefresh := client.AllowOfflineAccess && scopeIncludes(ac.Scope, scopeOfflineAccess)
	resp, err := b.issueUserTokens(ac.UserID, client.ClientID, ac.Scope, ac.Nonce, ac.AuthTime, ac.AMR, includeRefresh)
	if err != nil {
		tokenServerError(w, "issue tokens for authorization_code grant", err)
		return
	}
	b.auditEvent(r, auditEventTokenIssue, auditOutcomeSuccess,
		slog.String("client_id", client.ClientID),
		slog.String("user_id", ac.UserID),
		slog.String("grant_type", "authorization_code"),
		slog.String("scope", ac.Scope),
		slog.Bool("refresh_token", includeRefresh))
	writeJSON(w, http.StatusOK, resp)
}

//nolint:funlen // Each failure branch must emit its own audit event with the matching reason.
func (b *Broker) tokenRefresh(w http.ResponseWriter, r *http.Request, client Client) {
	rt := r.Form.Get("refresh_token")
	rtKey := hashSecret(rt)
	requestedScope := strings.TrimSpace(r.Form.Get("scope"))
	if handled, err := b.rejectConsumedRefreshToken(w, r, client, rtKey); err != nil {
		tokenServerError(w, "load consumed refresh token", err)
		return
	} else if handled {
		return
	}
	old, ok, err := b.store.GetRefreshToken(rtKey)
	if err != nil {
		tokenServerError(w, "load refresh token", err)
		return
	}
	if !ok {
		b.auditEvent(r, auditEventTokenIssue, auditOutcomeFailure,
			slog.String("client_id", client.ClientID),
			slog.String("grant_type", "refresh_token"),
			slog.String("reason", "unknown_refresh_token"))
		tokenError(w, "invalid_grant", "invalid refresh_token")
		return
	}
	if handled, err := b.rejectExpiredOrMismatchedRefreshToken(w, r, client, rtKey, old); err != nil {
		tokenServerError(w, "burn refresh token", err)
		return
	} else if handled {
		return
	}
	// Per RFC 6749 §6, the client may request a narrower scope on refresh,
	// but never one that exceeds the original grant. Reject scope expansion
	// without consuming the refresh token so the legitimate client can retry.
	if b.rejectRefreshScopeExpansion(w, r, client, old, requestedScope) {
		return
	}
	scope := old.Scope
	if requestedScope != "" {
		scope = requestedScope
	}
	rotation := b.newRefreshRotation(old, client.ClientID, scope)
	rotated, err := b.store.RotateRefreshToken(rtKey, rotation.key, rotation.next, rotation.consumed)
	if err != nil {
		tokenServerError(w, "rotate refresh token", err)
		return
	}
	if !rotated {
		// A concurrent request rotated this refresh token between our
		// GetRefreshToken and the rotation CAS. Treat as an honest retry:
		// return invalid_grant without re-reading the consumed bucket, so a
		// duplicate POST does not get reclassified as reuse and revoke the
		// family that the winning request just established. True reuse — a
		// second presentation after the rotation has fully committed — is
		// caught by rejectConsumedRefreshToken at the top of tokenRefresh.
		b.auditEvent(r, auditEventTokenIssue, auditOutcomeFailure,
			slog.String("client_id", client.ClientID),
			slog.String("user_id", old.UserID),
			slog.String("grant_type", "refresh_token"),
			slog.String("reason", "race_lost"))
		tokenError(w, "invalid_grant", "invalid refresh_token")
		return
	}
	resp, err := b.issueUserTokens(old.UserID, client.ClientID, scope, "", old.AuthTime, old.AMR, false)
	if err != nil {
		tokenServerError(w, "issue tokens for refresh_token grant", err)
		return
	}
	resp["refresh_token"] = rotation.plain
	b.auditEvent(r, auditEventTokenIssue, auditOutcomeSuccess,
		slog.String("client_id", client.ClientID),
		slog.String("user_id", old.UserID),
		slog.String("grant_type", "refresh_token"),
		slog.String("scope", scope),
		slog.Bool("refresh_token", true))
	writeJSON(w, http.StatusOK, resp)
}

func (b *Broker) rejectExpiredOrMismatchedRefreshToken(w http.ResponseWriter, r *http.Request, client Client, key string, old RefreshToken) (bool, error) {
	if !time.Now().After(old.ExpiresAt) && old.ClientID == client.ClientID {
		return false, nil
	}
	// Only delete the active token when it is actually expired. A client
	// mismatch by itself is treated as an audit-fail without mutating store
	// state: deleting on mismatch would let a hostile (but credentialed)
	// second client grief the legitimate holder by presenting their refresh
	// token to the wrong /token endpoint and burning it.
	expired := time.Now().After(old.ExpiresAt)
	reason := "client_mismatch"
	if expired {
		if _, err := b.store.DeleteRefreshToken(key); err != nil {
			return false, err
		}
		reason = "expired"
		if old.ClientID != client.ClientID {
			reason = "expired_and_client_mismatch"
		}
	}
	b.auditEvent(r, auditEventTokenIssue, auditOutcomeFailure,
		slog.String("client_id", client.ClientID),
		slog.String("user_id", old.UserID),
		slog.String("grant_type", "refresh_token"),
		slog.String("reason", reason))
	tokenError(w, "invalid_grant", "invalid refresh_token")
	return true, nil
}

func (b *Broker) rejectRefreshScopeExpansion(w http.ResponseWriter, r *http.Request, client Client, old RefreshToken, requestedScope string) bool {
	if requestedScope == "" || scopeSubset(requestedScope, old.Scope) {
		return false
	}
	b.auditEvent(r, auditEventTokenIssue, auditOutcomeFailure,
		slog.String("client_id", client.ClientID),
		slog.String("user_id", old.UserID),
		slog.String("grant_type", "refresh_token"),
		slog.String("reason", "scope_expansion"))
	tokenError(w, "invalid_scope", "requested scope exceeds original grant")
	return true
}

type refreshRotation struct {
	plain    string
	key      string
	next     RefreshToken
	consumed ConsumedRefreshToken
}

func (b *Broker) newRefreshRotation(old RefreshToken, clientID, scope string) refreshRotation {
	familyID := old.FamilyID
	if familyID == "" {
		familyID = randomB64(16)
	}
	plain := randomB64(32)
	next := RefreshToken{
		UserID:     old.UserID,
		ClientID:   clientID,
		Scope:      scope,
		AuthTime:   old.AuthTime,
		ExpiresAt:  time.Now().Add(time.Duration(b.cfg.RefreshTokenTTLDays) * 24 * time.Hour),
		AMR:        old.AMR,
		FamilyID:   familyID,
		Generation: old.Generation + 1,
	}
	consumed := ConsumedRefreshToken{
		UserID:    old.UserID,
		ClientID:  clientID,
		FamilyID:  familyID,
		ExpiresAt: old.ExpiresAt,
	}
	return refreshRotation{plain: plain, key: hashSecret(plain), next: next, consumed: consumed}
}

func (b *Broker) rejectConsumedRefreshToken(w http.ResponseWriter, r *http.Request, client Client, key string) (bool, error) {
	consumed, reused, err := b.store.GetConsumedRefreshToken(key)
	if err != nil {
		return false, err
	}
	if reused && !time.Now().After(consumed.ExpiresAt) {
		b.handleRefreshTokenReuse(w, r, client, consumed)
		return true, nil
	}
	return false, nil
}

func (b *Broker) handleRefreshTokenReuse(w http.ResponseWriter, r *http.Request, client Client, consumed ConsumedRefreshToken) {
	if consumed.ClientID == client.ClientID {
		if err := b.store.RevokeRefreshTokenFamily(consumed.FamilyID); err != nil {
			tokenServerError(w, "revoke refresh token family", err)
			return
		}
		b.auditEvent(r, auditEventRefreshReuse, auditOutcomeFailure,
			slog.String("client_id", client.ClientID),
			slog.String("user_id", consumed.UserID),
			slog.String("family_id", consumed.FamilyID))
	}
	tokenError(w, "invalid_grant", "invalid refresh_token")
}

func scopeSubset(requested, granted string) bool {
	grantedSet := map[string]bool{}
	for _, p := range strings.Fields(granted) {
		grantedSet[p] = true
	}
	for _, p := range strings.Fields(requested) {
		if !grantedSet[p] {
			return false
		}
	}
	return true
}

func (b *Broker) tokenClientCredentials(w http.ResponseWriter, r *http.Request, client Client) {
	if client.Public {
		b.auditEvent(r, auditEventTokenIssue, auditOutcomeFailure,
			slog.String("client_id", client.ClientID),
			slog.String("grant_type", "client_credentials"),
			slog.String("reason", "public_client"))
		tokenError(w, "unauthorized_client", "public clients cannot use client_credentials")
		return
	}
	now := time.Now()
	scope, err := validateClientCredentialsScope(client, r.Form.Get("scope"))
	if err != nil {
		b.auditEvent(r, auditEventTokenIssue, auditOutcomeFailure,
			slog.String("client_id", client.ClientID),
			slog.String("grant_type", "client_credentials"),
			slog.String("reason", "invalid_scope"))
		tokenError(w, "invalid_scope", err.Error())
		return
	}
	claims := map[string]any{
		"iss":       b.cfg.Issuer,
		"sub":       client.ClientID,
		"aud":       client.ClientID,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(time.Duration(b.cfg.AccessTokenTTLMinutes) * time.Minute).Unix(),
		"jti":       randomB64(16),
		"client_id": client.ClientID,
		"scope":     scope,
		"token_use": "access",
	}
	access, err := b.signJWT(claims)
	if err != nil {
		tokenServerError(w, "sign client_credentials access token", err)
		return
	}
	b.auditEvent(r, auditEventTokenIssue, auditOutcomeSuccess,
		slog.String("client_id", client.ClientID),
		slog.String("grant_type", "client_credentials"),
		slog.String("scope", scope))
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   b.cfg.AccessTokenTTLMinutes * 60,
		"scope":        scope,
	})
}

// OIDC `amr` values recorded for each authentication method we support, per
// RFC 8176. `pwd` is password authentication; `otp` covers TOTP; `hwk` marks
// WebAuthn (proof-of-possession of a hardware/software key); `mfa` is added
// whenever more than one factor was used at this login.
const (
	amrPassword = "pwd"
	amrOTP      = "otp"
	amrWebAuthn = "hwk"
	amrMFA      = "mfa"
)

//nolint:funlen // Access and ID token claims are intentionally assembled together.
func (b *Broker) issueUserTokens(userID, clientID, scope, nonce string, authTime time.Time, amr []string, includeRefresh bool) (map[string]any, error) {
	user, _ := b.store.GetUser(userID)
	now := time.Now()
	accessJTI := randomB64(16)
	accessClaims := map[string]any{
		"iss":                b.cfg.Issuer,
		"sub":                userID,
		"aud":                clientID,
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"exp":                now.Add(time.Duration(b.cfg.AccessTokenTTLMinutes) * time.Minute).Unix(),
		"jti":                accessJTI,
		"client_id":          clientID,
		"scope":              scope,
		"preferred_username": userID,
		"token_use":          "access",
	}
	b.addScopedProfileClaims(accessClaims, user, scope, clientID)
	access, err := b.signJWT(accessClaims)
	if err != nil {
		return nil, err
	}

	resp := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   b.cfg.AccessTokenTTLMinutes * 60,
		"scope":        scope,
	}
	// Per OIDC Core §3.1.2.1, the `openid` scope is the marker that this is an
	// OIDC request rather than a plain OAuth2 request — and only OIDC requests
	// receive an id_token. Without this gate, a non-OIDC client asking for
	// `profile email` alone would still get an id_token, which is a protocol
	// violation and exposes user claims the caller never asked for.
	if scopeIncludes(scope, scopeOpenID) {
		atHashSum := sha256.Sum256([]byte(access))
		idClaims := map[string]any{
			"iss":                b.cfg.Issuer,
			"sub":                userID,
			"aud":                clientID,
			"iat":                now.Unix(),
			"exp":                now.Add(time.Duration(b.cfg.IDTokenTTLMinutes) * time.Minute).Unix(),
			"auth_time":          authTime.Unix(),
			"preferred_username": userID,
			"at_hash":            base64RawURL(atHashSum[:sha256.Size/2]),
		}
		if len(amr) > 0 {
			idClaims["amr"] = amr
		}
		if nonce != "" {
			idClaims["nonce"] = nonce
		}
		b.addScopedProfileClaims(idClaims, user, scope, clientID)
		idToken, err := b.signJWT(idClaims)
		if err != nil {
			return nil, err
		}
		resp["id_token"] = idToken
	}
	if includeRefresh {
		rt := randomB64(32)
		refreshToken := RefreshToken{
			UserID:     userID,
			ClientID:   clientID,
			Scope:      scope,
			AuthTime:   authTime,
			ExpiresAt:  now.Add(time.Duration(b.cfg.RefreshTokenTTLDays) * 24 * time.Hour),
			AMR:        amr,
			FamilyID:   randomB64(16),
			Generation: 0,
		}
		if err := b.store.PutRefreshToken(hashSecret(rt), refreshToken); err != nil {
			return nil, err
		}
		resp["refresh_token"] = rt
	}
	return resp, nil
}

//nolint:nestif // Optional profile and group claims are grouped by source.
func (b *Broker) issueAppToken(sess Session, tokenCfg AppTokenConfig) (string, error) {
	user, _ := b.store.GetUser(sess.UserID)
	now := time.Now()
	scope := strings.TrimSpace(tokenCfg.Scope)
	claims := map[string]any{
		"iss":                b.cfg.Issuer,
		"sub":                sess.UserID,
		"aud":                tokenCfg.Audience,
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"exp":                now.Add(time.Duration(tokenCfg.TokenTTLMinutes) * time.Minute).Unix(),
		"jti":                randomB64(16),
		"client_id":          tokenCfg.ClientID,
		"scope":              scope,
		"auth_time":          sess.AuthTime.Unix(),
		"preferred_username": sess.UserID,
		"user_id":            sess.UserID,
		"app_token_id":       tokenCfg.ID,
		"token_use":          "access",
	}
	if user != nil {
		if scopeIncludes(scope, "email") {
			claims["email"] = user.Email
			if user.Email != "" {
				claims["user_email"] = user.Email
			}
		}
		if scopeIncludes(scope, "profile") {
			claims["name"] = displayName(user)
		}
		if scopeIncludes(scope, "groups") {
			if groups := mappedAppTokenGroups(tokenCfg.compiledMappings, user.Groups); len(groups) > 0 {
				claims["groups"] = groups
			}
		}
	}
	return b.signJWT(claims)
}

// addScopedProfileClaims writes OIDC profile/email/groups claims into target,
// each gated on the corresponding requested scope (OIDC Core §5.4). The
// helper is shared by access tokens, ID tokens, and UserInfo so all three
// surfaces honor the same consent decisions.
func (b *Broker) addScopedProfileClaims(target map[string]any, user *StoredUser, scope, clientID string) {
	if user == nil {
		return
	}
	if scopeIncludes(scope, "email") {
		target["email"] = user.Email
	}
	if scopeIncludes(scope, "profile") {
		target["name"] = displayName(user)
	}
	if scopeIncludes(scope, "groups") {
		if groups := b.mappedGroupsForClient(clientID, user); len(groups) > 0 {
			target["groups"] = groups
		}
	}
}

func displayName(u *StoredUser) string {
	if u == nil {
		return ""
	}
	if u.Name != "" {
		return u.Name
	}
	return u.Username
}

func (b *Broker) mappedGroupsForClient(clientID string, user *StoredUser) []string {
	if user == nil {
		return nil
	}
	client, ok := b.lookupClient(clientID)
	if !ok {
		return nil
	}
	return mappedClientGroups(client, user.Groups)
}

// userInfoBearerToken extracts the access token per RFC 6750. The
// Authorization: Bearer header takes precedence; for POST requests with a
// form-encoded body, the `access_token` parameter is also accepted, as
// required by OIDC Core §5.3.1.
//
// The body cap is applied unconditionally for POST regardless of which branch
// reads the body. This is defensive: today the Authorization-header branch
// never touches r.Body, but a future change that does (e.g. logging) cannot
// accidentally pull an unbounded payload.
func userInfoBearerToken(w http.ResponseWriter, r *http.Request) string {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxUserInfoBodyBytes)
	}
	authz := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(authz, bearerPrefix))
	if token != "" && token != authz {
		return token
	}
	if r.Method != http.MethodPost {
		return ""
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if ct != "application/x-www-form-urlencoded" {
		return ""
	}
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return strings.TrimSpace(r.PostForm.Get("access_token"))
}

func (b *Broker) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := userInfoBearerToken(w, r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="userinfo"`)
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	claims, err := b.verifyJWT(token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if tokenUse, _ := claims["token_use"].(string); tokenUse != "access" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="userinfo requires an access token"`)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	sub, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	if clientID == "" {
		clientID, _ = claims["aud"].(string)
	}
	scope, _ := claims["scope"].(string)
	user, _ := b.store.GetUser(sub)
	resp := map[string]any{
		"sub":                sub,
		"preferred_username": sub,
	}
	// Mirror the scope gating used at token issuance so UserInfo can't be
	// used to bypass an `openid`-only consent.
	b.addScopedProfileClaims(resp, user, scope, clientID)
	writeJSON(w, http.StatusOK, resp)
}

// handleIntrospect implements OAuth 2.0 Token Introspection (RFC 7662). The
// requesting client must authenticate, the response is always 200 with a JSON
// body, and active=true is returned only when the token was issued to the
// authenticated client (matching its client_id or audience). Any other state —
// unknown, expired, revoked, signed by an unknown key, or owned by a different
// client — is reported as {"active": false} so the endpoint cannot be used as
// a token oracle by an unrelated client.
func (b *Broker) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxIntrospectBodyBytes)
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "bad form")
		return
	}
	client, retry, err := b.authenticateClientRateLimited(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspect"`)
		b.auditEvent(r, auditEventTokenIntrospect, auditOutcomeFailure,
			slog.String("reason", "unauthenticated_client"))
		if errors.Is(err, errClientAuthRateLimited) {
			writeRetryAfter(w, retry)
			tokenErrorStatus(w, http.StatusTooManyRequests, "invalid_client", "too many client authentication attempts")
			return
		}
		tokenErrorStatus(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	tok := strings.TrimSpace(r.Form.Get("token"))
	if tok == "" {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	hint := r.Form.Get("token_type_hint")
	resp, ok := b.introspectToken(tok, hint, client)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, resp)
}

// introspectToken returns the active introspection response for tok when it
// belongs to client. token_type_hint just reorders the lookup attempts; when
// the hint is wrong or absent we still try the other shape, per RFC 7662 §2.1.
//
// Without a hint we try JWT first because verifyJWT is the cheap rejection
// path for opaque (refresh) tokens — it fails on the first malformed segment
// before any store lookup. Most non-refresh tokens reach this endpoint as
// JWTs, so JWT-first short-circuits the common case; refresh-token
// introspection still works via the fall-through to introspectRefreshToken.
func (b *Broker) introspectToken(tok, hint string, client Client) (map[string]any, bool) {
	tryRefreshFirst := hint == "refresh_token"
	if tryRefreshFirst {
		if resp, ok := b.introspectRefreshToken(tok, client); ok {
			return resp, true
		}
		return b.introspectJWT(tok, client)
	}
	if resp, ok := b.introspectJWT(tok, client); ok {
		return resp, true
	}
	return b.introspectRefreshToken(tok, client)
}

func (b *Broker) introspectRefreshToken(tok string, client Client) (map[string]any, bool) {
	rt, ok, err := b.store.GetRefreshToken(hashSecret(tok))
	if err != nil || !ok {
		return nil, false
	}
	if rt.ClientID != client.ClientID {
		return nil, false
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, false
	}
	resp := map[string]any{
		"active":     true,
		"token_type": "Bearer",
		"client_id":  rt.ClientID,
		"sub":        rt.UserID,
		"username":   rt.UserID,
		"aud":        rt.ClientID,
		"iss":        b.cfg.Issuer,
		"exp":        rt.ExpiresAt.Unix(),
	}
	if rt.Scope != "" {
		resp["scope"] = rt.Scope
	}
	return resp, true
}

func (b *Broker) introspectJWT(tok string, client Client) (map[string]any, bool) {
	claims, err := b.verifyJWT(tok)
	if err != nil {
		return nil, false
	}
	if !introspectClientOwnsToken(claims, client.ClientID) {
		return nil, false
	}
	resp := map[string]any{
		"active":     true,
		"token_type": "Bearer",
	}
	for _, k := range []string{"iss", "sub", "aud", "client_id", "scope", "jti", "token_use"} {
		if v, ok := claims[k]; ok {
			resp[k] = v
		}
	}
	for _, k := range []string{"exp", "iat", "nbf", "auth_time"} {
		if v, ok := numberClaim(claims[k]); ok {
			resp[k] = v
		}
	}
	if sub, ok := claims["sub"].(string); ok {
		resp["username"] = sub
		if name, ok := claims["preferred_username"].(string); ok && name != "" {
			resp["username"] = name
		}
	}
	return resp, true
}

// introspectClientOwnsToken reports whether the authenticated client is
// entitled to introspect the token. We accept either a client_id claim match
// (the common case for tokens issued to this client) or an aud claim match
// (so a resource server with its own credentials can introspect app tokens
// minted for its audience).
func introspectClientOwnsToken(claims map[string]any, clientID string) bool {
	if cid, _ := claims["client_id"].(string); cid == clientID {
		return true
	}
	switch aud := claims["aud"].(type) {
	case string:
		return aud == clientID
	case []any:
		for _, v := range aud {
			if s, ok := v.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

func (b *Broker) handleRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRevokeBodyBytes)
	_ = r.ParseForm()
	client, retry, err := b.authenticateClientRateLimited(r)
	if err != nil {
		// RFC 7009 expects client authentication; still avoid token oracle details.
		b.auditEvent(r, auditEventTokenRevoke, auditOutcomeFailure,
			slog.String("reason", "unauthenticated_client"))
		if errors.Is(err, errClientAuthRateLimited) {
			writeRetryAfter(w, retry)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tok := r.Form.Get("token")
	if err := b.revokeRefreshToken(tok, client); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if err := b.revokeJWT(tok, client); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	b.auditEvent(r, auditEventTokenRevoke, auditOutcomeSuccess,
		slog.String("client_id", client.ClientID))
	w.WriteHeader(http.StatusOK)
}

func (b *Broker) revokeRefreshToken(tok string, client Client) error {
	if tok == "" {
		return nil
	}
	key := hashSecret(tok)
	rt, ok, err := b.store.GetRefreshToken(key)
	if err != nil {
		return err
	}
	if !ok || rt.ClientID != client.ClientID {
		return nil
	}
	_, err = b.store.DeleteRefreshToken(key)
	return err
}

func (b *Broker) revokeJWT(tok string, client Client) error {
	claims, err := b.verifyJWT(tok)
	if err != nil {
		return nil
	}
	// Use clientIDFromTokenClaims so multi-audience tokens (azp present, or
	// aud as a single-element array) resolve to the authoritative client
	// rather than yielding "" and silently skipping the revoke.
	owner := clientIDFromTokenClaims(claims)
	jti, _ := claims["jti"].(string)
	expUnix, ok := numberClaim(claims["exp"])
	if owner != client.ClientID || jti == "" || !ok {
		return nil
	}
	return b.store.PutRevokedJTI(jti, time.Unix(expUnix, 0).Add(jwtClockSkew))
}

// clientAllowsRedirect / clientAllowsPostLogoutRedirect intentionally compare
// by exact byte-for-byte string equality, per OAuth 2.1 §4.1.2.2 ("Loopback
// Interface Redirection" excepted, which this broker does not implement).
// A trailing slash, an explicit `:443`, an added/dropped fragment, or any
// percent-encoding difference will NOT match. Do NOT change this to a
// url.Parse + structural compare — partial matches and host-only comparisons
// have repeatedly been the source of redirect-URI bypass CVEs across OAuth
// implementations. Operators must register the exact URI the client uses.
func clientAllowsRedirect(c Client, redirectURI string) bool {
	for _, allowed := range c.RedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func clientAllowsPostLogoutRedirect(c Client, redirectURI string) bool {
	for _, allowed := range c.PostLogoutRedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, code, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // redirectURI was already verified by clientAllowsRedirect against the registered redirect_uris (exact string match), so it cannot be attacker-controlled.
}

func tokenError(w http.ResponseWriter, code, desc string) {
	tokenErrorStatus(w, http.StatusBadRequest, code, desc)
}

func tokenErrorStatus(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// tokenServerError logs the underlying error server-side and returns a generic
// server_error response. Token-endpoint responses must not leak internal error
// strings (file paths, store internals) to OAuth clients.
func tokenServerError(w http.ResponseWriter, what string, err error) {
	log.Printf("token endpoint %s: %v", what, err)
	tokenErrorStatus(w, http.StatusInternalServerError, "server_error", "internal error")
}
