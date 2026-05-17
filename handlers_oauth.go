package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (b *Broker) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	client, ok := b.clients[q.Get("client_id")]
	if !ok {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !clientAllowsRedirect(client, redirectURI) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
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
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(time.Duration(b.cfg.AuthCodeTTLSeconds) * time.Second),
	}

	if sess, ok := b.validSession(r); ok {
		b.maybeExtendSession(w, r)
		if err := b.issueCodeRedirect(w, r, authReq, sess); err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
		}
		return
	}

	if err := b.putAuthRequest(authReq); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login?request_id="+url.QueryEscape(authReq.ID), http.StatusFound)
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
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.updateRuntimeStateLocked(func(state *StoredRuntimeState) (bool, error) {
		state.AuthRequests[ar.ID] = ar
		return true, nil
	})
}

func (b *Broker) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBodyBytes)
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "bad form")
		return
	}
	client, err := b.authenticateClient(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
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

func (b *Broker) authenticateClient(r *http.Request) (Client, error) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	client, exists := b.clients[id]
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

func (b *Broker) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request, client Client) {
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	codeKey := hashSecret(code)

	b.mu.Lock()
	var ac AuthCode
	var ok bool
	persistErr := b.updateRuntimeStateLocked(func(state *StoredRuntimeState) (bool, error) {
		ac, ok = state.AuthCodes[codeKey]
		if !ok {
			return false, nil
		}
		delete(state.AuthCodes, codeKey)
		return true, nil
	})
	b.mu.Unlock()
	if persistErr != nil {
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", persistErr.Error())
		return
	}

	if !ok || time.Now().After(ac.ExpiresAt) {
		tokenError(w, "invalid_grant", "invalid or expired code")
		return
	}
	if ac.ClientID != client.ClientID || ac.RedirectURI != redirectURI {
		tokenError(w, "invalid_grant", "client or redirect_uri mismatch")
		return
	}
	if ac.CodeChallenge != "" {
		verifier := r.Form.Get("code_verifier")
		if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, verifier) {
			tokenError(w, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	// Per OIDC core, refresh tokens are issued only when the grant has the
	// offline_access scope. Browsers can still re-establish tokens via a
	// silent /oauth2/authorize using the SSO session cookie.
	includeRefresh := scopeIncludes(ac.Scope, "offline_access")
	resp, err := b.issueUserTokens(ac.UserID, client.ClientID, ac.Scope, ac.Nonce, ac.AuthTime, includeRefresh)
	if err != nil {
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (b *Broker) tokenRefresh(w http.ResponseWriter, r *http.Request, client Client) {
	rt := r.Form.Get("refresh_token")
	rtKey := hashSecret(rt)
	requestedScope := strings.TrimSpace(r.Form.Get("scope"))
	b.mu.Lock()
	var old RefreshToken
	var ok bool
	invalidGrant := false
	invalidScope := false
	err := b.updateRuntimeStateLocked(func(state *StoredRuntimeState) (bool, error) {
		old, ok = state.RefreshTokens[rtKey]
		if !ok {
			invalidGrant = true
			return false, nil
		}
		if time.Now().After(old.ExpiresAt) || old.ClientID != client.ClientID {
			delete(state.RefreshTokens, rtKey)
			invalidGrant = true
			return true, nil
		}
		// Per RFC 6749 §6, the client may request a narrower scope on refresh,
		// but never one that exceeds the original grant. Reject scope expansion
		// without consuming the refresh token so the legitimate client can retry.
		if requestedScope != "" && !scopeSubset(requestedScope, old.Scope) {
			invalidScope = true
			return false, nil
		}
		delete(state.RefreshTokens, rtKey) // refresh token rotation
		return true, nil
	})
	b.mu.Unlock()
	if err != nil {
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if invalidGrant {
		tokenError(w, "invalid_grant", "invalid refresh_token")
		return
	}
	if invalidScope {
		tokenError(w, "invalid_scope", "requested scope exceeds original grant")
		return
	}
	scope := old.Scope
	if requestedScope != "" {
		scope = requestedScope
	}
	resp, err := b.issueUserTokens(old.UserID, client.ClientID, scope, "", old.AuthTime, true)
	if err != nil {
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
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
		tokenError(w, "unauthorized_client", "public clients cannot use client_credentials")
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss":       b.cfg.Issuer,
		"sub":       client.ClientID,
		"aud":       client.ClientID,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(time.Duration(b.cfg.AccessTokenTTLMinutes) * time.Minute).Unix(),
		"jti":       randomB64(16),
		"client_id": client.ClientID,
		"scope":     r.Form.Get("scope"),
		"token_use": "access",
	}
	access, err := b.signJWT(claims)
	if err != nil {
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   b.cfg.AccessTokenTTLMinutes * 60,
		"scope":        r.Form.Get("scope"),
	})
}

//nolint:gocognit,funlen // Access and ID token claims are intentionally assembled together.
func (b *Broker) issueUserTokens(userID, clientID, scope, nonce string, authTime time.Time, includeRefresh bool) (map[string]any, error) {
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
	if user != nil {
		accessClaims["email"] = user.Email
		accessClaims["name"] = displayName(user)
		if scopeIncludes(scope, "groups") {
			if groups := b.mappedGroupsForClient(clientID, user); len(groups) > 0 {
				accessClaims["groups"] = groups
			}
		}
	}
	access, err := b.signJWT(accessClaims)
	if err != nil {
		return nil, err
	}

	idClaims := map[string]any{
		"iss":                b.cfg.Issuer,
		"sub":                userID,
		"aud":                clientID,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Duration(b.cfg.IDTokenTTLMinutes) * time.Minute).Unix(),
		"auth_time":          authTime.Unix(),
		"preferred_username": userID,
	}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	if user != nil {
		idClaims["email"] = user.Email
		idClaims["name"] = displayName(user)
		if scopeIncludes(scope, "groups") {
			if groups := b.mappedGroupsForClient(clientID, user); len(groups) > 0 {
				idClaims["groups"] = groups
			}
		}
	}
	idToken, err := b.signJWT(idClaims)
	if err != nil {
		return nil, err
	}

	resp := map[string]any{
		"access_token": access,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   b.cfg.AccessTokenTTLMinutes * 60,
		"scope":        scope,
	}
	if includeRefresh {
		rt := randomB64(32)
		refreshToken := RefreshToken{
			UserID:    userID,
			ClientID:  clientID,
			Scope:     scope,
			AuthTime:  authTime,
			ExpiresAt: now.Add(time.Duration(b.cfg.RefreshTokenTTLDays) * 24 * time.Hour),
		}
		b.mu.Lock()
		if err := b.updateRuntimeStateLocked(func(state *StoredRuntimeState) (bool, error) {
			state.RefreshTokens[hashSecret(rt)] = refreshToken
			return true, nil
		}); err != nil {
			b.mu.Unlock()
			return nil, err
		}
		b.mu.Unlock()
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
		claims["email"] = user.Email
		claims["name"] = displayName(user)
		if user.Email != "" {
			claims["user_email"] = user.Email
		}
		if scopeIncludes(scope, "groups") {
			if groups := mappedAppTokenGroups(tokenCfg.GroupMappings, user.Groups); len(groups) > 0 {
				claims["groups"] = groups
			}
		}
	}
	return b.signJWT(claims)
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
	client, ok := b.clients[clientID]
	if !ok {
		return nil
	}
	return mappedClientGroups(client, user.Groups)
}

func (b *Broker) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), bearerPrefix))
	if token == r.Header.Get("Authorization") || token == "" {
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
	if user != nil {
		resp["email"] = user.Email
		resp["name"] = displayName(user)
		if scopeIncludes(scope, "groups") {
			if groups := b.mappedGroupsForClient(clientID, user); len(groups) > 0 {
				resp["groups"] = groups
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (b *Broker) handleRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRevokeBodyBytes)
	_ = r.ParseForm()
	client, err := b.authenticateClient(r)
	if err != nil {
		// RFC 7009 expects client authentication; still avoid token oracle details.
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
	w.WriteHeader(http.StatusOK)
}

func (b *Broker) revokeRefreshToken(tok string, client Client) error {
	if tok == "" {
		return nil
	}
	key := hashSecret(tok)
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.updateRuntimeStateLocked(func(state *StoredRuntimeState) (bool, error) {
		if rt, ok := state.RefreshTokens[key]; ok && rt.ClientID == client.ClientID {
			delete(state.RefreshTokens, key)
			return true, nil
		}
		return false, nil
	})
}

func (b *Broker) revokeJWT(tok string, client Client) error {
	claims, err := b.verifyJWT(tok)
	if err != nil {
		return nil
	}
	aud, _ := claims["aud"].(string)
	jti, _ := claims["jti"].(string)
	expUnix, ok := numberClaim(claims["exp"])
	if aud != client.ClientID || jti == "" || !ok {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.updateRuntimeStateLocked(func(state *StoredRuntimeState) (bool, error) {
		state.RevokedJTIs[jti] = time.Unix(expUnix, 0)
		return true, nil
	})
}

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
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // redirect URI was validated against the registered client redirect_uris.
}

func tokenError(w http.ResponseWriter, code, desc string) {
	tokenErrorStatus(w, http.StatusBadRequest, code, desc)
}

func tokenErrorStatus(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}
