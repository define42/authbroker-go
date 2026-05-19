package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func addSessionCookie(req *http.Request, sid string) {
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec // Test attaches a synthetic session cookie.
}

func TestHandleStylesheetAndScript(t *testing.T) {
	broker := newLogoutTestBroker(t)

	cssReq := httptest.NewRequest(http.MethodGet, "/assets/authbroker.css", nil)
	cssRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(cssRR, cssReq)
	if cssRR.Code != http.StatusOK {
		t.Fatalf("css status = %d", cssRR.Code)
	}
	if ct := cssRR.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("css Content-Type = %q", ct)
	}
	if cssRR.Body.Len() == 0 {
		t.Fatal("css body is empty")
	}

	jsReq := httptest.NewRequest(http.MethodGet, "/assets/authbroker.js", nil)
	jsRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(jsRR, jsReq)
	if jsRR.Code != http.StatusOK {
		t.Fatalf("js status = %d", jsRR.Code)
	}
	if ct := jsRR.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/javascript") {
		t.Fatalf("js Content-Type = %q", ct)
	}
}

func TestHandleHealthAndJWKS(t *testing.T) {
	broker := newLogoutTestBroker(t)

	healthReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(healthRR, healthReq)
	if healthRR.Code != http.StatusOK {
		t.Fatalf("health status = %d", healthRR.Code)
	}
	if !strings.Contains(healthRR.Body.String(), `"status":"ok"`) {
		t.Fatalf("health body = %q", healthRR.Body.String())
	}

	jwksReq := httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil)
	jwksRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(jwksRR, jwksReq)
	if jwksRR.Code != http.StatusOK {
		t.Fatalf("jwks status = %d", jwksRR.Code)
	}
	var jwks map[string]any
	if err := json.Unmarshal(jwksRR.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	keys, _ := jwks["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("jwks contained no keys")
	}
}

func TestHandleHomeNotFound(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodGet, "/no-such-path", nil)
	rr := httptest.NewRecorder()
	broker.handleHome(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestAuthorizeRejectsBadResponseType(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=token&client_id=demo-web", nil)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAuthorizeRejectsUnknownClient(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=missing", nil)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestAuthorizeRejectsBadRedirect(t *testing.T) {
	broker := newLogoutTestBroker(t)
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {"demo-web"},
		"redirect_uri":  {"http://evil/"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestAuthorizePKCEErrorRedirectsToClient(t *testing.T) {
	broker := newLogoutTestBroker(t)
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {"demo-web"},
		"redirect_uri":  {"http://app.example/callback"},
		"state":         {"xyz"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location %q: %v", loc, err)
	}
	if got := u.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("error = %q", got)
	}
	if got := u.Query().Get("state"); got != "xyz" {
		t.Fatalf("state = %q", got)
	}
}

func TestAuthorizePKCEErrorBadRedirectFallsBack(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	redirectOAuthError(rr, req, "://bad redirect", "", "invalid_request", "boom")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

// TestAuthorizePromptNoneWithoutSessionReturnsLoginRequired exercises OIDC
// Core §3.1.2.1: with prompt=none and no active session, the broker must
// redirect back to the client with error=login_required instead of showing
// the login page.
func TestAuthorizePromptNoneWithoutSessionReturnsLoginRequired(t *testing.T) {
	broker := newLogoutTestBroker(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"abc"},
		"prompt":                {"none"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := u.Query().Get("error"); got != "login_required" {
		t.Fatalf("error = %q, want login_required", got)
	}
	if got := u.Query().Get("state"); got != "abc" {
		t.Fatalf("state = %q, want abc", got)
	}
	if u.Scheme+"://"+u.Host+u.Path != "http://app.example/callback" {
		t.Fatalf("redirect target = %q, want http://app.example/callback", u.String())
	}
}

// TestAuthorizePromptNoneWithSessionIssuesCode confirms that prompt=none
// silently completes the grant when the user is already authenticated and the
// client does not require consent.
func TestAuthorizePromptNoneWithSessionIssuesCode(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "sess-prompt-none"
	if err := broker.store.PutSession(sid, Session{
		UserID:    "johndoe",
		ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: "csrf",
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"abc"},
		"prompt":                {"none"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := u.Query().Get("error"); got != "" {
		t.Fatalf("unexpected error = %q", got)
	}
	if got := u.Query().Get("code"); got == "" {
		t.Fatalf("missing authorization code in %q", u.String())
	}
}

// TestAuthorizePromptNoneConsentRequired covers the other §3.1.2.1 silent
// failure: session is valid but the client requires consent the user hasn't
// granted, so the broker must return consent_required instead of showing the
// consent UI.
func TestAuthorizePromptNoneConsentRequired(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "alice", false)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"scope":                 {"openid profile"},
		"state":                 {"st"},
		"prompt":                {"none"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := u.Query().Get("error"); got != "consent_required" {
		t.Fatalf("error = %q, want consent_required (location=%s)", got, u.String())
	}
	if got := u.Query().Get("state"); got != "st" {
		t.Fatalf("state = %q, want st", got)
	}
}

// TestAuthorizePromptLoginForcesReauthentication exercises OIDC Core
// §3.1.2.1: prompt=login MUST force a fresh login even when the SSO session
// is still valid, so the broker must redirect to the login page instead of
// issuing a code directly from the existing session.
func TestAuthorizePromptLoginForcesReauthentication(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "sess-prompt-login"
	if err := broker.store.PutSession(sid, Session{
		UserID:    "johndoe",
		ExpiresAt: time.Now().Add(time.Hour),
		AuthTime:  time.Now().Add(-time.Hour),
		CSRFToken: "csrf",
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"abc"},
		"prompt":                {"login"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?request_id=") {
		t.Fatalf("location = %q, want /login redirect (prompt=login must bypass existing session)", loc)
	}
}

// TestAuthorizePromptLoginWithoutSessionStillRedirectsToLogin verifies the
// degenerate case: prompt=login when no session exists behaves like the
// default unauthenticated flow.
func TestAuthorizePromptLoginWithoutSessionStillRedirectsToLogin(t *testing.T) {
	broker := newLogoutTestBroker(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"prompt":                {"login"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "/login?request_id=") {
		t.Fatalf("location = %q, want /login redirect", loc)
	}
}

// TestAuthorizePromptNoneRejectsCombination enforces the §3.1.2.1 rule that
// the "none" value MUST NOT appear alongside any other prompt value; the
// broker must surface invalid_request.
func TestAuthorizePromptNoneRejectsCombination(t *testing.T) {
	broker := newLogoutTestBroker(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"abc"},
		"prompt":                {"none login"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := u.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
}

// TestAuthorizeMaxAgeStaleForcesReauthentication exercises OIDC Core
// §3.1.2.1 max_age: when the session's auth_time is older than max_age
// seconds, the broker must re-authenticate the user rather than silently
// reuse the existing session.
func TestAuthorizeMaxAgeStaleForcesReauthentication(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "sess-stale"
	if err := broker.store.PutSession(sid, Session{
		UserID:    "johndoe",
		ExpiresAt: time.Now().Add(time.Hour),
		AuthTime:  time.Now().Add(-2 * time.Hour),
		CSRFToken: "csrf",
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"max_age":               {"60"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "/login?request_id=") {
		t.Fatalf("location = %q, want /login redirect (stale auth_time must force reauth)", loc)
	}
}

// TestAuthorizeMaxAgeFreshAllowsExistingSession covers the inverse path: a
// session within the max_age window must continue to short-circuit to a code.
func TestAuthorizeMaxAgeFreshAllowsExistingSession(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "sess-fresh"
	if err := broker.store.PutSession(sid, Session{
		UserID:    "johndoe",
		ExpiresAt: time.Now().Add(time.Hour),
		AuthTime:  time.Now(),
		CSRFToken: "csrf",
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"max_age":               {"3600"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	u, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := u.Query().Get("code"); got == "" {
		t.Fatalf("missing code in %q", u.String())
	}
}

// TestAuthorizeMaxAgeRejectsMalformed covers the parser: a non-numeric
// max_age must produce invalid_request rather than be silently ignored.
func TestAuthorizeMaxAgeRejectsMalformed(t *testing.T) {
	broker := newLogoutTestBroker(t)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"max_age":               {"not-a-number"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	u, _ := url.Parse(rr.Header().Get("Location"))
	if got := u.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
}

// TestIssueUserTokensEmitsAMRClaim verifies the id_token carries the OIDC
// `amr` array reflecting the authentication methods used at this login.
func TestIssueUserTokensEmitsAMRClaim(t *testing.T) {
	broker := newLogoutTestBroker(t)
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid", "",
		time.Now(), []string{amrPassword, amrOTP, amrMFA}, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	idToken, _ := tokens["id_token"].(string)
	claims, err := broker.verifyJWT(idToken)
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	rawAMR, ok := claims["amr"].([]any)
	if !ok {
		t.Fatalf("amr claim missing or wrong type: %#v", claims["amr"])
	}
	got := make([]string, len(rawAMR))
	for i, v := range rawAMR {
		got[i], _ = v.(string)
	}
	want := []string{amrPassword, amrOTP, amrMFA}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("amr = %v, want %v", got, want)
	}
}

// TestIssueUserTokensOmitsAMRWhenEmpty checks that we don't emit an empty
// `amr` claim — the id_token simply omits it when no method was recorded.
func TestIssueUserTokensOmitsAMRWhenEmpty(t *testing.T) {
	broker := newLogoutTestBroker(t)
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := broker.verifyJWT(tokens["id_token"].(string))
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if _, present := claims["amr"]; present {
		t.Fatalf("amr must be absent when no methods recorded, got %#v", claims["amr"])
	}
}

// TestUserInfoAcceptsPOSTWithBearerHeader checks the §5.3 requirement that
// /oauth2/userinfo accepts POST with the access token in the Authorization
// header.
func TestUserInfoAcceptsPOSTWithBearerHeader(t *testing.T) {
	broker := newLogoutTestBroker(t)
	if _, err := broker.store.UpsertProfile(UserProfile{Subject: "johndoe", Email: "j@e", Name: "John"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	access := tokens["access_token"].(string)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", bearerPrefix+access)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["sub"] != "johndoe" {
		t.Fatalf("sub = %v", resp["sub"])
	}
}

// TestUserInfoAcceptsPOSTWithFormToken covers the RFC 6750 §2.2 form-encoded
// body method: the access token may also be supplied in the request body of
// a POST.
func TestUserInfoAcceptsPOSTWithFormToken(t *testing.T) {
	broker := newLogoutTestBroker(t)
	if _, err := broker.store.UpsertProfile(UserProfile{Subject: "johndoe", Email: "j@e", Name: "John"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	form := url.Values{"access_token": {tokens["access_token"].(string)}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/userinfo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleTokenBadGrant(t *testing.T) {
	broker := newLogoutTestBroker(t)
	form := url.Values{"grant_type": {"unsupported"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleToken(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unsupported_grant_type") {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestHandleTokenRejectsBadClient(t *testing.T) {
	broker := newLogoutTestBroker(t)
	form := url.Values{"grant_type": {"authorization_code"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "wrong-secret")
	rr := httptest.NewRecorder()
	broker.handleToken(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate header")
	}
}

func TestTokenClientCredentialsIssues(t *testing.T) {
	broker := newLogoutTestBroker(t)
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"openid groups"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["access_token"] == nil {
		t.Fatalf("body missing access_token: %#v", body)
	}
}

func TestTokenRefreshSuccess(t *testing.T) {
	broker := newLogoutTestBroker(t)
	now := time.Now()
	rt := "raw-refresh"
	if err := broker.store.PutRefreshToken(hashSecret(rt), RefreshToken{
		UserID:    "johndoe",
		ClientID:  "demo-web",
		Scope:     "openid profile",
		AuthTime:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"scope":         {"openid"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok, _ := broker.store.GetRefreshToken(hashSecret(rt)); ok {
		t.Fatal("refresh token was not rotated")
	}
}

func TestTokenRefreshRejectsExpired(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rt := "expired-refresh"
	if err := broker.store.PutRefreshToken(hashSecret(rt), RefreshToken{
		UserID:    "johndoe",
		ClientID:  "demo-web",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleToken(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestTokenRefreshRejectsScopeExpansion(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rt := "scope-refresh"
	if err := broker.store.PutRefreshToken(hashSecret(rt), RefreshToken{
		UserID:    "johndoe",
		ClientID:  "demo-web",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"scope":         {"openid groups"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleToken(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid_scope") {
		t.Fatalf("body = %q", rr.Body.String())
	}
	if _, ok, _ := broker.store.GetRefreshToken(hashSecret(rt)); !ok {
		t.Fatal("refresh token must survive scope expansion rejection")
	}
}

func TestTokenRefreshUnknown(t *testing.T) {
	broker := newLogoutTestBroker(t)
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"never-issued"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleToken(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestScopeSubset(t *testing.T) {
	if !scopeSubset("openid", "openid groups") {
		t.Fatal("openid is subset of openid groups")
	}
	if scopeSubset("openid groups", "openid") {
		t.Fatal("openid groups is not subset of openid")
	}
	if !scopeSubset("", "anything") {
		t.Fatal("empty requested scope is always a subset")
	}
}

func TestHandleRevokeFlow(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rt := "rev-refresh"
	if err := broker.store.PutRefreshToken(hashSecret(rt), RefreshToken{
		UserID:    "johndoe",
		ClientID:  "demo-web",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	form := url.Values{"token": {rt}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleRevoke(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok, _ := broker.store.GetRefreshToken(hashSecret(rt)); ok {
		t.Fatal("refresh token still present after revoke")
	}
}

func TestHandleRevokeAccessTokenAddsJTI(t *testing.T) {
	broker := newLogoutTestBroker(t)
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue tokens: %v", err)
	}
	access, _ := tokens["access_token"].(string)
	if access == "" {
		t.Fatal("missing access token")
	}
	form := url.Values{"token": {access}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleRevoke(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if len(broker.store.RuntimeSnapshot().RevokedJTIs) == 0 {
		t.Fatal("revoked jti was not recorded")
	}
	if _, err := broker.verifyJWT(access); err == nil {
		t.Fatal("revoked token should fail verification")
	}

	parts := strings.Split(access, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed access token")
	}
	claims, err := decodeJWTClaims(parts[1])
	if err != nil {
		t.Fatalf("decode revoked token: %v", err)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Fatal("revoked token missing jti")
	}
	stored, ok, err := broker.store.GetRevokedJTI(jti)
	if err != nil || !ok {
		t.Fatalf("get revoked jti: ok=%v err=%v", ok, err)
	}
	expUnix, _ := numberClaim(claims["exp"])
	wantMin := time.Unix(expUnix, 0).Add(jwtClockSkew)
	if stored.Before(wantMin) {
		t.Fatalf("revoked tombstone must survive the verification skew window: stored=%v want>=%v", stored, wantMin)
	}
}

func TestHandleRevokeBadClient(t *testing.T) {
	broker := newLogoutTestBroker(t)
	form := url.Values{"token": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "wrong")
	rr := httptest.NewRecorder()
	broker.handleRevoke(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}

func introspectRequest(form url.Values, basicUser, basicPass string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(basicUser, basicPass)
	}
	return req
}

func TestIntrospectAccessToken(t *testing.T) {
	broker := newLogoutTestBroker(t)
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid profile", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	access, _ := tokens["access_token"].(string)

	rr := httptest.NewRecorder()
	broker.handleIntrospect(rr, introspectRequest(url.Values{"token": {access}}, "demo-web", "demo-secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["active"] != true {
		t.Fatalf("active = %v body=%s", resp["active"], rr.Body.String())
	}
	if resp["client_id"] != "demo-web" {
		t.Fatalf("client_id = %v", resp["client_id"])
	}
	if resp["sub"] != "johndoe" {
		t.Fatalf("sub = %v", resp["sub"])
	}
	if resp["scope"] != "openid profile" {
		t.Fatalf("scope = %v", resp["scope"])
	}
	if resp["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v", resp["token_type"])
	}
	if _, ok := numberClaim(resp["exp"]); !ok {
		t.Fatalf("exp missing or not numeric: %#v", resp["exp"])
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
}

func TestIntrospectRefreshToken(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rt := "intro-refresh"
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := broker.store.PutRefreshToken(hashSecret(rt), RefreshToken{
		UserID:    "johndoe",
		ClientID:  "demo-web",
		Scope:     "openid",
		ExpiresAt: exp,
	}); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	rr := httptest.NewRecorder()
	broker.handleIntrospect(rr, introspectRequest(url.Values{
		"token":           {rt},
		"token_type_hint": {"refresh_token"},
	}, "demo-web", "demo-secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["active"] != true {
		t.Fatalf("active = %v", resp["active"])
	}
	if resp["sub"] != "johndoe" {
		t.Fatalf("sub = %v", resp["sub"])
	}
	got, ok := numberClaim(resp["exp"])
	if !ok || got != exp.Unix() {
		t.Fatalf("exp = %v (want %d)", resp["exp"], exp.Unix())
	}
}

func TestIntrospectUnknownToken(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rr := httptest.NewRecorder()
	broker.handleIntrospect(rr, introspectRequest(url.Values{"token": {"never-issued"}}, "demo-web", "demo-secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["active"] != false {
		t.Fatalf("active = %v", resp["active"])
	}
}

func TestIntrospectEmptyTokenIsInactive(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rr := httptest.NewRecorder()
	broker.handleIntrospect(rr, introspectRequest(url.Values{}, "demo-web", "demo-secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"active":false`) {
		t.Fatalf("body = %s", rr.Body.String())
	}
}

func TestIntrospectRequiresClientAuth(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rr := httptest.NewRecorder()
	broker.handleIntrospect(rr, introspectRequest(url.Values{"token": {"x"}}, "demo-web", "wrong"))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}
}

// A refresh token issued to one client must look inactive to a different
// client — introspection must not leak token metadata across tenants.
func TestIntrospectOtherClientCannotSeeToken(t *testing.T) {
	broker := newLogoutTestBroker(t)
	// Seed a refresh token for a different client_id.
	rt := "intro-foreign"
	if err := broker.store.PutRefreshToken(hashSecret(rt), RefreshToken{
		UserID:    "johndoe",
		ClientID:  "litellm",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	rr := httptest.NewRecorder()
	broker.handleIntrospect(rr, introspectRequest(url.Values{"token": {rt}}, "demo-web", "demo-secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"active":false`) {
		t.Fatalf("body = %s", rr.Body.String())
	}
}

func TestUserInfoRequiresBearer(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	rr := httptest.NewRecorder()
	broker.handleUserInfo(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestUserInfoRejectsIDToken(t *testing.T) {
	broker := newLogoutTestBroker(t)
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid groups", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	idToken, _ := tokens["id_token"].(string)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", bearerPrefix+idToken)
	rr := httptest.NewRecorder()
	broker.handleUserInfo(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserInfoOnAccessToken(t *testing.T) {
	broker := newLogoutTestBroker(t)
	if _, err := broker.store.UpsertProfile(UserProfile{Subject: "johndoe", Email: "j@e", Name: "John"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid email", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	access, _ := tokens["access_token"].(string)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", bearerPrefix+access)
	rr := httptest.NewRecorder()
	broker.handleUserInfo(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["sub"] != "johndoe" || resp["email"] != "j@e" {
		t.Fatalf("body = %#v", resp)
	}
}

// TestIssueUserTokensSetsAtHash verifies OIDC Core §3.3.2.11: the ID Token
// must carry at_hash whenever an access_token is issued alongside it, and the
// value must equal base64url(left-most 128 bits of SHA-256(access_token)) when
// the ID Token is signed with RS256.
func TestIssueUserTokensSetsAtHash(t *testing.T) {
	broker := newLogoutTestBroker(t)
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	access, _ := tokens["access_token"].(string)
	idToken, _ := tokens["id_token"].(string)
	if access == "" || idToken == "" {
		t.Fatalf("missing tokens: access=%q id=%q", access, idToken)
	}
	claims, err := broker.verifyJWT(idToken)
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	got, _ := claims["at_hash"].(string)
	if got == "" {
		t.Fatal("id_token missing at_hash claim")
	}
	sum := sha256.Sum256([]byte(access))
	want := base64.RawURLEncoding.EncodeToString(sum[:sha256.Size/2])
	if got != want {
		t.Fatalf("at_hash = %q, want %q", got, want)
	}
}

func TestHandleLoginGetExpiredRequest(t *testing.T) {
	broker := newLogoutTestBroker(t)
	if err := broker.store.PutAuthRequest(AuthorizationRequest{
		ID:        "rid",
		ClientID:  "demo-web",
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/login?request_id=rid", nil)
	rr := httptest.NewRecorder()
	broker.handleLoginGet(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func loginCSRF(t *testing.T, broker *Broker) (string, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	broker.handleLoginGet(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login GET status = %d", rr.Code)
	}
	cookie := findCookie(rr, csrfCookieName)
	if cookie == nil {
		t.Fatal("login page did not set csrf cookie")
	}
	return csrfTokenFromHTML(t, rr.Body.String()), cookie
}

func TestHandleLoginPostBadCSRF(t *testing.T) {
	broker := newLogoutTestBroker(t)
	form := url.Values{"username": {"johndoe"}, "password": {"hunter2"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	broker.handleLoginPost(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleLoginPostRejectsBadCredentials(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.authn = staticAuthenticator{err: errors.New("nope")}
	token, cookie := loginCSRF(t, broker)
	form := url.Values{
		"username":   {"johndoe"},
		"password":   {"wrong"},
		"csrf_token": {token},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	broker.handleLoginPost(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleLoginPostOAuthFlow(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.authn = staticAuthenticator{profile: UserProfile{Subject: "johndoe", Name: "John", Email: "j@e"}}
	if err := broker.store.PutAuthRequest(AuthorizationRequest{
		ID:          "rid-1",
		ClientID:    "demo-web",
		RedirectURI: "http://app.example/callback",
		Scope:       "openid",
		State:       "abc",
		ExpiresAt:   time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	token, cookie := loginCSRF(t, broker)
	form := url.Values{
		"request_id": {"rid-1"},
		"username":   {"johndoe"},
		"password":   {"pw"},
		"csrf_token": {token},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	broker.handleLoginPost(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "http://app.example/callback?") {
		t.Fatalf("Location = %q", loc)
	}
}

func TestHandleReAuth(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.authn = staticAuthenticator{profile: UserProfile{Subject: "alice"}}
	sess, err := broker.createSession(httptest.NewRecorder(), "alice", false, nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Locate the session id.
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	if sid == "" {
		t.Fatal("no session persisted")
	}

	form := url.Values{"password": {"pw"}, "csrf_token": {sess.CSRFToken}}
	req := httptest.NewRequest(http.MethodPost, "/reauth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleReAuth(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	got, _, _ := broker.store.GetSession(sid)
	if got.ReAuthAt.IsZero() {
		t.Fatal("ReAuthAt was not refreshed")
	}
	if !sessionRecentlyReAuthenticated(got) {
		t.Fatal("session should be considered recently re-authenticated")
	}
}

func TestHandleReAuthNotAuthenticated(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/reauth", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	broker.handleReAuth(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleReAuthBadPassword(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.authn = staticAuthenticator{err: errors.New("nope")}
	sess, _ := broker.createSession(httptest.NewRecorder(), "alice", false, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}

	form := url.Values{"password": {"pw"}, "csrf_token": {sess.CSRFToken}}
	req := httptest.NewRequest(http.MethodPost, "/reauth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleReAuth(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestRequireRecentReAuthDenies(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rr := httptest.NewRecorder()
	if broker.requireRecentReAuth(rr, Session{UserID: "u"}) {
		t.Fatal("session without ReAuthAt should not satisfy reauth")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "re_auth_required") {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestRequireRecentReAuthAllowsFreshSession(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rr := httptest.NewRecorder()
	if !broker.requireRecentReAuth(rr, Session{ReAuthAt: time.Now()}) {
		t.Fatal("fresh ReAuthAt session should pass")
	}
	if rr.Body.Len() != 0 {
		t.Fatalf("unexpected body %q", rr.Body.String())
	}
}

func TestWriteRetryAfter(t *testing.T) {
	rr := httptest.NewRecorder()
	writeRetryAfter(rr, 0)
	if rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q", rr.Header().Get("Retry-After"))
	}
	rr = httptest.NewRecorder()
	writeRetryAfter(rr, 90*time.Second)
	if rr.Header().Get("Retry-After") != "90" {
		t.Fatalf("Retry-After = %q", rr.Header().Get("Retry-After"))
	}
}

func TestHandleTOTPEnrollRequiresAuth(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/enroll", nil)
	rr := httptest.NewRecorder()
	broker.handleTOTPEnroll(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleTOTPEnrollRequiresReAuth(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, _ = broker.createSession(httptest.NewRecorder(), "alice", false, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/enroll", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleTOTPEnroll(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleTOTPEnrollSuccess(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, _ = broker.createSession(httptest.NewRecorder(), "alice", true, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/enroll", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleTOTPEnroll(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["secret_base32"] == "" || !strings.HasPrefix(body["otpauth_uri"], "otpauth://totp/") {
		t.Fatalf("body = %#v", body)
	}
	user, _ := broker.store.GetUser("alice")
	if user.PendingTOTPSecretBase32 == "" {
		t.Fatal("pending totp secret was not persisted")
	}
	if user.TOTPSecretBase32 != "" {
		t.Fatal("active totp secret should not be set before verify-enrollment")
	}
}

func TestHandleWebAuthnRegisterBeginRequiresAuth(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil)
	rr := httptest.NewRecorder()
	broker.handleWebAuthnRegisterBegin(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleWebAuthnRegisterBeginSuccess(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, _ = broker.createSession(httptest.NewRecorder(), "alice", true, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/begin", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleWebAuthnRegisterBegin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	pk, _ := body["publicKey"].(map[string]any)
	if pk["challenge"] == "" {
		t.Fatalf("challenge missing from %#v", body)
	}
}

func TestHandleWebAuthnRegisterFinishBadJSON(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, _ = broker.createSession(httptest.NewRecorder(), "alice", true, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", strings.NewReader("not json"))
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleWebAuthnRegisterFinish(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleWebAuthnLoginBeginRequiresUsername(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	broker.handleWebAuthnLoginBegin(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleWebAuthnLoginBeginNonExistingUser(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", strings.NewReader(`{"username":"ghost"}`))
	rr := httptest.NewRecorder()
	broker.handleWebAuthnLoginBegin(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleWebAuthnLoginFinishBadJSON(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	broker.handleWebAuthnLoginFinish(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleWebAuthnLoginFinishExpiredChallenge(t *testing.T) {
	broker := newLogoutTestBroker(t)
	cd := webauthnClientData{Type: "webauthn.get", Challenge: "abc", Origin: "http://broker.example"}
	cdBytes, _ := json.Marshal(cd)
	body := fmt.Sprintf(`{"rawId":"raw","response":{"clientDataJSON":"%s"}}`, base64.RawURLEncoding.EncodeToString(cdBytes))
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	broker.handleWebAuthnLoginFinish(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAllowedOrigin(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.WebAuthn.Origins = []string{"http://broker.example/"}
	if !broker.allowedOrigin("http://broker.example") {
		t.Fatal("origin should match (trailing slash normalized)")
	}
	if broker.allowedOrigin("http://evil.example") {
		t.Fatal("foreign origin should not match")
	}
}

func TestPublicKeyFromStoredRejectsBadAlg(t *testing.T) {
	if _, err := publicKeyFromStored(WebAuthnCredential{Alg: "RS256"}); err == nil {
		t.Fatal("non-ES256 alg should be rejected")
	}
}

func TestPublicKeyFromStoredRejectsBadCoords(t *testing.T) {
	if _, err := publicKeyFromStored(WebAuthnCredential{Alg: "ES256", XBase64URL: "!!!"}); err == nil {
		t.Fatal("bad X should fail")
	}
	if _, err := publicKeyFromStored(WebAuthnCredential{Alg: "ES256", XBase64URL: base64.RawURLEncoding.EncodeToString([]byte{1}), YBase64URL: "!!!"}); err == nil {
		t.Fatal("bad Y should fail")
	}
}

func TestSecurityHeaders(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	broker.routes().ServeHTTP(rr, req)
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing X-Content-Type-Options")
	}
	if rr.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP")
	}
}

func TestSecurityHeadersHSTSWhenHTTPS(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.Issuer = "https://broker.example"
	broker.cfg.CookieSecure = nil
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	broker.routes().ServeHTTP(rr, req)
	if rr.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("missing HSTS header when issuer is HTTPS")
	}
}

func TestMaybeExtendSessionRefreshesNearExpiry(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "sess-id"
	now := time.Now()
	if err := broker.store.PutSession(sid, Session{
		UserID:    "u",
		ExpiresAt: now.Add(time.Minute), // < half the 8h TTL
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.maybeExtendSession(rr, req)
	got, _, _ := broker.store.GetSession(sid)
	if !got.ExpiresAt.After(now.Add(time.Hour)) {
		t.Fatalf("session was not extended: %v", got.ExpiresAt)
	}
}

func TestMaybeExtendSessionDeletesExpired(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "expired"
	if err := broker.store.PutSession(sid, Session{ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	addSessionCookie(req, sid)
	broker.maybeExtendSession(httptest.NewRecorder(), req)
	if _, ok, _ := broker.store.GetSession(sid); ok {
		t.Fatal("expired session was not removed")
	}
}

func TestClientIDFromTokenClaimsHandlesAudList(t *testing.T) {
	if got := clientIDFromTokenClaims(map[string]any{"client_id": "x"}); got != "x" {
		t.Fatalf("client_id branch = %q", got)
	}
	if got := clientIDFromTokenClaims(map[string]any{"aud": "y"}); got != "y" {
		t.Fatalf("aud string branch = %q", got)
	}
	if got := clientIDFromTokenClaims(map[string]any{"aud": []any{"single"}}); got != "single" {
		t.Fatalf("aud list branch = %q", got)
	}
	if got := clientIDFromTokenClaims(map[string]any{}); got != "" {
		t.Fatalf("no claim branch = %q", got)
	}
}

func TestNeedsTOTP(t *testing.T) {
	broker := newLogoutTestBroker(t)
	if broker.needsTOTP(&StoredUser{}) {
		t.Fatal("user without TOTP and global off should not need TOTP")
	}
	if !broker.needsTOTP(&StoredUser{TOTPSecretBase32: "s"}) {
		t.Fatal("user with TOTP should require TOTP")
	}
	broker.cfg.MFA.TOTPRequired = true
	if !broker.needsTOTP(&StoredUser{}) {
		t.Fatal("global TOTP requirement should require TOTP")
	}
}

func TestClientAllowsRedirectAndPostLogout(t *testing.T) {
	c := Client{
		RedirectURIs:           []string{"http://app/a"},
		PostLogoutRedirectURIs: []string{"http://app/b"},
	}
	if !clientAllowsRedirect(c, "http://app/a") {
		t.Fatal("known redirect should be allowed")
	}
	if clientAllowsRedirect(c, "http://other") {
		t.Fatal("unknown redirect should not be allowed")
	}
	if !clientAllowsPostLogoutRedirect(c, "http://app/b") {
		t.Fatal("known post-logout redirect should be allowed")
	}
	if clientAllowsPostLogoutRedirect(c, "http://other") {
		t.Fatal("unknown post-logout redirect should not be allowed")
	}
}

func TestNormalizeConfigDefaults(t *testing.T) {
	cfg := Config{}
	normalizeConfig(&cfg)
	if cfg.Listen != ":8080" || cfg.Issuer != "http://localhost:8080" || cfg.KeyID == "" {
		t.Fatalf("defaults missing: %#v", cfg)
	}
	if cfg.SessionTTLHrs <= 0 || cfg.AccessTokenTTLMinutes <= 0 {
		t.Fatal("TTL defaults missing")
	}
	if cfg.WebAuthn.RPID == "" || len(cfg.WebAuthn.Origins) != 1 {
		t.Fatalf("webauthn defaults missing: %#v", cfg.WebAuthn)
	}
	if cfg.DisplayName == "" {
		t.Fatal("DisplayName default missing")
	}
}

func TestNormalizeConfigCustomAppTokens(t *testing.T) {
	cfg := Config{AppTokens: []AppTokenConfig{{ID: "abc"}}}
	normalizeConfig(&cfg)
	got := cfg.AppTokens[0]
	if got.Audience != "abc" || got.ClientID != "abc" || got.Scope == "" || got.TokenTTLMinutes == 0 {
		t.Fatalf("app token defaults missing: %#v", got)
	}
}

func TestNormalizeACMEConfigDefaults(t *testing.T) {
	acme := ACMEConfig{Domains: []string{"", "  example.com  "}}
	normalizeACMEConfig(&acme)
	if len(acme.Domains) != 1 || acme.Domains[0] != "example.com" {
		t.Fatalf("domains = %#v", acme.Domains)
	}
	if acme.HTTPAddr != ":80" || acme.HTTPSAddr != ":443" {
		t.Fatalf("default addrs missing: %#v", acme)
	}
	if acme.CADirectory == "" {
		t.Fatal("CADirectory default missing")
	}
}

func TestLoadConfigReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	body := `{"issuer":"http://example","listen":":9000","clients":[{"client_id":"x","redirect_uris":["http://x/cb"]}]}`
	if err := writeFileAtomic(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Issuer != "http://example" || cfg.Listen != ":9000" || len(cfg.Clients) != 1 {
		t.Fatalf("cfg = %#v", cfg)
	}
	if _, err := loadConfig(path + ".missing"); err == nil {
		t.Fatal("missing config should fail")
	}
	bad := dir + "/bad.json"
	if err := writeFileAtomic(bad, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	if _, err := loadConfig(bad); err == nil {
		t.Fatal("bad json should fail")
	}
}

func TestTokenErrorHelpers(t *testing.T) {
	rr := httptest.NewRecorder()
	tokenError(rr, "invalid_grant", "boom")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid_grant") {
		t.Fatalf("body = %q", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	tokenErrorStatus(rr, http.StatusForbidden, "x", "y")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	tokenServerError(rr, "ctx", errors.New("disk full"))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "server_error") {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestAuthenticateClientPublic(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.clients["public-app"] = Client{ClientID: "public-app", Public: true}
	form := url.Values{"client_id": {"public-app"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := broker.authenticateClient(req)
	if err != nil {
		t.Fatalf("authenticateClient: %v", err)
	}
	if got.ClientID != "public-app" {
		t.Fatalf("got %#v", got)
	}
}

func TestHandleLocalLogoutGetUnauthRedirects(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rr := httptest.NewRecorder()
	broker.handleLocalLogoutGet(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleLocalLogoutPostNoSession(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	broker.handleLocalLogoutPost(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleLogoutWithoutHintClearsSession(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "sess-1"
	if err := broker.store.PutSession(sid, Session{UserID: "u", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// POST is the form-completion side of the RP-initiated logout flow;
	// GET with an active session intentionally renders an interstitial
	// rather than clearing the cookie in one round-trip.
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok := broker.store.RuntimeSnapshot().Sessions[sid]; ok {
		t.Fatal("session was not cleared")
	}
}

func TestHandleLogoutGetWithSessionShowsConfirm(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "sess-confirm"
	if err := broker.store.PutSession(sid, Session{UserID: "u", ExpiresAt: time.Now().Add(time.Hour), CSRFToken: "csrf-confirm"}); err != nil { //nolint:gosec // Test seeds a synthetic CSRF token.
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?post_logout_redirect_uri=http://app.example/", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "End this broker session") {
		t.Fatalf("expected interstitial body, got %s", rr.Body.String())
	}
	if _, ok := broker.store.RuntimeSnapshot().Sessions[sid]; !ok {
		t.Fatal("session should remain until user confirms")
	}
}

func TestSweepExpiredViaBroker(t *testing.T) {
	broker := newLogoutTestBroker(t)
	if err := broker.store.PutSession("old", Session{ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	broker.sweepExpired(time.Now())
	if _, ok := broker.store.RuntimeSnapshot().Sessions["old"]; ok {
		t.Fatal("expired session survived broker sweep")
	}
}

func TestSignAndVerifyJWTReadback(t *testing.T) {
	broker := newLogoutTestBroker(t)
	tok, err := broker.signJWT(map[string]any{
		"iss": broker.cfg.Issuer,
		"sub": "alice",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, err := broker.verifyJWT(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Fatalf("claims sub = %v", claims["sub"])
	}
	if _, err := broker.verifyJWT("not.a.jwt"); err == nil {
		t.Fatal("malformed token should fail verify")
	}
}

func TestRandomDecoder(t *testing.T) {
	// Round-trip via decodeB64URL to keep coverage on the padded branch.
	encoded := base64.URLEncoding.EncodeToString([]byte("hello"))
	got, err := decodeB64URL(encoded)
	if err != nil {
		t.Fatalf("decode padded: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
}

// TestRedirectOAuthErrorEscapesCRLFInState ensures that the OAuth error
// redirect helper does not allow attacker-controlled state values to inject
// CR/LF into the Location header (HTTP response splitting). url.Values.Encode
// percent-encodes \r and \n, so the literal bytes must never appear in the
// rendered Location header.
func TestRedirectOAuthErrorEscapesCRLFInState(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	hostile := "xyz\r\nSet-Cookie: pwn=1"
	redirectOAuthError(rr, req, "https://client.example/cb", hostile, "invalid_request", "boom")
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if strings.ContainsAny(loc, "\r\n") {
		t.Fatalf("Location header contains raw CR/LF: %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := u.Query().Get("state"); got != hostile {
		t.Fatalf("round-tripped state = %q want %q", got, hostile)
	}
}

func TestHandleTOTPEnrollVerifyCommitsPendingSecret(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, _ = broker.createSession(httptest.NewRecorder(), "alice", true, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}

	enrollReq := httptest.NewRequest(http.MethodPost, "/mfa/totp/enroll", nil)
	addSessionCookie(enrollReq, sid)
	enrollRR := httptest.NewRecorder()
	broker.handleTOTPEnroll(enrollRR, enrollReq)
	if enrollRR.Code != http.StatusOK {
		t.Fatalf("enroll status = %d body=%s", enrollRR.Code, enrollRR.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(enrollRR.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode enroll: %v", err)
	}
	secret := body["secret_base32"]
	if secret == "" {
		t.Fatal("missing pending secret in enroll response")
	}

	user, _ := broker.store.GetUser("alice")
	if user.TOTPSecretBase32 != "" {
		t.Fatal("active TOTP secret should be empty before verify")
	}
	if user.PendingTOTPSecretBase32 != secret {
		t.Fatalf("pending secret mismatch: store=%q response=%q", user.PendingTOTPSecretBase32, secret)
	}

	code := totpCode(secret, time.Now().Unix()/30)
	form := url.Values{"otp": {code}}
	verifyReq := httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", strings.NewReader(form.Encode()))
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(verifyReq, sid)
	verifyRR := httptest.NewRecorder()
	broker.handleTOTPEnrollVerify(verifyRR, verifyReq)
	if verifyRR.Code != http.StatusNoContent {
		t.Fatalf("verify status = %d body=%s", verifyRR.Code, verifyRR.Body.String())
	}

	user, _ = broker.store.GetUser("alice")
	if user.TOTPSecretBase32 != secret {
		t.Fatalf("active TOTP secret = %q want %q", user.TOTPSecretBase32, secret)
	}
	if user.PendingTOTPSecretBase32 != "" {
		t.Fatal("pending TOTP secret should be cleared after verify")
	}
}

func TestHandleTOTPEnrollVerifyRejectsBadCode(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, _ = broker.createSession(httptest.NewRecorder(), "alice", true, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	if err := broker.store.SetPendingTOTP("alice", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("seed pending: %v", err)
	}
	form := url.Values{"otp": {"000000"}}
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleTOTPEnrollVerify(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	user, _ := broker.store.GetUser("alice")
	if user.TOTPSecretBase32 != "" {
		t.Fatal("active secret must remain empty on bad code")
	}
	if user.PendingTOTPSecretBase32 == "" {
		t.Fatal("pending secret should remain available for retry")
	}
}

func TestHandleTOTPEnrollVerifyWithoutPendingReturnsGone(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, _ = broker.createSession(httptest.NewRecorder(), "alice", true, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	form := url.Values{"otp": {"123456"}}
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleTOTPEnrollVerify(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleTOTPEnrollVerifyAcceptsJSONBody(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, _ = broker.createSession(httptest.NewRecorder(), "alice", true, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	secret := "JBSWY3DPEHPK3PXP" //nolint:gosec // Standard RFC 6238 test vector.
	if err := broker.store.SetPendingTOTP("alice", secret); err != nil {
		t.Fatalf("seed pending: %v", err)
	}
	code := totpCode(secret, time.Now().Unix()/30)
	bodyJSON := fmt.Sprintf(`{"otp":%q}`, code)
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleTOTPEnrollVerify(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	user, _ := broker.store.GetUser("alice")
	if user.TOTPSecretBase32 != secret {
		t.Fatalf("active secret = %q want %q", user.TOTPSecretBase32, secret)
	}
}

func TestHandleTOTPEnrollVerifyRequiresReAuth(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, _ = broker.createSession(httptest.NewRecorder(), "alice", false, nil)
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	form := url.Values{"otp": {"123456"}}
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleTOTPEnrollVerify(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleTOTPEnrollVerifyRequiresAuth(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", strings.NewReader(""))
	rr := httptest.NewRecorder()
	broker.handleTOTPEnrollVerify(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}

// Drain a body to silence unused-import linter for io if needed.
var _ = io.Discard

// Ensure sha256 import remains used even if other refs are removed.
var _ = sha256.Size
