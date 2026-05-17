package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTokenAuthorizationCodeSuccess(t *testing.T) {
	broker := newLogoutTestBroker(t)
	now := time.Now()
	code := "raw-code"
	if err := broker.store.PutAuthCode(hashSecret(code), AuthCode{
		UserID:      "johndoe",
		ClientID:    "demo-web",
		RedirectURI: "http://app.example/callback",
		Scope:       "openid offline_access",
		AuthTime:    now,
		ExpiresAt:   now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("seed code: %v", err)
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://app.example/callback"},
	}
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
	if body["refresh_token"] == nil {
		t.Fatalf("offline_access did not produce refresh token: %#v", body)
	}
	if _, ok, _ := broker.store.ConsumeAuthCode(hashSecret(code)); ok {
		t.Fatal("auth code should have been consumed")
	}
}

func TestTokenAuthorizationCodeRejectsExpired(t *testing.T) {
	broker := newLogoutTestBroker(t)
	code := "expired-code"
	if err := broker.store.PutAuthCode(hashSecret(code), AuthCode{
		ClientID:    "demo-web",
		RedirectURI: "http://app.example/callback",
		ExpiresAt:   time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://app.example/callback"},
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

func TestTokenAuthorizationCodeRejectsRedirectMismatch(t *testing.T) {
	broker := newLogoutTestBroker(t)
	code := "mismatch-code"
	if err := broker.store.PutAuthCode(hashSecret(code), AuthCode{
		ClientID:    "demo-web",
		RedirectURI: "http://app.example/callback",
		ExpiresAt:   time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://app.example/other"},
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

func TestValidSessionAssignsCSRFOnDemand(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "needs-csrf"
	if err := broker.store.PutSession(sid, Session{UserID: "u", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	addSessionCookie(req, sid)
	sess, ok := broker.validSession(req)
	if !ok {
		t.Fatal("expected valid session")
	}
	if sess.CSRFToken == "" {
		t.Fatal("CSRF token should have been provisioned")
	}
}

func TestValidSessionDropsExpired(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "expired-sess"
	if err := broker.store.PutSession(sid, Session{UserID: "u", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	addSessionCookie(req, sid)
	if _, ok := broker.validSession(req); ok {
		t.Fatal("expired session should not validate")
	}
	if _, ok, _ := broker.store.GetSession(sid); ok {
		t.Fatal("expired session must be cleared")
	}
}

func TestValidateJWTClaimsBadIssuer(t *testing.T) {
	broker := newLogoutTestBroker(t)
	token, err := broker.signJWT(map[string]any{
		"iss": "http://different-issuer",
		"sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := broker.verifyJWT(token); err == nil {
		t.Fatal("expected bad-issuer error")
	}
}

func TestValidateJWTClaimsExpired(t *testing.T) {
	broker := newLogoutTestBroker(t)
	token, err := broker.signJWT(map[string]any{
		"iss": broker.cfg.Issuer,
		"exp": time.Now().Add(-time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := broker.verifyJWT(token); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func TestValidateJWTClaimsNotBefore(t *testing.T) {
	broker := newLogoutTestBroker(t)
	token, err := broker.signJWT(map[string]any{
		"iss": broker.cfg.Issuer,
		"nbf": time.Now().Add(10 * time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := broker.verifyJWT(token); err == nil {
		t.Fatal("expected not-yet-active token to fail")
	}
}

func TestNumberClaimAcceptedKinds(t *testing.T) {
	cases := []any{
		json.Number("42"),
		float64(42),
		int64(42),
		42,
	}
	for _, c := range cases {
		n, ok := numberClaim(c)
		if !ok || n != 42 {
			t.Fatalf("numberClaim(%T %v) = %d ok=%v", c, c, n, ok)
		}
	}
	if _, ok := numberClaim("nope"); ok {
		t.Fatal("string should not match")
	}
}

func TestRunACMERequiresAgreedTOS(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.ACME = ACMEConfig{Enabled: true, Domains: []string{"example.com"}}
	err := runACME(context.Background(), broker, t.TempDir(), func() {})
	if err == nil || !strings.Contains(err.Error(), "agreed_tos") {
		t.Fatalf("expected agreed_tos error, got %v", err)
	}
}

func TestLDAPSearchNestedADGroupsRequiresUserDN(t *testing.T) {
	authn := &LDAPAuthenticator{}
	if _, err := authn.searchNestedADGroups(nil, "  "); err == nil {
		t.Fatal("blank user DN should fail")
	}
}

func TestLDAPAttributeDefaults(t *testing.T) {
	if got := ldapAttribute("", "fallback"); got != "fallback" {
		t.Fatalf("ldapAttribute fallback = %q", got)
	}
	if got := ldapAttribute(" custom ", "fallback"); got != "custom" {
		t.Fatalf("ldapAttribute custom = %q", got)
	}
}

func TestStoreSeedRuntimeStateRoundTrip(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	state := StoredRuntimeState{
		Sessions:      map[string]Session{"s1": {UserID: "u", ExpiresAt: now.Add(time.Hour)}},
		AuthRequests:  map[string]AuthorizationRequest{},
		AuthCodes:     map[string]AuthCode{},
		RefreshTokens: map[string]RefreshToken{"r1": {UserID: "u", ExpiresAt: now.Add(time.Hour)}},
		RevokedJTIs:   map[string]time.Time{"j1": now.Add(time.Minute)},
		WebAuthnReg:   map[string]ChallengeRecord{"w1": {ExpiresAt: now.Add(time.Minute)}},
		WebAuthnLog:   map[string]ChallengeRecord{"w2": {ExpiresAt: now.Add(time.Minute)}},
	}
	if err := store.SeedRuntimeState(state); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got := store.RuntimeSnapshot()
	if _, ok := got.Sessions["s1"]; !ok {
		t.Fatal("session missing after seed")
	}
	if _, ok := got.RefreshTokens["r1"]; !ok {
		t.Fatal("refresh missing after seed")
	}
}

func TestSigningKeyConfigIsActiveDefaults(t *testing.T) {
	if !signingKeyConfigIsActive(SigningKeyConfig{KeyID: "only"}, 0, 1, "", "only") {
		t.Fatal("single key without Active flag should be considered active")
	}
	if !signingKeyConfigIsActive(SigningKeyConfig{KeyID: "named"}, 0, 2, "named", "named") {
		t.Fatal("matching cfg KeyID should be considered active")
	}
	if signingKeyConfigIsActive(SigningKeyConfig{KeyID: "other"}, 0, 2, "named", "other") {
		t.Fatal("non-matching KeyID without Active flag should not be active")
	}
}

func TestParseRSAPrivateKeyPEMHandlesNonRSAPKCS8(t *testing.T) {
	// ECDSA in PKCS8 will parse but should be rejected by the type assertion.
	const ecdsaPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----`
	if _, err := parseRSAPrivateKeyPEM([]byte(ecdsaPEM)); err == nil {
		t.Fatal("ECDSA PKCS8 key should not be accepted as RSA")
	}
}
