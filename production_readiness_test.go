package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func productionTestConfig() Config {
	return Config{
		Production:            true,
		Issuer:                "https://auth.example.com",
		Listen:                ":0",
		CookieSecure:          boolPtr(true),
		AdminGroups:           []string{"authbroker-admins"},
		AccessTokenTTLMinutes: 15,
		IDTokenTTLMinutes:     15,
		RefreshTokenTTLDays:   14,
		AuthCodeTTLSeconds:    120,
		SessionTTLHrs:         8,
		SessionAbsoluteTTLHrs: 24,
		LDAP: LDAPConfig{
			URL:            "ldaps://dc01.example.com:636",
			BaseDN:         "dc=example,dc=com",
			UserFilter:     "(userPrincipalName={login})",
			TimeoutSeconds: 5,
		},
		MFA: MFAConfig{TOTPRequired: true},
		WebAuthn: WebAuthnConfig{
			RPID:          "auth.example.com",
			RPDisplayName: "Example Auth",
			Origins:       []string{"https://auth.example.com"},
		},
		Clients: []Client{{
			ClientID:               "internal-web",
			ClientSecretSHA256:     strings.Repeat("a", 64),
			RedirectURIs:           []string{"https://app.example.com/callback"},
			PostLogoutRedirectURIs: []string{"https://app.example.com/"},
			RequirePKCE:            true,
			RequireConsent:         true,
		}},
		AppTokens: []AppTokenConfig{{
			ID:              "internal-api",
			TokenTTLMinutes: 120,
		}},
	}
}

func TestProductionConfigValidationPasses(t *testing.T) {
	cfg := productionTestConfig()
	normalizeConfig(&cfg)
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("validate production config: %v", err)
	}
}

func TestProductionConfigValidationFailures(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{
			name: "http issuer",
			edit: func(cfg *Config) { cfg.Issuer = "http://auth.example.com" },
			want: "https issuer",
		},
		{
			name: "insecure cookies",
			edit: func(cfg *Config) { cfg.CookieSecure = boolPtr(false) },
			want: "secure cookies",
		},
		{
			name: "totp optional",
			edit: func(cfg *Config) { cfg.MFA.TOTPRequired = false },
			want: "totp_required",
		},
		{
			name: "absolute session ttl missing",
			edit: func(cfg *Config) { cfg.SessionAbsoluteTTLHrs = 0 },
			want: "session_absolute_ttl_hours",
		},
		{
			name: "ldap insecure skip verify",
			edit: func(cfg *Config) { cfg.LDAP.InsecureSkipVerify = true },
			want: "insecure_skip_verify",
		},
		{
			name: "pkce optional",
			edit: func(cfg *Config) { cfg.Clients[0].RequirePKCE = false },
			want: "PKCE",
		},
		{
			name: "localhost redirect",
			edit: func(cfg *Config) { cfg.Clients[0].RedirectURIs = []string{"https://localhost/callback"} },
			want: "localhost",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := productionTestConfig()
			tt.edit(&cfg)
			normalizeConfig(&cfg)
			err := validateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validate error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestProductionMetricsRequireBearerHash(t *testing.T) {
	cfg := productionTestConfig()
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = "/metrics"
	normalizeConfig(&cfg)
	err := validateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "metrics.bearer_token_sha256") {
		t.Fatalf("validate error = %v, want metrics.bearer_token_sha256", err)
	}
}

func TestDuplicateClientIDRejected(t *testing.T) {
	cfg := productionTestConfig()
	cfg.Production = false
	cfg.Clients = append(cfg.Clients, cfg.Clients[0])
	normalizeConfig(&cfg)
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "duplicate client_id") {
		t.Fatalf("validate duplicate client = %v", err)
	}
}

func TestTrustedProxyClientIP(t *testing.T) {
	cfg := productionTestConfig()
	cfg.Production = false
	cfg.TrustedProxies = []string{"10.0.0.0/8"}
	cfg.ClientIPHeader = "X-Forwarded-For"
	broker, err := NewBroker(cfg, mustNewStore(t))
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.2.3.4:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 10.2.3.4")
	if got := broker.clientIP(req); got != "203.0.113.10" {
		t.Fatalf("trusted proxy client ip = %q", got)
	}

	req.RemoteAddr = "192.0.2.20:12345"
	if got := broker.clientIP(req); got != "192.0.2.20" {
		t.Fatalf("untrusted proxy client ip = %q", got)
	}

	// Spoof attempt: attacker prepends a fake IP at the head of X-Forwarded-For.
	// A typical proxy will append the observed client behind it, so we must
	// walk right-to-left and return the rightmost untrusted IP rather than
	// the leftmost (attacker-controlled) one.
	spoof := httptest.NewRequest(http.MethodGet, "/", nil)
	spoof.RemoteAddr = "10.2.3.4:12345"
	spoof.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.5, 10.2.3.4")
	if got := broker.clientIP(spoof); got != "198.51.100.5" {
		t.Fatalf("spoofed XFF head client ip = %q, want %q", got, "198.51.100.5")
	}

	// All entries trusted: fall back to the leftmost parseable entry.
	allTrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	allTrusted.RemoteAddr = "10.0.0.1:443"
	allTrusted.Header.Set("X-Forwarded-For", "10.1.1.1, 10.0.0.1")
	if got := broker.clientIP(allTrusted); got != "10.1.1.1" {
		t.Fatalf("all-trusted client ip = %q, want %q", got, "10.1.1.1")
	}
}

func TestHealthReadyAndMetricsEndpoints(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.Metrics.Enabled = true
	broker.cfg.Metrics.Path = "/metrics"
	broker.cfg.Metrics.BearerSHA256 = sha256Hex("probe")

	for _, path := range []string{"/healthz", "/livez", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		broker.routes().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, rr.Code, rr.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics status = %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer probe")
	rr = httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "authbroker_http_requests_total") {
		t.Fatalf("metrics body = %q", rr.Body.String())
	}
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestOAuthClientAuthenticationRateLimited(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.tokenLimiter = newLoginRateLimiter(time.Minute, 1, time.Hour)
	form := url.Values{"grant_type": {"client_credentials"}}

	req1 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.RemoteAddr = "192.0.2.50:1234"
	req1.SetBasicAuth("demo-web", "wrong")
	rr1 := httptest.NewRecorder()
	broker.handleToken(rr1, req1)
	if rr1.Code != http.StatusUnauthorized {
		t.Fatalf("first bad auth status = %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.RemoteAddr = "192.0.2.50:1234"
	req2.SetBasicAuth("demo-web", "wrong")
	rr2 := httptest.NewRecorder()
	broker.handleToken(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second bad auth status = %d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestTOTPEnrollVerifyRateLimited(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.loginLimiter = newLoginRateLimiter(time.Minute, 1, time.Hour)
	sid := "totp-session"
	sess := Session{
		UserID:    "alice",
		ExpiresAt: time.Now().Add(time.Hour),
		AuthTime:  time.Now(),
		ReAuthAt:  time.Now(),
		CSRFToken: "csrf",
	}
	if err := broker.store.PutSession(sid, sess); err != nil {
		t.Fatalf("put session: %v", err)
	}
	if err := broker.store.SetPendingTOTP("alice", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("set pending totp: %v", err)
	}

	for i, want := range []int{http.StatusUnauthorized, http.StatusTooManyRequests} {
		req := httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", strings.NewReader("otp=000000"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.0.2.60:1234"
		addSessionCookie(req, sid)
		addSessionCSRF(req, sess)
		rr := httptest.NewRecorder()
		broker.handleTOTPEnrollVerify(rr, req)
		if rr.Code != want {
			t.Fatalf("attempt %d status = %d want %d body=%s", i+1, rr.Code, want, rr.Body.String())
		}
	}
}

func TestRefreshTokenReuseRevokesFamily(t *testing.T) {
	broker := newLogoutTestBroker(t)
	now := time.Now()
	original := "refresh-original"
	if err := broker.store.PutRefreshToken(hashSecret(original), RefreshToken{
		UserID:    "alice",
		ClientID:  "demo-web",
		Scope:     "openid offline_access",
		AuthTime:  now,
		ExpiresAt: now.Add(time.Hour),
		FamilyID:  "family-1",
	}); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	first := refreshTokenRequest(original)
	firstRR := httptest.NewRecorder()
	broker.handleToken(firstRR, first)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("first refresh status = %d body=%s", firstRR.Code, firstRR.Body.String())
	}
	var firstBody map[string]any
	if err := json.Unmarshal(firstRR.Body.Bytes(), &firstBody); err != nil {
		t.Fatalf("decode first refresh: %v", err)
	}
	rotated, _ := firstBody["refresh_token"].(string)
	if rotated == "" {
		t.Fatal("first refresh did not return a rotated refresh token")
	}

	reuse := refreshTokenRequest(original)
	reuseRR := httptest.NewRecorder()
	broker.handleToken(reuseRR, reuse)
	if reuseRR.Code != http.StatusBadRequest {
		t.Fatalf("reuse status = %d body=%s", reuseRR.Code, reuseRR.Body.String())
	}
	if _, ok, err := broker.store.GetRefreshToken(hashSecret(rotated)); err != nil || ok {
		t.Fatalf("rotated token active after family revoke: ok=%v err=%v", ok, err)
	}
	if _, ok, err := broker.store.GetConsumedRefreshToken(hashSecret(original)); err != nil || !ok {
		t.Fatalf("consumed original missing: ok=%v err=%v", ok, err)
	}
}

func TestPreAuthRateLimitWebAuthnLoginBegin(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.preAuthLimiter = newLoginRateLimiter(time.Minute, 1, time.Hour)

	first := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", strings.NewReader(`{"username":"alice"}`))
	first.RemoteAddr = "192.0.2.80:1234"
	rr1 := httptest.NewRecorder()
	broker.handleWebAuthnLoginBegin(rr1, first)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first begin status = %d body=%s", rr1.Code, rr1.Body.String())
	}

	second := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", strings.NewReader(`{"username":"alice"}`))
	second.RemoteAddr = "192.0.2.80:1234"
	rr2 := httptest.NewRecorder()
	broker.handleWebAuthnLoginBegin(rr2, second)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second begin status = %d body=%s", rr2.Code, rr2.Body.String())
	}
	if rr2.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on 429")
	}

	// A different IP must not be affected by the first IP's lockout.
	other := httptest.NewRequest(http.MethodPost, "/webauthn/login/begin", strings.NewReader(`{"username":"alice"}`))
	other.RemoteAddr = "192.0.2.81:1234"
	rr3 := httptest.NewRecorder()
	broker.handleWebAuthnLoginBegin(rr3, other)
	if rr3.Code != http.StatusOK {
		t.Fatalf("other-IP begin status = %d body=%s", rr3.Code, rr3.Body.String())
	}
}

func TestPreAuthRateLimitAuthorize(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.preAuthLimiter = newLoginRateLimiter(time.Minute, 1, time.Hour)

	target := "/oauth2/authorize?response_type=code&client_id=demo-web&redirect_uri=http%3A%2F%2Fapp.example%2Fcallback&scope=openid&state=s&code_challenge=abc&code_challenge_method=S256"
	first := httptest.NewRequest(http.MethodGet, target, nil)
	first.RemoteAddr = "192.0.2.90:1234"
	rr1 := httptest.NewRecorder()
	broker.handleAuthorize(rr1, first)
	if rr1.Code != http.StatusFound {
		t.Fatalf("first authorize status = %d body=%s", rr1.Code, rr1.Body.String())
	}

	second := httptest.NewRequest(http.MethodGet, target, nil)
	second.RemoteAddr = "192.0.2.90:1234"
	rr2 := httptest.NewRecorder()
	broker.handleAuthorize(rr2, second)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second authorize status = %d body=%s", rr2.Code, rr2.Body.String())
	}
}

func refreshTokenRequest(refreshToken string) *http.Request {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.70:1234"
	req.SetBasicAuth("demo-web", "demo-secret")
	return req
}
