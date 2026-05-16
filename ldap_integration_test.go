package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLDAPBindName(t *testing.T) {
	tests := []struct {
		name     string
		cfg      LDAPConfig
		username string
		want     string
	}{
		{
			name:     "domain suffix",
			cfg:      LDAPConfig{DomainSuffix: "@example.com"},
			username: "ingestuser",
			want:     "ingestuser@example.com",
		},
		{
			name:     "existing upn",
			cfg:      LDAPConfig{DomainSuffix: "@example.com"},
			username: "ingestuser@example.net",
			want:     "ingestuser@example.net",
		},
		{
			name:     "domain slash username",
			cfg:      LDAPConfig{DomainSuffix: "@example.com"},
			username: `EXAMPLE\ingestuser`,
			want:     `EXAMPLE\ingestuser`,
		},
		{
			name:     "dn template placeholder escapes dn value",
			cfg:      LDAPConfig{UserDNTemplate: "uid={username},ou=people,dc=example,dc=com"},
			username: `john,doe`,
			want:     `uid=john\2cdoe,ou=people,dc=example,dc=com`,
		},
		{
			name:     "legacy dn template",
			cfg:      LDAPConfig{UserDNTemplate: "uid=%s,ou=people,dc=example,dc=com"},
			username: `john=doe`,
			want:     `uid=john\3ddoe,ou=people,dc=example,dc=com`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authn := &LDAPAuthenticator{cfg: tt.cfg}
			if got := authn.bindName(tt.username); got != tt.want {
				t.Fatalf("bindName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLDAPUserFilterTemplateEscaping(t *testing.T) {
	authn := &LDAPAuthenticator{cfg: LDAPConfig{
		DomainSuffix: "@example.com",
		UserFilter:   "(|(uid={username})(mail={login})(dn={bind})(legacy=%s))",
	}}
	got := authn.userFilter("a*b(user)", authn.bindName("a*b(user)"))
	want := `(|(uid=a\2ab\28user\29)(mail=a\2ab\28user\29@example.com)(dn=a\2ab\28user\29@example.com)(legacy=a\2ab\28user\29@example.com))`
	if got != want {
		t.Fatalf("userFilter() = %q, want %q", got, want)
	}
}

func TestLDAPProfileSearchConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     LDAPConfig
		wantOK  bool
		wantErr bool
	}{
		{name: "disabled", cfg: LDAPConfig{}, wantOK: false},
		{name: "enabled", cfg: LDAPConfig{BaseDN: "dc=example,dc=com", UserFilter: "(uid={username})"}, wantOK: true},
		{name: "missing filter", cfg: LDAPConfig{BaseDN: "dc=example,dc=com"}, wantErr: true},
		{name: "missing base", cfg: LDAPConfig{UserFilter: "(uid={username})"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&LDAPAuthenticator{cfg: tt.cfg}).profileSearchEnabled()
			if (err != nil) != tt.wantErr {
				t.Fatalf("profileSearchEnabled() err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.wantOK {
				t.Fatalf("profileSearchEnabled() = %v, want %v", got, tt.wantOK)
			}
		})
	}
}

func TestLDAPBrokerOAuthIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker-backed LDAP integration test in short mode")
	}
	requireDocker(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ldapURL, stopLDAP := startDockerGlauth(ctx, t)
	defer stopLDAP()

	ldapCfg := LDAPConfig{
		URL:                ldapURL,
		DomainSuffix:       "@example.com",
		BaseDN:             "dc=glauth,dc=com",
		UserFilter:         "(mail=%s)",
		EmailAttribute:     "mail",
		NameAttribute:      "cn",
		InsecureSkipVerify: true,
		TimeoutSeconds:     5,
	}
	waitForLDAPReady(ctx, t, ldapCfg)

	baseURL, broker, client, stopBroker := startTestBroker(ctx, t, ldapCfg)
	defer stopBroker()

	t.Run("successful oauth code flow populates ldap profile claims", func(t *testing.T) {
		tokens := performAuthCodeFlow(ctx, t, client, baseURL, "ingestuser", "dogood")

		accessClaims, err := broker.verifyJWT(tokens.AccessToken)
		if err != nil {
			t.Fatalf("verify access token: %v", err)
		}
		assertStringClaim(t, accessClaims, "sub", "ingestuser")
		assertStringClaim(t, accessClaims, "email", "ingestuser@example.com")
		assertStringClaim(t, accessClaims, "name", "ingestuser")

		idClaims, err := broker.verifyJWT(tokens.IDToken)
		if err != nil {
			t.Fatalf("verify id token: %v", err)
		}
		assertStringClaim(t, idClaims, "sub", "ingestuser")
		assertStringClaim(t, idClaims, "email", "ingestuser@example.com")
		assertStringClaim(t, idClaims, "name", "ingestuser")

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/oauth2/userinfo", nil)
		if err != nil {
			t.Fatalf("build userinfo request: %v", err)
		}
		req.Header.Set("Authorization", bearerPrefix+tokens.AccessToken)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("send userinfo request: %v", err)
		}
		defer resp.Body.Close()
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected userinfo status 200, got %d: %s", resp.StatusCode, body)
		}
		var userinfo map[string]any
		if err := json.Unmarshal([]byte(body), &userinfo); err != nil {
			t.Fatalf("decode userinfo: %v", err)
		}
		assertStringClaim(t, userinfo, "sub", "ingestuser")
		assertStringClaim(t, userinfo, "email", "ingestuser@example.com")
		assertStringClaim(t, userinfo, "name", "ingestuser")
	})

	t.Run("wrong password is unauthorized and issues no auth code", func(t *testing.T) {
		requestID := beginAuthorize(ctx, t, client, baseURL)
		form := url.Values{
			"request_id": {requestID},
			"username":   {"ingestuser"},
			"password":   {"wrongpass"},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/login", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("build login request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("send login request: %v", err)
		}
		defer resp.Body.Close()
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected status 401, got %d: %s", resp.StatusCode, body)
		}
		if location := resp.Header.Get("Location"); location != "" {
			t.Fatalf("failed login should not redirect, got Location %q", location)
		}
		broker.mu.Lock()
		authCodes := len(broker.authCodes)
		broker.mu.Unlock()
		if authCodes != 0 {
			t.Fatalf("failed login issued %d auth codes", authCodes)
		}
	})
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

func performAuthCodeFlow(ctx context.Context, t *testing.T, client *http.Client, baseURL, username, password string) tokenResponse {
	t.Helper()

	requestID := beginAuthorize(ctx, t, client, baseURL)
	form := url.Values{
		"request_id": {requestID},
		"username":   {username},
		"password":   {password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send login request: %v", err)
	}
	defer resp.Body.Close()
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected login status 302, got %d: %s", resp.StatusCode, body)
	}
	redirectLocation := resp.Header.Get("Location")
	code, err := codeFromRedirect(redirectLocation)
	if err != nil {
		t.Fatalf("parse code redirect %q: %v", redirectLocation, err)
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {baseURL + "/callback"},
		"code_verifier": {testCodeVerifier},
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/oauth2/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth("demo-web", "demo-secret")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		t.Fatalf("send token request: %v", err)
	}
	defer tokenResp.Body.Close()
	tokenBody := readBody(t, tokenResp)
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("expected token status 200, got %d: %s", tokenResp.StatusCode, tokenBody)
	}
	var tokens tokenResponse
	if err := json.Unmarshal([]byte(tokenBody), &tokens); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		t.Fatalf("token response missing access or id token: %#v", tokens)
	}
	return tokens
}

const testCodeVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

func beginAuthorize(ctx context.Context, t *testing.T, client *http.Client, baseURL string) string {
	t.Helper()

	hash := sha256.Sum256([]byte(testCodeVerifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {baseURL + "/callback"},
		"scope":                 {"openid profile email"},
		"state":                 {"ldap-test-state"},
		"nonce":                 {"ldap-test-nonce"},
		"code_challenge":        {base64RawURL(hash[:])},
		"code_challenge_method": {"S256"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/oauth2/authorize?"+q.Encode(), nil)
	if err != nil {
		t.Fatalf("build authorize request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send authorize request: %v", err)
	}
	defer resp.Body.Close()
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected authorize status 302, got %d: %s", resp.StatusCode, body)
	}
	location := resp.Header.Get("Location")
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse authorize redirect %q: %v", location, err)
	}
	requestID := u.Query().Get("request_id")
	if requestID == "" {
		t.Fatalf("authorize redirect missing request_id: %q", location)
	}
	return requestID
}

func codeFromRedirect(location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	code := u.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("missing code")
	}
	if state := u.Query().Get("state"); state != "ldap-test-state" {
		return "", fmt.Errorf("state = %q, want ldap-test-state", state)
	}
	return code, nil
}

func startTestBroker(ctx context.Context, t *testing.T, ldapCfg LDAPConfig) (string, *Broker, *http.Client, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for broker: %v", err)
	}
	baseURL := "http://" + listener.Addr().String()
	store, err := NewStore("")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	cfg := Config{
		Issuer:       baseURL,
		Listen:       ":0",
		KeyID:        "ldap-test-key",
		LDAP:         ldapCfg,
		CookieSecure: boolPtr(false),
		Clients: []Client{
			{
				ClientID:     "demo-web",
				ClientSecret: "demo-secret",
				RedirectURIs: []string{
					baseURL + "/callback",
				},
				RequirePKCE: true,
			},
		},
	}
	broker, err := NewBroker(cfg, store)
	if err != nil {
		t.Fatalf("create broker: %v", err)
	}
	srv := &http.Server{
		Handler:           broker.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	cleanup := func() {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("broker exited with error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for broker shutdown")
		}
	}
	return baseURL, broker, client, cleanup
}

func boolPtr(v bool) *bool {
	return &v
}

func assertStringClaim(t *testing.T, claims map[string]any, name, want string) {
	t.Helper()

	if got, _ := claims[name].(string); got != want {
		t.Fatalf("claim %s = %#v, want %q", name, claims[name], want)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return string(body)
}

func requireDocker(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	cmd := exec.Command("docker", "info")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("docker is not available: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

func startDockerGlauth(ctx context.Context, t *testing.T) (string, func()) {
	t.Helper()

	cfgPath := repoPath(t, "testldap", "default-config.cfg")
	certPath := repoPath(t, "testldap", "cert.pem")
	keyPath := repoPath(t, "testldap", "key.pem")
	containerName := fmt.Sprintf("authbroker-ldap-test-%d", time.Now().UnixNano())

	runArgs := []string{
		"run", "--detach", "--rm",
		"--publish", "127.0.0.1::389",
		"--name", containerName,
		"--env", "GLAUTH_CONFIG=/app/config/config.cfg",
		"--volume", cfgPath + ":/app/config/config.cfg:ro",
		"--volume", certPath + ":/app/config/cert.pem:ro",
		"--volume", keyPath + ":/app/config/key.pem:ro",
		"glauth/glauth:latest",
	}
	if out, err := exec.CommandContext(ctx, "docker", runArgs...).CombinedOutput(); err != nil {
		t.Fatalf("start glauth container: %v\n%s", err, string(out))
	}

	cleanup := func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = exec.CommandContext(stopCtx, "docker", "rm", "-f", containerName).CombinedOutput()
	}
	t.Cleanup(cleanup)

	port, err := dockerMappedPort(ctx, containerName, "389/tcp")
	if err != nil {
		t.Fatalf("resolve glauth mapped port: %v", err)
	}

	return "ldaps://127.0.0.1:" + port, cleanup
}

func dockerMappedPort(ctx context.Context, containerName, containerPort string) (string, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := exec.CommandContext(ctx, "docker", "port", containerName, containerPort).CombinedOutput()
		if err == nil {
			mapping := strings.TrimSpace(string(out))
			if mapping != "" {
				hostPort := mapping[strings.LastIndex(mapping, ":")+1:]
				if hostPort != "" {
					return hostPort, nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("timed out waiting for docker port mapping for %s", containerName)
}

func waitForLDAPReady(ctx context.Context, t *testing.T, cfg LDAPConfig) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, err := (&LDAPAuthenticator{cfg: cfg}).Authenticate(ctx, "ingestuser", "dogood")
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("LDAP did not become ready: %v", ctx.Err())
		case <-time.After(1 * time.Second):
		}
	}
	t.Fatalf("LDAP did not become ready in time")
}

func repoPath(t *testing.T, elems ...string) string {
	t.Helper()

	path := filepath.Join(elems...)
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve path %q: %v", path, err)
	}
	return abs
}
