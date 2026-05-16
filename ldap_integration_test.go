// Package main contains tests for the single-file authbroker.
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
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
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

func TestLDAPEntryAttributeValuesMergeCaseVariants(t *testing.T) {
	entry := &ldap.Entry{Attributes: []*ldap.EntryAttribute{
		{Name: "memberOf", Values: []string{"ou=app_elk_team10_user,ou=groups,dc=glauth,dc=com"}},
		{Name: "memberof", Values: []string{"CN=demo_reports,OU=Demo,DC=glauth,DC=com"}},
	}}
	got := ldapEntryAttributeValues(entry, "memberOf")
	want := []string{
		"ou=app_elk_team10_user,ou=groups,dc=glauth,dc=com",
		"CN=demo_reports,OU=Demo,DC=glauth,DC=com",
	}
	assertStringSlicesEqual(t, got, want)
}

func TestLDAPGroupNames(t *testing.T) {
	got := ldapGroupNames([]string{
		"cn=app_elk_team10_ingest,ou=groups,dc=glauth,dc=com",
		"ou=app_elk_team10_user,ou=groups,dc=glauth,dc=com",
		"plain-group",
		"cn=app_elk_team10_ingest,ou=groups,dc=glauth,dc=com",
		"",
	})
	want := []string{"app_elk_team10_ingest", "app_elk_team10_user", "plain-group"}
	if len(got) != len(want) {
		t.Fatalf("ldapGroupNames() = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ldapGroupNames() = %#v, want %#v", got, want)
		}
	}
}

func TestLDAPGroupIdentifiers(t *testing.T) {
	got := ldapGroupIdentifiers([]string{
		"cn=app_elk_team10_ingest,ou=groups,dc=glauth,dc=com",
		"CN=app_elk_team10_ingest,OU=groups,DC=glauth,DC=com",
		"plain-group",
		"",
	})
	want := []string{"cn=app_elk_team10_ingest,ou=groups,dc=glauth,dc=com", "plain-group"}
	assertStringSlicesEqual(t, got, want)
}

func TestLDAPNestedADGroupFilter(t *testing.T) {
	authn := &LDAPAuthenticator{cfg: LDAPConfig{
		GroupSearchFilter: "objectClass=group",
	}}
	got := authn.nestedADGroupFilter(`CN=Jane *(Ops),OU=Users,DC=example,DC=com`)
	want := `(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=CN=Jane \2a\28Ops\29,OU=Users,DC=example,DC=com))`
	if got != want {
		t.Fatalf("nestedADGroupFilter() = %q, want %q", got, want)
	}
}

func TestMergeStrings(t *testing.T) {
	got := mergeStrings(
		[]string{"direct-b", "direct-a"},
		[]string{"nested-a", "direct-a", ""},
	)
	want := []string{"direct-a", "direct-b", "nested-a"}
	if len(got) != len(want) {
		t.Fatalf("mergeStrings() = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mergeStrings() = %#v, want %#v", got, want)
		}
	}
}

func TestEnvOrDefault(t *testing.T) {
	const envName = "AUTHBROKER_TEST_PATH"

	if got := envOrDefault(envName, "fallback.json"); got != "fallback.json" {
		t.Fatalf("envOrDefault() without env = %q, want fallback.json", got)
	}

	t.Setenv(envName, "/etc/authbroker/config.json")
	if got := envOrDefault(envName, "fallback.json"); got != "/etc/authbroker/config.json" {
		t.Fatalf("envOrDefault() with env = %q, want /etc/authbroker/config.json", got)
	}

	t.Setenv(envName, "  ")
	if got := envOrDefault(envName, "fallback.json"); got != "fallback.json" {
		t.Fatalf("envOrDefault() with blank env = %q, want fallback.json", got)
	}
}

func TestMappedClientGroups(t *testing.T) {
	client := Client{GroupMappings: map[string]string{
		"app_elk_team10_ingest":                         "elk-ingest",
		"CN=Finance Admins,OU=Groups,DC=example,DC=com": "finance-admin",
	}}
	groupMappings, err := normalizeClientGroupMappings(client.GroupMappings)
	if err != nil {
		t.Fatalf("normalizeClientGroupMappings(): %v", err)
	}
	client.GroupMappings = groupMappings

	got := mappedClientGroups(client, []string{
		"APP_ELK_TEAM10_INGEST",
		"cn=Finance Admins,ou=Groups,dc=example,dc=com",
		"unmapped-directory-group",
	})
	want := []string{"elk-ingest", "finance-admin"}
	assertStringSlicesEqual(t, got, want)

	if got := mappedClientGroups(Client{}, []string{"app_elk_team10_ingest"}); len(got) != 0 {
		t.Fatalf("mappedClientGroups() with no mapping = %#v, want no groups", got)
	}
}

func TestMappedClientGroupsScopedOU(t *testing.T) {
	client := Client{GroupMappings: map[string]string{
		"OU=Demo,DC=example,DC=com": "{cn}",
	}}
	groupMappings, err := normalizeClientGroupMappings(client.GroupMappings)
	if err != nil {
		t.Fatalf("normalizeClientGroupMappings(): %v", err)
	}
	client.GroupMappings = groupMappings

	got := mappedClientGroups(client, []string{
		"CN=Reports,OU=Demo,DC=example,DC=com",
		"CN=Nested Reports,OU=Child,OU=Demo,DC=example,DC=com",
		"CN=Outside,OU=Other,DC=example,DC=com",
		"OU=Demo,DC=example,DC=com",
		"plain-group",
	})
	want := []string{"Nested Reports", "Reports"}
	assertStringSlicesEqual(t, got, want)
}

func TestMappedClientGroupsCNWildcardSource(t *testing.T) {
	client := Client{GroupMappings: map[string]string{
		"CN=*,OU=Demo,DC=example,DC=com": "demo-{cn}",
	}}
	groupMappings, err := normalizeClientGroupMappings(client.GroupMappings)
	if err != nil {
		t.Fatalf("normalizeClientGroupMappings(): %v", err)
	}
	client.GroupMappings = groupMappings

	got := mappedClientGroups(client, []string{
		"CN=Reports,OU=Demo,DC=example,DC=com",
		"CN=Outside,OU=Other,DC=example,DC=com",
	})
	want := []string{"demo-Reports"}
	assertStringSlicesEqual(t, got, want)
}

func TestMappedClientGroupsRegexSource(t *testing.T) {
	client := Client{GroupMappings: map[string]string{
		"regex:(?i)^CN=app_gitlab_[^,]+,": "{cn}",
	}}
	groupMappings, err := normalizeClientGroupMappings(client.GroupMappings)
	if err != nil {
		t.Fatalf("normalizeClientGroupMappings(): %v", err)
	}
	client.GroupMappings = groupMappings

	got := mappedClientGroups(client, []string{
		"CN=app_gitlab_admins,OU=GitLab,DC=example,DC=com",
		"cn=app_gitlab_users,OU=Engineering,DC=example,DC=com",
		"CN=app_elk_team10_ingest,OU=Logging,DC=example,DC=com",
	})
	want := []string{"app_gitlab_admins", "app_gitlab_users"}
	assertStringSlicesEqual(t, got, want)
}

func TestMappedClientGroupsRegexCaptures(t *testing.T) {
	client := Client{GroupMappings: map[string]string{
		"regex:(?i)^CN=app_gitlab_(?P<role>[^,]+),": "gitlab-{role}",
	}}
	groupMappings, err := normalizeClientGroupMappings(client.GroupMappings)
	if err != nil {
		t.Fatalf("normalizeClientGroupMappings(): %v", err)
	}
	client.GroupMappings = groupMappings

	got := mappedClientGroups(client, []string{
		"CN=app_gitlab_admins,OU=Any,DC=example,DC=com",
	})
	want := []string{"gitlab-admins"}
	assertStringSlicesEqual(t, got, want)
}

func TestNormalizeClientGroupMappingsValidation(t *testing.T) {
	if _, err := normalizeClientGroupMappings(map[string]string{"": "app-user"}); err == nil {
		t.Fatalf("blank group mapping source should fail")
	}
	if _, err := normalizeClientGroupMappings(map[string]string{"app-source": ""}); err == nil {
		t.Fatalf("blank group mapping target should fail")
	}
	if _, err := normalizeClientGroupMappings(map[string]string{
		"CN=Ops,OU=Groups,DC=example,DC=com": "ops",
		"ops":                                "other-ops",
	}); err == nil {
		t.Fatalf("duplicate normalized group mapping source should fail")
	}
	if _, err := normalizeClientGroupMappings(map[string]string{
		"OU=*,DC=example,DC=com": "demo-{cn}",
	}); err == nil {
		t.Fatalf("wildcard outside CN should fail")
	}
	if _, err := normalizeClientGroupMappings(map[string]string{
		"OU=Demo,DC=example,DC=com":      "{cn}",
		"CN=*,OU=Demo,DC=example,DC=com": "demo-{cn}",
	}); err == nil {
		t.Fatalf("duplicate scoped group mapping source should fail")
	}
	if _, err := normalizeClientGroupMappings(map[string]string{
		"regex:*": "{cn}",
	}); err == nil {
		t.Fatalf("invalid regex source should fail")
	}
}

func TestScopeIncludes(t *testing.T) {
	if !scopeIncludes("openid profile email groups", "groups") {
		t.Fatalf("expected groups scope to be detected")
	}
	if scopeIncludes("openid profile groupish", "groups") {
		t.Fatalf("partial scope name should not match")
	}
}

//nolint:gosec // Fixed demo secret hash is a test fixture.
func TestClientSecretMatchesSHA256(t *testing.T) {
	client := Client{
		ClientID:           "demo-web",
		ClientSecretSHA256: "cd577fe2561ebff23505db0bb006300c7cdecbd46bc0e03c449afafaca2c25bf",
	}
	if !clientSecretMatches(client, "demo-secret") {
		t.Fatalf("expected hashed client secret to match")
	}
	if clientSecretMatches(client, "wrong-secret") {
		t.Fatalf("wrong client secret should not match")
	}
	if clientSecretMatches(Client{ClientSecretSHA256: "not-hex"}, "demo-secret") {
		t.Fatalf("invalid hash config should not match")
	}
	if clientSecretMatches(Client{}, "demo-secret") {
		t.Fatalf("missing hash config should not match")
	}
}

func TestDiscoveryAdvertisesEndSessionEndpoint(t *testing.T) {
	broker := newLogoutTestBroker(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	broker.handleDiscovery(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var discovery map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &discovery); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	assertStringClaim(t, discovery, "end_session_endpoint", "http://broker.example/oauth2/logout")
}

func TestBrokerLogoutClearsSessionAndRedirects(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.mu.Lock()
	broker.sessions["logout-session"] = Session{
		UserID:    "johndoe",
		ExpiresAt: time.Now().Add(time.Hour),
		AuthTime:  time.Now(),
	}
	broker.mu.Unlock()

	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid", "", time.Now(), false)
	if err != nil {
		t.Fatalf("issue tokens: %v", err)
	}
	idToken, _ := tokens["id_token"].(string)
	if idToken == "" {
		t.Fatalf("missing id token in %#v", tokens)
	}
	q := url.Values{
		"id_token_hint":            {idToken},
		"post_logout_redirect_uri": {"http://app.example/"},
		"state":                    {"logout-state"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "logout-session"}) //nolint:gosec // Test attaches a synthetic session cookie.
	rr := httptest.NewRecorder()
	broker.handleLogout(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d: %s", rr.Code, rr.Body.String())
	}
	if location := rr.Header().Get("Location"); location != "http://app.example/?state=logout-state" {
		t.Fatalf("Location = %q", location)
	}
	broker.mu.Lock()
	_, stillActive := broker.sessions["logout-session"]
	broker.mu.Unlock()
	if stillActive {
		t.Fatalf("broker session was not cleared")
	}
	assertDeletedCookie(t, rr, sessionCookieName)
}

func TestBrokerLogoutRejectsUnregisteredRedirect(t *testing.T) {
	broker := newLogoutTestBroker(t)
	q := url.Values{
		"client_id":                {"demo-web"},
		"post_logout_redirect_uri": {"http://evil.example/"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	broker.handleLogout(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

//nolint:gocognit,cyclop,funlen // End-to-end page flow test intentionally exercises several states.
func TestBrokerStandaloneLoginAndLogoutPages(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.authn = staticAuthenticator{profile: UserProfile{
		Subject: "johndoe",
		Email:   "johndoe@example.com",
		Name:    "John Doe",
		Groups:  []string{"CN=demo_reports,OU=Demo,DC=example,DC=com", "CN=unmapped,OU=Other,DC=example,DC=com"},
	}}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected home status 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "You are not signed in") {
		t.Fatalf("home page did not show signed-out state: %s", rr.Body.String())
	}

	unauthTokenReq := httptest.NewRequest(http.MethodPost, "/app-tokens/litellm", nil)
	unauthTokenRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(unauthTokenRR, unauthTokenReq)
	if unauthTokenRR.Code != http.StatusFound {
		t.Fatalf("expected unauthenticated app token status 302, got %d: %s", unauthTokenRR.Code, unauthTokenRR.Body.String())
	}
	if location := unauthTokenRR.Header().Get("Location"); location != "/login" {
		t.Fatalf("unauthenticated app token Location = %q, want /login", location)
	}

	loginPageReq := httptest.NewRequest(http.MethodGet, "/login", nil)
	loginPageRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(loginPageRR, loginPageReq)
	if loginPageRR.Code != http.StatusOK {
		t.Fatalf("expected login page status 200, got %d: %s", loginPageRR.Code, loginPageRR.Body.String())
	}
	loginCSRFToken := csrfTokenFromHTML(t, loginPageRR.Body.String())
	loginCSRFCookie := findCookie(loginPageRR, csrfCookieName)
	if loginCSRFCookie == nil {
		t.Fatalf("login page did not set %s cookie", csrfCookieName)
	}

	form := url.Values{
		"username":   {"johndoe"},
		"password":   {"dogood"},
		"csrf_token": {loginCSRFToken},
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.AddCookie(loginCSRFCookie)
	loginRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusFound {
		t.Fatalf("expected login status 302, got %d: %s", loginRR.Code, loginRR.Body.String())
	}
	if location := loginRR.Header().Get("Location"); location != "/" {
		t.Fatalf("login Location = %q, want /", location)
	}
	sessionCookie := findCookie(loginRR, sessionCookieName)
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatalf("login response did not set %s cookie; cookies=%#v", sessionCookieName, loginRR.Result().Cookies())
	}

	homeReq := httptest.NewRequest(http.MethodGet, "/", nil)
	homeReq.AddCookie(sessionCookie)
	homeRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(homeRR, homeReq)
	if homeRR.Code != http.StatusOK {
		t.Fatalf("expected signed-in home status 200, got %d: %s", homeRR.Code, homeRR.Body.String())
	}
	if !strings.Contains(homeRR.Body.String(), "Signed in as <strong>johndoe</strong>") {
		t.Fatalf("home page did not show signed-in state: %s", homeRR.Body.String())
	}
	if csp := homeRR.Header().Get("Content-Security-Policy"); csp == "" || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("home CSP = %q, want strict policy without unsafe-inline", csp)
	}
	if !strings.Contains(homeRR.Body.String(), "App tokens") || !strings.Contains(homeRR.Body.String(), "LiteLLM") || !strings.Contains(homeRR.Body.String(), "Internal API") {
		t.Fatalf("home page did not show configured app token actions: %s", homeRR.Body.String())
	}
	sessionCSRFToken := csrfTokenFromHTML(t, homeRR.Body.String())

	badTokenReq := httptest.NewRequest(http.MethodPost, "/app-tokens/litellm", nil)
	badTokenReq.AddCookie(sessionCookie)
	badTokenRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(badTokenRR, badTokenReq)
	if badTokenRR.Code != http.StatusForbidden {
		t.Fatalf("expected app token without csrf status 403, got %d: %s", badTokenRR.Code, badTokenRR.Body.String())
	}

	tokenReq := httptest.NewRequest(http.MethodPost, "/app-tokens/litellm", strings.NewReader(url.Values{"csrf_token": {sessionCSRFToken}}.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.AddCookie(sessionCookie)
	tokenRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(tokenRR, tokenReq)
	if tokenRR.Code != http.StatusOK {
		t.Fatalf("expected app token status 200, got %d: %s", tokenRR.Code, tokenRR.Body.String())
	}
	if cacheControl := tokenRR.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("app token Cache-Control = %q, want no-store", cacheControl)
	}
	token := appTokenFromHTML(t, tokenRR.Body.String())
	claims, err := broker.verifyJWT(token)
	if err != nil {
		t.Fatalf("verify app token: %v", err)
	}
	assertStringClaim(t, claims, "sub", "johndoe")
	assertStringClaim(t, claims, "aud", "litellm")
	assertStringClaim(t, claims, "client_id", "litellm")
	assertStringClaim(t, claims, "app_token_id", "litellm")
	assertStringClaim(t, claims, "email", "johndoe@example.com")
	assertStringClaim(t, claims, "name", "John Doe")
	assertStringClaim(t, claims, "user_id", "johndoe")
	if ttl := claimInt64(t, claims, "exp") - claimInt64(t, claims, "iat"); ttl != 480*60 {
		t.Fatalf("app token ttl = %d seconds, want %d", ttl, 480*60)
	}
	groups := stringSliceClaim(claims["groups"])
	if len(groups) != 1 || groups[0] != "demo_reports" {
		t.Fatalf("app token groups = %#v, want [demo_reports]", groups)
	}

	apiTokenReq := httptest.NewRequest(http.MethodPost, "/app-tokens/internal-api", strings.NewReader(url.Values{"csrf_token": {sessionCSRFToken}}.Encode()))
	apiTokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	apiTokenReq.AddCookie(sessionCookie)
	apiTokenRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(apiTokenRR, apiTokenReq)
	if apiTokenRR.Code != http.StatusOK {
		t.Fatalf("expected second app token status 200, got %d: %s", apiTokenRR.Code, apiTokenRR.Body.String())
	}
	apiToken := appTokenFromHTML(t, apiTokenRR.Body.String())
	apiClaims, err := broker.verifyJWT(apiToken)
	if err != nil {
		t.Fatalf("verify second app token: %v", err)
	}
	assertStringClaim(t, apiClaims, "aud", "internal-api")
	assertStringClaim(t, apiClaims, "client_id", "internal-api")
	assertStringClaim(t, apiClaims, "app_token_id", "internal-api")
	if groups := stringSliceClaim(apiClaims["groups"]); len(groups) != 0 {
		t.Fatalf("second app token groups = %#v, want none", groups)
	}

	logoutPageReq := httptest.NewRequest(http.MethodGet, "/logout", nil)
	logoutPageReq.AddCookie(sessionCookie)
	logoutPageRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(logoutPageRR, logoutPageReq)
	if logoutPageRR.Code != http.StatusOK {
		t.Fatalf("expected logout page status 200, got %d: %s", logoutPageRR.Code, logoutPageRR.Body.String())
	}
	if !strings.Contains(logoutPageRR.Body.String(), "Sign out of authbroker") {
		t.Fatalf("logout page did not render confirmation: %s", logoutPageRR.Body.String())
	}
	logoutCSRFToken := csrfTokenFromHTML(t, logoutPageRR.Body.String())

	badLogoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	badLogoutReq.AddCookie(sessionCookie)
	badLogoutRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(badLogoutRR, badLogoutReq)
	if badLogoutRR.Code != http.StatusForbidden {
		t.Fatalf("expected logout without csrf status 403, got %d: %s", badLogoutRR.Code, badLogoutRR.Body.String())
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(url.Values{"csrf_token": {logoutCSRFToken}}.Encode()))
	logoutReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logoutReq.AddCookie(sessionCookie)
	logoutRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(logoutRR, logoutReq)
	if logoutRR.Code != http.StatusFound {
		t.Fatalf("expected logout status 302, got %d: %s", logoutRR.Code, logoutRR.Body.String())
	}
	assertDeletedCookie(t, logoutRR, sessionCookieName)
	broker.mu.Lock()
	_, stillActive := broker.sessions[sessionCookie.Value]
	broker.mu.Unlock()
	if stillActive {
		t.Fatalf("standalone logout did not remove broker session")
	}
}

//nolint:gocognit,cyclop,funlen // Docker-backed integration test covers the full OAuth profile flow.
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
		GroupsAttribute:    "memberOf",
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
		assertStringSliceClaimContains(t, accessClaims, "groups", "elk-ingest")
		assertStringSliceClaimNotContains(t, accessClaims, "groups", "app_elk_team10_ingest")

		idClaims, err := broker.verifyJWT(tokens.IDToken)
		if err != nil {
			t.Fatalf("verify id token: %v", err)
		}
		assertStringClaim(t, idClaims, "sub", "ingestuser")
		assertStringClaim(t, idClaims, "email", "ingestuser@example.com")
		assertStringClaim(t, idClaims, "name", "ingestuser")
		assertStringSliceClaimContains(t, idClaims, "groups", "elk-ingest")
		assertStringSliceClaimNotContains(t, idClaims, "groups", "app_elk_team10_ingest")

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
		assertStringSliceClaimContains(t, userinfo, "groups", "elk-ingest")
		assertStringSliceClaimNotContains(t, userinfo, "groups", "app_elk_team10_ingest")
	})

	t.Run("scoped demo ou group mapping forwards johndoe demo group", func(t *testing.T) {
		tokens := performAuthCodeFlow(ctx, t, client, baseURL, "johndoe", "dogood")

		accessClaims, err := broker.verifyJWT(tokens.AccessToken)
		if err != nil {
			t.Fatalf("verify access token: %v", err)
		}
		assertStringClaim(t, accessClaims, "sub", "johndoe")
		assertStringClaim(t, accessClaims, "email", "johndoe@example.com")
		assertStringSliceClaimContains(t, accessClaims, "groups", "demo_reports")

		idClaims, err := broker.verifyJWT(tokens.IDToken)
		if err != nil {
			t.Fatalf("verify id token: %v", err)
		}
		assertStringClaim(t, idClaims, "sub", "johndoe")
		assertStringSliceClaimContains(t, idClaims, "groups", "demo_reports")

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
		assertStringClaim(t, userinfo, "sub", "johndoe")
		assertStringSliceClaimContains(t, userinfo, "groups", "demo_reports")
	})

	t.Run("wrong password is unauthorized and issues no auth code", func(t *testing.T) {
		requestID := beginAuthorize(ctx, t, client, baseURL)
		csrfToken, csrfCookie := loginCSRFForRequest(ctx, t, client, baseURL, requestID)
		form := url.Values{
			"request_id": {requestID},
			"username":   {"ingestuser"},
			"password":   {"wrongpass"},
			"csrf_token": {csrfToken},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/login", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("build login request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrfCookie)
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
	csrfToken, csrfCookie := loginCSRFForRequest(ctx, t, client, baseURL, requestID)
	form := url.Values{
		"request_id": {requestID},
		"username":   {username},
		"password":   {password},
		"csrf_token": {csrfToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
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
		"scope":                 {"openid profile email groups"},
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

func loginCSRFForRequest(ctx context.Context, t *testing.T, client *http.Client, baseURL, requestID string) (string, *http.Cookie) {
	t.Helper()

	loginURL := baseURL + "/login?request_id=" + url.QueryEscape(requestID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		t.Fatalf("build login page request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("send login page request: %v", err)
	}
	defer resp.Body.Close()
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected login page status 200, got %d: %s", resp.StatusCode, body)
	}
	cookie := findResponseCookie(resp, csrfCookieName)
	if cookie == nil {
		t.Fatalf("login page did not set %s cookie", csrfCookieName)
	}
	return csrfTokenFromHTML(t, body), cookie
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

//nolint:gosec // Fixed demo secret hash is a test fixture.
func newLogoutTestBroker(t *testing.T) *Broker {
	t.Helper()

	store, err := NewStore("")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	cfg := Config{
		Issuer:       "http://broker.example",
		Listen:       ":0",
		KeyID:        "logout-test-key",
		CookieSecure: boolPtr(false),
		AppTokens: []AppTokenConfig{
			{
				ID:              "litellm",
				DisplayName:     "LiteLLM",
				Audience:        "litellm",
				ClientID:        "litellm",
				Scope:           "openid profile email groups",
				TokenTTLMinutes: 480,
				GroupMappings: map[string]string{
					"OU=Demo,DC=example,DC=com": "{cn}",
				},
			},
			{
				ID:              "internal-api",
				DisplayName:     "Internal API",
				TokenTTLMinutes: 120,
			},
		},
		Clients: []Client{
			{
				ClientID:           "demo-web",
				ClientSecretSHA256: "cd577fe2561ebff23505db0bb006300c7cdecbd46bc0e03c449afafaca2c25bf",
				RedirectURIs: []string{
					"http://app.example/callback",
				},
				PostLogoutRedirectURIs: []string{
					"http://app.example/",
				},
				RequirePKCE: true,
			},
		},
	}
	broker, err := NewBroker(cfg, store)
	if err != nil {
		t.Fatalf("create broker: %v", err)
	}
	return broker
}

type staticAuthenticator struct {
	profile UserProfile
	err     error
}

func (a staticAuthenticator) Authenticate(context.Context, string, string) (UserProfile, error) {
	if a.err != nil {
		return UserProfile{}, a.err
	}
	return a.profile, nil
}

//nolint:funlen,gosec // Integration broker setup is clearer as one fixture helper with fixed test credentials.
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
				ClientID:           "demo-web",
				ClientSecretSHA256: "cd577fe2561ebff23505db0bb006300c7cdecbd46bc0e03c449afafaca2c25bf",
				RedirectURIs: []string{
					baseURL + "/callback",
				},
				PostLogoutRedirectURIs: []string{
					baseURL + "/",
				},
				RequirePKCE: true,
				GroupMappings: map[string]string{
					"app_elk_team10_ingest":    "elk-ingest",
					"OU=Demo,DC=glauth,DC=com": "{cn}",
				},
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

func assertStringSliceClaimContains(t *testing.T, claims map[string]any, name, want string) {
	t.Helper()

	values := stringSliceClaim(claims[name])
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("claim %s = %#v, want it to contain %q", name, claims[name], want)
}

func assertStringSliceClaimNotContains(t *testing.T, claims map[string]any, name, unwanted string) {
	t.Helper()

	values := stringSliceClaim(claims[name])
	for _, value := range values {
		if value == unwanted {
			t.Fatalf("claim %s = %#v, should not contain %q", name, claims[name], unwanted)
		}
	}
}

func assertStringSlicesEqual(t *testing.T, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func assertDeletedCookie(t *testing.T, rr *httptest.ResponseRecorder, name string) {
	t.Helper()

	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge < 0 {
			return
		}
	}
	t.Fatalf("response did not delete cookie %q; cookies=%#v", name, rr.Result().Cookies())
}

func findCookie(rr *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func findResponseCookie(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

var csrfTokenPattern = regexp.MustCompile(`<input[^>]*name="csrf_token"[^>]*value="([^"]*)"`)

func csrfTokenFromHTML(t *testing.T, body string) string {
	t.Helper()

	matches := csrfTokenPattern.FindStringSubmatch(body)
	if len(matches) != 2 || strings.TrimSpace(matches[1]) == "" {
		t.Fatalf("csrf token input not found in body: %s", body)
	}
	return strings.TrimSpace(matches[1])
}

var appTokenPattern = regexp.MustCompile(`<textarea[^>]*id="app-token-value"[^>]*>([^<]+)</textarea>`)

func appTokenFromHTML(t *testing.T, body string) string {
	t.Helper()

	matches := appTokenPattern.FindStringSubmatch(body)
	if len(matches) != 2 {
		t.Fatalf("app token textarea not found in body: %s", body)
	}
	return strings.TrimSpace(matches[1])
}

func claimInt64(t *testing.T, claims map[string]any, name string) int64 {
	t.Helper()

	got, ok := numberClaim(claims[name])
	if !ok {
		t.Fatalf("claim %s = %#v, want number", name, claims[name])
	}
	return got
}

func stringSliceClaim(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		values := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				values = append(values, s)
			}
		}
		return values
	default:
		return nil
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

//nolint:gosec // Docker arguments are built from test fixture paths and a generated container name.
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

//nolint:gosec // Docker command arguments are fixed except for the generated test container name and port.
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
