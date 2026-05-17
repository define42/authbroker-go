package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

//nolint:gosec // Fixed demo secret hash is a test fixture.
func newAdminTestBroker(t *testing.T) *Broker {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), defaultDataFile))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := Config{
		Issuer:       "http://broker.example",
		Listen:       ":0",
		KeyID:        "admin-test-key",
		CookieSecure: boolPtr(false),
		AdminGroups:  []string{"administrators"},
		Clients: []Client{{
			ClientID:           "demo-web",
			ClientSecretSHA256: "cd577fe2561ebff23505db0bb006300c7cdecbd46bc0e03c449afafaca2c25bf",
			RedirectURIs:       []string{"http://app.example/callback"},
			RequirePKCE:        true,
			RequireConsent:     true,
		}},
	}
	broker, err := NewBroker(cfg, store)
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	return broker
}

// adminSession persists a session whose user has the admin group. Returns the
// session id, csrf token, and a helper to attach the session cookie.
func adminSession(t *testing.T, broker *Broker, username string, isAdmin bool) (sid, csrf string) {
	t.Helper()
	groups := []string{}
	if isAdmin {
		groups = []string{"administrators"}
	}
	if _, err := broker.store.UpsertProfile(UserProfile{Subject: username, Groups: groups}); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	sess, err := broker.createSession(httptest.NewRecorder(), username, true, nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}
	return sid, sess.CSRFToken
}

func TestAdminRequiresAdminGroup(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "alice", false)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminHomeRendersForAdmin(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "admin", true)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "demo-web") {
		t.Fatalf("config-defined client missing from list: %q", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "config") {
		t.Fatal("expected the config badge to be shown")
	}
}

func TestAdminClientCreateAndDelete(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "admin", true)

	form := url.Values{
		"csrf_token":      {csrf},
		"client_id":       {"team-app"},
		"redirect_uris":   {"https://team.example/cb"},
		"require_pkce":    {"on"},
		"require_consent": {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "team-app") {
		t.Fatalf("body missing client_id: %q", rr.Body.String())
	}
	if c, ok := broker.lookupClient("team-app"); !ok {
		t.Fatal("client not registered after create")
	} else if !c.RequireConsent {
		t.Fatal("require_consent not preserved")
	}

	// Cannot delete config-defined client.
	deleteReq := httptest.NewRequest(http.MethodPost, "/admin/clients/demo-web/delete", strings.NewReader("csrf_token="+csrf))
	deleteReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(deleteReq, sid)
	deleteRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(deleteRR, deleteReq)
	if deleteRR.Code != http.StatusForbidden {
		t.Fatalf("delete config-defined status = %d", deleteRR.Code)
	}

	// Can delete stored client.
	deleteReq2 := httptest.NewRequest(http.MethodPost, "/admin/clients/team-app/delete", strings.NewReader("csrf_token="+csrf))
	deleteReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(deleteReq2, sid)
	deleteRR2 := httptest.NewRecorder()
	broker.routes().ServeHTTP(deleteRR2, deleteReq2)
	if deleteRR2.Code != http.StatusFound {
		t.Fatalf("delete stored status = %d body=%s", deleteRR2.Code, deleteRR2.Body.String())
	}
	if _, ok := broker.lookupClient("team-app"); ok {
		t.Fatal("client not removed after delete")
	}
}

func TestAdminClientCreateRejectsBadInput(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "admin", true)

	cases := []struct {
		name string
		form url.Values
	}{
		{
			name: "blank client_id",
			form: url.Values{"csrf_token": {csrf}, "client_id": {""}, "redirect_uris": {"https://team.example/cb"}},
		},
		{
			name: "no redirect",
			form: url.Values{"csrf_token": {csrf}, "client_id": {"team-app"}},
		},
		{
			name: "bad redirect",
			form: url.Values{"csrf_token": {csrf}, "client_id": {"team-app"}, "redirect_uris": {"not a url"}},
		},
		{
			name: "duplicate id",
			form: url.Values{"csrf_token": {csrf}, "client_id": {"demo-web"}, "redirect_uris": {"https://team.example/cb"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(c.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			addSessionCookie(req, sid)
			rr := httptest.NewRecorder()
			broker.routes().ServeHTTP(rr, req)
			if rr.Code != http.StatusFound {
				t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
			}
			if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "/admin/clients/new?error=") {
				t.Fatalf("Location = %q", loc)
			}
		})
	}
}

func TestAdminAppTokenCreateAndDelete(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "admin", true)

	form := url.Values{
		"csrf_token":        {csrf},
		"id":                {"team-token"},
		"display_name":      {"Team Token"},
		"audience":          {"team-svc"},
		"scope":             {"openid profile"},
		"token_ttl_minutes": {"60"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/app-tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	tok, ok := broker.lookupAppToken("team-token")
	if !ok || tok.TokenTTLMinutes != 60 || tok.Audience != "team-svc" {
		t.Fatalf("app token not registered correctly: %+v ok=%v", tok, ok)
	}

	delReq := httptest.NewRequest(http.MethodPost, "/admin/app-tokens/team-token/delete", strings.NewReader("csrf_token="+csrf))
	delReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(delReq, sid)
	delRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusFound {
		t.Fatalf("delete status = %d", delRR.Code)
	}
	if _, ok := broker.lookupAppToken("team-token"); ok {
		t.Fatal("app token persisted after delete")
	}
}

func TestAdminAppTokenCreateRejectsBadTTL(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "admin", true)
	form := url.Values{
		"csrf_token":        {csrf},
		"id":                {"bad-ttl"},
		"token_ttl_minutes": {"abc"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/app-tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "error=") {
		t.Fatalf("Location = %q", rr.Header().Get("Location"))
	}
}

func TestAdminCSRFEnforced(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "admin", true)
	form := url.Values{
		"csrf_token":    {"wrong"},
		"client_id":     {"team-app"},
		"redirect_uris": {"https://team.example/cb"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

//nolint:funlen // End-to-end consent test walks authorize → consent GET → consent POST → repeat-authorize in one flow.
func TestConsentPromptedThenPersisted(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "alice", false)

	// First authorize: session exists, demo-web requires consent → redirect to /consent.
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"scope":                 {"openid profile"},
		"state":                 {"st"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "/consent?request_id=") {
		t.Fatalf("expected redirect to /consent, got %q", loc)
	}
	u, _ := url.Parse(loc)
	rid := u.Query().Get("request_id")

	// Consent GET renders the page.
	getReq := httptest.NewRequest(http.MethodGet, "/consent?request_id="+rid, nil)
	addSessionCookie(getReq, sid)
	getRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("consent GET = %d body=%s", getRR.Code, getRR.Body.String())
	}
	if !strings.Contains(getRR.Body.String(), "openid") {
		t.Fatalf("consent body missing scope: %q", getRR.Body.String())
	}

	// Approve.
	approveForm := url.Values{
		"csrf_token": {csrf},
		"request_id": {rid},
		"decision":   {"approve"},
	}
	approveReq := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(approveForm.Encode()))
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(approveReq, sid)
	approveRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(approveRR, approveReq)
	if approveRR.Code != http.StatusFound {
		t.Fatalf("approve status = %d body=%s", approveRR.Code, approveRR.Body.String())
	}
	if !strings.HasPrefix(approveRR.Header().Get("Location"), "http://app.example/callback?") {
		t.Fatalf("approve redirect = %q", approveRR.Header().Get("Location"))
	}

	rec, ok, err := broker.store.GetConsent("alice", "demo-web")
	if err != nil || !ok {
		t.Fatalf("consent not persisted: ok=%v err=%v", ok, err)
	}
	if !consentCovers(rec, []string{"openid", "profile"}) {
		t.Fatalf("consent record missing scopes: %+v", rec)
	}

	// Second authorize: same scope set → no consent prompt, direct code redirect.
	req2 := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	addSessionCookie(req2, sid)
	rr2 := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusFound {
		t.Fatalf("second authorize = %d", rr2.Code)
	}
	loc2 := rr2.Header().Get("Location")
	if !strings.HasPrefix(loc2, "http://app.example/callback?") {
		t.Fatalf("expected direct code redirect, got %q", loc2)
	}
}

func TestConsentDenyReturnsError(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "alice", false)

	ar := AuthorizationRequest{
		ID:          "deny-rid",
		ClientID:    "demo-web",
		RedirectURI: "http://app.example/callback",
		Scope:       "openid",
		State:       "xyz",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(consentRequestExpiry),
	}
	if err := broker.store.PutAuthRequest(ar); err != nil {
		t.Fatalf("seed ar: %v", err)
	}
	form := url.Values{
		"csrf_token": {csrf},
		"request_id": {ar.ID},
		"decision":   {"deny"},
	}
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("expected access_denied error, got %q", loc)
	}
	if !strings.Contains(loc, "state=xyz") {
		t.Fatalf("state missing from deny redirect: %q", loc)
	}
}

func TestConsentRePromptsOnNewScope(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "alice", false)
	if err := broker.store.PutConsent(ConsentRecord{
		UserID:    "alice",
		ClientID:  "demo-web",
		Scopes:    []string{"openid"},
		GrantedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed consent: %v", err)
	}

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"scope":                 {"openid email"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Location"), "/consent") {
		t.Fatalf("expected new-scope re-prompt, got %q", rr.Header().Get("Location"))
	}
}

func TestUserIsAdminMatchesDN(t *testing.T) {
	broker := newAdminTestBroker(t)
	user := &StoredUser{Username: "u", Groups: []string{"CN=administrators,OU=Demo,DC=example,DC=com"}}
	if !broker.userIsAdmin(user) {
		t.Fatal("expected admin via DN-encoded group")
	}
	user.Groups = []string{"developers"}
	if broker.userIsAdmin(user) {
		t.Fatal("non-admin group should not satisfy")
	}
}

func TestParseAdminTokenTTL(t *testing.T) {
	if n, err := parseAdminTokenTTL(""); err != nil || n != 480 {
		t.Fatalf("default = %d err=%v", n, err)
	}
	if _, err := parseAdminTokenTTL("0"); err == nil {
		t.Fatal("zero must be rejected")
	}
	if _, err := parseAdminTokenTTL("abc"); err == nil {
		t.Fatal("non-numeric must be rejected")
	}
	if _, err := parseAdminTokenTTL("99999999"); err == nil {
		t.Fatal("absurdly large value must be rejected")
	}
	if n, err := parseAdminTokenTTL("120"); err != nil || n != 120 {
		t.Fatalf("120 = %d err=%v", n, err)
	}
}

func TestSplitFormLines(t *testing.T) {
	got := splitFormLines("a\n b \n\nc\n")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("got = %v", got)
	}
}

func TestValidClientID(t *testing.T) {
	if !validClientID("ok.id_1-2") {
		t.Fatal("valid id should pass")
	}
	if validClientID("") {
		t.Fatal("empty must fail")
	}
	if validClientID("has space") {
		t.Fatal("space must fail")
	}
	if validClientID(strings.Repeat("a", 65)) {
		t.Fatal("over-length must fail")
	}
}

func TestAdminUnauthenticatedRedirectsToLogin(t *testing.T) {
	broker := newAdminTestBroker(t)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.HasPrefix(rr.Header().Get("Location"), "/login") {
		t.Fatalf("Location = %q", rr.Header().Get("Location"))
	}
}

func TestAdminClientFormGET(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "admin", true)
	req := httptest.NewRequest(http.MethodGet, "/admin/clients/new?error=duplicate", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "duplicate") {
		t.Fatalf("error not surfaced: %q", rr.Body.String())
	}
}

func TestAdminAppTokenFormGET(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "admin", true)
	req := httptest.NewRequest(http.MethodGet, "/admin/app-tokens/new", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestAdminPublicClientHasNoSecret(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "admin", true)
	form := url.Values{
		"csrf_token":    {csrf},
		"client_id":     {"pub-app"},
		"redirect_uris": {"https://pub.example/cb"},
		"public":        {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	c, ok := broker.lookupClient("pub-app")
	if !ok || !c.Public || c.ClientSecretSHA256 != "" {
		t.Fatalf("public client misconfigured: %+v ok=%v", c, ok)
	}
}

func TestAdminAppTokenDuplicateRejected(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "admin", true)
	form := url.Values{"csrf_token": {csrf}, "id": {"dup"}}
	create := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/app-tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addSessionCookie(req, sid)
		rr := httptest.NewRecorder()
		broker.routes().ServeHTTP(rr, req)
		return rr
	}
	first := create()
	if first.Code != http.StatusFound || strings.Contains(first.Header().Get("Location"), "error=") {
		t.Fatalf("first create failed: %d %q", first.Code, first.Header().Get("Location"))
	}
	second := create()
	if !strings.Contains(second.Header().Get("Location"), "error=") {
		t.Fatalf("expected duplicate error, got %q", second.Header().Get("Location"))
	}
}

func TestConsentGetExpiredReturnsError(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "alice", false)
	ar := AuthorizationRequest{
		ID:        "expired-rid",
		ClientID:  "demo-web",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	_ = broker.store.PutAuthRequest(ar)
	req := httptest.NewRequest(http.MethodGet, "/consent?request_id="+ar.ID, nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestConsentGetWithoutSessionRedirects(t *testing.T) {
	broker := newAdminTestBroker(t)
	req := httptest.NewRequest(http.MethodGet, "/consent?request_id=x", nil)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestStoredClientShadowingConfigIsDropped(t *testing.T) {
	broker := newAdminTestBroker(t)
	// Put a stored client with the same id as a config-defined one.
	if err := broker.store.PutStoredClient(Client{
		ClientID:     "demo-web",
		RedirectURIs: []string{"https://hijack.example/cb"},
		StoredAt:     time.Now(),
	}); err != nil {
		t.Fatalf("put stored: %v", err)
	}
	if err := broker.reloadStoredRegistries(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	c, _ := broker.lookupClient("demo-web")
	if c.RedirectURIs[0] == "https://hijack.example/cb" {
		t.Fatal("stored client should not override config-defined client")
	}
}

func TestRequestedScopeList(t *testing.T) {
	got := requestedScopeList("openid  profile openid email")
	if len(got) != 3 || got[0] != "email" || got[1] != "openid" || got[2] != "profile" {
		t.Fatalf("got = %v", got)
	}
	if got := requestedScopeList(""); len(got) != 0 {
		t.Fatalf("empty scope -> %v", got)
	}
}

func TestAdminClientDeleteBadCSRF(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "admin", true)
	req := httptest.NewRequest(http.MethodPost, "/admin/clients/x/delete", strings.NewReader("csrf_token=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestAdminAppTokenDeleteCSRFAndConfigGuard(t *testing.T) {
	broker := newAdminTestBroker(t)
	// Add a config-defined app token so we can verify deletion is blocked.
	broker.appTokens["builtin"] = AppTokenConfig{ID: "builtin", TokenTTLMinutes: 60}
	sid, csrf := adminSession(t, broker, "admin", true)

	t.Run("bad csrf", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/app-tokens/x/delete", strings.NewReader("csrf_token=bad"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addSessionCookie(req, sid)
		rr := httptest.NewRecorder()
		broker.routes().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d", rr.Code)
		}
	})

	t.Run("config-defined blocked", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/app-tokens/builtin/delete", strings.NewReader("csrf_token="+csrf))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		addSessionCookie(req, sid)
		rr := httptest.NewRecorder()
		broker.routes().ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d", rr.Code)
		}
	})
}

func TestAdminAppTokenViewsIncludeConfig(t *testing.T) {
	broker := newAdminTestBroker(t)
	broker.appTokens["cfg-tok"] = AppTokenConfig{ID: "cfg-tok", DisplayName: "Cfg", TokenTTLMinutes: 60}
	views := broker.adminAppTokenViews()
	if len(views) == 0 {
		t.Fatal("no app token views returned")
	}
	var found bool
	for _, v := range views {
		if v.ID == "cfg-tok" && v.ReadOnly {
			found = true
		}
	}
	if !found {
		t.Fatalf("config app token not flagged read-only: %+v", views)
	}
}

func TestConsentPostMissingRequestID(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "alice", false)
	form := url.Values{"csrf_token": {csrf}, "decision": {"approve"}}
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestConsentPostUnauthenticated(t *testing.T) {
	broker := newAdminTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestConsentPostExpiredAR(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "alice", false)
	ar := AuthorizationRequest{
		ID:        "stale-rid",
		ClientID:  "demo-web",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	_ = broker.store.PutAuthRequest(ar)
	form := url.Values{"csrf_token": {csrf}, "decision": {"approve"}, "request_id": {ar.ID}}
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestConsentApproveMergesExistingScopes(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "alice", false)
	// Pre-existing consent covers "openid".
	_ = broker.store.PutConsent(ConsentRecord{
		UserID:    "alice",
		ClientID:  "demo-web",
		Scopes:    []string{"openid"},
		GrantedAt: time.Now(),
	})
	ar := AuthorizationRequest{
		ID:          "merge-rid",
		ClientID:    "demo-web",
		RedirectURI: "http://app.example/callback",
		Scope:       "openid email",
		ExpiresAt:   time.Now().Add(consentRequestExpiry),
	}
	_ = broker.store.PutAuthRequest(ar)
	form := url.Values{"csrf_token": {csrf}, "decision": {"approve"}, "request_id": {ar.ID}}
	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	rec, ok, _ := broker.store.GetConsent("alice", "demo-web")
	if !ok || !consentCovers(rec, []string{"openid", "email"}) {
		t.Fatalf("merged consent missing scopes: %+v", rec)
	}
}

func TestProceedAfterAuthnUnknownClientFails(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "alice", false)
	ar := AuthorizationRequest{
		ID:        "ghost-rid",
		ClientID:  "ghost",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	sess, _, _ := broker.store.GetSession(sid)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := broker.proceedAfterAuthn(rr, req, ar, sess); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestStoredAppTokenShadowingConfigIsDropped(t *testing.T) {
	broker := newAdminTestBroker(t)
	broker.appTokens["cfg-tok"] = AppTokenConfig{ID: "cfg-tok", TokenTTLMinutes: 60}
	if err := broker.store.PutStoredAppToken(AppTokenConfig{ID: "cfg-tok", TokenTTLMinutes: 999, StoredAt: time.Now()}); err != nil {
		t.Fatalf("put stored: %v", err)
	}
	if err := broker.reloadStoredRegistries(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	tok, _ := broker.lookupAppToken("cfg-tok")
	if tok.TokenTTLMinutes != 60 {
		t.Fatal("stored app token should not override config-defined")
	}
}

func TestConsentDeletedOnClientDelete(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "admin", true)
	// Create a stored client and seed a consent for it.
	form := url.Values{
		"csrf_token":    {csrf},
		"client_id":     {"to-delete"},
		"redirect_uris": {"https://to-delete.example/cb"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status = %d", rr.Code)
	}
	_ = broker.store.PutConsent(ConsentRecord{UserID: "alice", ClientID: "to-delete", Scopes: []string{"openid"}, GrantedAt: time.Now()})

	delReq := httptest.NewRequest(http.MethodPost, "/admin/clients/to-delete/delete", strings.NewReader("csrf_token="+csrf))
	delReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(delReq, sid)
	delRR := httptest.NewRecorder()
	broker.routes().ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusFound {
		t.Fatalf("delete status = %d", delRR.Code)
	}
	if _, ok, _ := broker.store.GetConsent("alice", "to-delete"); ok {
		t.Fatal("consent should have been removed when client was deleted")
	}
}

func TestStoreSortHelpers(t *testing.T) {
	clients := []Client{{ClientID: "z"}, {ClientID: "a"}, {ClientID: "m"}}
	sortClientsByID(clients)
	if clients[0].ClientID != "a" || clients[1].ClientID != "m" || clients[2].ClientID != "z" {
		t.Fatalf("sortClientsByID: %+v", clients)
	}
	toks := []AppTokenConfig{{ID: "z"}, {ID: "a"}, {ID: "m"}}
	sortAppTokensByID(toks)
	if toks[0].ID != "a" || toks[1].ID != "m" || toks[2].ID != "z" {
		t.Fatalf("sortAppTokensByID: %+v", toks)
	}
}

func TestStorePutStoredClientRejectsBlankID(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), defaultDataFile))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.PutStoredClient(Client{}); err == nil {
		t.Fatal("expected error for blank client_id")
	}
	if err := store.PutStoredAppToken(AppTokenConfig{}); err == nil {
		t.Fatal("expected error for blank app token id")
	}
	if err := store.PutConsent(ConsentRecord{}); err == nil {
		t.Fatal("expected error for blank consent fields")
	}
}

func TestAdminClientCreateBadID(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "admin", true)
	form := url.Values{
		"csrf_token":    {csrf},
		"client_id":     {"bad id"},
		"redirect_uris": {"https://x.example/cb"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "error=") {
		t.Fatalf("bad id should redirect with error: %q", rr.Header().Get("Location"))
	}
}

func TestAdminCreateBadFormParse(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "admin", true)
	// Send body with bad content-type form encoding (semicolon as separator
	// is technically allowed; force a real parse error with a malformed %).
	req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader("client_id=%ZZ"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestConsentGetMissingRequestID(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "alice", false)
	req := httptest.NewRequest(http.MethodGet, "/consent", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestConsentGetUnknownClient(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "alice", false)
	ar := AuthorizationRequest{
		ID:        "no-client",
		ClientID:  "missing",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	_ = broker.store.PutAuthRequest(ar)
	req := httptest.NewRequest(http.MethodGet, "/consent?request_id="+ar.ID, nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestAdminAppTokenBadCSRF(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, _ := adminSession(t, broker, "admin", true)
	form := url.Values{"csrf_token": {"bad"}, "id": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/app-tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestAdminAppTokenBadID(t *testing.T) {
	broker := newAdminTestBroker(t)
	sid, csrf := adminSession(t, broker, "admin", true)
	form := url.Values{"csrf_token": {csrf}, "id": {"bad id"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/app-tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "error=") {
		t.Fatalf("expected error redirect, got %d %q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestConsentCoversAndMerge(t *testing.T) {
	rec := ConsentRecord{Scopes: []string{"openid", "profile"}}
	if !consentCovers(rec, []string{"openid"}) {
		t.Fatal("openid should be covered")
	}
	if consentCovers(rec, []string{"openid", "email"}) {
		t.Fatal("email not granted; should not be covered")
	}
	merged := mergeScopeSets([]string{"openid"}, []string{"profile", "openid"})
	if len(merged) != 2 || merged[0] != "openid" || merged[1] != "profile" {
		t.Fatalf("merged = %v", merged)
	}
}
