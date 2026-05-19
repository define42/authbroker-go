package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
)

// --- main.go: waitForServerStop / run / prepareCertMagic / listen / ACME paths ---

func TestWaitForServerStopReportsBindError(t *testing.T) {
	broker := newLogoutTestBroker(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer occupied.Close()

	srv := newHTTPServer(broker)
	srv.Addr = occupied.Addr().String()

	shouldDrain, err := waitForServerStop(context.Background(), srv, broker)
	if err == nil {
		t.Fatal("expected bind error from occupied port")
	}
	if shouldDrain {
		t.Fatal("shouldDrain must be false when ListenAndServe fails")
	}
}

func TestWaitForServerStopDrainsOnContextCancel(t *testing.T) {
	broker := newLogoutTestBroker(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := newHTTPServer(broker)
	srv.Addr = listener.Addr().String()
	// Release the port so ListenAndServe (inside waitForServerStop) can grab
	// it cleanly.
	_ = listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		drain bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		drain, err := waitForServerStop(ctx, srv, broker)
		done <- result{drain: drain, err: err}
	}()

	// Give ListenAndServe time to start before signalling shutdown.
	time.Sleep(100 * time.Millisecond)
	cancel()
	_ = srv.Close()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("unexpected err: %v", got.err)
		}
		if !got.drain {
			t.Fatal("shouldDrain must be true after context cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitForServerStop did not return")
	}
}

func TestRunSurfacesServerError(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer occupied.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	body := fmt.Sprintf(`{"issuer":"http://broker.example","listen":%q,"clients":[{"client_id":"demo","redirect_uris":["http://demo/cb"]}]}`, occupied.Addr().String())
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}

	err = run(cliOptions{configPath: cfgPath, dataPath: filepath.Join(dir, "data")})
	if err == nil {
		t.Fatal("expected error from occupied listen address")
	}
}

func TestPrepareCertMagicSucceedsWithoutCustomRoots(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	storage := t.TempDir()
	magicCfg, tlsCfg, err := prepareCertMagic(ctx, ACMEConfig{Domains: []string{"example.com"}}, storage)
	if err != nil {
		t.Fatalf("prepareCertMagic: %v", err)
	}
	if magicCfg == nil || tlsCfg == nil {
		t.Fatal("nil result from prepareCertMagic")
	}
	if len(tlsCfg.NextProtos) == 0 || tlsCfg.NextProtos[0] != "h2" {
		t.Fatalf("tlsConfig.NextProtos = %v", tlsCfg.NextProtos)
	}
}

func TestPrepareCertMagicRejectsBadCACert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	missing := filepath.Join(t.TempDir(), "missing.pem")
	if _, _, err := prepareCertMagic(ctx, ACMEConfig{CACertPath: missing}, t.TempDir()); err == nil {
		t.Fatal("expected error loading missing ca cert")
	}
}

func TestRunACMEPropagatesCertMagicError(t *testing.T) {
	broker := newLogoutTestBroker(t)
	missing := filepath.Join(t.TempDir(), "no-such.pem")
	broker.cfg.ACME = ACMEConfig{
		Enabled:    true,
		AgreedTOS:  true,
		Domains:    []string{"example.com"},
		HTTPAddr:   "127.0.0.1:0",
		HTTPSAddr:  "127.0.0.1:0",
		CACertPath: missing,
	}
	err := runACME(context.Background(), broker, t.TempDir(), func() {})
	if err == nil || !strings.Contains(err.Error(), "ca cert") {
		t.Fatalf("expected ca cert error, got %v", err)
	}
}

func TestListenIsLocalhostOnlyEdgeCases(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":   true,
		"[::1]:8080":       true,
		"localhost:8080":   true,
		"LocalHost:8080":   true,
		"":                 false,
		":8080":            false,
		"0.0.0.0:8080":     false,
		"[::]:8080":        false,
		"192.168.1.1:8080": false,
		"not-a-host":       false,
	}
	for in, want := range cases {
		if got := listenIsLocalhostOnly(in); got != want {
			t.Errorf("listenIsLocalhostOnly(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFirstACMEIssuerFindsACMEIssuer(t *testing.T) {
	cfg := &certmagic.Config{Issuers: []certmagic.Issuer{&certmagic.ACMEIssuer{}}}
	if got := firstACMEIssuer(cfg); got == nil {
		t.Fatal("expected to find ACME issuer in slice")
	}
}

func TestListenACMEHappyPath(t *testing.T) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("test stub")
		},
	}
	cfg := ACMEConfig{HTTPSAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0"}
	httpsL, httpL, err := listenACME(cfg, tlsCfg)
	if err != nil {
		t.Fatalf("listenACME: %v", err)
	}
	defer func() {
		_ = httpsL.Close()
		_ = httpL.Close()
	}()
	if httpsL.Addr() == nil || httpL.Addr() == nil {
		t.Fatal("listeners missing addresses")
	}
}

// --- util.go: writeFileAtomic / loadRootCAs error and success paths ---

func TestWriteFileAtomicFailsOnUnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) //nolint:gosec // Restore so t.TempDir cleanup can remove the directory.
	if err := writeFileAtomic(filepath.Join(locked, "out.bin"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected error writing into read-only directory")
	}
}

func TestSyncDirReportsMissingPath(t *testing.T) {
	if err := syncDir(filepath.Join(t.TempDir(), "no-such-dir")); err == nil {
		t.Fatal("expected error opening missing directory")
	}
}

func TestLoadRootCAsEmptyPathReturnsNil(t *testing.T) {
	pool, err := loadRootCAs("   ")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if pool != nil {
		t.Fatal("empty path should yield nil pool so the system pool is used")
	}
}

func TestLoadRootCAsRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadRootCAs(path); err == nil {
		t.Fatal("expected error for non-PEM content")
	}
}

func TestLoadRootCAsMissingFile(t *testing.T) {
	if _, err := loadRootCAs(filepath.Join(t.TempDir(), "no-such.pem")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// --- signing_keys.go: rotateAndPrune / validate edge cases ---

func TestRotateAndPruneInitialKeyAndForceRotate(t *testing.T) {
	now := time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC)
	set := managedSigningKeySet{}
	changed, err := set.rotateAndPrune("kid", 30, 60, false, now)
	if err != nil {
		t.Fatalf("initial: %v", err)
	}
	if !changed || len(set.Keys) != 1 || set.ActiveKeyID == "" {
		t.Fatalf("initial create did not happen: %+v", set)
	}

	// Force rotate on a fresh key.
	originalID := set.ActiveKeyID
	changed, err = set.rotateAndPrune("kid", 30, 60, true, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("force rotate: %v", err)
	}
	if !changed {
		t.Fatal("force rotate should report changed=true")
	}
	if set.ActiveKeyID == originalID {
		t.Fatal("force rotate should produce a new active key id")
	}
	if len(set.Keys) != 2 {
		t.Fatalf("expected old + new key, got %d", len(set.Keys))
	}
}

func TestRotateAndPrunePrunesRetiredKeys(t *testing.T) {
	now := time.Date(2026, 5, 17, 0, 0, 0, 0, time.UTC)
	// Seed an active key plus a long-retired old key.
	active, err := newManagedSigningKey("active", now)
	if err != nil {
		t.Fatalf("active key: %v", err)
	}
	retired, err := newManagedSigningKey("retired", now.AddDate(0, 0, -120))
	if err != nil {
		t.Fatalf("retired key: %v", err)
	}
	retired.RetiredAt = now.AddDate(0, 0, -90).Unix()
	set := managedSigningKeySet{ActiveKeyID: active.KeyID, Keys: []managedSigningKey{active, retired}}

	changed, err := set.rotateAndPrune("active", 0, 30, false, now)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !changed {
		t.Fatal("expected pruning to mark set as changed")
	}
	if len(set.Keys) != 1 || set.Keys[0].KeyID != active.KeyID {
		t.Fatalf("retired key was not pruned: %+v", set.Keys)
	}
}

func TestValidateManagedSigningKeySetRejectsBadInputs(t *testing.T) {
	// Empty active key id.
	if err := (&managedSigningKeySet{}).validate(); err == nil {
		t.Fatal("empty active id must fail")
	}

	// Active key not in the slice.
	if err := (&managedSigningKeySet{ActiveKeyID: "missing"}).validate(); err == nil {
		t.Fatal("missing active key must fail")
	}

	// Active key marked retired.
	good, err := newManagedSigningKey("kid", time.Now())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	good.RetiredAt = time.Now().Unix()
	set := &managedSigningKeySet{ActiveKeyID: good.KeyID, Keys: []managedSigningKey{good}}
	if err := set.validate(); err == nil {
		t.Fatal("retired active key must fail validation")
	}

	// Duplicate key ids.
	dup, err := newManagedSigningKey("kid", time.Now())
	if err != nil {
		t.Fatalf("dup key: %v", err)
	}
	dup.KeyID = good.KeyID
	good.RetiredAt = 0
	dupSet := &managedSigningKeySet{ActiveKeyID: good.KeyID, Keys: []managedSigningKey{good, dup}}
	if err := dupSet.validate(); err == nil {
		t.Fatal("duplicate key ids must fail validation")
	}

	// Missing PEM.
	noPEM := managedSigningKey{KeyID: "kid", SigningKeyPEM: ""}
	missingSet := &managedSigningKeySet{ActiveKeyID: "kid", Keys: []managedSigningKey{noPEM}}
	if err := missingSet.validate(); err == nil {
		t.Fatal("missing pem must fail validation")
	}

	// Bad PEM body.
	//nolint:gosec // Fixture PEM body is intentionally invalid for the parse-failure check.
	badPEM := managedSigningKey{KeyID: "kid", SigningKeyPEM: "-----BEGIN RSA PRIVATE KEY-----\nQQ==\n-----END RSA PRIVATE KEY-----"}
	badSet := &managedSigningKeySet{ActiveKeyID: "kid", Keys: []managedSigningKey{badPEM}}
	if err := badSet.validate(); err == nil {
		t.Fatal("unparseable pem must fail validation")
	}
}

func TestSanitizeKeyIDPrefixStripsInvalidChars(t *testing.T) {
	if got := sanitizeKeyIDPrefix("  foo/bar-baz_42  "); got != "foobar-baz_42" {
		t.Fatalf("sanitizeKeyIDPrefix = %q", got)
	}
	if got := sanitizeKeyIDPrefix("---__-"); got != "" {
		t.Fatalf("trimming leftovers = %q", got)
	}
}

// --- handlers_session.go: more login / logout / resolve coverage ---

func TestResolveLogoutClientIDFromIDTokenHint(t *testing.T) {
	broker := newLogoutTestBroker(t)
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	idToken, _ := tokens["id_token"].(string)

	rr := httptest.NewRecorder()
	got, ok := broker.resolveLogoutClientID(rr, "", idToken)
	if !ok {
		t.Fatalf("resolveLogoutClientID returned ok=false: %s", rr.Body.String())
	}
	if got != "demo-web" {
		t.Fatalf("client id = %q", got)
	}
}

func TestResolveLogoutClientIDMismatchFails(t *testing.T) {
	broker := newLogoutTestBroker(t)
	tokens, err := broker.issueUserTokens("johndoe", "demo-web", "openid", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	idToken, _ := tokens["id_token"].(string)

	rr := httptest.NewRecorder()
	if _, ok := broker.resolveLogoutClientID(rr, "wrong-client", idToken); ok {
		t.Fatal("mismatched client_id must fail")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestResolveLogoutClientIDInvalidHint(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rr := httptest.NewRecorder()
	if _, ok := broker.resolveLogoutClientID(rr, "", "not.a.jwt"); ok {
		t.Fatal("invalid hint with no client_id must fail")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestResolveLogoutClientIDInvalidHintWithClientIDPasses(t *testing.T) {
	broker := newLogoutTestBroker(t)
	rr := httptest.NewRecorder()
	got, ok := broker.resolveLogoutClientID(rr, "demo-web", "not.a.jwt")
	if !ok {
		t.Fatal("invalid hint should not block when client_id is present")
	}
	if got != "demo-web" {
		t.Fatalf("client id = %q", got)
	}
}

func TestLogoutParamPicksFormOrQuery(t *testing.T) {
	postReq := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader("client_id=via-form"))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := postReq.ParseForm(); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := logoutParam(postReq, "client_id"); got != "via-form" {
		t.Fatalf("post form = %q", got)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/oauth2/logout?client_id=via-query", nil)
	if got := logoutParam(getReq, "client_id"); got != "via-query" {
		t.Fatalf("get query = %q", got)
	}
}

func TestHandleLoginPostInvalidatedRequestID(t *testing.T) {
	broker := newLogoutTestBroker(t)
	token, cookie := loginCSRF(t, broker)
	form := url.Values{
		"request_id": {"never-existed"},
		"username":   {"alice"},
		"password":   {"pw"},
		"csrf_token": {token},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	broker.handleLoginPost(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleLoginPostBadForm(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("%ZZ"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	broker.handleLoginPost(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestMaybeExtendSessionRefreshesCookie(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "extend-session"
	// TTL = 8 hours by default. Seed an expiry near "less than half remaining"
	// so maybeExtendSession refreshes it.
	if err := broker.store.PutSession(sid, Session{
		UserID:    "alice",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.maybeExtendSession(rr, req)

	c := findCookie(rr, sessionCookieName)
	if c == nil {
		t.Fatal("expected refreshed cookie")
	}
	if c.Value != sid {
		t.Fatalf("cookie value = %q", c.Value)
	}
	got, _, _ := broker.store.GetSession(sid)
	if time.Until(got.ExpiresAt) < 2*time.Hour {
		t.Fatalf("expiry did not extend: %v", got.ExpiresAt)
	}
}

func TestMaybeExtendSessionDeletesExpiredCookie(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "stale-session"
	if err := broker.store.PutSession(sid, Session{
		UserID:    "alice",
		ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.maybeExtendSession(rr, req)

	if _, ok, _ := broker.store.GetSession(sid); ok {
		t.Fatal("expired session should be deleted by maybeExtendSession")
	}
}

func TestMaybeExtendSessionNoCookieIsNoop(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	broker.maybeExtendSession(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if findCookie(rr, sessionCookieName) != nil {
		t.Fatal("did not expect a cookie to be set when no session is present")
	}
}

func TestMarkSessionReAuthRequiresCookie(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/reauth", nil)
	if err := broker.markSessionReAuth(req); err == nil {
		t.Fatal("expected error when cookie is missing")
	}
}

func TestMarkSessionReAuthUnknownSessionIsNoop(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/reauth", nil)
	addSessionCookie(req, "no-such-session")
	if err := broker.markSessionReAuth(req); err != nil {
		t.Fatalf("unknown session should be silently ignored, got %v", err)
	}
}

func TestClearSessionDeletesCookieAndStoreEntry(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "clear-me"
	if err := broker.store.PutSession(sid, Session{UserID: "alice", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	if err := broker.clearSession(rr, req); err != nil {
		t.Fatalf("clearSession: %v", err)
	}
	if _, ok, _ := broker.store.GetSession(sid); ok {
		t.Fatal("session was not deleted")
	}
	c := findCookie(rr, sessionCookieName)
	if c == nil || c.MaxAge >= 0 {
		t.Fatalf("expected expired cookie, got %#v", c)
	}
}

func TestHandleLogoutEmptyParameters(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout", nil)
	rr := httptest.NewRecorder()
	broker.handleLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "logged out") {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestHandleLogoutPostInvalidRedirectURI(t *testing.T) {
	broker := newLogoutTestBroker(t)
	form := url.Values{"post_logout_redirect_uri": {"http://attacker.example/"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	broker.handleLogout(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleLogoutAllowedPostLogoutRedirect(t *testing.T) {
	broker := newLogoutTestBroker(t)
	q := url.Values{
		"client_id":                {"demo-web"},
		"post_logout_redirect_uri": {"http://app.example/"},
		"state":                    {"xyz"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/logout?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	broker.handleLogout(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "state=xyz") {
		t.Fatalf("Location = %q", loc)
	}
}

func TestClientIDFromTokenClaims(t *testing.T) {
	if got := clientIDFromTokenClaims(map[string]any{"client_id": "via-claim"}); got != "via-claim" {
		t.Fatalf("client_id claim = %q", got)
	}
	if got := clientIDFromTokenClaims(map[string]any{"aud": "demo-aud"}); got != "demo-aud" {
		t.Fatalf("aud string = %q", got)
	}
	if got := clientIDFromTokenClaims(map[string]any{"aud": []any{"single-aud"}}); got != "single-aud" {
		t.Fatalf("aud single list = %q", got)
	}
	if got := clientIDFromTokenClaims(map[string]any{"aud": []any{"a", "b"}}); got != "" {
		t.Fatalf("multi aud should yield empty, got %q", got)
	}
	if got := clientIDFromTokenClaims(map[string]any{"azp": "via-azp", "aud": []any{"a", "b"}}); got != "via-azp" {
		t.Fatalf("azp should win over multi aud, got %q", got)
	}
	if got := clientIDFromTokenClaims(map[string]any{"azp": "via-azp", "client_id": "via-claim"}); got != "via-azp" {
		t.Fatalf("azp should win over client_id, got %q", got)
	}
}

// --- handlers_webauthn.go: register/login finish error paths ---

func TestHandleWebAuthnRegisterFinishExpiredChallenge(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.WebAuthn.RPID = "broker.example"
	broker.cfg.WebAuthn.Origins = []string{"http://broker.example"}

	sid := enrollSessionFor(t, broker, "alice")

	// Beginning seeds a record we will overwrite with an expired one.
	challenge := beginRegistration(t, broker, sid)
	if err := broker.store.PutWebAuthnRegistration(challenge, ChallengeRecord{
		UserID:    "alice",
		Challenge: challenge,
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed expired challenge: %v", err)
	}

	cd := webauthnClientData{Type: "webauthn.create", Challenge: challenge, Origin: broker.cfg.WebAuthn.Origins[0]}
	cdBytes, _ := json.Marshal(cd)
	body := map[string]any{
		"rawId": base64.RawURLEncoding.EncodeToString([]byte("id")),
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdBytes),
			"attestationObject": base64.RawURLEncoding.EncodeToString([]byte{0x80}),
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", strings.NewReader(string(bodyBytes)))
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleWebAuthnRegisterFinish(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleWebAuthnRegisterFinishUnauthenticated(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	broker.handleWebAuthnRegisterFinish(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleWebAuthnLoginFinishBadClientData(t *testing.T) {
	broker := newLogoutTestBroker(t)
	body := map[string]any{
		"response": map[string]any{
			"clientDataJSON":    "!!!",
			"authenticatorData": "AA",
			"signature":         "AA",
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", strings.NewReader(string(bodyBytes)))
	rr := httptest.NewRecorder()
	broker.handleWebAuthnLoginFinish(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

// --- handlers_oauth.go: client_credentials & user info & revoke ---

func TestTokenClientCredentialsRejectsPublicClient(t *testing.T) {
	broker := newLogoutTestBroker(t)
	pubID := "public-demo"
	broker.clients[pubID] = Client{ClientID: pubID, Public: true}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {pubID}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	broker.handleToken(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unauthorized_client") {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestHandleRevokeIgnoresUnknownRefresh(t *testing.T) {
	broker := newLogoutTestBroker(t)
	form := url.Values{"token": {"never-issued"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleRevoke(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestHandleRevokeWithEmptyTokenIsNoop(t *testing.T) {
	broker := newLogoutTestBroker(t)
	form := url.Values{"token": {""}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleRevoke(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserInfoSurfacesGroupsForOwningClient(t *testing.T) {
	broker := newLogoutTestBroker(t)
	if _, err := broker.store.UpsertProfile(UserProfile{
		Subject: "alice",
		Name:    "Alice",
		Email:   "a@example",
		Groups:  []string{"admins"},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	tokens, err := broker.issueUserTokens("alice", "demo-web", "openid email groups", "", time.Now(), nil, false)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	access := tokens["access_token"].(string)

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
	if resp["email"] != "a@example" {
		t.Fatalf("email = %v", resp["email"])
	}
}

func TestMappedGroupsForClientUnknownClient(t *testing.T) {
	broker := newLogoutTestBroker(t)
	got := broker.mappedGroupsForClient("missing-client", &StoredUser{Groups: []string{"x"}})
	if got != nil {
		t.Fatalf("unknown client should return nil, got %v", got)
	}
}

func TestMappedGroupsForClientNilUser(t *testing.T) {
	broker := newLogoutTestBroker(t)
	if got := broker.mappedGroupsForClient("demo-web", nil); got != nil {
		t.Fatalf("nil user should return nil, got %v", got)
	}
}

// --- handlers_totp.go: enrollment requires reauth + happy path ---

func TestHandleTOTPEnrollIssuesSecret(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "enroll-ok"
	if err := broker.store.PutSession(sid, Session{
		UserID:    "alice",
		CSRFToken: "tok",
		ReAuthAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed: %v", err)
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
	if body["secret_base32"] == "" {
		t.Fatal("missing secret")
	}
	if !strings.HasPrefix(body["otpauth_uri"], "otpauth://totp/") {
		t.Fatalf("otpauth = %q", body["otpauth_uri"])
	}
}

// --- store.go SeedRuntimeState empty path ---

func TestStoreSeedRuntimeStateEmpty(t *testing.T) {
	store := newTestStore(t)
	if err := store.SeedRuntimeState(StoredRuntimeState{}); err != nil {
		t.Fatalf("empty seed: %v", err)
	}
}

// --- shutdown wrapper sanity check ---

func TestShutdownACMERunsBothShutdowns(_ *testing.T) {
	srv1 := &http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: time.Second}
	srv2 := &http.Server{Addr: "127.0.0.1:0", ReadHeaderTimeout: time.Second}
	shutdownACME(srv1, srv2)
}

// --- Additional login/TOTP/login-rate coverage ---

func TestHandleLoginPostTOTPNotEnrolled(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.MFA.TOTPRequired = true
	broker.authn = staticAuthenticator{profile: UserProfile{Subject: "alice"}}

	token, cookie := loginCSRF(t, broker)
	form := url.Values{
		"username":   {"alice"},
		"password":   {"pw"},
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

func TestHandleLoginPostTOTPInvalidCode(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.MFA.TOTPRequired = true
	broker.authn = staticAuthenticator{profile: UserProfile{Subject: "alice"}}
	if _, err := broker.store.UpsertProfile(UserProfile{Subject: "alice"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := broker.store.SetTOTP("alice", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("set totp: %v", err)
	}

	token, cookie := loginCSRF(t, broker)
	form := url.Values{
		"username":   {"alice"},
		"password":   {"pw"},
		"otp":        {"000000"},
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

func TestHandleLoginPostRateLimited(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.authn = staticAuthenticator{profile: UserProfile{Subject: "alice"}}

	// Drive the limiter into lockout for the synthetic test IP + user.
	rateKey := "ip:192.0.2.1/user:alice"
	for i := 0; i < loginRateLimitMaxAttempts; i++ {
		broker.loginLimiter.recordFailure(rateKey)
	}

	token, cookie := loginCSRF(t, broker)
	form := url.Values{
		"username":   {"alice"},
		"password":   {"pw"},
		"csrf_token": {token},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	broker.handleLoginPost(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
}

func TestHandleReAuthRateLimited(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sess, err := broker.createSession(httptest.NewRecorder(), "alice", false, nil)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	var sid string
	for id := range broker.store.RuntimeSnapshot().Sessions {
		sid = id
	}

	rateKey := "ip:192.0.2.1/user:alice"
	for i := 0; i < loginRateLimitMaxAttempts; i++ {
		broker.loginLimiter.recordFailure(rateKey)
	}

	form := url.Values{"password": {"pw"}, "csrf_token": {sess.CSRFToken}}
	req := httptest.NewRequest(http.MethodPost, "/reauth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleReAuth(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

// --- handlers_oauth.go: PKCE failure + race lost rotation ---

func TestTokenAuthorizationCodePKCEFails(t *testing.T) {
	broker := newLogoutTestBroker(t)
	code := "pkce-code"
	if err := broker.store.PutAuthCode(hashSecret(code), AuthCode{
		ClientID:            "demo-web",
		RedirectURI:         "http://app.example/callback",
		CodeChallenge:       "challenge-bytes",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://app.example/callback"},
		"code_verifier": {"wrong-verifier"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("demo-web", "demo-secret")
	rr := httptest.NewRecorder()
	broker.handleToken(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "PKCE") {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestAuthorizePKCERequiredWhenClientFlagged(t *testing.T) {
	broker := newLogoutTestBroker(t)
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {"demo-web"},
		"redirect_uri":  {"http://app.example/callback"},
		"state":         {"st"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("Location = %q", loc)
	}
}

func TestAuthorizeWithValidSessionIssuesCode(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "valid-sess"
	if err := broker.store.PutSession(sid, Session{
		UserID:    "alice",
		ExpiresAt: time.Now().Add(time.Hour),
		AuthTime:  time.Now(),
		CSRFToken: "tok",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Use a code_verifier and matching S256 challenge to satisfy RequirePKCE.
	verifier := "test-verifier-12345678901234567890123456789012"
	challengeBytes := sha256Sum(verifier)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"demo-web"},
		"redirect_uri":          {"http://app.example/callback"},
		"scope":                 {"openid"},
		"state":                 {"xyz"},
		"code_challenge":        {challengeBytes},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleAuthorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Location"), "code=") {
		t.Fatalf("missing code in redirect: %q", rr.Header().Get("Location"))
	}
}

func sha256Sum(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// --- WebAuthn coverage ---

func TestHandleWebAuthnLoginFinishRateLimited(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.WebAuthn.RPID = "broker.example"
	broker.cfg.WebAuthn.Origins = []string{"http://broker.example"}

	if _, err := broker.store.UpsertProfile(UserProfile{Subject: "alice"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	challenge := beginLogin(t, broker, "alice")

	// Lock the user out.
	rateKey := "ip:127.0.0.1/user:alice"
	for i := 0; i < loginRateLimitMaxAttempts; i++ {
		broker.loginLimiter.recordFailure(rateKey)
	}

	cd := webauthnClientData{Type: "webauthn.get", Challenge: challenge, Origin: "http://broker.example"}
	cdBytes, _ := json.Marshal(cd)
	body := map[string]any{
		"rawId": base64.RawURLEncoding.EncodeToString([]byte("id")),
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdBytes),
			"authenticatorData": base64.RawURLEncoding.EncodeToString([]byte{0x00}),
			"signature":         base64.RawURLEncoding.EncodeToString([]byte("sig")),
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", strings.NewReader(string(bodyBytes)))
	req.RemoteAddr = "127.0.0.1:4040"
	rr := httptest.NewRecorder()
	broker.handleWebAuthnLoginFinish(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleWebAuthnRegisterFinishRejectsBadAttestation(t *testing.T) {
	broker := newLogoutTestBroker(t)
	broker.cfg.WebAuthn.RPID = "broker.example"
	broker.cfg.WebAuthn.Origins = []string{"http://broker.example"}
	sid := enrollSessionFor(t, broker, "alice")
	challenge := beginRegistration(t, broker, sid)

	cd := webauthnClientData{Type: "webauthn.create", Challenge: challenge, Origin: "http://broker.example"}
	cdBytes, _ := json.Marshal(cd)
	body := map[string]any{
		"rawId": base64.RawURLEncoding.EncodeToString([]byte("id")),
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdBytes),
			"attestationObject": base64.RawURLEncoding.EncodeToString([]byte{0x00}),
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", strings.NewReader(string(bodyBytes)))
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleWebAuthnRegisterFinish(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

// --- ldap.go small helpers ---

func TestLDAPAuthenticatorNestedADGroupsRequiresUserDN(t *testing.T) {
	authn := &LDAPAuthenticator{}
	if got := authn.nestedADGroupFilter("CN=Alice,DC=Example,DC=com"); !strings.Contains(got, "Alice") {
		t.Fatalf("nestedADGroupFilter = %q", got)
	}
	if got := authn.loginName("alice"); got != "alice" {
		t.Fatalf("loginName w/o DomainSuffix = %q", got)
	}
	withSuffix := &LDAPAuthenticator{cfg: LDAPConfig{DomainSuffix: "@example.com"}}
	if got := withSuffix.loginName("alice"); got != "alice@example.com" {
		t.Fatalf("loginName w/ DomainSuffix = %q", got)
	}
	if got := withSuffix.loginName("already@elsewhere"); got != "already@elsewhere" {
		t.Fatalf("loginName preserves explicit upn = %q", got)
	}
}

// --- handlers_home.go: appToken issuance ---

func TestHandleAppTokenIssues(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "app-token-sess"
	now := time.Now()
	if err := broker.store.PutSession(sid, Session{
		UserID:    "alice",
		ExpiresAt: now.Add(time.Hour),
		AuthTime:  now,
		ReAuthAt:  now,
		CSRFToken: "csrf-token",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	form := url.Values{"csrf_token": {"csrf-token"}}
	req := httptest.NewRequest(http.MethodPost, "/app-tokens/litellm", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", "litellm")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleAppToken(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "app-token-value") {
		t.Fatalf("body did not include the token textarea: %s", rr.Body.String())
	}
}

func TestHandleAppTokenUnknownIDReturns404(t *testing.T) {
	broker := newLogoutTestBroker(t)
	sid := "unknown-app-token"
	if err := broker.store.PutSession(sid, Session{
		UserID:    "alice",
		ExpiresAt: time.Now().Add(time.Hour),
		ReAuthAt:  time.Now(),
		CSRFToken: "csrf-token",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	form := url.Values{"csrf_token": {"csrf-token"}}
	req := httptest.NewRequest(http.MethodPost, "/app-tokens/missing", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", "missing")
	addSessionCookie(req, sid)
	rr := httptest.NewRecorder()
	broker.handleAppToken(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleAppTokenRedirectsWithoutSession(t *testing.T) {
	broker := newLogoutTestBroker(t)
	req := httptest.NewRequest(http.MethodPost, "/app-tokens/litellm", nil)
	req.SetPathValue("id", "litellm")
	rr := httptest.NewRecorder()
	broker.handleAppToken(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
}

// Compile-time references so unused-import linting doesn't complain when
// the file is trimmed during edits.
var _ = errors.New
