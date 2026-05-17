package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "abc123abc123abc123abc123abc123abc123abc123abc"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !verifyPKCE(challenge, "S256", verifier) {
		t.Fatal("expected matching PKCE to verify")
	}
	if verifyPKCE(challenge, "S256", "wrong-verifier") {
		t.Fatal("mismatched verifier should fail")
	}
	if verifyPKCE("", "S256", verifier) {
		t.Fatal("empty challenge should fail")
	}
	if verifyPKCE(challenge, "plain", verifier) {
		t.Fatal("plain method should be rejected")
	}
	if verifyPKCE(challenge, "S256", "") {
		t.Fatal("empty verifier should fail")
	}
}

func TestNormalizeChallenge(t *testing.T) {
	raw := []byte("hello world!")
	rawURL := base64.RawURLEncoding.EncodeToString(raw)
	padded := base64.URLEncoding.EncodeToString(raw)
	if got := normalizeChallenge(rawURL); got != rawURL {
		t.Fatalf("rawURL normalized to %q, want %q", got, rawURL)
	}
	if got := normalizeChallenge(padded); got != rawURL {
		t.Fatalf("padded normalized to %q, want %q", got, rawURL)
	}
	if got := normalizeChallenge("!!!invalid!!!"); got != "!!!invalid!!!" {
		t.Fatalf("invalid input should pass through, got %q", got)
	}
}

func TestRandomB64AndBase64(t *testing.T) {
	s := randomB64(16)
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode random: %v", err)
	}
	if len(decoded) != 16 {
		t.Fatalf("decoded length = %d, want 16", len(decoded))
	}
	if base64RawURL([]byte("xx")) != "eHg" {
		t.Fatalf("base64RawURL produced unexpected encoding")
	}
}

func TestDecodeB64URLRejectsEmpty(t *testing.T) {
	if _, err := decodeB64URL(""); err == nil {
		t.Fatal("decodeB64URL must reject empty input")
	}
	if _, err := decodeB64URL("not base64!!"); err == nil {
		t.Fatal("decodeB64URL must reject garbage input")
	}
}

func TestUniqueNonEmpty(t *testing.T) {
	got := uniqueNonEmpty("a", "", " a ", "b", "a")
	want := []string{"a", "b"}
	assertStringSlicesEqual(t, got, want)
}

func TestWriteJSONSetsContentType(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusTeapot, map[string]string{"hello": "world"})
	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if !strings.Contains(rr.Body.String(), `"hello":"world"`) {
		t.Fatalf("body = %q", rr.Body.String())
	}
}

func TestLoadRootCAs(t *testing.T) {
	if pool, err := loadRootCAs(""); err != nil || pool != nil {
		t.Fatalf("empty path: pool=%v err=%v", pool, err)
	}
	if _, err := loadRootCAs(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing path should fail")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a pem cert"), 0o600); err != nil {
		t.Fatalf("write bad pem: %v", err)
	}
	if _, err := loadRootCAs(bad); err == nil {
		t.Fatal("non-pem content should fail")
	}
}

func TestWriteFileAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "value")
	content := []byte("hello atomic")
	if err := writeFileAtomic(path, content, 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // Test reads a file in t.TempDir.
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("got %q, want %q", got, content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}

func TestCBORGetStringAndInt(t *testing.T) {
	m := map[any]cborValue{
		"name":   {kind: cborString, strValue: "x"},
		int64(2): {kind: cborInt, intValue: 7},
	}
	if v, ok := cborGetString(m, "name"); !ok || v.strValue != "x" {
		t.Fatalf("cborGetString(name) = %#v ok=%v", v, ok)
	}
	if _, ok := cborGetString(m, "missing"); ok {
		t.Fatal("cborGetString must report missing key")
	}
	if v, ok := cborGetInt(m, 2); !ok || v.intValue != 7 {
		t.Fatalf("cborGetInt(2) = %#v ok=%v", v, ok)
	}
}

func TestVerifyTOTPRoundTrip(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP" //nolint:gosec // Standard RFC 6238 test vector.
	now := time.Unix(1700000000, 0)
	code := totpCode(secret, now.Unix()/30)
	if len(code) != 6 {
		t.Fatalf("totp code length = %d", len(code))
	}
	if !verifyTOTP(secret, code, now, 1) {
		t.Fatal("matching code did not verify")
	}
	if verifyTOTP(secret, "123", now, 1) {
		t.Fatal("short code should fail")
	}
	if verifyTOTP(secret, "999999", now.Add(10*time.Minute), 0) {
		t.Fatal("wildly wrong code at distant time should fail")
	}
	if totpCode(secret, -1) != "000000" {
		t.Fatal("negative counter should return zero string")
	}
	if totpCode("!!!", 1) != "000000" {
		t.Fatal("non-base32 secret should return zero string")
	}
}

func TestLoginRateLimiterLockoutAndRecovery(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	limiter := newLoginRateLimiter(time.Minute, 3, 5*time.Minute)
	limiter.now = func() time.Time { return clock }

	if ok, _ := limiter.allow("k"); !ok {
		t.Fatal("first attempt should be allowed")
	}
	for i := 0; i < 3; i++ {
		limiter.recordFailure("k")
	}
	allowed, retry := limiter.allow("k")
	if allowed || retry <= 0 {
		t.Fatalf("expected lockout; allowed=%v retry=%v", allowed, retry)
	}

	// Advance past lockout. Entry should reset.
	clock = clock.Add(6 * time.Minute)
	allowed, _ = limiter.allow("k")
	if !allowed {
		t.Fatal("expected lockout to expire")
	}

	// recordSuccess clears the entry.
	limiter.recordFailure("k")
	limiter.recordSuccess("k")
	limiter.mu.Lock()
	if _, ok := limiter.entries["k"]; ok {
		limiter.mu.Unlock()
		t.Fatal("recordSuccess did not clear entry")
	}
	limiter.mu.Unlock()

	// sweep removes idle entries.
	limiter.recordFailure("idle")
	clock = clock.Add(time.Hour)
	limiter.sweep(clock)
	limiter.mu.Lock()
	if _, ok := limiter.entries["idle"]; ok {
		limiter.mu.Unlock()
		t.Fatal("sweep did not remove idle entry")
	}
	limiter.mu.Unlock()

	// Nil receiver is a no-op.
	var nilL *loginRateLimiter
	if ok, _ := nilL.allow("x"); !ok {
		t.Fatal("nil limiter should always allow")
	}
	nilL.recordFailure("x")
	nilL.recordSuccess("x")
	nilL.sweep(clock)
}

func TestClientIPSplitsHostPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5050"
	if got := clientIP(req); got != "10.0.0.1" {
		t.Fatalf("clientIP = %q", got)
	}
	req.RemoteAddr = "no-port"
	if got := clientIP(req); got != "no-port" {
		t.Fatalf("clientIP = %q", got)
	}
}

func TestValidAppTokenID(t *testing.T) {
	cases := map[string]bool{
		"":            false,
		"abc":         true,
		"abc-123_v.1": true,
		"has space":   false,
		"weird/slash": false,
		"weird:colon": false,
	}
	for input, want := range cases {
		if got := validAppTokenID(input); got != want {
			t.Errorf("validAppTokenID(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestSanitizeKeyIDPrefix(t *testing.T) {
	if got := sanitizeKeyIDPrefix(" abc!@#XYZ_-9 "); got != "abcXYZ_-9" {
		t.Fatalf("sanitizeKeyIDPrefix = %q", got)
	}
	if got := sanitizeKeyIDPrefix("---"); got != "" {
		t.Fatalf("sanitizeKeyIDPrefix(---) = %q", got)
	}
}

func TestPluralizeAndFormatTokenTTL(t *testing.T) {
	if got := pluralize(1, "day"); got != "1 day" {
		t.Fatalf("singular pluralize = %q", got)
	}
	if got := pluralize(2, "hour"); got != "2 hours" {
		t.Fatalf("plural pluralize = %q", got)
	}
	if got := formatTokenTTL(1440); got != "1 day" {
		t.Fatalf("formatTokenTTL(1440) = %q", got)
	}
	if got := formatTokenTTL(60); got != "1 hour" {
		t.Fatalf("formatTokenTTL(60) = %q", got)
	}
	if got := formatTokenTTL(45); got != "45 minutes" {
		t.Fatalf("formatTokenTTL(45) = %q", got)
	}
}
