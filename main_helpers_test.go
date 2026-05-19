package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"  Example.com.  ": "example.com",
		"FOO":              "foo",
		"":                 "",
	}
	for input, want := range cases {
		if got := normalizeHost(input); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRequestHostname(t *testing.T) {
	host, ok := requestHostname("Example.com:8080")
	if !ok || host != "example.com" {
		t.Fatalf("ip:port -> %q ok=%v", host, ok)
	}
	host, ok = requestHostname("plain.example")
	if !ok || host != "plain.example" {
		t.Fatalf("plain -> %q ok=%v", host, ok)
	}
	if _, ok := requestHostname(""); ok {
		t.Fatal("empty should be rejected")
	}
	if _, ok := requestHostname("bad:host:port"); ok {
		t.Fatal("malformed host:port should be rejected")
	}
	if _, ok := requestHostname("contains/slash"); ok {
		t.Fatal("slash should be rejected")
	}
}

func TestRedirectHostMatches(t *testing.T) {
	domains := []string{"Example.com", "demo.test"}
	if host, ok := redirectHost("example.com:80", domains); !ok || host != "example.com" {
		t.Fatalf("matched host = %q ok=%v", host, ok)
	}
	if _, ok := redirectHost("other.test", domains); ok {
		t.Fatal("unlisted host should not be allowed")
	}
	if _, ok := redirectHost("", domains); ok {
		t.Fatal("empty host should not be allowed")
	}
}

func TestRedirectToHTTPSRedirectsKnownHost(t *testing.T) {
	handler := redirectToHTTPS([]string{"example.com"})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?foo=bar", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "https://example.com/path?foo=bar" {
		t.Fatalf("Location = %q", got)
	}
}

func TestRedirectToHTTPSBadHost(t *testing.T) {
	handler := redirectToHTTPS([]string{"example.com"})
	req := httptest.NewRequest(http.MethodGet, "http://other/", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestParseCLIOptionsDefaults(t *testing.T) {
	oldArgs := os.Args
	oldFS := flag.CommandLine
	t.Cleanup(func() { os.Args = oldArgs; flag.CommandLine = oldFS })
	os.Args = []string{"authbroker-go"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	t.Setenv(envConfigPath, "")
	t.Setenv(envDataPath, "")

	opts := parseCLIOptions()
	if opts.configPath != defaultConfigPath {
		t.Fatalf("configPath = %q", opts.configPath)
	}
	if opts.dataPath != defaultDataDir {
		t.Fatalf("dataPath = %q", opts.dataPath)
	}
	if opts.printKey || opts.rotateSigningKey {
		t.Fatalf("unexpected flag defaults: %#v", opts)
	}
}

func TestParseCLIOptionsCustomFlags(t *testing.T) {
	oldArgs := os.Args
	oldFS := flag.CommandLine
	t.Cleanup(func() { os.Args = oldArgs; flag.CommandLine = oldFS })
	os.Args = []string{"authbroker-go", "-config", "/tmp/cfg.json", "-data", "/tmp/data", "-generate-key", "-rotate-key"}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	opts := parseCLIOptions()
	if opts.configPath != "/tmp/cfg.json" || opts.dataPath != "/tmp/data" {
		t.Fatalf("opts = %#v", opts)
	}
	if !opts.printKey || !opts.rotateSigningKey {
		t.Fatalf("bool flags not set: %#v", opts)
	}
}

func TestGenerateAndPrintKey(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()

	if err := generateAndPrintKey(); err != nil {
		t.Fatalf("generateAndPrintKey: %v", err)
	}
	_ = w.Close()
	bs := <-done

	block, _ := pem.Decode(bs)
	if block == nil {
		t.Fatalf("no PEM block in output: %q", bs)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse generated key: %v", err)
	}
	if _, ok := any(key).(*rsa.PrivateKey); !ok {
		t.Fatal("not an RSA key")
	}
}

func TestStartBackgroundSweeperStops(t *testing.T) {
	broker := newLogoutTestBroker(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		broker.startBackgroundSweeper(ctx, time.Millisecond)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sweeper did not stop after cancel")
	}
}

func TestStartBackgroundSweeperDefaultsInterval(t *testing.T) {
	broker := newLogoutTestBroker(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Pass zero so it falls into the default branch, then return immediately.
	broker.startBackgroundSweeper(ctx, 0)
}

func TestStartSignalSweeperRoundTrip(t *testing.T) {
	broker := newLogoutTestBroker(t)
	_, cleanup := startSignalSweeper(broker)
	cleanup()
	// Calling cleanup twice should be a no-op.
	cleanup()
}

func TestNewHTTPServerUsesBrokerListen(t *testing.T) {
	broker := newLogoutTestBroker(t)
	srv := newHTTPServer(broker)
	if srv.Addr != broker.cfg.Listen {
		t.Fatalf("Addr = %q want %q", srv.Addr, broker.cfg.Listen)
	}
	if srv.Handler == nil {
		t.Fatal("Handler missing")
	}
}

func TestNewConfiguredBrokerFailsOnMissingConfig(t *testing.T) {
	_, _, err := newConfiguredBroker(cliOptions{configPath: filepath.Join(t.TempDir(), "missing.json")})
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestNewConfiguredBrokerLoadsValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg.json")
	body := `{"issuer":"http://broker.example","listen":":0","clients":[{"client_id":"demo","redirect_uris":["http://demo/cb"]}]}`
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	broker, dataDir, err := newConfiguredBroker(cliOptions{configPath: cfgPath, dataPath: filepath.Join(dir, "data")})
	if err != nil {
		t.Fatalf("newConfiguredBroker: %v", err)
	}
	t.Cleanup(func() { _ = broker.store.Close() })
	if dataDir == "" {
		t.Fatal("dataDir not set")
	}
	if broker.cfg.Issuer != "http://broker.example" {
		t.Fatalf("issuer = %q", broker.cfg.Issuer)
	}
}

func TestPrepareACMEStorageRequiresDataDir(t *testing.T) {
	if _, err := prepareACMEStorage(ACMEConfig{}, ""); err == nil {
		t.Fatal("missing storage and data dir should fail")
	}
	dir := t.TempDir()
	got, err := prepareACMEStorage(ACMEConfig{}, dir)
	if err != nil {
		t.Fatalf("prepareACMEStorage: %v", err)
	}
	if !strings.HasPrefix(got, dir) {
		t.Fatalf("storage = %q", got)
	}
}

func TestPrepareACMEStorageWithExplicitPath(t *testing.T) {
	dir := t.TempDir()
	got, err := prepareACMEStorage(ACMEConfig{StoragePath: filepath.Join(dir, "acme-store")}, "")
	if err != nil {
		t.Fatalf("prepareACMEStorage: %v", err)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("storage dir not created: %v", err)
	}
}

func TestParseRSAPrivateKeyPEMErrors(t *testing.T) {
	if _, err := parseRSAPrivateKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("non-pem should fail")
	}
	if _, err := parseRSAPrivateKeyPEM([]byte("-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----\n")); err == nil {
		t.Fatal("bad PKCS8 body should fail")
	}
}
