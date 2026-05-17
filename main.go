package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
)

type cliOptions struct {
	configPath       string
	dataPath         string
	printKey         bool
	rotateSigningKey bool
}

func main() {
	opts := parseCLIOptions()
	if opts.printKey {
		if err := generateAndPrintKey(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := run(opts); err != nil {
		log.Fatal(err)
	}
}

func parseCLIOptions() cliOptions {
	configPath := flag.String("config", envOrDefault(envConfigPath, defaultConfigPath), "Path to JSON config")
	dataPath := flag.String("data", envOrDefault(envDataPath, defaultDataDir), "Path to persistent authbroker data directory")
	printKey := flag.Bool("generate-key", false, "Generate a PEM RSA key and exit")
	rotateSigningKey := flag.Bool("rotate-key", false, "Force managed signing key rotation on startup")
	flag.Parse()

	return cliOptions{
		configPath:       *configPath,
		dataPath:         *dataPath,
		printKey:         *printKey,
		rotateSigningKey: *rotateSigningKey,
	}
}

func generateAndPrintKey() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	keyPEM, err := marshalRSAPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(keyPEM)
	return err
}

func run(opts cliOptions) error {
	broker, dataDir, err := newConfiguredBroker(opts)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := broker.store.Close(); cerr != nil {
			log.Printf("close store: %v", cerr)
		}
	}()

	ctx, cleanup := startSignalSweeper(broker)
	defer cleanup()

	dumpRoutes()

	if broker.cfg.ACME.Enabled && len(broker.cfg.ACME.Domains) > 0 {
		return runACME(ctx, broker, dataDir, cleanup)
	}

	srv := newHTTPServer(broker)
	shouldDrain, err := waitForServerStop(ctx, srv, broker)
	if err != nil {
		return err
	}
	if !shouldDrain {
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown: %v", err)
	}
	cleanup()
	log.Printf("shutdown complete")
	return nil
}

func newConfiguredBroker(opts cliOptions) (*Broker, string, error) {
	cfg, err := loadConfig(opts.configPath)
	if err != nil {
		return nil, "", fmt.Errorf("load config: %w", err)
	}
	normalizeConfig(&cfg)
	dataDir, err := resolveDataDir(opts.dataPath)
	if err != nil {
		return nil, "", fmt.Errorf("resolve data path: %w", err)
	}
	store, err := NewStore(filepath.Join(dataDir, defaultDataFile))
	if err != nil {
		return nil, "", fmt.Errorf("open store: %w", err)
	}
	if err := prepareSigningKeys(&cfg, store, dataDir, opts.rotateSigningKey); err != nil {
		_ = store.Close()
		return nil, "", fmt.Errorf("prepare signing key: %w", err)
	}
	broker, err := NewBroker(cfg, store)
	if err != nil {
		return nil, "", fmt.Errorf("new broker: %w", err)
	}
	warnIfCookieInsecure(broker)
	return broker, dataDir, nil
}

// warnIfCookieInsecure logs a startup warning when session cookies will be
// issued without the Secure attribute and the broker is reachable beyond the
// loopback interface. The most common cause is configuring issuer with an
// http:// scheme behind a TLS-terminating proxy; in that case CookieSecure
// must be set explicitly to true so browsers attach the cookie only over TLS.
func warnIfCookieInsecure(broker *Broker) {
	if broker.cookieSecure() {
		return
	}
	if !broker.cfg.ACME.Enabled && listenIsLocalhostOnly(broker.cfg.Listen) {
		return
	}
	log.Printf("WARNING: session cookies will be issued without the Secure attribute (issuer=%q, listen=%q). Set cookie_secure=true when terminating TLS at a proxy.", broker.cfg.Issuer, broker.cfg.Listen)
}

// listenIsLocalhostOnly reports whether addr binds exclusively to a loopback
// interface (127.0.0.1, ::1, or "localhost"). An empty host (":8080") or a
// wildcard host (0.0.0.0, ::) is treated as non-localhost.
func listenIsLocalhostOnly(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		host = addr
	}
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// runACME serves the broker over HTTPS using certmagic-managed certificates,
// with a parallel HTTP listener that solves ACME HTTP-01 challenges and
// 301-redirects everything else to HTTPS. cfg.Listen is intentionally ignored
// in this mode.
func runACME(ctx context.Context, broker *Broker, dataDir string, cleanup func()) error {
	acme := broker.cfg.ACME
	if !acme.AgreedTOS {
		return errors.New("acme: set \"agreed_tos\": true to accept the CA Subscriber Agreement")
	}

	storage, err := prepareACMEStorage(acme, dataDir)
	if err != nil {
		return err
	}
	magicCfg, tlsConfig, err := prepareCertMagic(ctx, acme, storage)
	if err != nil {
		return err
	}
	httpsSrv, httpSrv := newACMEServers(broker, acme, magicCfg, tlsConfig)
	httpsListener, httpListener, err := listenACME(acme, tlsConfig)
	if err != nil {
		return err
	}

	errCh := serveACME(acme, broker.cfg.Issuer, httpsSrv, httpSrv, httpsListener, httpListener)
	if err := waitForACMEStop(ctx, errCh); err != nil {
		return err
	}

	shutdownACME(httpsSrv, httpSrv)
	cleanup()
	log.Printf("shutdown complete")
	return nil
}

func prepareACMEStorage(acme ACMEConfig, dataDir string) (string, error) {
	storage := acme.StoragePath
	if storage == "" {
		if dataDir == "" {
			return "", errors.New("acme: data dir is required when storage_path is unset")
		}
		storage = filepath.Join(dataDir, "acme")
	}
	if err := os.MkdirAll(storage, 0o700); err != nil {
		return "", fmt.Errorf("create acme storage: %w", err)
	}
	return storage, nil
}

func prepareCertMagic(ctx context.Context, acme ACMEConfig, storage string) (*certmagic.Config, *tls.Config, error) {
	trustedRoots, err := loadRootCAs(acme.CACertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("acme ca cert: %w", err)
	}

	certmagic.Default.Storage = &certmagic.FileStorage{Path: storage}
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = acme.Email
	certmagic.DefaultACME.CA = acme.CADirectory
	certmagic.DefaultACME.TrustedRoots = trustedRoots
	if trustedRoots != nil {
		log.Printf("acme: trusting additional roots from %s", acme.CACertPath)
	}
	log.Printf("acme: using CA %s storage=%s domains=%v", acme.CADirectory, storage, acme.Domains)

	magicCfg := certmagic.NewDefault()
	if err := magicCfg.ManageAsync(ctx, acme.Domains); err != nil {
		return nil, nil, fmt.Errorf("acme manage: %w", err)
	}

	tlsConfig := magicCfg.TLSConfig()
	tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
	return magicCfg, tlsConfig, nil
}

func newACMEServers(broker *Broker, acme ACMEConfig, magicCfg *certmagic.Config, tlsConfig *tls.Config) (*http.Server, *http.Server) {
	httpsSrv := &http.Server{
		Addr:              acme.HTTPSAddr,
		Handler:           broker.routes(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}
	httpSrv := &http.Server{
		Addr:              acme.HTTPAddr,
		Handler:           newACMEHTTPHandler(magicCfg, acme.Domains),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return httpsSrv, httpSrv
}

func newACMEHTTPHandler(magicCfg *certmagic.Config, domains []string) http.Handler {
	httpHandler := http.Handler(http.HandlerFunc(redirectToHTTPS(domains)))
	if issuer := firstACMEIssuer(magicCfg); issuer != nil {
		return issuer.HTTPChallengeHandler(httpHandler)
	}
	return httpHandler
}

func firstACMEIssuer(magicCfg *certmagic.Config) *certmagic.ACMEIssuer {
	for _, issuer := range magicCfg.Issuers {
		if acmeIssuer, ok := issuer.(*certmagic.ACMEIssuer); ok {
			return acmeIssuer
		}
	}
	return nil
}

func listenACME(acme ACMEConfig, tlsConfig *tls.Config) (net.Listener, net.Listener, error) {
	httpsListener, err := tls.Listen("tcp", acme.HTTPSAddr, tlsConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("listen https %s: %w", acme.HTTPSAddr, err)
	}
	httpListener, err := net.Listen("tcp", acme.HTTPAddr)
	if err != nil {
		_ = httpsListener.Close()
		return nil, nil, fmt.Errorf("listen http %s: %w", acme.HTTPAddr, err)
	}
	return httpsListener, httpListener, nil
}

func serveACME(acme ACMEConfig, issuer string, httpsSrv, httpSrv *http.Server, httpsListener, httpListener net.Listener) chan error {
	errCh := make(chan error, 2)
	go func() {
		log.Printf("auth broker listening on %s (https) for domains %v issuer=%s", acme.HTTPSAddr, acme.Domains, issuer)
		if serveErr := httpsSrv.Serve(httpsListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("https serve: %w", serveErr)
		}
	}()
	go func() {
		log.Printf("acme http listener on %s (challenge + redirect)", acme.HTTPAddr)
		if serveErr := httpSrv.Serve(httpListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http serve: %w", serveErr)
		}
	}()
	return errCh
}

func waitForACMEStop(ctx context.Context, errCh <-chan error) error {
	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received; draining")
		return nil
	case err := <-errCh:
		return err
	}
}

func shutdownACME(httpsSrv, httpSrv *http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpsSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("https shutdown: %v", err)
	}
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
}

func redirectToHTTPS(domains []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, ok := redirectHost(r.Host, domains)
		if !ok {
			http.Error(w, "bad host", http.StatusBadRequest)
			return
		}
		target := url.URL{
			Scheme:   "https",
			Host:     host,
			Path:     r.URL.Path,
			RawPath:  r.URL.RawPath,
			RawQuery: r.URL.RawQuery,
		}
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
	}
}

func redirectHost(requestHost string, domains []string) (string, bool) {
	host, ok := requestHostname(requestHost)
	if !ok {
		return "", false
	}
	for _, domain := range domains {
		normalized := normalizeHost(domain)
		if host == normalized {
			return normalized, true
		}
	}
	return "", false
}

func requestHostname(requestHost string) (string, bool) {
	host := strings.TrimSpace(requestHost)
	if host == "" {
		return "", false
	}
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	} else if strings.Contains(host, ":") {
		return "", false
	}
	if strings.ContainsAny(host, `/\@`) {
		return "", false
	}
	return normalizeHost(host), true
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func startSignalSweeper(broker *Broker) (context.Context, func()) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var sweeperWG sync.WaitGroup
	sweeperWG.Add(1)
	go func() {
		defer sweeperWG.Done()
		broker.startBackgroundSweeper(ctx, time.Minute)
	}()

	var cleanupOnce sync.Once
	return ctx, func() {
		cleanupOnce.Do(func() {
			stop()
			sweeperWG.Wait()
		})
	}
}

func newHTTPServer(broker *Broker) *http.Server {
	return &http.Server{
		Addr:              broker.cfg.Listen,
		Handler:           broker.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func waitForServerStop(ctx context.Context, srv *http.Server, broker *Broker) (bool, error) {
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("auth broker listening on %s issuer=%s", broker.cfg.Listen, broker.cfg.Issuer)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received; draining")
	case err := <-serverErr:
		if err != nil {
			return false, fmt.Errorf("server error: %w", err)
		}
		return false, nil
	}
	return true, nil
}

func dumpRoutes() {
	routes := []string{
		"/",
		"/healthz",
		"/login",
		"/logout",
		"/reauth",
		"/consent",
		"/app-tokens/{id}",
		"/admin",
		"/admin/clients",
		"/admin/clients/new",
		"/admin/clients/{id}/delete",
		"/admin/app-tokens",
		"/admin/app-tokens/new",
		"/admin/app-tokens/{id}/delete",
		"/.well-known/openid-configuration",
		"/oauth2/authorize",
		"/oauth2/token",
		"/oauth2/jwks",
		"/oauth2/userinfo",
		"/oauth2/revoke",
		"/oauth2/introspect",
		"/oauth2/logout",
		"/mfa/totp/enroll",
		"/mfa/totp/verify",
		"/webauthn/register/begin",
		"/webauthn/register/finish",
		"/webauthn/login/begin",
		"/webauthn/login/finish",
	}
	sort.Strings(routes)
	log.Printf("endpoints: %s", strings.Join(routes, ", "))
}
