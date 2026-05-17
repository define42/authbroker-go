package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
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
	broker, err := newConfiguredBroker(opts)
	if err != nil {
		return err
	}

	ctx, cleanup := startSignalSweeper(broker)
	defer cleanup()

	dumpRoutes()
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

func newConfiguredBroker(opts cliOptions) (*Broker, error) {
	cfg, err := loadConfig(opts.configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	normalizeConfig(&cfg)
	dataDir, err := resolveDataDir(opts.dataPath)
	if err != nil {
		return nil, fmt.Errorf("resolve data path: %w", err)
	}
	if err := prepareSigningKeys(&cfg, dataDir, opts.rotateSigningKey); err != nil {
		return nil, fmt.Errorf("prepare signing key: %w", err)
	}
	store, err := NewStore(filepath.Join(dataDir, defaultDataFile))
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	broker, err := NewBroker(cfg, store)
	if err != nil {
		return nil, fmt.Errorf("new broker: %w", err)
	}
	return broker, nil
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
		"/app-tokens/{id}",
		"/.well-known/openid-configuration",
		"/oauth2/authorize",
		"/oauth2/token",
		"/oauth2/jwks",
		"/oauth2/userinfo",
		"/oauth2/revoke",
		"/oauth2/logout",
		"/mfa/totp/enroll",
		"/webauthn/register/begin",
		"/webauthn/register/finish",
		"/webauthn/login/begin",
		"/webauthn/login/finish",
	}
	sort.Strings(routes)
	log.Printf("endpoints: %s", strings.Join(routes, ", "))
}
