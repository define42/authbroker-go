package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Session, AuthorizationRequest, AuthCode, RefreshToken and ChallengeRecord
// are persisted via Store. AuthCode and RefreshToken hold metadata only — the
// opaque random secret is keyed into the map by hashSecret(...) so a leaked
// data.json does not expose live tokens.
type Session struct {
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
	AuthTime  time.Time `json:"auth_time"`
	CSRFToken string    `json:"csrf_token,omitempty"`
	// ReAuthAt marks the most recent password (or factor) re-confirmation. The
	// TOTP enroll and WebAuthn register endpoints require this to be set
	// within reAuthValidity to mutate second-factor material.
	ReAuthAt time.Time `json:"re_auth_at,omitempty"`
	// AMR records the OIDC `amr` (Authentication Methods References) values
	// for the most recent authentication. Values follow RFC 8176 (e.g.,
	// "pwd", "otp", "hwk", "mfa") and are emitted in the id_token.
	AMR []string `json:"amr,omitempty"`
}

type AuthorizationRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

// AuthCode is keyed in the AuthCodes map by hashSecret(code). The code
// plaintext only exists in flight (URL parameter and form post body).
type AuthCode struct {
	UserID              string
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	ExpiresAt           time.Time
	AMR                 []string
}

// RefreshToken is keyed in the RefreshTokens map by hashSecret(token).
type RefreshToken struct {
	UserID    string
	ClientID  string
	Scope     string
	AuthTime  time.Time
	ExpiresAt time.Time
	AMR       []string
}

type ChallengeRecord struct {
	UserID    string
	Challenge string
	ExpiresAt time.Time
}

type Broker struct {
	cfg        Config
	store      *Store
	authn      Authenticator
	activeKey  signingKey
	verifyKeys map[string]*rsa.PublicKey
	publicJWKs []any

	// clients and appTokens hold the immutable config-defined entries. The
	// stored* maps hold admin-managed entries persisted to bolt. Admin
	// mutations rebuild storedClients/storedAppTokens under registryMu so
	// reads (under RLock) observe a consistent snapshot.
	clients   map[string]Client
	appTokens map[string]AppTokenConfig

	registryMu      sync.RWMutex
	storedClients   map[string]Client
	storedAppTokens map[string]AppTokenConfig

	loginLimiter *loginRateLimiter

	audit *slog.Logger
}

const (
	// reAuthValidity is how long a freshly-entered password (or factor)
	// remains valid for second-factor mutations (TOTP enroll, WebAuthn
	// register). Short enough that a stolen session is unlikely to satisfy
	// it; long enough that a real user can enroll without re-entering the
	// password constantly. See handleReAuth.
	reAuthValidity = 5 * time.Minute

	// loginRateLimit configuration. After loginRateLimitMaxAttempts failed
	// attempts within loginRateLimitWindow, the limiter locks out the key
	// (per IP + username) for loginRateLockout.
	loginRateLimitWindow      = 5 * time.Minute
	loginRateLimitMaxAttempts = 10
	loginRateLockout          = 15 * time.Minute
)

//nolint:gocognit,funlen // Broker construction validates clients, app tokens, and signing material together.
func NewBroker(cfg Config, store *Store) (*Broker, error) {
	normalizeConfig(&cfg)

	activeKey, verifyKeys, publicJWKs, err := buildSigningKeySet(cfg)
	if err != nil {
		return nil, err
	}
	if activeKey.privateKey == nil {
		activeKey.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		activeKey.keyID = cfg.KeyID
		activeKey.publicJWK = makePublicJWK(activeKey.keyID, &activeKey.privateKey.PublicKey)
		verifyKeys = map[string]*rsa.PublicKey{activeKey.keyID: &activeKey.privateKey.PublicKey}
		publicJWKs = []any{activeKey.publicJWK}
		log.Printf("WARNING: generated ephemeral RSA signing key. Configure signing_key_pem or AUTHBROKER_DATA for stable tokens.")
	}
	cfg.KeyID = activeKey.keyID

	clientMap := map[string]Client{}
	for _, c := range cfg.Clients {
		if c.ClientID == "" {
			return nil, fmt.Errorf("client_id is required")
		}
		groupMappings, err := normalizeClientGroupMappings(c.GroupMappings)
		if err != nil {
			return nil, fmt.Errorf("client %q: %w", c.ClientID, err)
		}
		c.GroupMappings = groupMappings
		c.compiledMappings = compileGroupMappings(groupMappings)
		clientMap[c.ClientID] = c
	}
	appTokenMap := map[string]AppTokenConfig{}
	for i, tokenCfg := range cfg.AppTokens {
		if tokenCfg.ID == "" {
			return nil, fmt.Errorf("app_tokens[%d].id is required", i)
		}
		if !validAppTokenID(tokenCfg.ID) {
			return nil, fmt.Errorf("app token %q: id must be 1-%d chars of letters, digits, dot, underscore, or hyphen", tokenCfg.ID, maxAppTokenIDLen)
		}
		groupMappings, err := normalizeClientGroupMappings(tokenCfg.GroupMappings)
		if err != nil {
			return nil, fmt.Errorf("app token %q: %w", tokenCfg.ID, err)
		}
		tokenCfg.GroupMappings = groupMappings
		tokenCfg.compiledMappings = compileGroupMappings(groupMappings)
		cfg.AppTokens[i] = tokenCfg
		if _, exists := appTokenMap[tokenCfg.ID]; exists {
			return nil, fmt.Errorf("duplicate app token id %q", tokenCfg.ID)
		}
		appTokenMap[tokenCfg.ID] = tokenCfg
	}

	if cfg.LDAP.InsecureSkipVerify {
		log.Printf("WARNING: ldap.insecure_skip_verify is enabled — server TLS certificate is not validated. Use only for local fixtures.")
	}

	b := &Broker{
		cfg:             cfg,
		store:           store,
		authn:           &LDAPAuthenticator{cfg: cfg.LDAP},
		activeKey:       activeKey,
		verifyKeys:      verifyKeys,
		publicJWKs:      publicJWKs,
		clients:         clientMap,
		appTokens:       appTokenMap,
		storedClients:   map[string]Client{},
		storedAppTokens: map[string]AppTokenConfig{},
		loginLimiter:    newLoginRateLimiter(loginRateLimitWindow, loginRateLimitMaxAttempts, loginRateLockout),
		audit:           newAuditLogger(nil),
	}
	if err := b.reloadStoredRegistries(); err != nil {
		return nil, fmt.Errorf("load stored registries: %w", err)
	}
	b.sweepExpired(time.Now())
	return b, nil
}

// reloadStoredRegistries rebuilds the stored client/app-token maps from bolt.
// Called at startup and after every admin mutation so subsequent OAuth and
// app-token requests see the new entries without restart.
func (b *Broker) reloadStoredRegistries() error {
	clients, err := b.store.ListStoredClients()
	if err != nil {
		return err
	}
	tokens, err := b.store.ListStoredAppTokens()
	if err != nil {
		return err
	}
	clientMap := make(map[string]Client, len(clients))
	for _, c := range clients {
		if _, isConfig := b.clients[c.ClientID]; isConfig {
			// Config-defined entries always win — drop the shadowed stored copy.
			continue
		}
		c.compiledMappings = compileGroupMappings(c.GroupMappings)
		clientMap[c.ClientID] = c
	}
	tokenMap := make(map[string]AppTokenConfig, len(tokens))
	for _, t := range tokens {
		if _, isConfig := b.appTokens[t.ID]; isConfig {
			continue
		}
		t.compiledMappings = compileGroupMappings(t.GroupMappings)
		tokenMap[t.ID] = t
	}
	b.registryMu.Lock()
	b.storedClients = clientMap
	b.storedAppTokens = tokenMap
	b.registryMu.Unlock()
	return nil
}

// lookupClient returns the merged client (config first, then stored) for
// OAuth handlers. Stored mutations are reflected because the snapshot is
// rebuilt on reloadStoredRegistries.
func (b *Broker) lookupClient(id string) (Client, bool) {
	if c, ok := b.clients[id]; ok {
		return c, true
	}
	b.registryMu.RLock()
	defer b.registryMu.RUnlock()
	c, ok := b.storedClients[id]
	return c, ok
}

func (b *Broker) lookupAppToken(id string) (AppTokenConfig, bool) {
	if t, ok := b.appTokens[id]; ok {
		return t, true
	}
	b.registryMu.RLock()
	defer b.registryMu.RUnlock()
	t, ok := b.storedAppTokens[id]
	return t, ok
}

// snapshotClients returns config + stored clients in a single map for admin
// list views. Snapshot is a copy so callers can iterate without holding
// registryMu.
func (b *Broker) snapshotClients() map[string]Client {
	b.registryMu.RLock()
	defer b.registryMu.RUnlock()
	out := make(map[string]Client, len(b.clients)+len(b.storedClients))
	for k, v := range b.clients {
		out[k] = v
	}
	for k, v := range b.storedClients {
		out[k] = v
	}
	return out
}

func (b *Broker) snapshotAppTokens() map[string]AppTokenConfig {
	b.registryMu.RLock()
	defer b.registryMu.RUnlock()
	out := make(map[string]AppTokenConfig, len(b.appTokens)+len(b.storedAppTokens))
	for k, v := range b.appTokens {
		out[k] = v
	}
	for k, v := range b.storedAppTokens {
		out[k] = v
	}
	return out
}

// userIsAdmin reports whether the user has at least one group matching
// cfg.AdminGroups. Matching is case-insensitive and tolerates raw LDAP DNs by
// extracting the CN segment for comparison.
func (b *Broker) userIsAdmin(user *StoredUser) bool {
	if user == nil || len(b.cfg.AdminGroups) == 0 {
		return false
	}
	allowed := map[string]bool{}
	for _, g := range b.cfg.AdminGroups {
		trimmed := strings.TrimSpace(g)
		if trimmed == "" {
			continue
		}
		allowed[strings.ToLower(ldapGroupName(trimmed))] = true
		allowed[strings.ToLower(trimmed)] = true
	}
	if len(allowed) == 0 {
		return false
	}
	for _, g := range user.Groups {
		if allowed[strings.ToLower(ldapGroupName(g))] || allowed[strings.ToLower(g)] {
			return true
		}
	}
	return false
}

// sweepExpired removes expired entries from shared runtime state so abandoned
// grants do not accumulate indefinitely.
func (b *Broker) sweepExpired(now time.Time) {
	if _, err := b.store.SweepExpired(now); err != nil {
		log.Printf("persist runtime state after sweep: %v", err)
	}
	b.loginLimiter.sweep(now)
}

// startBackgroundSweeper periodically calls sweepExpired until ctx is done.
// It returns when the context is cancelled, letting the caller wait for the
// sweeper to drain during graceful shutdown.
func (b *Broker) startBackgroundSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			b.sweepExpired(t)
		}
	}
}

// maxAppTokenIDLen caps the app-token id length. The id is reflected in URL
// paths, HTML, and JWT claims; HTML escaping and exact path matching make
// this cap defensive insurance rather than a security boundary.
const maxAppTokenIDLen = 64

func validAppTokenID(id string) bool {
	if id == "" || len(id) > maxAppTokenIDLen {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func (b *Broker) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/authbroker.css", b.handleStylesheet)
	mux.HandleFunc("GET /assets/authbroker.js", b.handleScript)
	mux.HandleFunc("GET /", b.handleHome)
	mux.HandleFunc("GET /healthz", b.handleHealth)
	mux.HandleFunc("GET /.well-known/openid-configuration", b.handleDiscovery)
	mux.HandleFunc("GET /oauth2/jwks", b.handleJWKS)
	mux.HandleFunc("GET /oauth2/authorize", b.handleAuthorize)
	mux.HandleFunc("GET /login", b.handleLoginGet)
	mux.HandleFunc("POST /login", b.handleLoginPost)
	mux.HandleFunc("GET /logout", b.handleLocalLogoutGet)
	mux.HandleFunc("POST /logout", b.handleLocalLogoutPost)
	mux.HandleFunc("POST /reauth", b.handleReAuth)
	mux.HandleFunc("POST /app-tokens/{id}", b.handleAppToken)
	mux.HandleFunc("POST /oauth2/token", b.handleToken)
	mux.HandleFunc("GET /oauth2/userinfo", b.handleUserInfo)
	mux.HandleFunc("POST /oauth2/userinfo", b.handleUserInfo)
	mux.HandleFunc("POST /oauth2/revoke", b.handleRevoke)
	mux.HandleFunc("GET /oauth2/logout", b.handleLogout)
	mux.HandleFunc("POST /oauth2/logout", b.handleLogout)
	mux.HandleFunc("POST /mfa/totp/enroll", b.handleTOTPEnroll)
	mux.HandleFunc("POST /mfa/totp/verify", b.handleTOTPEnrollVerify)
	mux.HandleFunc("POST /webauthn/register/begin", b.handleWebAuthnRegisterBegin)
	mux.HandleFunc("POST /webauthn/register/finish", b.handleWebAuthnRegisterFinish)
	mux.HandleFunc("POST /webauthn/login/begin", b.handleWebAuthnLoginBegin)
	mux.HandleFunc("POST /webauthn/login/finish", b.handleWebAuthnLoginFinish)
	mux.HandleFunc("GET /consent", b.handleConsentGet)
	mux.HandleFunc("POST /consent", b.handleConsentPost)
	mux.HandleFunc("GET /admin", b.handleAdminHome)
	mux.HandleFunc("GET /admin/clients/new", b.handleAdminClientsNew)
	mux.HandleFunc("POST /admin/clients", b.handleAdminClientsCreate)
	mux.HandleFunc("POST /admin/clients/{id}/delete", b.handleAdminClientsDelete)
	mux.HandleFunc("GET /admin/app-tokens/new", b.handleAdminAppTokensNew)
	mux.HandleFunc("POST /admin/app-tokens", b.handleAdminAppTokensCreate)
	mux.HandleFunc("POST /admin/app-tokens/{id}/delete", b.handleAdminAppTokensDelete)
	return b.securityHeaders(mux)
}

func (b *Broker) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", authbrokerCSP)
		// Default to no-store; cacheable endpoints (JWKS, discovery) override
		// this header explicitly before writing their response.
		w.Header().Set("Cache-Control", "no-store")
		if b.cookieSecure() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
