package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

const (
	sessionCookieName = "broker_session"
	csrfCookieName    = "broker_csrf"
	csrfFormField     = "csrf_token"
	csrfHeaderName    = "X-CSRF-Token"
	bearerPrefix      = "Bearer "

	defaultConfigPath = "config.json"
	defaultDataDir    = "data"
	defaultDataFile   = "data.db"
	defaultKeysPath   = "signing-keys.json"
	envConfigPath     = "AUTHBROKER_CONFIG"
	envDataPath       = "AUTHBROKER_DATA"

	defaultSigningKeyRotationDays  = 90
	defaultSigningKeyRetentionDays = 30

	defaultLoginRateWindowSeconds    = 5 * 60
	defaultLoginRateMaxAttempts      = 10
	defaultLoginRateLockoutSeconds   = 15 * 60
	defaultTokenRateWindowSeconds    = 5 * 60
	defaultTokenRateMaxAttempts      = 20
	defaultTokenRateLockoutSeconds   = 15 * 60
	defaultPreAuthRateWindowSeconds  = 60
	defaultPreAuthRateMaxAttempts    = 60
	defaultPreAuthRateLockoutSeconds = 60
	defaultMetricsPath               = "/metrics"
)

// Body size limits applied via http.MaxBytesReader. Keep these generous enough
// for typical payloads while preventing trivially huge bodies from filling
// memory. Login forms are small; WebAuthn attestation objects are usually
// well under 16 KiB.
const (
	maxLoginBodyBytes        = 16 << 10
	maxTokenBodyBytes        = 16 << 10
	maxLogoutBodyBytes       = 64 << 10
	maxRevokeBodyBytes       = 16 << 10
	maxIntrospectBodyBytes   = 16 << 10
	maxWebAuthnBodyBytes     = 64 << 10
	maxAppTokenFormBodyBytes = 4 << 10
	maxTOTPEnrollBodyBytes   = 4 << 10
	maxTOTPVerifyBodyBytes   = 1 << 10
	maxUserInfoBodyBytes     = 4 << 10
)

// Config is intentionally small. It is enough to run a modern LDAP-backed
// OAuth2/OIDC broker. Use this as a baseline, not as a complete enterprise IdP.
type Config struct {
	Issuer         string   `json:"issuer"`
	Listen         string   `json:"listen"`
	DisplayName    string   `json:"display_name,omitempty"`
	Production     bool     `json:"production,omitempty"`
	SigningKeyPEM  string   `json:"signing_key_pem,omitempty"`
	KeyID          string   `json:"key_id"`
	CookieSecure   *bool    `json:"cookie_secure,omitempty"`
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	ClientIPHeader string   `json:"client_ip_header,omitempty"`

	SigningKeys             []SigningKeyConfig `json:"signing_keys,omitempty"`
	SigningKeyRotationDays  int                `json:"signing_key_rotation_days,omitempty"`
	SigningKeyRetentionDays int                `json:"signing_key_retention_days,omitempty"`

	LDAP        LDAPConfig       `json:"ldap"`
	Clients     []Client         `json:"clients"`
	MFA         MFAConfig        `json:"mfa"`
	WebAuthn    WebAuthnConfig   `json:"webauthn"`
	AppTokens   []AppTokenConfig `json:"app_tokens,omitempty"`
	ACME        ACMEConfig       `json:"acme,omitempty"`
	RateLimit   RateLimitConfig  `json:"rate_limit,omitempty"`
	Metrics     MetricsConfig    `json:"metrics,omitempty"`
	AdminGroups []string         `json:"admin_groups,omitempty"`

	AccessTokenTTLMinutes int `json:"access_token_ttl_minutes"`
	IDTokenTTLMinutes     int `json:"id_token_ttl_minutes"`
	RefreshTokenTTLDays   int `json:"refresh_token_ttl_days"`
	AuthCodeTTLSeconds    int `json:"auth_code_ttl_seconds"`
	// SessionTTLHrs is the sliding (idle) session TTL — every authenticated
	// request resets the cookie expiry up to this many hours from now.
	SessionTTLHrs int `json:"session_ttl_hours"`
	// SessionAbsoluteTTLHrs caps total session lifetime regardless of
	// activity. When set, createSession stamps Session.AbsoluteExpiresAt and
	// validSession rejects the session past that point — even if
	// maybeExtendSession would otherwise extend it. Zero (the default) keeps
	// the legacy behavior of "idle TTL only" for backwards compatibility;
	// compliance regimes that require re-authentication on a fixed cadence
	// should set this to a multiple of SessionTTLHrs.
	SessionAbsoluteTTLHrs int `json:"session_absolute_ttl_hours,omitempty"`
}

type RateLimitConfig struct {
	LoginWindowSeconds    int `json:"login_window_seconds,omitempty"`
	LoginMaxAttempts      int `json:"login_max_attempts,omitempty"`
	LoginLockoutSeconds   int `json:"login_lockout_seconds,omitempty"`
	TokenWindowSeconds    int `json:"token_window_seconds,omitempty"`
	TokenMaxAttempts      int `json:"token_max_attempts,omitempty"`
	TokenLockoutSeconds   int `json:"token_lockout_seconds,omitempty"`
	PreAuthWindowSeconds  int `json:"preauth_window_seconds,omitempty"`
	PreAuthMaxAttempts    int `json:"preauth_max_attempts,omitempty"`
	PreAuthLockoutSeconds int `json:"preauth_lockout_seconds,omitempty"`
}

type MetricsConfig struct {
	Enabled bool   `json:"enabled,omitempty"`
	Path    string `json:"path,omitempty"`
	// BearerSHA256 is the SHA-256 hex digest of the bearer value required to
	// scrape metrics. The plaintext token is never stored in config.
	BearerSHA256 string `json:"bearer_token_sha256,omitempty"`
}

type SigningKeyConfig struct {
	KeyID         string `json:"key_id"`
	SigningKeyPEM string `json:"signing_key_pem"`
	Active        bool   `json:"active,omitempty"`
}

type LDAPConfig struct {
	URL                string `json:"url"`
	UserDNTemplate     string `json:"user_dn_template,omitempty"` // e.g. "uid={username},ou=people,dc=example,dc=com"
	DomainSuffix       string `json:"domain_suffix,omitempty"`    // e.g. "@example.com" for AD UPN bind
	BaseDN             string `json:"base_dn,omitempty"`
	UserFilter         string `json:"user_filter,omitempty"`
	EmailAttribute     string `json:"email_attribute,omitempty"`
	NameAttribute      string `json:"name_attribute,omitempty"`
	GroupsAttribute    string `json:"groups_attribute,omitempty"`
	NestedGroups       bool   `json:"nested_groups,omitempty"`
	GroupSearchBaseDN  string `json:"group_search_base_dn,omitempty"`
	GroupSearchFilter  string `json:"group_search_filter,omitempty"`
	GroupNameAttribute string `json:"group_name_attribute,omitempty"`
	StartTLS           bool   `json:"start_tls,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	// CACertPath points at a PEM file with one or more root certificates the
	// broker must trust for the LDAP server's TLS certificate. Use this for
	// internal/private CAs whose roots aren't in the system trust store.
	// Empty means use the system pool only.
	CACertPath     string `json:"ca_cert_path,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

type Client struct {
	ClientID                string            `json:"client_id"`
	ClientSecretSHA256      string            `json:"client_secret_sha256,omitempty"`
	RedirectURIs            []string          `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string          `json:"post_logout_redirect_uris,omitempty"`
	Public                  bool              `json:"public"`
	RequirePKCE             bool              `json:"require_pkce"`
	AllowedScopes           []string          `json:"allowed_scopes,omitempty"`
	ClientCredentialsScopes []string          `json:"client_credentials_scopes,omitempty"`
	AllowOfflineAccess      bool              `json:"allow_offline_access,omitempty"`
	GroupMappings           map[string]string `json:"group_mappings,omitempty"`
	// RequireConsent enables the per-user consent screen for this client.
	// Off by default for backwards compatibility with config-defined first-
	// party clients. Admin-created clients via /admin set it to true so
	// authorize prompts the user before redirecting back with a code.
	RequireConsent bool `json:"require_consent,omitempty"`

	// StoredAt distinguishes admin-created stored clients (non-zero) from
	// config-defined ones (zero). Set by the admin handler; never written via
	// config. Drives the read-only badge in the admin list view.
	StoredAt time.Time `json:"stored_at,omitempty"`

	// compiledMappings caches the parsed direct/scoped/regex mapping
	// representation. Populated by NewBroker after normalizeClientGroupMappings.
	compiledMappings               *compiledGroupMappings
	allowedScopeSet                map[string]bool
	clientCredentialsAllowedScopes map[string]bool
}

type MFAConfig struct {
	TOTPRequired bool `json:"totp_required"`
}

type WebAuthnConfig struct {
	RPID          string   `json:"rp_id"`           // e.g. "auth.example.com" or "localhost"
	RPDisplayName string   `json:"rp_display_name"` // e.g. "Example Auth Broker"
	Origins       []string `json:"origins"`         // e.g. ["https://auth.example.com"]
}

// ACMEConfig drives certmagic-managed TLS. When Enabled is true (and at least
// one domain is set), the broker listens on HTTPSAddr for HTTPS and HTTPAddr
// for HTTP-01 challenges plus a redirect-to-HTTPS handler; cfg.Listen is
// ignored in that mode.
type ACMEConfig struct {
	Enabled     bool     `json:"enabled,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	Email       string   `json:"email,omitempty"`
	CADirectory string   `json:"ca_directory,omitempty"`
	// CACertPath points at a PEM file with one or more root certificates the
	// broker must trust when connecting to the ACME server. Use this for
	// internal/private CAs (e.g. step-ca) whose roots aren't in the system
	// trust store. Empty means use the system pool only.
	CACertPath  string `json:"ca_cert_path,omitempty"`
	StoragePath string `json:"storage_path,omitempty"`
	HTTPAddr    string `json:"http_addr,omitempty"`
	HTTPSAddr   string `json:"https_addr,omitempty"`
	AgreedTOS   bool   `json:"agreed_tos,omitempty"`
}

type AppTokenConfig struct {
	ID              string            `json:"id"`
	DisplayName     string            `json:"display_name,omitempty"`
	Audience        string            `json:"audience,omitempty"`
	ClientID        string            `json:"client_id,omitempty"`
	Scope           string            `json:"scope,omitempty"`
	TokenTTLMinutes int               `json:"token_ttl_minutes,omitempty"`
	GroupMappings   map[string]string `json:"group_mappings,omitempty"`
	StoredAt        time.Time         `json:"stored_at,omitempty"`

	// compiledMappings caches the parsed direct/scoped/regex mapping
	// representation. Populated by NewBroker after normalizeClientGroupMappings.
	compiledMappings *compiledGroupMappings
}

//nolint:gocognit,cyclop,funlen // Defaulting the flat JSON config is intentionally centralized.
func normalizeConfig(cfg *Config) {
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.Issuer == "" {
		cfg.Issuer = "http://localhost:8080"
	}
	if cfg.KeyID == "" {
		cfg.KeyID = "broker-key-1"
	}
	if cfg.SigningKeyRotationDays == 0 {
		cfg.SigningKeyRotationDays = defaultSigningKeyRotationDays
	}
	if cfg.SigningKeyRetentionDays == 0 {
		cfg.SigningKeyRetentionDays = defaultSigningKeyRetentionDays
	}
	if cfg.LDAP.TimeoutSeconds == 0 {
		cfg.LDAP.TimeoutSeconds = 5
	}
	if cfg.AccessTokenTTLMinutes == 0 {
		cfg.AccessTokenTTLMinutes = 15
	}
	if cfg.IDTokenTTLMinutes == 0 {
		cfg.IDTokenTTLMinutes = 15
	}
	if cfg.RefreshTokenTTLDays == 0 {
		cfg.RefreshTokenTTLDays = 14
	}
	if cfg.AuthCodeTTLSeconds == 0 {
		cfg.AuthCodeTTLSeconds = 120
	}
	if cfg.SessionTTLHrs == 0 {
		cfg.SessionTTLHrs = 8
	}
	if cfg.ClientIPHeader == "" && len(cfg.TrustedProxies) > 0 {
		cfg.ClientIPHeader = "X-Forwarded-For"
	}
	if cfg.WebAuthn.RPDisplayName == "" {
		cfg.WebAuthn.RPDisplayName = "Go Auth Broker"
	}
	if strings.TrimSpace(cfg.DisplayName) == "" {
		cfg.DisplayName = cfg.WebAuthn.RPDisplayName
	}
	if cfg.WebAuthn.RPID == "" {
		if u, err := url.Parse(cfg.Issuer); err == nil {
			cfg.WebAuthn.RPID = u.Hostname()
		}
	}
	if len(cfg.WebAuthn.Origins) == 0 {
		if u, err := url.Parse(cfg.Issuer); err == nil {
			cfg.WebAuthn.Origins = []string{u.Scheme + "://" + u.Host}
		}
	}
	normalizeACMEConfig(&cfg.ACME)
	normalizeRateLimitConfig(&cfg.RateLimit)
	normalizeMetricsConfig(&cfg.Metrics)
	for i := range cfg.AppTokens {
		if cfg.AppTokens[i].DisplayName == "" {
			cfg.AppTokens[i].DisplayName = cfg.AppTokens[i].ID
		}
		if cfg.AppTokens[i].Audience == "" {
			cfg.AppTokens[i].Audience = cfg.AppTokens[i].ID
		}
		if cfg.AppTokens[i].ClientID == "" {
			cfg.AppTokens[i].ClientID = cfg.AppTokens[i].Audience
		}
		if cfg.AppTokens[i].Scope == "" {
			cfg.AppTokens[i].Scope = "openid profile email groups"
		}
		if cfg.AppTokens[i].TokenTTLMinutes <= 0 {
			cfg.AppTokens[i].TokenTTLMinutes = 480
		}
	}
}

func normalizeRateLimitConfig(cfg *RateLimitConfig) {
	if cfg.LoginWindowSeconds == 0 {
		cfg.LoginWindowSeconds = defaultLoginRateWindowSeconds
	}
	if cfg.LoginMaxAttempts == 0 {
		cfg.LoginMaxAttempts = defaultLoginRateMaxAttempts
	}
	if cfg.LoginLockoutSeconds == 0 {
		cfg.LoginLockoutSeconds = defaultLoginRateLockoutSeconds
	}
	if cfg.TokenWindowSeconds == 0 {
		cfg.TokenWindowSeconds = defaultTokenRateWindowSeconds
	}
	if cfg.TokenMaxAttempts == 0 {
		cfg.TokenMaxAttempts = defaultTokenRateMaxAttempts
	}
	if cfg.TokenLockoutSeconds == 0 {
		cfg.TokenLockoutSeconds = defaultTokenRateLockoutSeconds
	}
	if cfg.PreAuthWindowSeconds == 0 {
		cfg.PreAuthWindowSeconds = defaultPreAuthRateWindowSeconds
	}
	if cfg.PreAuthMaxAttempts == 0 {
		cfg.PreAuthMaxAttempts = defaultPreAuthRateMaxAttempts
	}
	if cfg.PreAuthLockoutSeconds == 0 {
		cfg.PreAuthLockoutSeconds = defaultPreAuthRateLockoutSeconds
	}
}

func normalizeMetricsConfig(cfg *MetricsConfig) {
	if strings.TrimSpace(cfg.Path) == "" {
		cfg.Path = defaultMetricsPath
	}
}

func normalizeACMEConfig(acme *ACMEConfig) {
	cleaned := acme.Domains[:0]
	for _, d := range acme.Domains {
		if d = strings.TrimSpace(d); d != "" {
			cleaned = append(cleaned, d)
		}
	}
	acme.Domains = cleaned
	if acme.HTTPAddr == "" {
		acme.HTTPAddr = ":80"
	}
	if acme.HTTPSAddr == "" {
		acme.HTTPSAddr = ":443"
	}
	if strings.TrimSpace(acme.CADirectory) == "" {
		acme.CADirectory = certmagic.LetsEncryptProductionCA
	}
}

func validateConfig(cfg Config) error {
	if err := validateConfigShape(cfg); err != nil {
		return err
	}
	if !cfg.Production {
		return nil
	}
	if err := validateProductionBase(cfg); err != nil {
		return err
	}
	if err := validateProductionLDAP(cfg.LDAP); err != nil {
		return err
	}
	return validateProductionClients(cfg)
}

//nolint:gocognit // Shape validation enumerates the small fixed set of cross-field constraints linearly.
func validateConfigShape(cfg Config) error {
	seenClients := map[string]bool{}
	for _, c := range cfg.Clients {
		if strings.TrimSpace(c.ClientID) == "" {
			return fmt.Errorf("client_id is required")
		}
		if seenClients[c.ClientID] {
			return fmt.Errorf("duplicate client_id %q", c.ClientID)
		}
		seenClients[c.ClientID] = true
		if err := validateClientScopeConfig(c); err != nil {
			return fmt.Errorf("client %q: %w", c.ClientID, err)
		}
	}
	seenTokens := map[string]bool{}
	for _, tokenCfg := range cfg.AppTokens {
		if strings.TrimSpace(tokenCfg.ID) == "" {
			return fmt.Errorf("app token id is required")
		}
		if seenTokens[tokenCfg.ID] {
			return fmt.Errorf("duplicate app token id %q", tokenCfg.ID)
		}
		seenTokens[tokenCfg.ID] = true
	}
	if err := validateTrustedProxyConfig(cfg); err != nil {
		return err
	}
	if err := validateMetricsConfigShape(cfg.Metrics); err != nil {
		return err
	}
	if cfg.SessionAbsoluteTTLHrs > 0 && cfg.SessionAbsoluteTTLHrs < cfg.SessionTTLHrs {
		return fmt.Errorf("session_absolute_ttl_hours (%d) must be >= session_ttl_hours (%d)", cfg.SessionAbsoluteTTLHrs, cfg.SessionTTLHrs)
	}
	return nil
}

func validateMetricsConfigShape(metrics MetricsConfig) error {
	if !metrics.Enabled {
		return nil
	}
	if !validHTTPPath(metrics.Path) {
		return fmt.Errorf("metrics.path must be an absolute path")
	}
	if strings.TrimSpace(metrics.BearerSHA256) != "" && !validSHA256Hex(metrics.BearerSHA256) {
		return fmt.Errorf("metrics.bearer_token_sha256 must be a SHA-256 hex digest")
	}
	return nil
}

func validateTrustedProxyConfig(cfg Config) error {
	for _, raw := range cfg.TrustedProxies {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			if _, _, err := net.ParseCIDR(raw); err != nil {
				return fmt.Errorf("trusted proxy %q is not a valid CIDR: %w", raw, err)
			}
			continue
		}
		if net.ParseIP(raw) == nil {
			return fmt.Errorf("trusted proxy %q is not a valid IP or CIDR", raw)
		}
	}
	if strings.ContainsAny(cfg.ClientIPHeader, "\r\n") {
		return fmt.Errorf("client_ip_header must not contain control characters")
	}
	if len(cfg.TrustedProxies) > 0 && strings.TrimSpace(cfg.ClientIPHeader) == "" {
		return fmt.Errorf("client_ip_header is required when trusted_proxies is set")
	}
	return nil
}

func validateProductionBase(cfg Config) error {
	if !isHTTPSURL(cfg.Issuer) {
		return fmt.Errorf("production requires an https issuer")
	}
	if !cookieSecureForConfig(cfg) {
		return fmt.Errorf("production requires secure cookies")
	}
	if len(nonEmptyStrings(cfg.AdminGroups)) == 0 {
		return fmt.Errorf("production requires at least one admin_group")
	}
	if !cfg.MFA.TOTPRequired {
		return fmt.Errorf("production requires mfa.totp_required=true")
	}
	if cfg.Metrics.Enabled && !validSHA256Hex(cfg.Metrics.BearerSHA256) {
		return fmt.Errorf("production metrics requires metrics.bearer_token_sha256")
	}
	if !within(cfg.AccessTokenTTLMinutes, 1, 60) {
		return fmt.Errorf("production access_token_ttl_minutes must be between 1 and 60")
	}
	if !within(cfg.IDTokenTTLMinutes, 1, 60) {
		return fmt.Errorf("production id_token_ttl_minutes must be between 1 and 60")
	}
	if !within(cfg.RefreshTokenTTLDays, 1, 30) {
		return fmt.Errorf("production refresh_token_ttl_days must be between 1 and 30")
	}
	if !within(cfg.AuthCodeTTLSeconds, 30, 300) {
		return fmt.Errorf("production auth_code_ttl_seconds must be between 30 and 300")
	}
	if !within(cfg.SessionTTLHrs, 1, 24) {
		return fmt.Errorf("production session_ttl_hours must be between 1 and 24")
	}
	if cfg.SessionAbsoluteTTLHrs <= 0 {
		return fmt.Errorf("production requires session_absolute_ttl_hours to cap total session lifetime")
	}
	if !within(cfg.SessionAbsoluteTTLHrs, cfg.SessionTTLHrs, 168) {
		return fmt.Errorf("production session_absolute_ttl_hours must be between session_ttl_hours and 168")
	}
	return validateProductionWebAuthn(cfg.WebAuthn)
}

func validateProductionWebAuthn(cfg WebAuthnConfig) error {
	if localhostOrLoopback(cfg.RPID) {
		return fmt.Errorf("production webauthn.rp_id must not be localhost or loopback")
	}
	for _, origin := range cfg.Origins {
		if !isHTTPSURL(origin) {
			return fmt.Errorf("production webauthn origin %q must be https", origin)
		}
		if host, ok := urlHostname(origin); !ok || localhostOrLoopback(host) {
			return fmt.Errorf("production webauthn origin %q must not use localhost or loopback", origin)
		}
	}
	return nil
}

func validateProductionLDAP(cfg LDAPConfig) error {
	ldapURL, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || ldapURL.Scheme == "" {
		return fmt.Errorf("production requires a valid ldap.url")
	}
	if ldapURL.Scheme != "ldaps" && !cfg.StartTLS {
		return fmt.Errorf("production requires LDAPS or ldap.start_tls=true")
	}
	if cfg.InsecureSkipVerify {
		return fmt.Errorf("production forbids ldap.insecure_skip_verify")
	}
	return nil
}

func validateProductionClients(cfg Config) error {
	for _, c := range cfg.Clients {
		if err := validateProductionClient(c); err != nil {
			return err
		}
	}
	for _, t := range cfg.AppTokens {
		if !within(t.TokenTTLMinutes, 1, 1440) {
			return fmt.Errorf("production app token %q ttl must be between 1 and 1440 minutes", t.ID)
		}
	}
	return nil
}

func validateProductionClient(c Client) error {
	if !c.RequirePKCE {
		return fmt.Errorf("production client %q must require PKCE", c.ClientID)
	}
	if !c.Public && !validSHA256Hex(c.ClientSecretSHA256) {
		return fmt.Errorf("production confidential client %q requires a SHA-256 client secret hash", c.ClientID)
	}
	for _, redirectURI := range c.RedirectURIs {
		if err := validateProductionRedirectURI(c.ClientID, redirectURI); err != nil {
			return err
		}
	}
	for _, redirectURI := range c.PostLogoutRedirectURIs {
		if err := validateProductionRedirectURI(c.ClientID, redirectURI); err != nil {
			return err
		}
	}
	return nil
}

func validateProductionRedirectURI(clientID, redirectURI string) error {
	if !isHTTPSURL(redirectURI) {
		return fmt.Errorf("production client %q redirect URI %q must be https", clientID, redirectURI)
	}
	if host, ok := urlHostname(redirectURI); !ok || localhostOrLoopback(host) {
		return fmt.Errorf("production client %q redirect URI %q must not use localhost or loopback", clientID, redirectURI)
	}
	return nil
}

func cookieSecureForConfig(cfg Config) bool {
	if cfg.CookieSecure != nil {
		return *cfg.CookieSecure
	}
	return strings.HasPrefix(cfg.Issuer, "https://")
}

func isHTTPSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && u.Scheme == "https" && u.Hostname() != ""
}

func urlHostname(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	return u.Hostname(), true
}

func localhostOrLoopback(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validSHA256Hex(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

func validHTTPPath(path string) bool {
	path = strings.TrimSpace(path)
	return strings.HasPrefix(path, "/") && !strings.ContainsAny(path, " \t\r\n")
}

func within(v, minValue, maxValue int) bool {
	return v >= minValue && v <= maxValue
}

// nonEmptyStrings returns a new slice containing the input's non-blank entries.
// It does NOT alias the caller's backing array — earlier revisions used the
// `values[:0]` trick, which silently overwrote positions in the caller's slice
// (e.g. ["", "admin", "ops"] became ["admin", "ops", "ops"]) even though the
// returned slice had the right length. Allocating a fresh slice is cheap here
// (every caller passes a config list with a handful of entries) and avoids
// surprising future callers that read the input after this function returns.
func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	b, err := readOperatorFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func resolveDataDir(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if info, statErr := os.Stat(path); statErr == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("%s must be a directory", path)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	return filepath.Clean(path), nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
