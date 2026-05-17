package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

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
	maxWebAuthnBodyBytes     = 64 << 10
	maxAppTokenFormBodyBytes = 4 << 10
	maxTOTPEnrollBodyBytes   = 4 << 10
)

// Config is intentionally small. It is enough to run a modern LDAP-backed
// OAuth2/OIDC broker. Use this as a baseline, not as a complete enterprise IdP.
type Config struct {
	Issuer        string `json:"issuer"`
	Listen        string `json:"listen"`
	DisplayName   string `json:"display_name,omitempty"`
	SigningKeyPEM string `json:"signing_key_pem,omitempty"`
	KeyID         string `json:"key_id"`
	CookieSecure  *bool  `json:"cookie_secure,omitempty"`

	SigningKeys             []SigningKeyConfig `json:"signing_keys,omitempty"`
	SigningKeyRotationDays  int                `json:"signing_key_rotation_days,omitempty"`
	SigningKeyRetentionDays int                `json:"signing_key_retention_days,omitempty"`

	LDAP      LDAPConfig       `json:"ldap"`
	Clients   []Client         `json:"clients"`
	MFA       MFAConfig        `json:"mfa"`
	WebAuthn  WebAuthnConfig   `json:"webauthn"`
	AppTokens []AppTokenConfig `json:"app_tokens,omitempty"`
	ACME      ACMEConfig       `json:"acme,omitempty"`

	AccessTokenTTLMinutes int `json:"access_token_ttl_minutes"`
	IDTokenTTLMinutes     int `json:"id_token_ttl_minutes"`
	RefreshTokenTTLDays   int `json:"refresh_token_ttl_days"`
	AuthCodeTTLSeconds    int `json:"auth_code_ttl_seconds"`
	SessionTTLHrs         int `json:"session_ttl_hours"`
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
	ClientID               string            `json:"client_id"`
	ClientSecretSHA256     string            `json:"client_secret_sha256,omitempty"`
	RedirectURIs           []string          `json:"redirect_uris"`
	PostLogoutRedirectURIs []string          `json:"post_logout_redirect_uris,omitempty"`
	Public                 bool              `json:"public"`
	RequirePKCE            bool              `json:"require_pkce"`
	GroupMappings          map[string]string `json:"group_mappings,omitempty"`

	// compiledMappings caches the parsed direct/scoped/regex mapping
	// representation. Populated by NewBroker after normalizeClientGroupMappings.
	compiledMappings *compiledGroupMappings
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

func loadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path) //nolint:gosec // config path is supplied by the local operator.
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
