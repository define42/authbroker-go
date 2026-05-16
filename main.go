package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // TOTP RFC 6238 uses HMAC-SHA1.
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

const (
	sessionCookieName = "broker_session"
	bearerPrefix      = "Bearer "

	defaultConfigPath = "config.json"
	defaultDataDir    = "data"
	defaultDataFile   = "data.json"
	defaultKeysPath   = "signing-keys.json"
	envConfigPath     = "AUTHBROKER_CONFIG"
	envDataPath       = "AUTHBROKER_DATA"

	defaultSigningKeyRotationDays  = 90
	defaultSigningKeyRetentionDays = 30
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
	TimeoutSeconds     int    `json:"timeout_seconds"`
}

type Client struct {
	ClientID               string            `json:"client_id"`
	ClientSecretSHA256     string            `json:"client_secret_sha256,omitempty"`
	RedirectURIs           []string          `json:"redirect_uris"`
	PostLogoutRedirectURIs []string          `json:"post_logout_redirect_uris,omitempty"`
	Public                 bool              `json:"public"`
	RequirePKCE            bool              `json:"require_pkce"`
	GroupMappings          map[string]string `json:"group_mappings,omitempty"`
}

type MFAConfig struct {
	TOTPRequired bool `json:"totp_required"`
}

type WebAuthnConfig struct {
	RPID          string   `json:"rp_id"`           // e.g. "auth.example.com" or "localhost"
	RPDisplayName string   `json:"rp_display_name"` // e.g. "Example Auth Broker"
	Origins       []string `json:"origins"`         // e.g. ["https://auth.example.com"]
}

type AppTokenConfig struct {
	ID              string            `json:"id"`
	DisplayName     string            `json:"display_name,omitempty"`
	Audience        string            `json:"audience,omitempty"`
	ClientID        string            `json:"client_id,omitempty"`
	Scope           string            `json:"scope,omitempty"`
	TokenTTLMinutes int               `json:"token_ttl_minutes,omitempty"`
	GroupMappings   map[string]string `json:"group_mappings,omitempty"`
}

type StoredUser struct {
	Username            string               `json:"username"`
	Email               string               `json:"email,omitempty"`
	Name                string               `json:"name,omitempty"`
	Groups              []string             `json:"groups,omitempty"`
	TOTPSecretBase32    string               `json:"totp_secret_base32,omitempty"`
	WebAuthnCredentials []WebAuthnCredential `json:"webauthn_credentials,omitempty"`
}

type WebAuthnCredential struct {
	IDBase64URL string `json:"id_base64url"`
	Alg         string `json:"alg"` // currently ES256
	XBase64URL  string `json:"x_base64url"`
	YBase64URL  string `json:"y_base64url"`
	SignCount   uint32 `json:"sign_count"`
	CreatedAt   int64  `json:"created_at"`
}

type PersistentData struct {
	Users         map[string]*StoredUser          `json:"users"`
	Sessions      map[string]Session              `json:"sessions,omitempty"`
	AuthRequests  map[string]AuthorizationRequest `json:"auth_requests,omitempty"`
	AuthCodes     map[string]AuthCode             `json:"authorization_codes,omitempty"`
	RefreshTokens map[string]RefreshToken         `json:"refresh_tokens,omitempty"`
	RevokedJTIs   map[string]time.Time            `json:"revoked_jtis,omitempty"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	data PersistentData
}

type StoredRuntimeState struct {
	Sessions      map[string]Session
	AuthRequests  map[string]AuthorizationRequest
	AuthCodes     map[string]AuthCode
	RefreshTokens map[string]RefreshToken
	RevokedJTIs   map[string]time.Time
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path, data: newPersistentData()}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // data path is supplied by the local operator.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(b, &s.data); err != nil {
		return nil, err
	}
	s.ensureMaps()
	return s, nil
}

func newPersistentData() PersistentData {
	return PersistentData{
		Users:         map[string]*StoredUser{},
		Sessions:      map[string]Session{},
		AuthRequests:  map[string]AuthorizationRequest{},
		AuthCodes:     map[string]AuthCode{},
		RefreshTokens: map[string]RefreshToken{},
		RevokedJTIs:   map[string]time.Time{},
	}
}

func (s *Store) ensureMaps() {
	if s.data.Users == nil {
		s.data.Users = map[string]*StoredUser{}
	}
	if s.data.Sessions == nil {
		s.data.Sessions = map[string]Session{}
	}
	if s.data.AuthRequests == nil {
		s.data.AuthRequests = map[string]AuthorizationRequest{}
	}
	if s.data.AuthCodes == nil {
		s.data.AuthCodes = map[string]AuthCode{}
	}
	if s.data.RefreshTokens == nil {
		s.data.RefreshTokens = map[string]RefreshToken{}
	}
	if s.data.RevokedJTIs == nil {
		s.data.RevokedJTIs = map[string]time.Time{}
	}
}

func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) UpsertProfile(p UserProfile) (*StoredUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.data.Users[p.Subject]
	if u == nil {
		u = &StoredUser{Username: p.Subject}
		s.data.Users[p.Subject] = u
	}
	if p.Email != "" {
		u.Email = p.Email
	}
	if p.Name != "" {
		u.Name = p.Name
	}
	if p.Groups != nil {
		u.Groups = append([]string(nil), p.Groups...)
	}
	out := cloneStoredUser(u)
	return out, s.saveLocked()
}

func (s *Store) GetUser(username string) (*StoredUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.data.Users[username]
	if !ok || u == nil {
		return nil, false
	}
	return cloneStoredUser(u), true
}

func (s *Store) SetTOTP(username, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.data.Users[username]
	if u == nil {
		u = &StoredUser{Username: username}
		s.data.Users[username] = u
	}
	u.TOTPSecretBase32 = secret
	return s.saveLocked()
}

func (s *Store) AddWebAuthnCredential(username string, cred WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.data.Users[username]
	if u == nil {
		u = &StoredUser{Username: username}
		s.data.Users[username] = u
	}
	for _, existing := range u.WebAuthnCredentials {
		if existing.IDBase64URL == cred.IDBase64URL {
			return fmt.Errorf("credential already registered")
		}
	}
	u.WebAuthnCredentials = append(u.WebAuthnCredentials, cred)
	return s.saveLocked()
}

func (s *Store) UpdateWebAuthnSignCount(username, credID string, signCount uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.data.Users[username]
	if u == nil {
		return fmt.Errorf("user not found")
	}
	for i := range u.WebAuthnCredentials {
		if u.WebAuthnCredentials[i].IDBase64URL == credID {
			u.WebAuthnCredentials[i].SignCount = signCount
			return s.saveLocked()
		}
	}
	return fmt.Errorf("credential not found")
}

func (s *Store) RuntimeState() StoredRuntimeState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return StoredRuntimeState{
		Sessions:      cloneSessionMap(s.data.Sessions),
		AuthRequests:  cloneAuthorizationRequestMap(s.data.AuthRequests),
		AuthCodes:     cloneAuthCodeMap(s.data.AuthCodes),
		RefreshTokens: cloneRefreshTokenMap(s.data.RefreshTokens),
		RevokedJTIs:   cloneRevokedJTIMap(s.data.RevokedJTIs),
	}
}

func (s *Store) ReplaceRuntimeState(state StoredRuntimeState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Sessions = cloneSessionMap(state.Sessions)
	s.data.AuthRequests = cloneAuthorizationRequestMap(state.AuthRequests)
	s.data.AuthCodes = cloneAuthCodeMap(state.AuthCodes)
	s.data.RefreshTokens = cloneRefreshTokenMap(state.RefreshTokens)
	s.data.RevokedJTIs = cloneRevokedJTIMap(state.RevokedJTIs)
	return s.saveLocked()
}

func cloneStoredUser(u *StoredUser) *StoredUser {
	if u == nil {
		return nil
	}
	c := *u
	if u.Groups != nil {
		c.Groups = append([]string(nil), u.Groups...)
	}
	if u.WebAuthnCredentials != nil {
		c.WebAuthnCredentials = append([]WebAuthnCredential(nil), u.WebAuthnCredentials...)
	}
	return &c
}

func cloneSessionMap(in map[string]Session) map[string]Session {
	out := make(map[string]Session, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneAuthorizationRequestMap(in map[string]AuthorizationRequest) map[string]AuthorizationRequest {
	out := make(map[string]AuthorizationRequest, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneAuthCodeMap(in map[string]AuthCode) map[string]AuthCode {
	out := make(map[string]AuthCode, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRefreshTokenMap(in map[string]RefreshToken) map[string]RefreshToken {
	out := make(map[string]RefreshToken, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneRevokedJTIMap(in map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type UserProfile struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (UserProfile, error)
}

type LDAPAuthenticator struct {
	cfg LDAPConfig
}

func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (UserProfile, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return UserProfile{}, fmt.Errorf("invalid username or password")
	}
	if a.cfg.URL == "" {
		return UserProfile{}, fmt.Errorf("ldap url is not configured")
	}
	bindName := a.bindName(username)

	conn, err := dialLDAP(ctx, a.cfg)
	if err != nil {
		return UserProfile{}, err
	}
	defer conn.Close()

	if err := conn.Bind(bindName, password); err != nil {
		return UserProfile{}, fmt.Errorf("ldap bind failed: %w", err)
	}

	profile := a.fallbackProfile(username)
	enabled, err := a.profileSearchEnabled()
	if err != nil {
		return UserProfile{}, err
	}
	if !enabled {
		return profile, nil
	}
	profile, err = a.searchProfile(conn, username, bindName, profile)
	if err != nil {
		return UserProfile{}, err
	}
	return profile, nil
}

func (a *LDAPAuthenticator) fallbackProfile(username string) UserProfile {
	email := ""
	if strings.Contains(username, "@") {
		email = username
	} else if a.cfg.DomainSuffix != "" && strings.HasPrefix(a.cfg.DomainSuffix, "@") {
		email = username + a.cfg.DomainSuffix
	}
	return UserProfile{Subject: username, Email: email, Name: username}
}

func (a *LDAPAuthenticator) profileSearchEnabled() (bool, error) {
	baseDN := strings.TrimSpace(a.cfg.BaseDN)
	filter := strings.TrimSpace(a.cfg.UserFilter)
	if baseDN == "" && filter == "" {
		return false, nil
	}
	if baseDN == "" || filter == "" {
		return false, fmt.Errorf("ldap base_dn and user_filter must be configured together")
	}
	return true, nil
}

func (a *LDAPAuthenticator) searchProfile(conn *ldap.Conn, username, bindName string, profile UserProfile) (UserProfile, error) {
	emailAttr := ldapAttribute(a.cfg.EmailAttribute, "mail")
	nameAttr := ldapAttribute(a.cfg.NameAttribute, "cn")
	groupsAttr := strings.TrimSpace(a.cfg.GroupsAttribute)
	searchReq := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		a.cfg.TimeoutSeconds,
		false,
		a.userFilter(username, bindName),
		uniqueNonEmpty(emailAttr, nameAttr, groupsAttr),
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return UserProfile{}, fmt.Errorf("ldap profile search failed: %w", err)
	}
	if len(result.Entries) != 1 {
		return UserProfile{}, fmt.Errorf("ldap profile search returned %d entries", len(result.Entries))
	}
	entry := result.Entries[0]
	if email := strings.TrimSpace(ldapEntryAttributeValue(entry, emailAttr)); email != "" {
		profile.Email = email
	}
	if name := strings.TrimSpace(ldapEntryAttributeValue(entry, nameAttr)); name != "" {
		profile.Name = name
	}
	if groupsAttr != "" {
		profile.Groups = ldapGroupIdentifiers(ldapEntryAttributeValues(entry, groupsAttr))
	}
	if a.cfg.NestedGroups {
		nestedGroups, err := a.searchNestedADGroups(conn, entry.DN)
		if err != nil {
			return UserProfile{}, err
		}
		profile.Groups = mergeStrings(profile.Groups, nestedGroups)
	}
	return profile, nil
}

func (a *LDAPAuthenticator) searchNestedADGroups(conn *ldap.Conn, userDN string) ([]string, error) {
	userDN = strings.TrimSpace(userDN)
	if userDN == "" {
		return nil, fmt.Errorf("ldap nested group search requires a user DN")
	}
	baseDN := strings.TrimSpace(a.cfg.GroupSearchBaseDN)
	if baseDN == "" {
		baseDN = a.cfg.BaseDN
	}
	nameAttr := ldapAttribute(a.cfg.GroupNameAttribute, "cn")
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		a.cfg.TimeoutSeconds,
		false,
		a.nestedADGroupFilter(userDN),
		uniqueNonEmpty(nameAttr),
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap nested group search failed: %w", err)
	}

	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if group := strings.TrimSpace(entry.DN); group != "" {
			groups = append(groups, group)
		}
		if group := strings.TrimSpace(ldapEntryAttributeValue(entry, nameAttr)); group != "" {
			groups = append(groups, group)
		}
	}
	return ldapGroupIdentifiers(groups), nil
}

func (a *LDAPAuthenticator) nestedADGroupFilter(userDN string) string {
	groupFilter := strings.TrimSpace(a.cfg.GroupSearchFilter)
	if groupFilter == "" {
		groupFilter = "(objectClass=group)"
	}
	memberFilter := "(member:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(userDN) + ")"
	return ldapAndFilter(groupFilter, memberFilter)
}

func (a *LDAPAuthenticator) userFilter(username, bindName string) string {
	login := a.loginName(username)
	replacer := strings.NewReplacer(
		"{username}", ldap.EscapeFilter(username),
		"{login}", ldap.EscapeFilter(login),
		"{bind}", ldap.EscapeFilter(bindName),
		"%s", ldap.EscapeFilter(login),
	)
	return replacer.Replace(a.cfg.UserFilter)
}

func (a *LDAPAuthenticator) loginName(username string) string {
	if a.cfg.DomainSuffix != "" && !strings.Contains(username, "@") && !strings.Contains(username, "\\") {
		return username + a.cfg.DomainSuffix
	}
	return username
}

func (a *LDAPAuthenticator) bindName(username string) string {
	if a.cfg.UserDNTemplate != "" {
		escaped := escapeLDAPDN(username)
		if strings.Contains(a.cfg.UserDNTemplate, "{username}") {
			return strings.ReplaceAll(a.cfg.UserDNTemplate, "{username}", escaped)
		}
		if strings.Contains(a.cfg.UserDNTemplate, "%s") {
			return fmt.Sprintf(a.cfg.UserDNTemplate, escaped)
		}
		return a.cfg.UserDNTemplate
	}
	return a.loginName(username)
}

func ldapGroupNames(values []string) []string {
	seen := map[string]bool{}
	groups := []string{}
	for _, value := range values {
		value = ldapGroupName(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		groups = append(groups, value)
	}
	sort.Strings(groups)
	return groups
}

func ldapGroupIdentifiers(values []string) []string {
	seen := map[string]bool{}
	groups := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		groups = append(groups, value)
	}
	sort.Strings(groups)
	return groups
}

//nolint:gocognit,nestif // LDAP DN fallback parsing is clearest kept together.
func ldapGroupName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "=") {
		dn, err := ldap.ParseDN(value)
		if err == nil && len(dn.RDNs) > 0 {
			fallback := ""
			for _, attr := range dn.RDNs[0].Attributes {
				if fallback == "" && strings.TrimSpace(attr.Value) != "" {
					fallback = strings.TrimSpace(attr.Value)
				}
				if strings.EqualFold(attr.Type, "cn") && strings.TrimSpace(attr.Value) != "" {
					return strings.TrimSpace(attr.Value)
				}
			}
			if fallback != "" {
				return fallback
			}
		}
	}
	return value
}

func ldapAndFilter(filters ...string) string {
	parts := make([]string, 0, len(filters))
	for _, filter := range filters {
		filter = strings.TrimSpace(filter)
		if filter == "" {
			continue
		}
		if !strings.HasPrefix(filter, "(") {
			filter = "(" + filter + ")"
		}
		parts = append(parts, filter)
	}
	if len(parts) == 0 {
		return "(objectClass=*)"
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return "(&" + strings.Join(parts, "") + ")"
}

func mergeStrings(values ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, slice := range values {
		for _, value := range slice {
			value = strings.TrimSpace(value)
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

type scopedGroupMapping struct {
	Source string
	Target string
	BaseDN *ldap.DN
}

type regexGroupMapping struct {
	Source  string
	Target  string
	Pattern *regexp.Regexp
}

//nolint:gocognit,cyclop // Validation branches mirror the supported group mapping forms.
func normalizeClientGroupMappings(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	seenSources := map[string]string{}
	seenScoped := map[string]string{}
	seenRegex := map[string]string{}
	for source, target := range in {
		source = strings.TrimSpace(source)
		target = strings.TrimSpace(target)
		if source == "" {
			return nil, fmt.Errorf("group_mappings source cannot be blank")
		}
		if target == "" {
			return nil, fmt.Errorf("group_mappings target for %q cannot be blank", source)
		}
		if regexMapping, ok, err := parseRegexGroupMapping(source, target); err != nil {
			return nil, err
		} else if ok {
			sourceKey := strings.ToLower(regexMapping.Source)
			if existing, ok := seenRegex[sourceKey]; ok && existing != target {
				return nil, fmt.Errorf("group_mappings has duplicate regex source %q with different targets", regexMapping.Source)
			}
			seenRegex[sourceKey] = target
			out[regexMapping.Source] = target
			continue
		}
		if scoped, ok, err := parseScopedGroupMapping(source, target); err != nil {
			return nil, err
		} else if ok {
			sourceKey := strings.ToLower(scoped.BaseDN.String())
			if existing, ok := seenScoped[sourceKey]; ok && existing != target {
				return nil, fmt.Errorf("group_mappings has duplicate scoped source %q with different targets", scoped.BaseDN.String())
			}
			seenScoped[sourceKey] = target
			out[scoped.Source] = target
			continue
		}
		normalizedSource := ldapGroupName(source)
		sourceKey := strings.ToLower(normalizedSource)
		if sourceKey == "" {
			return nil, fmt.Errorf("group_mappings source cannot be blank")
		}
		if existing, ok := seenSources[sourceKey]; ok && existing != target {
			return nil, fmt.Errorf("group_mappings has duplicate source %q with different targets", normalizedSource)
		}
		seenSources[sourceKey] = target
		out[normalizedSource] = target
	}
	return out, nil
}

//nolint:gocognit,cyclop,funlen // Mapping modes are evaluated in one pass to preserve deterministic output.
func mappedClientGroups(client Client, userGroups []string) []string {
	if len(userGroups) == 0 || len(client.GroupMappings) == 0 {
		return nil
	}
	mappings := map[string]string{}
	scopedMappings := []scopedGroupMapping{}
	regexMappings := []regexGroupMapping{}
	for source, target := range client.GroupMappings {
		if regexMapping, ok, err := parseRegexGroupMapping(source, target); err == nil && ok {
			regexMappings = append(regexMappings, regexMapping)
			continue
		}
		if scoped, ok, err := parseScopedGroupMapping(source, target); err == nil && ok {
			scopedMappings = append(scopedMappings, scoped)
			continue
		}
		sourceName := ldapGroupName(source)
		if sourceName == "" || strings.TrimSpace(target) == "" {
			continue
		}
		mappings[strings.ToLower(sourceName)] = strings.TrimSpace(target)
	}
	seen := map[string]bool{}
	groups := []string{}
	for _, group := range userGroups {
		groupName := ldapGroupName(group)
		if target := mappings[strings.ToLower(groupName)]; target != "" {
			mapped := renderGroupMappingTarget(target, groupName, group)
			if mapped != "" && !seen[mapped] {
				seen[mapped] = true
				groups = append(groups, mapped)
			}
		}
		for _, scoped := range scopedMappings {
			cn, dn, ok := scopedGroupMatch(scoped, group)
			if !ok {
				continue
			}
			mapped := renderGroupMappingTarget(scoped.Target, cn, dn)
			if mapped == "" || seen[mapped] {
				continue
			}
			seen[mapped] = true
			groups = append(groups, mapped)
		}
		for _, regexMapping := range regexMappings {
			matches := regexMapping.Pattern.FindStringSubmatch(group)
			if matches == nil {
				continue
			}
			mapped := renderRegexGroupMappingTarget(regexMapping, groupName, group, matches)
			if mapped == "" || seen[mapped] {
				continue
			}
			seen[mapped] = true
			groups = append(groups, mapped)
		}
	}
	sort.Strings(groups)
	return groups
}

func parseRegexGroupMapping(source, target string) (regexGroupMapping, bool, error) {
	source = strings.TrimSpace(source)
	target = strings.TrimSpace(target)
	prefix := "regex:"
	if !strings.HasPrefix(strings.ToLower(source), prefix) {
		return regexGroupMapping{}, false, nil
	}
	pattern := strings.TrimSpace(source[len(prefix):])
	if pattern == "" {
		return regexGroupMapping{}, false, fmt.Errorf("regex group_mappings source cannot be blank")
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return regexGroupMapping{}, false, fmt.Errorf("invalid regex group_mappings source %q: %w", source, err)
	}
	return regexGroupMapping{
		Source:  prefix + pattern,
		Target:  target,
		Pattern: compiled,
	}, true, nil
}

func parseScopedGroupMapping(source, target string) (scopedGroupMapping, bool, error) {
	source = strings.TrimSpace(source)
	target = strings.TrimSpace(target)
	dn, err := ldap.ParseDN(source)
	if err != nil {
		if strings.Contains(source, "*") || groupMappingTargetHasPlaceholder(target) {
			return scopedGroupMapping{}, false, fmt.Errorf("invalid scoped group_mappings DN %q: %w", source, err)
		}
		return scopedGroupMapping{}, false, nil
	}
	if baseDN, ok := cnWildcardBaseDN(dn); ok {
		return scopedGroupMapping{
			Source: "CN=*," + baseDN.String(),
			Target: target,
			BaseDN: baseDN,
		}, true, nil
	}
	if strings.Contains(source, "*") {
		return scopedGroupMapping{}, false, fmt.Errorf("wildcard group_mappings source %q must use CN=*,<base_dn>", source)
	}
	if groupMappingTargetHasPlaceholder(target) && !firstRDNHasAttribute(dn, "cn") {
		return scopedGroupMapping{
			Source: dn.String(),
			Target: target,
			BaseDN: dn,
		}, true, nil
	}
	return scopedGroupMapping{}, false, nil
}

func cnWildcardBaseDN(dn *ldap.DN) (*ldap.DN, bool) {
	if dn == nil || len(dn.RDNs) < 2 || len(dn.RDNs[0].Attributes) != 1 {
		return nil, false
	}
	attr := dn.RDNs[0].Attributes[0]
	if !strings.EqualFold(attr.Type, "cn") || attr.Value != "*" {
		return nil, false
	}
	return &ldap.DN{RDNs: dn.RDNs[1:]}, true
}

func scopedGroupMatch(mapping scopedGroupMapping, group string) (string, string, bool) {
	groupDN, err := ldap.ParseDN(strings.TrimSpace(group))
	if err != nil || mapping.BaseDN == nil || !mapping.BaseDN.AncestorOfFold(groupDN) {
		return "", "", false
	}
	cn, ok := firstRDNAttribute(groupDN, "cn")
	if !ok || strings.TrimSpace(cn) == "" {
		return "", "", false
	}
	return strings.TrimSpace(cn), groupDN.String(), true
}

func firstRDNHasAttribute(dn *ldap.DN, attrType string) bool {
	_, ok := firstRDNAttribute(dn, attrType)
	return ok
}

func firstRDNAttribute(dn *ldap.DN, attrType string) (string, bool) {
	if dn == nil || len(dn.RDNs) == 0 {
		return "", false
	}
	for _, attr := range dn.RDNs[0].Attributes {
		if strings.EqualFold(attr.Type, attrType) {
			return attr.Value, true
		}
	}
	return "", false
}

func groupMappingTargetHasPlaceholder(target string) bool {
	return target == "*" || strings.Contains(target, "{cn}") || strings.Contains(target, "{group}") || strings.Contains(target, "{dn}")
}

func renderGroupMappingTarget(target, groupName, groupDN string) string {
	target = strings.TrimSpace(target)
	if target == "*" {
		target = "{cn}"
	}
	replacer := strings.NewReplacer(
		"{cn}", strings.TrimSpace(groupName),
		"{group}", strings.TrimSpace(groupName),
		"{dn}", strings.TrimSpace(groupDN),
	)
	return strings.TrimSpace(replacer.Replace(target))
}

func renderRegexGroupMappingTarget(mapping regexGroupMapping, groupName, groupDN string, matches []string) string {
	mapped := renderGroupMappingTarget(mapping.Target, groupName, groupDN)
	replacements := []string{}
	if len(matches) > 0 {
		replacements = append(replacements, "{match}", matches[0], "{0}", matches[0])
	}
	for i := 1; i < len(matches); i++ {
		replacements = append(replacements, fmt.Sprintf("{%d}", i), matches[i])
	}
	names := mapping.Pattern.SubexpNames()
	for i := 1; i < len(matches) && i < len(names); i++ {
		if names[i] != "" {
			replacements = append(replacements, "{"+names[i]+"}", matches[i])
		}
	}
	if len(replacements) > 0 {
		mapped = strings.NewReplacer(replacements...).Replace(mapped)
	}
	return strings.TrimSpace(mapped)
}

func scopeIncludes(scope, wanted string) bool {
	for _, part := range strings.Fields(scope) {
		if part == wanted {
			return true
		}
	}
	return false
}

func escapeLDAPDN(s string) string {
	replacer := strings.NewReplacer(
		"\\", "\\5c",
		",", "\\2c",
		"+", "\\2b",
		"\"", "\\22",
		"<", "\\3c",
		">", "\\3e",
		";", "\\3b",
		"=", "\\3d",
		"#", "\\23",
	)
	return replacer.Replace(s)
}

type Broker struct {
	cfg        Config
	store      *Store
	authn      Authenticator
	activeKey  signingKey
	verifyKeys map[string]*rsa.PublicKey
	publicJWKs []any

	clients   map[string]Client
	appTokens map[string]AppTokenConfig

	mu           sync.Mutex
	sessions     map[string]Session
	authRequests map[string]AuthorizationRequest
	authCodes    map[string]AuthCode
	refresh      map[string]RefreshToken
	revokedJTIs  map[string]time.Time
	webauthnReg  map[string]ChallengeRecord
	webauthnLog  map[string]ChallengeRecord
}

type signingKey struct {
	keyID      string
	privateKey *rsa.PrivateKey
	publicJWK  map[string]any
}

func buildSigningKeySet(cfg Config) (signingKey, map[string]*rsa.PublicKey, []any, error) {
	keyConfigs := effectiveSigningKeyConfigs(cfg)
	if len(keyConfigs) == 0 {
		return signingKey{}, nil, nil, nil
	}

	verifyKeys := make(map[string]*rsa.PublicKey, len(keyConfigs))
	publicJWKs := make([]any, 0, len(keyConfigs))
	var active signingKey
	activeCount := 0
	activeFlags := countActiveSigningKeyConfigs(keyConfigs)
	for i, keyCfg := range keyConfigs {
		keyID, key, publicJWK, err := parseSigningKeyConfig(keyCfg, i)
		if err != nil {
			return signingKey{}, nil, nil, err
		}
		if _, exists := verifyKeys[keyID]; exists {
			return signingKey{}, nil, nil, fmt.Errorf("duplicate signing key id %q", keyID)
		}
		verifyKeys[keyID] = &key.PublicKey
		publicJWKs = append(publicJWKs, publicJWK)
		if signingKeyConfigIsActive(keyCfg, activeFlags, len(keyConfigs), cfg.KeyID, keyID) {
			activeCount++
			active = signingKey{keyID: keyID, privateKey: key, publicJWK: publicJWK}
		}
	}
	if activeCount != 1 {
		return signingKey{}, nil, nil, fmt.Errorf("exactly one signing key must be active")
	}
	return active, verifyKeys, publicJWKs, nil
}

func effectiveSigningKeyConfigs(cfg Config) []SigningKeyConfig {
	if len(cfg.SigningKeys) > 0 || strings.TrimSpace(cfg.SigningKeyPEM) == "" {
		return cfg.SigningKeys
	}
	return []SigningKeyConfig{{
		KeyID:         cfg.KeyID,
		SigningKeyPEM: cfg.SigningKeyPEM,
		Active:        true,
	}}
}

func countActiveSigningKeyConfigs(keyConfigs []SigningKeyConfig) int {
	count := 0
	for _, keyCfg := range keyConfigs {
		if keyCfg.Active {
			count++
		}
	}
	return count
}

func parseSigningKeyConfig(keyCfg SigningKeyConfig, index int) (string, *rsa.PrivateKey, map[string]any, error) {
	keyID := strings.TrimSpace(keyCfg.KeyID)
	if keyID == "" {
		return "", nil, nil, fmt.Errorf("signing_keys[%d].key_id is required", index)
	}
	keyPEM := strings.TrimSpace(keyCfg.SigningKeyPEM)
	if keyPEM == "" {
		return "", nil, nil, fmt.Errorf("signing key %q: signing_key_pem is required", keyID)
	}
	key, err := parseRSAPrivateKeyPEM([]byte(keyPEM))
	if err != nil {
		return "", nil, nil, fmt.Errorf("parse signing key %q: %w", keyID, err)
	}
	return keyID, key, makePublicJWK(keyID, &key.PublicKey), nil
}

func signingKeyConfigIsActive(keyCfg SigningKeyConfig, activeFlags, keyCount int, cfgKeyID, keyID string) bool {
	if activeFlags > 0 {
		return keyCfg.Active
	}
	return keyCount == 1 || (cfgKeyID != "" && keyID == cfgKeyID)
}

type Session struct {
	UserID    string
	ExpiresAt time.Time
	AuthTime  time.Time
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

type AuthCode struct {
	Code                string
	UserID              string
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	ExpiresAt           time.Time
}

type RefreshToken struct {
	Token     string
	UserID    string
	ClientID  string
	Scope     string
	AuthTime  time.Time
	ExpiresAt time.Time
}

type ChallengeRecord struct {
	UserID    string
	Challenge string
	ExpiresAt time.Time
}

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
		clientMap[c.ClientID] = c
	}
	appTokenMap := map[string]AppTokenConfig{}
	for i, tokenCfg := range cfg.AppTokens {
		if tokenCfg.ID == "" {
			return nil, fmt.Errorf("app_tokens[%d].id is required", i)
		}
		if !validAppTokenID(tokenCfg.ID) {
			return nil, fmt.Errorf("app token %q: id may only contain letters, digits, dot, underscore, and hyphen", tokenCfg.ID)
		}
		groupMappings, err := normalizeClientGroupMappings(tokenCfg.GroupMappings)
		if err != nil {
			return nil, fmt.Errorf("app token %q: %w", tokenCfg.ID, err)
		}
		tokenCfg.GroupMappings = groupMappings
		cfg.AppTokens[i] = tokenCfg
		if _, exists := appTokenMap[tokenCfg.ID]; exists {
			return nil, fmt.Errorf("duplicate app token id %q", tokenCfg.ID)
		}
		appTokenMap[tokenCfg.ID] = tokenCfg
	}

	runtimeState := store.RuntimeState()
	b := &Broker{
		cfg:          cfg,
		store:        store,
		authn:        &LDAPAuthenticator{cfg: cfg.LDAP},
		activeKey:    activeKey,
		verifyKeys:   verifyKeys,
		publicJWKs:   publicJWKs,
		clients:      clientMap,
		appTokens:    appTokenMap,
		sessions:     runtimeState.Sessions,
		authRequests: runtimeState.AuthRequests,
		authCodes:    runtimeState.AuthCodes,
		refresh:      runtimeState.RefreshTokens,
		revokedJTIs:  runtimeState.RevokedJTIs,
		webauthnReg:  map[string]ChallengeRecord{},
		webauthnLog:  map[string]ChallengeRecord{},
	}
	b.sweepExpired(time.Now())
	return b, nil
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

// sweepExpired removes expired entries from every in-memory map. Without
// this, revoked-JTI markers and abandoned WebAuthn/OAuth challenges
// accumulate indefinitely until the process restarts. Each map is swept
// independently; collapsing into a generic helper would obscure the
// per-map field accesses.
func (b *Broker) sweepExpired(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	changed := sweepExpiredMap(b.sessions, now, func(v Session) time.Time { return v.ExpiresAt })
	changed = sweepExpiredMap(b.authRequests, now, func(v AuthorizationRequest) time.Time { return v.ExpiresAt }) || changed
	changed = sweepExpiredMap(b.authCodes, now, func(v AuthCode) time.Time { return v.ExpiresAt }) || changed
	changed = sweepExpiredMap(b.refresh, now, func(v RefreshToken) time.Time { return v.ExpiresAt }) || changed
	changed = sweepExpiredMap(b.revokedJTIs, now, func(v time.Time) time.Time { return v }) || changed
	sweepExpiredMap(b.webauthnReg, now, func(v ChallengeRecord) time.Time { return v.ExpiresAt })
	sweepExpiredMap(b.webauthnLog, now, func(v ChallengeRecord) time.Time { return v.ExpiresAt })
	if changed {
		if err := b.persistRuntimeStateLocked(); err != nil {
			log.Printf("persist runtime state after sweep: %v", err)
		}
	}
}

func sweepExpiredMap[T any](m map[string]T, now time.Time, expiresAt func(T) time.Time) bool {
	changed := false
	for k, v := range m {
		if now.After(expiresAt(v)) {
			delete(m, k)
			changed = true
		}
	}
	return changed
}

// startBackgroundSweeper periodically calls sweepExpired. It is intended for
// long-running server instances; tests construct brokers without invoking it
// so they do not leak goroutines.
func (b *Broker) startBackgroundSweeper(interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for t := range ticker.C {
			b.sweepExpired(t)
		}
	}()
}

func (b *Broker) runtimeStateLocked() StoredRuntimeState {
	return StoredRuntimeState{
		Sessions:      cloneSessionMap(b.sessions),
		AuthRequests:  cloneAuthorizationRequestMap(b.authRequests),
		AuthCodes:     cloneAuthCodeMap(b.authCodes),
		RefreshTokens: cloneRefreshTokenMap(b.refresh),
		RevokedJTIs:   cloneRevokedJTIMap(b.revokedJTIs),
	}
}

func (b *Broker) persistRuntimeStateLocked() error {
	if b.store == nil {
		return nil
	}
	return b.store.ReplaceRuntimeState(b.runtimeStateLocked())
}

func validAppTokenID(id string) bool {
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return id != ""
}

func (b *Broker) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", b.handleHome)
	mux.HandleFunc("GET /healthz", b.handleHealth)
	mux.HandleFunc("GET /.well-known/openid-configuration", b.handleDiscovery)
	mux.HandleFunc("GET /oauth2/jwks", b.handleJWKS)
	mux.HandleFunc("GET /oauth2/authorize", b.handleAuthorize)
	mux.HandleFunc("GET /login", b.handleLoginGet)
	mux.HandleFunc("POST /login", b.handleLoginPost)
	mux.HandleFunc("GET /logout", b.handleLocalLogoutGet)
	mux.HandleFunc("POST /logout", b.handleLocalLogoutPost)
	mux.HandleFunc("POST /app-tokens/{id}", b.handleAppToken)
	mux.HandleFunc("POST /oauth2/token", b.handleToken)
	mux.HandleFunc("GET /oauth2/userinfo", b.handleUserInfo)
	mux.HandleFunc("POST /oauth2/revoke", b.handleRevoke)
	mux.HandleFunc("GET /oauth2/logout", b.handleLogout)
	mux.HandleFunc("POST /oauth2/logout", b.handleLogout)
	mux.HandleFunc("POST /mfa/totp/enroll", b.handleTOTPEnroll)
	mux.HandleFunc("POST /webauthn/register/begin", b.handleWebAuthnRegisterBegin)
	mux.HandleFunc("POST /webauthn/register/finish", b.handleWebAuthnRegisterFinish)
	mux.HandleFunc("POST /webauthn/login/begin", b.handleWebAuthnLoginBegin)
	mux.HandleFunc("POST /webauthn/login/finish", b.handleWebAuthnLoginFinish)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Default to no-store; cacheable endpoints (JWKS, discovery) override
		// this header explicitly before writing their response.
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (b *Broker) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (b *Broker) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	issuer := b.cfg.Issuer
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"userinfo_endpoint":                     issuer + "/oauth2/userinfo",
		"jwks_uri":                              issuer + "/oauth2/jwks",
		"revocation_endpoint":                   issuer + "/oauth2/revoke",
		"end_session_endpoint":                  issuer + "/oauth2/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups", "offline_access"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "preferred_username", "email", "name", "groups"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (b *Broker) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
	writeJSON(w, http.StatusOK, map[string]any{"keys": b.publicJWKs})
}

func (b *Broker) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b.maybeExtendSession(w, r)
	data := b.homeData(r, nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = brokerHomeTemplate.Execute(w, data)
}

type appTokenView struct {
	ID              string
	DisplayName     string
	Audience        string
	ClientID        string
	Scope           string
	TokenTTLSeconds int
	JWKSURL         string
}

type issuedAppTokenView struct {
	appTokenView

	Token string
}

func (b *Broker) homeData(r *http.Request, issued *issuedAppTokenView) map[string]any {
	data := map[string]any{
		"Issuer":    b.cfg.Issuer,
		"AppTokens": b.appTokenViews(),
	}
	if sess, ok := b.validSession(r); ok {
		data["Authenticated"] = true
		data["UserID"] = sess.UserID
		data["ExpiresAt"] = sess.ExpiresAt.Format(time.RFC1123)
	}
	if issued != nil {
		data["IssuedAppToken"] = issued
	}
	return data
}

func (b *Broker) appTokenViews() []appTokenView {
	views := make([]appTokenView, 0, len(b.cfg.AppTokens))
	for _, cfg := range b.cfg.AppTokens {
		views = append(views, b.appTokenView(cfg))
	}
	return views
}

func (b *Broker) appTokenView(cfg AppTokenConfig) appTokenView {
	return appTokenView{
		ID:              cfg.ID,
		DisplayName:     cfg.DisplayName,
		Audience:        cfg.Audience,
		ClientID:        cfg.ClientID,
		Scope:           cfg.Scope,
		TokenTTLSeconds: cfg.TokenTTLMinutes * 60,
		JWKSURL:         b.cfg.Issuer + "/oauth2/jwks",
	}
}

func (b *Broker) handleAppToken(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	b.maybeExtendSession(w, r)
	tokenID := r.PathValue("id")
	tokenCfg, ok := b.appTokens[tokenID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	token, err := b.issueAppToken(sess, tokenCfg)
	if err != nil {
		http.Error(w, "could not issue app token", http.StatusInternalServerError)
		return
	}
	issued := &issuedAppTokenView{
		appTokenView: b.appTokenView(tokenCfg),
		Token:        token,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = brokerHomeTemplate.Execute(w, b.homeData(r, issued))
}

func (b *Broker) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	}
	client, ok := b.clients[q.Get("client_id")]
	if !ok {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !clientAllowsRedirect(client, redirectURI) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	method := q.Get("code_challenge_method")
	challenge := q.Get("code_challenge")
	if method == "" && challenge != "" {
		method = "S256"
	}
	if msg := authorizePKCEError(client, challenge, method); msg != "" {
		redirectOAuthError(w, r, redirectURI, q.Get("state"), "invalid_request", msg)
		return
	}

	authReq := AuthorizationRequest{
		ID:                  randomB64(32),
		ClientID:            client.ClientID,
		RedirectURI:         redirectURI,
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(time.Duration(b.cfg.AuthCodeTTLSeconds) * time.Second),
	}

	if sess, ok := b.validSession(r); ok {
		b.maybeExtendSession(w, r)
		if err := b.issueCodeRedirect(w, r, authReq, sess); err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
		}
		return
	}

	if err := b.putAuthRequest(authReq); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login?request_id="+url.QueryEscape(authReq.ID), http.StatusFound)
}

func authorizePKCEError(client Client, challenge, method string) string {
	if (client.RequirePKCE || client.Public) && (challenge == "" || method != "S256") {
		return "PKCE S256 is required"
	}
	if challenge != "" && method != "S256" {
		return "only PKCE S256 is accepted"
	}
	return ""
}

func (b *Broker) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	rid := r.URL.Query().Get("request_id")
	clientID := "authbroker"
	if rid != "" {
		b.mu.Lock()
		ar, ok := b.authRequests[rid]
		b.mu.Unlock()
		if !ok || time.Now().After(ar.ExpiresAt) {
			http.Error(w, "login request expired", http.StatusBadRequest)
			return
		}
		clientID = ar.ClientID
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, map[string]any{
		"RequestID": rid,
		"ClientID":  clientID,
		"TOTPHint":  b.cfg.MFA.TOTPRequired,
	})
}

//nolint:gocognit,cyclop,nestif,funlen // Login keeps OAuth request restoration and TOTP handling in one flow.
func (b *Broker) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	rid := r.Form.Get("request_id")
	oauthLogin := rid != ""
	var ar AuthorizationRequest
	if oauthLogin {
		var ok bool
		b.mu.Lock()
		ar, ok = b.authRequests[rid]
		if ok {
			delete(b.authRequests, rid)
		}
		var persistErr error
		if ok {
			persistErr = b.persistRuntimeStateLocked()
		}
		b.mu.Unlock()
		if persistErr != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		if !ok || time.Now().After(ar.ExpiresAt) {
			http.Error(w, "login request expired", http.StatusBadRequest)
			return
		}
	}

	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	profile, err := b.authn.Authenticate(r.Context(), username, password)
	if err != nil {
		if oauthLogin {
			if err := b.putAuthRequest(ar); err != nil {
				log.Printf("restore auth request after login failure: %v", err)
			}
		}
		http.Error(w, "invalid username or password", http.StatusUnauthorized)
		return
	}
	user, err := b.store.UpsertProfile(profile)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}

	if b.needsTOTP(user) {
		otp := strings.TrimSpace(r.Form.Get("otp"))
		if user.TOTPSecretBase32 == "" {
			if oauthLogin {
				if err := b.putAuthRequest(ar); err != nil {
					log.Printf("restore auth request after missing totp enrollment: %v", err)
				}
			}
			http.Error(w, "TOTP is required but the user is not enrolled", http.StatusUnauthorized)
			return
		}
		if !verifyTOTP(user.TOTPSecretBase32, otp, time.Now(), 1) {
			if oauthLogin {
				if err := b.putAuthRequest(ar); err != nil {
					log.Printf("restore auth request after totp failure: %v", err)
				}
			}
			http.Error(w, "invalid TOTP code", http.StatusUnauthorized)
			return
		}
	}

	sess, err := b.createSession(w, user.Username)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if oauthLogin {
		if err := b.issueCodeRedirect(w, r, ar, sess); err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
		}
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (b *Broker) handleLocalLogoutGet(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = brokerLogoutTemplate.Execute(w, map[string]any{
		"UserID": sess.UserID,
	})
}

func (b *Broker) handleLocalLogoutPost(w http.ResponseWriter, r *http.Request) {
	if err := b.clearSession(w, r); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (b *Broker) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
	}

	idTokenHint := strings.TrimSpace(logoutParam(r, "id_token_hint"))
	clientID := strings.TrimSpace(logoutParam(r, "client_id"))
	clientID, ok := b.resolveLogoutClientID(w, clientID, idTokenHint)
	if !ok {
		return
	}

	postLogoutRedirectURI := strings.TrimSpace(logoutParam(r, "post_logout_redirect_uri"))
	state := logoutParam(r, "state")
	if postLogoutRedirectURI != "" {
		b.handlePostLogoutRedirect(w, r, clientID, postLogoutRedirectURI, state)
		return
	}

	if err := b.clearSession(w, r); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("logged out\n"))
}

func (b *Broker) handlePostLogoutRedirect(w http.ResponseWriter, r *http.Request, clientID, redirectURI, state string) {
	client, ok := b.clients[clientID]
	if !ok || !clientAllowsPostLogoutRedirect(client, redirectURI) {
		http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	if err := b.clearSession(w, r); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	if state != "" {
		q := u.Query()
		q.Set("state", state)
		u.RawQuery = q.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // redirect URI was validated against registered post_logout_redirect_uris.
}

func (b *Broker) resolveLogoutClientID(w http.ResponseWriter, clientID, idTokenHint string) (string, bool) {
	if idTokenHint == "" {
		return clientID, true
	}
	hintClientID, err := b.logoutClientIDFromIDTokenHint(idTokenHint)
	if err != nil && clientID == "" {
		http.Error(w, "invalid id_token_hint", http.StatusBadRequest)
		return "", false
	}
	if err != nil || hintClientID == "" {
		return clientID, true
	}
	if clientID != "" && clientID != hintClientID {
		http.Error(w, "client_id does not match id_token_hint", http.StatusBadRequest)
		return "", false
	}
	return hintClientID, true
}

func logoutParam(r *http.Request, name string) string {
	if r.Method == http.MethodPost {
		return r.Form.Get(name)
	}
	return r.URL.Query().Get(name)
}

func (b *Broker) logoutClientIDFromIDTokenHint(idTokenHint string) (string, error) {
	claims, err := b.verifyJWT(idTokenHint)
	if err != nil {
		return "", err
	}
	return clientIDFromTokenClaims(claims), nil
}

func clientIDFromTokenClaims(claims map[string]any) string {
	if clientID, _ := claims["client_id"].(string); clientID != "" {
		return clientID
	}
	if aud, _ := claims["aud"].(string); aud != "" {
		return aud
	}
	if audList, ok := claims["aud"].([]any); ok && len(audList) == 1 {
		clientID, _ := audList[0].(string)
		return clientID
	}
	return ""
}

func (b *Broker) putAuthRequest(ar AuthorizationRequest) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.authRequests[ar.ID] = ar
	return b.persistRuntimeStateLocked()
}

func (b *Broker) needsTOTP(user *StoredUser) bool {
	return b.cfg.MFA.TOTPRequired || (user != nil && user.TOTPSecretBase32 != "")
}

func (b *Broker) validSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	b.mu.Lock()
	s, ok := b.sessions[c.Value]
	if !ok || time.Now().After(s.ExpiresAt) {
		if ok {
			delete(b.sessions, c.Value)
			if err := b.persistRuntimeStateLocked(); err != nil {
				log.Printf("persist expired session removal: %v", err)
			}
		}
		b.mu.Unlock()
		return Session{}, false
	}
	b.mu.Unlock()
	return s, true
}

// maybeExtendSession refreshes the broker session's expiry on activity once
// more than half of the TTL has been consumed. The cookie is re-set so the
// browser does not drop it at the original expiration.
func (b *Broker) maybeExtendSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return
	}
	ttl := time.Duration(b.cfg.SessionTTLHrs) * time.Hour
	if ttl <= 0 {
		return
	}
	now := time.Now()
	b.mu.Lock()
	s, ok := b.sessions[c.Value]
	if !ok || now.After(s.ExpiresAt) {
		if ok {
			delete(b.sessions, c.Value)
			if err := b.persistRuntimeStateLocked(); err != nil {
				log.Printf("persist expired session removal: %v", err)
			}
		}
		b.mu.Unlock()
		return
	}
	if time.Until(s.ExpiresAt) > ttl/2 {
		b.mu.Unlock()
		return
	}
	s.ExpiresAt = now.Add(ttl)
	b.sessions[c.Value] = s
	newExpiry := s.ExpiresAt
	if err := b.persistRuntimeStateLocked(); err != nil {
		log.Printf("persist extended session: %v", err)
	}
	b.mu.Unlock()

	secure := strings.HasPrefix(b.cfg.Issuer, "https://")
	if b.cfg.CookieSecure != nil {
		secure = *b.cfg.CookieSecure
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is controlled by issuer/config for local HTTP demos and HTTPS deployments.
		Name:     sessionCookieName,
		Value:    c.Value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  newExpiry,
	})
}

func (b *Broker) clearSession(w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		b.mu.Lock()
		if _, ok := b.sessions[c.Value]; ok {
			delete(b.sessions, c.Value)
			if err := b.persistRuntimeStateLocked(); err != nil {
				b.mu.Unlock()
				return err
			}
		}
		b.mu.Unlock()
	}
	secure := strings.HasPrefix(b.cfg.Issuer, "https://")
	if b.cfg.CookieSecure != nil {
		secure = *b.cfg.CookieSecure
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is controlled by issuer/config for local HTTP demos and HTTPS deployments.
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	return nil
}

func (b *Broker) createSession(w http.ResponseWriter, userID string) (Session, error) {
	sid := randomB64(32)
	now := time.Now()
	sess := Session{UserID: userID, ExpiresAt: now.Add(time.Duration(b.cfg.SessionTTLHrs) * time.Hour), AuthTime: now}
	b.mu.Lock()
	b.sessions[sid] = sess
	if err := b.persistRuntimeStateLocked(); err != nil {
		delete(b.sessions, sid)
		b.mu.Unlock()
		return Session{}, err
	}
	b.mu.Unlock()
	secure := strings.HasPrefix(b.cfg.Issuer, "https://")
	if b.cfg.CookieSecure != nil {
		secure = *b.cfg.CookieSecure
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is controlled by issuer/config for local HTTP demos and HTTPS deployments.
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})
	return sess, nil
}

func (b *Broker) issueCodeRedirect(w http.ResponseWriter, r *http.Request, ar AuthorizationRequest, sess Session) error {
	code := randomB64(32)
	ac := AuthCode{
		Code:                code,
		UserID:              sess.UserID,
		ClientID:            ar.ClientID,
		RedirectURI:         ar.RedirectURI,
		Scope:               ar.Scope,
		Nonce:               ar.Nonce,
		CodeChallenge:       ar.CodeChallenge,
		CodeChallengeMethod: ar.CodeChallengeMethod,
		AuthTime:            sess.AuthTime,
		ExpiresAt:           time.Now().Add(time.Duration(b.cfg.AuthCodeTTLSeconds) * time.Second),
	}
	b.mu.Lock()
	b.authCodes[code] = ac
	if err := b.persistRuntimeStateLocked(); err != nil {
		delete(b.authCodes, code)
		b.mu.Unlock()
		return err
	}
	b.mu.Unlock()

	u, _ := url.Parse(ar.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if ar.State != "" {
		q.Set("state", ar.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return nil
}

func (b *Broker) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "bad form")
		return
	}
	client, err := b.authenticateClient(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		tokenErrorStatus(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	switch r.Form.Get("grant_type") {
	case "authorization_code":
		b.tokenAuthorizationCode(w, r, client)
	case "refresh_token":
		b.tokenRefresh(w, r, client)
	case "client_credentials":
		b.tokenClientCredentials(w, r, client)
	default:
		tokenError(w, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (b *Broker) authenticateClient(r *http.Request) (Client, error) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}
	client, exists := b.clients[id]
	if !exists || id == "" {
		return Client{}, fmt.Errorf("unknown client")
	}
	if client.Public {
		return client, nil
	}
	if !clientSecretMatches(client, secret) {
		return Client{}, fmt.Errorf("bad client credentials")
	}
	return client, nil
}

func clientSecretMatches(client Client, secret string) bool {
	if secret == "" {
		return false
	}
	expected, err := hex.DecodeString(strings.TrimSpace(client.ClientSecretSHA256))
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	actual := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(expected, actual[:]) == 1
}

func (b *Broker) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request, client Client) {
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")

	b.mu.Lock()
	ac, ok := b.authCodes[code]
	if ok {
		delete(b.authCodes, code)
	}
	var persistErr error
	if ok {
		persistErr = b.persistRuntimeStateLocked()
	}
	b.mu.Unlock()
	if persistErr != nil {
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", persistErr.Error())
		return
	}

	if !ok || time.Now().After(ac.ExpiresAt) {
		tokenError(w, "invalid_grant", "invalid or expired code")
		return
	}
	if ac.ClientID != client.ClientID || ac.RedirectURI != redirectURI {
		tokenError(w, "invalid_grant", "client or redirect_uri mismatch")
		return
	}
	if ac.CodeChallenge != "" {
		verifier := r.Form.Get("code_verifier")
		if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, verifier) {
			tokenError(w, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	resp, err := b.issueUserTokens(ac.UserID, client.ClientID, ac.Scope, ac.Nonce, ac.AuthTime, true)
	if err != nil {
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (b *Broker) tokenRefresh(w http.ResponseWriter, r *http.Request, client Client) {
	rt := r.Form.Get("refresh_token")
	requestedScope := strings.TrimSpace(r.Form.Get("scope"))
	b.mu.Lock()
	old, ok := b.refresh[rt]
	if !ok {
		b.mu.Unlock()
		tokenError(w, "invalid_grant", "invalid refresh_token")
		return
	}
	if time.Now().After(old.ExpiresAt) || old.ClientID != client.ClientID {
		delete(b.refresh, rt)
		if err := b.persistRuntimeStateLocked(); err != nil {
			b.mu.Unlock()
			tokenErrorStatus(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		b.mu.Unlock()
		tokenError(w, "invalid_grant", "invalid refresh_token")
		return
	}
	// Per RFC 6749 §6, the client may request a narrower scope on refresh,
	// but never one that exceeds the original grant. Reject scope expansion
	// without consuming the refresh token so the legitimate client can retry.
	if requestedScope != "" && !scopeSubset(requestedScope, old.Scope) {
		b.mu.Unlock()
		tokenError(w, "invalid_scope", "requested scope exceeds original grant")
		return
	}
	delete(b.refresh, rt) // refresh token rotation
	if err := b.persistRuntimeStateLocked(); err != nil {
		b.mu.Unlock()
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	b.mu.Unlock()
	scope := old.Scope
	if requestedScope != "" {
		scope = requestedScope
	}
	resp, err := b.issueUserTokens(old.UserID, client.ClientID, scope, "", old.AuthTime, true)
	if err != nil {
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func scopeSubset(requested, granted string) bool {
	grantedSet := map[string]bool{}
	for _, p := range strings.Fields(granted) {
		grantedSet[p] = true
	}
	for _, p := range strings.Fields(requested) {
		if !grantedSet[p] {
			return false
		}
	}
	return true
}

func (b *Broker) tokenClientCredentials(w http.ResponseWriter, r *http.Request, client Client) {
	if client.Public {
		tokenError(w, "unauthorized_client", "public clients cannot use client_credentials")
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss":       b.cfg.Issuer,
		"sub":       client.ClientID,
		"aud":       client.ClientID,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(time.Duration(b.cfg.AccessTokenTTLMinutes) * time.Minute).Unix(),
		"jti":       randomB64(16),
		"client_id": client.ClientID,
		"scope":     r.Form.Get("scope"),
		"token_use": "access",
	}
	access, err := b.signJWT(claims)
	if err != nil {
		tokenErrorStatus(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   b.cfg.AccessTokenTTLMinutes * 60,
		"scope":        r.Form.Get("scope"),
	})
}

//nolint:gocognit,funlen // Access and ID token claims are intentionally assembled together.
func (b *Broker) issueUserTokens(userID, clientID, scope, nonce string, authTime time.Time, includeRefresh bool) (map[string]any, error) {
	user, _ := b.store.GetUser(userID)
	now := time.Now()
	accessJTI := randomB64(16)
	accessClaims := map[string]any{
		"iss":                b.cfg.Issuer,
		"sub":                userID,
		"aud":                clientID,
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"exp":                now.Add(time.Duration(b.cfg.AccessTokenTTLMinutes) * time.Minute).Unix(),
		"jti":                accessJTI,
		"client_id":          clientID,
		"scope":              scope,
		"preferred_username": userID,
		"token_use":          "access",
	}
	if user != nil {
		accessClaims["email"] = user.Email
		accessClaims["name"] = displayName(user)
		if scopeIncludes(scope, "groups") {
			if groups := b.mappedGroupsForClient(clientID, user); len(groups) > 0 {
				accessClaims["groups"] = groups
			}
		}
	}
	access, err := b.signJWT(accessClaims)
	if err != nil {
		return nil, err
	}

	idClaims := map[string]any{
		"iss":                b.cfg.Issuer,
		"sub":                userID,
		"aud":                clientID,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Duration(b.cfg.IDTokenTTLMinutes) * time.Minute).Unix(),
		"auth_time":          authTime.Unix(),
		"preferred_username": userID,
	}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	if user != nil {
		idClaims["email"] = user.Email
		idClaims["name"] = displayName(user)
		if scopeIncludes(scope, "groups") {
			if groups := b.mappedGroupsForClient(clientID, user); len(groups) > 0 {
				idClaims["groups"] = groups
			}
		}
	}
	idToken, err := b.signJWT(idClaims)
	if err != nil {
		return nil, err
	}

	resp := map[string]any{
		"access_token": access,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   b.cfg.AccessTokenTTLMinutes * 60,
		"scope":        scope,
	}
	if includeRefresh {
		rt := randomB64(32)
		refreshToken := RefreshToken{
			Token:     rt,
			UserID:    userID,
			ClientID:  clientID,
			Scope:     scope,
			AuthTime:  authTime,
			ExpiresAt: now.Add(time.Duration(b.cfg.RefreshTokenTTLDays) * 24 * time.Hour),
		}
		b.mu.Lock()
		b.refresh[rt] = refreshToken
		if err := b.persistRuntimeStateLocked(); err != nil {
			delete(b.refresh, rt)
			b.mu.Unlock()
			return nil, err
		}
		b.mu.Unlock()
		resp["refresh_token"] = rt
	}
	return resp, nil
}

//nolint:nestif // Optional profile and group claims are grouped by source.
func (b *Broker) issueAppToken(sess Session, tokenCfg AppTokenConfig) (string, error) {
	user, _ := b.store.GetUser(sess.UserID)
	now := time.Now()
	scope := strings.TrimSpace(tokenCfg.Scope)
	claims := map[string]any{
		"iss":                b.cfg.Issuer,
		"sub":                sess.UserID,
		"aud":                tokenCfg.Audience,
		"iat":                now.Unix(),
		"nbf":                now.Unix(),
		"exp":                now.Add(time.Duration(tokenCfg.TokenTTLMinutes) * time.Minute).Unix(),
		"jti":                randomB64(16),
		"client_id":          tokenCfg.ClientID,
		"scope":              scope,
		"auth_time":          sess.AuthTime.Unix(),
		"preferred_username": sess.UserID,
		"user_id":            sess.UserID,
		"app_token_id":       tokenCfg.ID,
		"token_use":          "access",
	}
	if user != nil {
		claims["email"] = user.Email
		claims["name"] = displayName(user)
		if user.Email != "" {
			claims["user_email"] = user.Email
		}
		if scopeIncludes(scope, "groups") {
			if groups := mappedClientGroups(Client{GroupMappings: tokenCfg.GroupMappings}, user.Groups); len(groups) > 0 {
				claims["groups"] = groups
			}
		}
	}
	return b.signJWT(claims)
}

func displayName(u *StoredUser) string {
	if u == nil {
		return ""
	}
	if u.Name != "" {
		return u.Name
	}
	return u.Username
}

func (b *Broker) mappedGroupsForClient(clientID string, user *StoredUser) []string {
	if user == nil {
		return nil
	}
	client, ok := b.clients[clientID]
	if !ok {
		return nil
	}
	return mappedClientGroups(client, user.Groups)
}

func (b *Broker) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), bearerPrefix))
	if token == r.Header.Get("Authorization") || token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	claims, err := b.verifyJWT(token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if tokenUse, _ := claims["token_use"].(string); tokenUse != "access" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="userinfo requires an access token"`)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	sub, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	if clientID == "" {
		clientID, _ = claims["aud"].(string)
	}
	scope, _ := claims["scope"].(string)
	user, _ := b.store.GetUser(sub)
	resp := map[string]any{
		"sub":                sub,
		"preferred_username": sub,
	}
	if user != nil {
		resp["email"] = user.Email
		resp["name"] = displayName(user)
		if scopeIncludes(scope, "groups") {
			if groups := b.mappedGroupsForClient(clientID, user); len(groups) > 0 {
				resp["groups"] = groups
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (b *Broker) handleRevoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	client, err := b.authenticateClient(r)
	if err != nil {
		// RFC 7009 expects client authentication; still avoid token oracle details.
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tok := r.Form.Get("token")
	if err := b.revokeRefreshToken(tok, client); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if err := b.revokeJWT(tok, client); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (b *Broker) revokeRefreshToken(tok string, client Client) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if rt, ok := b.refresh[tok]; ok && rt.ClientID == client.ClientID {
		delete(b.refresh, tok)
		return b.persistRuntimeStateLocked()
	}
	return nil
}

func (b *Broker) revokeJWT(tok string, client Client) error {
	claims, err := b.verifyJWT(tok)
	if err != nil {
		return nil
	}
	aud, _ := claims["aud"].(string)
	jti, _ := claims["jti"].(string)
	expUnix, ok := numberClaim(claims["exp"])
	if aud != client.ClientID || jti == "" || !ok {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revokedJTIs[jti] = time.Unix(expUnix, 0)
	return b.persistRuntimeStateLocked()
}

func (b *Broker) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	b.maybeExtendSession(w, r)
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		http.Error(w, "random error", http.StatusInternalServerError)
		return
	}
	secret := strings.TrimRight(base32.StdEncoding.EncodeToString(secretBytes), "=")
	if err := b.store.SetTOTP(sess.UserID, secret); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	issuerName := strings.TrimSpace(b.cfg.DisplayName)
	if issuerName == "" {
		issuerName = "Authbroker"
	}
	label := url.QueryEscape(issuerName + ":" + sess.UserID)
	issuer := url.QueryEscape(issuerName)
	otpauth := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", label, secret, issuer)
	writeJSON(w, http.StatusOK, map[string]string{"secret_base32": secret, "otpauth_uri": otpauth})
}

func (b *Broker) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	b.maybeExtendSession(w, r)
	user, _ := b.store.GetUser(sess.UserID)
	if user == nil {
		user = &StoredUser{Username: sess.UserID}
	}
	challenge := randomB64(32)
	b.mu.Lock()
	// Key by challenge (not user ID) so parallel registration attempts from
	// the same account don't overwrite one another's challenge state.
	b.webauthnReg[challenge] = ChallengeRecord{UserID: sess.UserID, Challenge: challenge, ExpiresAt: time.Now().Add(5 * time.Minute)}
	b.mu.Unlock()

	creds := make([]map[string]string, 0, len(user.WebAuthnCredentials))
	for _, c := range user.WebAuthnCredentials {
		creds = append(creds, map[string]string{"type": "public-key", "id": c.IDBase64URL})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"publicKey": map[string]any{
			"challenge": challenge,
			"rp": map[string]string{
				"name": b.cfg.WebAuthn.RPDisplayName,
				"id":   b.cfg.WebAuthn.RPID,
			},
			"user": map[string]string{
				"id":          base64RawURL([]byte(sess.UserID)),
				"name":        sess.UserID,
				"displayName": displayName(user),
			},
			"pubKeyCredParams":   []map[string]any{{"type": "public-key", "alg": -7}}, // ES256
			"timeout":            60000,
			"attestation":        "none",
			"excludeCredentials": creds,
			"authenticatorSelection": map[string]any{
				"userVerification": "preferred",
			},
		},
	})
}

func (b *Broker) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess, ok := b.validSession(r)
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	b.maybeExtendSession(w, r)
	var req webauthnAttestationResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	clientDataBytes, err := decodeB64URL(req.Response.ClientDataJSON)
	if err != nil {
		http.Error(w, "bad clientDataJSON", http.StatusBadRequest)
		return
	}
	var cd webauthnClientData
	if err := json.Unmarshal(clientDataBytes, &cd); err != nil {
		http.Error(w, "bad client data", http.StatusBadRequest)
		return
	}
	challenge := normalizeChallenge(cd.Challenge)

	b.mu.Lock()
	ch, ok := b.webauthnReg[challenge]
	if ok {
		delete(b.webauthnReg, challenge)
	}
	b.mu.Unlock()
	if !ok || time.Now().After(ch.ExpiresAt) || ch.UserID != sess.UserID {
		http.Error(w, "registration challenge expired", http.StatusBadRequest)
		return
	}

	cred, err := b.verifyWebAuthnAttestation(req, ch.Challenge)
	if err != nil {
		http.Error(w, "invalid attestation: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := b.store.AddWebAuthnCredential(sess.UserID, cred); err != nil {
		http.Error(w, "store error: "+err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

func (b *Broker) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}
	// Always return a valid challenge with an allowCredentials list, even
	// when the user does not exist or has no passkeys enrolled. This keeps
	// /webauthn/login/begin from leaking whether an account is registered.
	// The browser handles an empty allowCredentials by surfacing the
	// standard "no credential" dialog; /webauthn/login/finish rejects the
	// flow when the challenge is bound to no user.
	var creds []WebAuthnCredential
	userID := ""
	if user, ok := b.store.GetUser(req.Username); ok {
		creds = user.WebAuthnCredentials
		userID = user.Username
	}
	challenge := randomB64(32)
	b.mu.Lock()
	b.webauthnLog[challenge] = ChallengeRecord{UserID: userID, Challenge: challenge, ExpiresAt: time.Now().Add(5 * time.Minute)}
	b.mu.Unlock()
	allow := make([]map[string]string, 0, len(creds))
	for _, c := range creds {
		allow = append(allow, map[string]string{"type": "public-key", "id": c.IDBase64URL})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"publicKey": map[string]any{
			"challenge":        challenge,
			"timeout":          60000,
			"rpId":             b.cfg.WebAuthn.RPID,
			"allowCredentials": allow,
			"userVerification": "preferred",
		},
	})
}

func (b *Broker) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req webauthnAssertionResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	clientDataBytes, err := decodeB64URL(req.Response.ClientDataJSON)
	if err != nil {
		http.Error(w, "bad clientDataJSON", http.StatusBadRequest)
		return
	}
	var cd webauthnClientData
	if err := json.Unmarshal(clientDataBytes, &cd); err != nil {
		http.Error(w, "bad client data", http.StatusBadRequest)
		return
	}
	challenge := normalizeChallenge(cd.Challenge)

	b.mu.Lock()
	ch, ok := b.webauthnLog[challenge]
	if ok {
		delete(b.webauthnLog, challenge)
	}
	b.mu.Unlock()
	if !ok || time.Now().After(ch.ExpiresAt) || ch.UserID == "" {
		http.Error(w, "login challenge expired", http.StatusBadRequest)
		return
	}
	if err := b.verifyWebAuthnAssertion(req, ch.UserID, ch.Challenge, clientDataBytes, cd); err != nil {
		http.Error(w, "invalid assertion: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := b.createSession(w, ch.UserID); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "authenticated"})
}

//nolint:gocognit,cyclop // WebAuthn validation is kept linear to match the protocol checks.
func (b *Broker) verifyWebAuthnAttestation(req webauthnAttestationResponse, expectedChallenge string) (WebAuthnCredential, error) {
	rawID, err := decodeB64URL(req.RawID)
	if err != nil || len(rawID) == 0 {
		return WebAuthnCredential{}, fmt.Errorf("bad rawId")
	}
	clientDataBytes, err := decodeB64URL(req.Response.ClientDataJSON)
	if err != nil {
		return WebAuthnCredential{}, fmt.Errorf("bad clientDataJSON")
	}
	var cd webauthnClientData
	if err := json.Unmarshal(clientDataBytes, &cd); err != nil {
		return WebAuthnCredential{}, fmt.Errorf("bad client data")
	}
	if cd.Type != "webauthn.create" {
		return WebAuthnCredential{}, fmt.Errorf("wrong clientData type")
	}
	if normalizeChallenge(cd.Challenge) != expectedChallenge {
		return WebAuthnCredential{}, fmt.Errorf("challenge mismatch")
	}
	if !b.allowedOrigin(cd.Origin) {
		return WebAuthnCredential{}, fmt.Errorf("origin not allowed")
	}

	attBytes, err := decodeB64URL(req.Response.AttestationObject)
	if err != nil {
		return WebAuthnCredential{}, fmt.Errorf("bad attestationObject")
	}
	val, rest, err := parseCBOR(attBytes)
	if err != nil || len(rest) != 0 {
		return WebAuthnCredential{}, fmt.Errorf("bad cbor attestation")
	}
	m := val.mapValue
	fmtVal, ok := cborGetString(m, "fmt")
	if !ok || fmtVal.strValue != "none" {
		return WebAuthnCredential{}, fmt.Errorf("only attestation fmt 'none' is accepted")
	}
	authDataVal, ok := cborGetString(m, "authData")
	if !ok || authDataVal.kind != cborBytes {
		return WebAuthnCredential{}, fmt.Errorf("missing authData")
	}
	parsed, err := parseAttestedAuthData(authDataVal.bytesValue, b.cfg.WebAuthn.RPID)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	if !bytes.Equal(parsed.CredentialID, rawID) {
		return WebAuthnCredential{}, fmt.Errorf("credential id mismatch")
	}
	pub, err := parseCOSEES256PublicKey(parsed.COSEPublicKey)
	if err != nil {
		return WebAuthnCredential{}, err
	}
	return WebAuthnCredential{
		IDBase64URL: base64RawURL(rawID),
		Alg:         "ES256",
		XBase64URL:  base64RawURL(pub.X.Bytes()),
		YBase64URL:  base64RawURL(pub.Y.Bytes()),
		SignCount:   parsed.SignCount,
		CreatedAt:   time.Now().Unix(),
	}, nil
}

//nolint:gocognit,cyclop // WebAuthn assertion checks are intentionally explicit and ordered.
func (b *Broker) verifyWebAuthnAssertion(req webauthnAssertionResponse, username, expectedChallenge string, clientDataBytes []byte, cd webauthnClientData) error {
	if cd.Type != "webauthn.get" {
		return fmt.Errorf("wrong clientData type")
	}
	if normalizeChallenge(cd.Challenge) != expectedChallenge {
		return fmt.Errorf("challenge mismatch")
	}
	if !b.allowedOrigin(cd.Origin) {
		return fmt.Errorf("origin not allowed")
	}
	rawID, err := decodeB64URL(req.RawID)
	if err != nil || len(rawID) == 0 {
		return fmt.Errorf("bad rawId")
	}
	credID := base64RawURL(rawID)
	user, ok := b.store.GetUser(username)
	if !ok {
		return fmt.Errorf("user not found")
	}
	var cred *WebAuthnCredential
	for i := range user.WebAuthnCredentials {
		if user.WebAuthnCredentials[i].IDBase64URL == credID {
			cred = &user.WebAuthnCredentials[i]
			break
		}
	}
	if cred == nil {
		return fmt.Errorf("credential not registered")
	}
	authData, err := decodeB64URL(req.Response.AuthenticatorData)
	if err != nil {
		return fmt.Errorf("bad authenticatorData")
	}
	signCount, err := verifyAssertionAuthData(authData, b.cfg.WebAuthn.RPID)
	if err != nil {
		return err
	}
	if cred.SignCount != 0 && signCount != 0 && signCount <= cred.SignCount {
		return fmt.Errorf("signature counter did not increase")
	}
	signature, err := decodeB64URL(req.Response.Signature)
	if err != nil {
		return fmt.Errorf("bad signature")
	}
	pub, err := publicKeyFromStored(*cred)
	if err != nil {
		return err
	}
	clientHash := sha256.Sum256(clientDataBytes)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return fmt.Errorf("signature verification failed")
	}
	return b.store.UpdateWebAuthnSignCount(username, credID, signCount)
}

func (b *Broker) allowedOrigin(origin string) bool {
	for _, allowed := range b.cfg.WebAuthn.Origins {
		if strings.TrimRight(origin, "/") == strings.TrimRight(allowed, "/") {
			return true
		}
	}
	return false
}

type webauthnClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

type webauthnAttestationResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	} `json:"response"`
}

type webauthnAssertionResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle,omitempty"`
	} `json:"response"`
}

type parsedAttestationData struct {
	SignCount     uint32
	CredentialID  []byte
	COSEPublicKey []byte
}

func parseAttestedAuthData(data []byte, rpID string) (parsedAttestationData, error) {
	if len(data) < 37 {
		return parsedAttestationData{}, fmt.Errorf("authData too short")
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(data[:32], rpHash[:]) {
		return parsedAttestationData{}, fmt.Errorf("rpId hash mismatch")
	}
	flags := data[32]
	if flags&0x01 == 0 {
		return parsedAttestationData{}, fmt.Errorf("user presence flag missing")
	}
	if flags&0x40 == 0 {
		return parsedAttestationData{}, fmt.Errorf("attested credential data flag missing")
	}
	signCount := binary.BigEndian.Uint32(data[33:37])
	off := 37 + 16 // skip AAGUID
	if len(data) < off+2 {
		return parsedAttestationData{}, fmt.Errorf("missing credential id length")
	}
	credLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if len(data) < off+credLen {
		return parsedAttestationData{}, fmt.Errorf("credential id truncated")
	}
	credID := append([]byte{}, data[off:off+credLen]...)
	off += credLen
	if len(data) <= off {
		return parsedAttestationData{}, fmt.Errorf("missing credential public key")
	}
	return parsedAttestationData{SignCount: signCount, CredentialID: credID, COSEPublicKey: append([]byte{}, data[off:]...)}, nil
}

func verifyAssertionAuthData(data []byte, rpID string) (uint32, error) {
	if len(data) < 37 {
		return 0, fmt.Errorf("authenticatorData too short")
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(data[:32], rpHash[:]) {
		return 0, fmt.Errorf("rpId hash mismatch")
	}
	flags := data[32]
	if flags&0x01 == 0 {
		return 0, fmt.Errorf("user presence flag missing")
	}
	return binary.BigEndian.Uint32(data[33:37]), nil
}

func parseCOSEES256PublicKey(data []byte) (*ecdsa.PublicKey, error) {
	val, rest, err := parseCBOR(data)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("bad COSE key")
	}
	if val.kind != cborMap {
		return nil, fmt.Errorf("COSE key is not a map")
	}
	m := val.mapValue
	kty, ok := cborGetInt(m, 1)
	if !ok || kty.intValue != 2 {
		return nil, fmt.Errorf("COSE kty is not EC2")
	}
	alg, ok := cborGetInt(m, 3)
	if !ok || alg.intValue != -7 {
		return nil, fmt.Errorf("COSE alg is not ES256")
	}
	crv, ok := cborGetInt(m, -1)
	if !ok || crv.intValue != 1 {
		return nil, fmt.Errorf("COSE curve is not P-256")
	}
	xVal, ok := cborGetInt(m, -2)
	if !ok || xVal.kind != cborBytes {
		return nil, fmt.Errorf("missing x coordinate")
	}
	yVal, ok := cborGetInt(m, -3)
	if !ok || yVal.kind != cborBytes {
		return nil, fmt.Errorf("missing y coordinate")
	}
	x := new(big.Int).SetBytes(xVal.bytesValue)
	y := new(big.Int).SetBytes(yVal.bytesValue)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func publicKeyFromStored(c WebAuthnCredential) (*ecdsa.PublicKey, error) {
	if c.Alg != "ES256" {
		return nil, fmt.Errorf("unsupported credential alg")
	}
	xBytes, err := decodeB64URL(c.XBase64URL)
	if err != nil {
		return nil, fmt.Errorf("bad x coordinate")
	}
	yBytes, err := decodeB64URL(c.YBase64URL)
	if err != nil {
		return nil, fmt.Errorf("bad y coordinate")
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("stored public key is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// Minimal CBOR decoder for WebAuthn attestationObject and COSE_Key. It supports
// definite-length integers, byte strings, text strings, arrays and maps.
type cborKind int

const (
	cborInvalid cborKind = iota
	cborInt
	cborBytes
	cborString
	cborArray
	cborMap
)

type cborValue struct {
	kind       cborKind
	intValue   int64
	bytesValue []byte
	strValue   string
	arrayValue []cborValue
	mapValue   map[any]cborValue
}

//nolint:gocognit,cyclop,funlen // This minimal CBOR decoder is deliberately local and explicit for WebAuthn.
func parseCBOR(data []byte) (cborValue, []byte, error) {
	if len(data) == 0 {
		return cborValue{}, nil, io.ErrUnexpectedEOF
	}
	b := data[0]
	major := b >> 5
	ai := b & 0x1f
	n, rest, err := cborReadLen(ai, data[1:])
	if err != nil {
		return cborValue{}, nil, err
	}
	switch major {
	case 0:
		if n > uint64(^uint64(0)>>1) {
			return cborValue{}, nil, fmt.Errorf("integer too large")
		}
		return cborValue{kind: cborInt, intValue: int64(n)}, rest, nil
	case 1:
		if n > uint64(^uint64(0)>>1) {
			return cborValue{}, nil, fmt.Errorf("integer too large")
		}
		return cborValue{kind: cborInt, intValue: -1 - int64(n)}, rest, nil
	case 2:
		if uint64(len(rest)) < n {
			return cborValue{}, nil, io.ErrUnexpectedEOF
		}
		return cborValue{kind: cborBytes, bytesValue: append([]byte{}, rest[:n]...)}, rest[n:], nil
	case 3:
		if uint64(len(rest)) < n {
			return cborValue{}, nil, io.ErrUnexpectedEOF
		}
		return cborValue{kind: cborString, strValue: string(rest[:n])}, rest[n:], nil
	case 4:
		arr := make([]cborValue, 0, n)
		cur := rest
		for i := uint64(0); i < n; i++ {
			v, r, err := parseCBOR(cur)
			if err != nil {
				return cborValue{}, nil, err
			}
			arr = append(arr, v)
			cur = r
		}
		return cborValue{kind: cborArray, arrayValue: arr}, cur, nil
	case 5:
		m := make(map[any]cborValue, n)
		cur := rest
		for i := uint64(0); i < n; i++ {
			k, r, err := parseCBOR(cur)
			if err != nil {
				return cborValue{}, nil, err
			}
			cur = r
			v, r, err := parseCBOR(cur)
			if err != nil {
				return cborValue{}, nil, err
			}
			cur = r
			switch k.kind {
			case cborInt:
				m[k.intValue] = v
			case cborString:
				m[k.strValue] = v
			case cborInvalid, cborBytes, cborArray, cborMap:
				return cborValue{}, nil, fmt.Errorf("unsupported cbor map key")
			default:
				return cborValue{}, nil, fmt.Errorf("unsupported cbor map key")
			}
		}
		return cborValue{kind: cborMap, mapValue: m}, cur, nil
	default:
		return cborValue{}, nil, fmt.Errorf("unsupported cbor major type %d", major)
	}
}

func cborReadLen(ai byte, data []byte) (uint64, []byte, error) {
	switch {
	case ai < 24:
		return uint64(ai), data, nil
	case ai == 24:
		if len(data) < 1 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return uint64(data[0]), data[1:], nil
	case ai == 25:
		if len(data) < 2 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return uint64(binary.BigEndian.Uint16(data[:2])), data[2:], nil
	case ai == 26:
		if len(data) < 4 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return uint64(binary.BigEndian.Uint32(data[:4])), data[4:], nil
	case ai == 27:
		if len(data) < 8 {
			return 0, nil, io.ErrUnexpectedEOF
		}
		return binary.BigEndian.Uint64(data[:8]), data[8:], nil
	default:
		return 0, nil, fmt.Errorf("unsupported indefinite or reserved cbor length")
	}
}

func cborGetString(m map[any]cborValue, key string) (cborValue, bool) {
	v, ok := m[key]
	return v, ok
}

func cborGetInt(m map[any]cborValue, key int64) (cborValue, bool) {
	v, ok := m[key]
	return v, ok
}

func makePublicJWK(keyID string, pub *rsa.PublicKey) map[string]any {
	n := base64RawURL(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": keyID,
		"alg": "RS256",
		"n":   n,
		"e":   base64RawURL(eBytes),
	}
}

func (b *Broker) signJWT(claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": b.activeKey.keyID}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signingInput := base64RawURL(hb) + "." + base64RawURL(cb)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, b.activeKey.privateKey, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64RawURL(sig), nil
}

//nolint:cyclop // JWT parsing and claim checks stay together for readability.
func (b *Broker) verifyJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed jwt")
	}
	headerBytes, err := decodeB64URL(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	kid, _ := header["kid"].(string)
	verifyKey, ok := b.verifyKeys[kid]
	if header["alg"] != "RS256" || kid == "" || !ok {
		return nil, fmt.Errorf("bad header")
	}
	sig, err := decodeB64URL(parts[2])
	if err != nil {
		return nil, err
	}
	signingInput := parts[0] + "." + parts[1]
	h := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(verifyKey, crypto.SHA256, h[:], sig); err != nil {
		return nil, err
	}
	claimsBytes, err := decodeB64URL(parts[1])
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(claimsBytes))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, err
	}
	if iss, _ := claims["iss"].(string); iss != b.cfg.Issuer {
		return nil, fmt.Errorf("bad issuer")
	}
	if exp, ok := numberClaim(claims["exp"]); ok && time.Now().After(time.Unix(exp, 0)) {
		return nil, fmt.Errorf("token expired")
	}
	if nbf, ok := numberClaim(claims["nbf"]); ok && time.Now().Before(time.Unix(nbf, 0).Add(-30*time.Second)) {
		return nil, fmt.Errorf("token not active")
	}
	if err := b.verifyTokenNotRevoked(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (b *Broker) verifyTokenNotRevoked(claims map[string]any) error {
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil
	}
	b.mu.Lock()
	exp, revoked := b.revokedJTIs[jti]
	if revoked && time.Now().After(exp) {
		delete(b.revokedJTIs, jti)
		if err := b.persistRuntimeStateLocked(); err != nil {
			log.Printf("persist expired revocation removal: %v", err)
		}
		revoked = false
	}
	b.mu.Unlock()
	if revoked {
		return fmt.Errorf("token revoked")
	}
	return nil
}

func numberClaim(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	default:
		return 0, false
	}
}

func parseRSAPrivateKeyPEM(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no pem block found")
	}
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return rsaKey, nil
}

func marshalRSAPrivateKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func verifyPKCE(expectedChallenge, method, verifier string) bool {
	if method != "S256" || verifier == "" || expectedChallenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	actual := base64RawURL(sum[:])
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expectedChallenge)) == 1
}

func clientAllowsRedirect(c Client, redirectURI string) bool {
	for _, allowed := range c.RedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func clientAllowsPostLogoutRedirect(c Client, redirectURI string) bool {
	for _, allowed := range c.PostLogoutRedirectURIs {
		if redirectURI == allowed {
			return true
		}
	}
	return false
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, code, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound) //nolint:gosec // redirect URI was validated against the registered client redirect_uris.
}

func tokenError(w http.ResponseWriter, code, desc string) {
	tokenErrorStatus(w, http.StatusBadRequest, code, desc)
}

func tokenErrorStatus(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var brokerHomeTemplate = template.Must(template.New("broker-home").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Authbroker</title></head>
<body style="font-family: sans-serif; max-width: 42rem; margin: 3rem auto; line-height: 1.45;">
  <h1>Authbroker</h1>
  <p style="color:#555">Issuer: <code>{{.Issuer}}</code></p>
  {{if .Authenticated}}
    <p>Signed in as <strong>{{.UserID}}</strong>.</p>
    <p style="color:#555">Session expires: {{.ExpiresAt}}</p>
    {{if .AppTokens}}
      <section style="border:1px solid #ddd; border-radius:8px; padding:1rem; margin:1.5rem 0;">
        <h2 style="margin-top:0; font-size:1.15rem;">App tokens</h2>
        {{range .AppTokens}}
          <div style="border-top:1px solid #eee; padding-top:1rem; margin-top:1rem;">
            <h3 style="margin:.25rem 0; font-size:1rem;">{{.DisplayName}}</h3>
            <p style="color:#555">Audience: <code>{{.Audience}}</code> · Client ID: <code>{{.ClientID}}</code> · JWKS: <code>{{.JWKSURL}}</code></p>
            <p style="color:#555">Scope: <code>{{.Scope}}</code> · Expires in {{.TokenTTLSeconds}} seconds</p>
            <form method="post" action="/app-tokens/{{.ID}}">
              <button type="submit">Generate JWT</button>
            </form>
          </div>
        {{end}}
        {{with .IssuedAppToken}}
          <div style="border-top:1px solid #ddd; padding-top:1rem; margin-top:1rem;">
            <h3 style="margin:.25rem 0; font-size:1rem;">{{.DisplayName}} JWT</h3>
            <p style="color:#555">Expires in {{.TokenTTLSeconds}} seconds. Use it as a bearer token.</p>
            <textarea id="app-token-value" readonly spellcheck="false" autocomplete="off" style="width:100%; min-height:9rem; box-sizing:border-box; font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;">{{.Token}}</textarea>
            <p><button type="button" onclick="navigator.clipboard.writeText(document.getElementById('app-token-value').value)">Copy JWT</button></p>
          </div>
        {{end}}
      </section>
    {{end}}
    <form method="get" action="/logout">
      <button type="submit">Sign out</button>
    </form>
  {{else}}
    <p>You are not signed in to authbroker.</p>
    <p><a href="/login">Sign in</a></p>
  {{end}}
</body>
</html>`))

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var brokerLogoutTemplate = template.Must(template.New("broker-logout").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Logout</title></head>
<body style="font-family: sans-serif; max-width: 36rem; margin: 3rem auto; line-height: 1.45;">
  <h1>Logout</h1>
  <p>Signed in as <strong>{{.UserID}}</strong>.</p>
  <form method="post" action="/logout">
    <button type="submit">Sign out of authbroker</button>
    <a href="/" style="margin-left:1rem">Cancel</a>
  </form>
</body>
</html>`))

//nolint:gochecknoglobals // Parsed templates are immutable and shared by handlers.
var loginTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Login</title></head>
<body style="font-family: sans-serif; max-width: 36rem; margin: 3rem auto;">
  <h1>Login</h1>
  <p>Client: <strong>{{.ClientID}}</strong></p>
  <form method="post" action="/login">
    <input type="hidden" name="request_id" value="{{.RequestID}}" />
    <label>Username<br><input name="username" autocomplete="username" required style="width:100%"></label><br><br>
    <label>Password<br><input name="password" type="password" autocomplete="current-password" required style="width:100%"></label><br><br>
    <label>TOTP code {{if not .TOTPHint}}(if enrolled){{end}}<br><input name="otp" inputmode="numeric" autocomplete="one-time-code" style="width:100%"></label><br><br>
    <button type="submit">Continue</button>
  </form>
</body>
</html>`))

// TOTP, RFC 6238 style, HMAC-SHA1/6 digits/30 sec.
func verifyTOTP(secretBase32, code string, now time.Time, window int) bool {
	if len(code) != 6 {
		return false
	}
	code = strings.TrimSpace(code)
	step := now.Unix() / 30
	for i := -window; i <= window; i++ {
		if subtle.ConstantTimeCompare([]byte(totpCode(secretBase32, step+int64(i))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpCode(secretBase32 string, counter int64) string {
	if counter < 0 {
		return "000000"
	}
	secretBase32 = strings.ToUpper(strings.TrimSpace(secretBase32))
	pad := len(secretBase32) % 8
	if pad != 0 {
		secretBase32 += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(secretBase32)
	if err != nil {
		return "000000"
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 | (uint32(sum[offset+1])&0xff)<<16 | (uint32(sum[offset+2])&0xff)<<8 | (uint32(sum[offset+3]) & 0xff)
	otp := bin % 1000000
	return fmt.Sprintf("%06d", otp)
}

func randomB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64RawURL(b)
}

func base64RawURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeB64URL(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty base64url")
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func normalizeChallenge(ch string) string {
	b, err := decodeB64URL(ch)
	if err != nil {
		return ch
	}
	return base64RawURL(b)
}

func dialLDAP(ctx context.Context, cfg LDAPConfig) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	if cfg.StartTLS && strings.EqualFold(u.Scheme, "ldaps") {
		return nil, fmt.Errorf("ldap start_tls cannot be used with ldaps URL")
	}
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	tlsConfig := &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // InsecureSkipVerify is operator-configurable for local LDAP fixtures.
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(timeout)
	if cfg.StartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func ldapAttribute(configured, fallback string) string {
	if v := strings.TrimSpace(configured); v != "" {
		return v
	}
	return fallback
}

func ldapEntryAttributeValue(entry *ldap.Entry, attribute string) string {
	values := ldapEntryAttributeValues(entry, attribute)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func ldapEntryAttributeValues(entry *ldap.Entry, attribute string) []string {
	if entry == nil {
		return nil
	}
	values := []string{}
	for _, attr := range entry.Attributes {
		if strings.EqualFold(attr.Name, attribute) {
			values = append(values, attr.Values...)
		}
	}
	return values
}

func uniqueNonEmpty(values ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
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

type managedSigningKeySet struct {
	ActiveKeyID string              `json:"active_key_id"`
	Keys        []managedSigningKey `json:"keys"`
}

type managedSigningKey struct {
	KeyID         string `json:"key_id"`
	SigningKeyPEM string `json:"signing_key_pem"`
	CreatedAt     int64  `json:"created_at"`
	RetiredAt     int64  `json:"retired_at,omitempty"`
}

func prepareSigningKeys(cfg *Config, dataDir string, forceRotate bool) error {
	if strings.TrimSpace(cfg.SigningKeyPEM) != "" || len(cfg.SigningKeys) > 0 || dataDir == "" {
		return nil
	}

	path := filepath.Join(dataDir, defaultKeysPath)
	keySet, loaded, err := loadManagedSigningKeySet(path)
	if err != nil {
		return err
	}
	if !loaded {
		keySet, err = initialManagedSigningKeySet(cfg.KeyID, time.Now())
		if err != nil {
			return err
		}
	}
	changed, err := keySet.rotateAndPrune(cfg.KeyID, cfg.SigningKeyRotationDays, cfg.SigningKeyRetentionDays, forceRotate && loaded, time.Now())
	if err != nil {
		return err
	}
	if !loaded || changed {
		if err := saveManagedSigningKeySet(path, keySet); err != nil {
			return err
		}
	}
	cfg.SigningKeys = keySet.signingKeyConfigs()
	cfg.KeyID = keySet.ActiveKeyID
	switch {
	case !loaded:
		log.Printf("generated RSA signing key set at %s", path)
	case changed:
		log.Printf("updated RSA signing key set at %s", path)
	default:
		log.Printf("loaded RSA signing key set from %s", path)
	}
	return nil
}

func loadManagedSigningKeySet(path string) (managedSigningKeySet, bool, error) {
	var keySet managedSigningKeySet
	b, err := os.ReadFile(path) //nolint:gosec // key path is derived from operator-supplied data directory.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return keySet, false, nil
		}
		return keySet, false, err
	}
	if err := json.Unmarshal(b, &keySet); err != nil {
		return keySet, false, err
	}
	return keySet, true, nil
}

func initialManagedSigningKeySet(keyIDPrefix string, now time.Time) (managedSigningKeySet, error) {
	key, err := newManagedSigningKey(keyIDPrefix, now)
	if err != nil {
		return managedSigningKeySet{}, err
	}
	return managedSigningKeySet{ActiveKeyID: key.KeyID, Keys: []managedSigningKey{key}}, nil
}

func (s *managedSigningKeySet) rotateAndPrune(keyIDPrefix string, rotationDays, retentionDays int, forceRotate bool, now time.Time) (bool, error) {
	changed := false
	createdInitial := false
	if len(s.Keys) == 0 {
		key, err := newManagedSigningKey(keyIDPrefix, now)
		if err != nil {
			return false, err
		}
		s.ActiveKeyID = key.KeyID
		s.Keys = []managedSigningKey{key}
		changed = true
		createdInitial = true
	}
	if err := s.validate(); err != nil {
		return false, err
	}
	activeIndex := s.activeIndex()
	if activeIndex < 0 {
		return false, fmt.Errorf("active signing key %q not found", s.ActiveKeyID)
	}
	if !createdInitial && shouldRotateSigningKey(s.Keys[activeIndex], rotationDays, forceRotate, now) {
		s.Keys[activeIndex].RetiredAt = now.Unix()
		key, err := newManagedSigningKey(keyIDPrefix, now)
		if err != nil {
			return false, err
		}
		s.ActiveKeyID = key.KeyID
		s.Keys = append(s.Keys, key)
		changed = true
	}
	if s.prune(retentionDays, now) {
		changed = true
	}
	return changed, s.validate()
}

func (s *managedSigningKeySet) validate() error {
	if strings.TrimSpace(s.ActiveKeyID) == "" {
		return fmt.Errorf("active signing key id is required")
	}
	seen := map[string]bool{}
	activeSeen := false
	for i, key := range s.Keys {
		if err := validateManagedSigningKey(key, i, seen); err != nil {
			return err
		}
		if key.KeyID == s.ActiveKeyID {
			activeSeen = true
			if key.RetiredAt != 0 {
				return fmt.Errorf("active signing key %q is retired", key.KeyID)
			}
		}
	}
	if !activeSeen {
		return fmt.Errorf("active signing key %q not found", s.ActiveKeyID)
	}
	return nil
}

func validateManagedSigningKey(key managedSigningKey, index int, seen map[string]bool) error {
	if strings.TrimSpace(key.KeyID) == "" {
		return fmt.Errorf("signing key %d: key_id is required", index)
	}
	if seen[key.KeyID] {
		return fmt.Errorf("duplicate signing key id %q", key.KeyID)
	}
	seen[key.KeyID] = true
	if strings.TrimSpace(key.SigningKeyPEM) == "" {
		return fmt.Errorf("signing key %q: signing_key_pem is required", key.KeyID)
	}
	if _, err := parseRSAPrivateKeyPEM([]byte(key.SigningKeyPEM)); err != nil {
		return fmt.Errorf("parse signing key %q: %w", key.KeyID, err)
	}
	return nil
}

func (s *managedSigningKeySet) activeIndex() int {
	for i, key := range s.Keys {
		if key.KeyID == s.ActiveKeyID {
			return i
		}
	}
	return -1
}

func shouldRotateSigningKey(key managedSigningKey, rotationDays int, forceRotate bool, now time.Time) bool {
	if forceRotate {
		return true
	}
	if rotationDays <= 0 {
		return false
	}
	createdAt := time.Unix(key.CreatedAt, 0)
	return !createdAt.IsZero() && !now.Before(createdAt.AddDate(0, 0, rotationDays))
}

func (s *managedSigningKeySet) prune(retentionDays int, now time.Time) bool {
	if retentionDays < 0 {
		return false
	}
	cutoff := now.AddDate(0, 0, -retentionDays).Unix()
	keys := s.Keys[:0]
	changed := false
	for _, key := range s.Keys {
		if key.KeyID != s.ActiveKeyID && key.RetiredAt != 0 && key.RetiredAt < cutoff {
			changed = true
			continue
		}
		keys = append(keys, key)
	}
	s.Keys = keys
	return changed
}

func (s *managedSigningKeySet) signingKeyConfigs() []SigningKeyConfig {
	out := make([]SigningKeyConfig, 0, len(s.Keys))
	for _, key := range s.Keys {
		out = append(out, SigningKeyConfig{
			KeyID:         key.KeyID,
			SigningKeyPEM: key.SigningKeyPEM,
			Active:        key.KeyID == s.ActiveKeyID,
		})
	}
	return out
}

func newManagedSigningKey(keyIDPrefix string, now time.Time) (managedSigningKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return managedSigningKey{}, err
	}
	keyPEM, err := marshalRSAPrivateKeyPEM(key)
	if err != nil {
		return managedSigningKey{}, err
	}
	return managedSigningKey{
		KeyID:         newSigningKeyID(keyIDPrefix, now),
		SigningKeyPEM: string(keyPEM),
		CreatedAt:     now.Unix(),
	}, nil
}

func newSigningKeyID(prefix string, now time.Time) string {
	prefix = sanitizeKeyIDPrefix(prefix)
	if prefix == "" {
		prefix = "broker-key"
	}
	return prefix + "-" + now.UTC().Format("20060102T150405Z") + "-" + randomB64(6)
}

func sanitizeKeyIDPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	var b strings.Builder
	for _, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), "-_")
}

func saveManagedSigningKeySet(path string, keySet managedSigningKeySet) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func main() {
	configPath := flag.String("config", envOrDefault(envConfigPath, defaultConfigPath), "Path to JSON config")
	dataPath := flag.String("data", envOrDefault(envDataPath, defaultDataDir), "Path to persistent authbroker data directory")
	printKey := flag.Bool("generate-key", false, "Generate a PEM RSA key and exit")
	rotateSigningKey := flag.Bool("rotate-key", false, "Force managed signing key rotation on startup")
	flag.Parse()

	if *printKey {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		keyPEM, err := marshalRSAPrivateKeyPEM(key)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := os.Stdout.Write(keyPEM); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	normalizeConfig(&cfg)
	dataDir, err := resolveDataDir(*dataPath)
	if err != nil {
		log.Fatalf("resolve data path: %v", err)
	}
	if err := prepareSigningKeys(&cfg, dataDir, *rotateSigningKey); err != nil {
		log.Fatalf("prepare signing key: %v", err)
	}
	store, err := NewStore(filepath.Join(dataDir, defaultDataFile))
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	broker, err := NewBroker(cfg, store)
	if err != nil {
		log.Fatalf("new broker: %v", err)
	}
	broker.startBackgroundSweeper(time.Minute)
	dumpRoutes(broker)
	srv := &http.Server{
		Addr:              broker.cfg.Listen,
		Handler:           broker.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("auth broker listening on %s issuer=%s", broker.cfg.Listen, broker.cfg.Issuer)
	log.Fatal(srv.ListenAndServe())
}

func dumpRoutes(_ *Broker) {
	routes := []string{
		"/.well-known/openid-configuration",
		"/oauth2/authorize",
		"/oauth2/token",
		"/oauth2/jwks",
		"/oauth2/userinfo",
		"/oauth2/revoke",
		"/app-tokens/{id}",
		"/mfa/totp/enroll",
		"/webauthn/register/begin",
		"/webauthn/register/finish",
		"/webauthn/login/begin",
		"/webauthn/login/finish",
	}
	sort.Strings(routes)
	log.Printf("endpoints: %s", strings.Join(routes, ", "))
}
