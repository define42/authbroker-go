package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

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

// mergeStrings concatenates the inputs and removes duplicates. Dedup is
// case-insensitive to match ldapGroupIdentifiers — otherwise a direct
// memberOf entry like `CN=admins,…` and a nested-search entry like
// `CN=Admins,…` would both survive, and downstream group_mappings would
// fire twice for what AD/OpenLDAP treat as the same group.
func mergeStrings(values ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, slice := range values {
		for _, value := range slice {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
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
	rootCAs, err := loadRootCAs(cfg.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("ldap ca cert: %w", err)
	}
	tlsConfig := &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: cfg.InsecureSkipVerify, RootCAs: rootCAs} //nolint:gosec // InsecureSkipVerify is operator-configurable for local LDAP fixtures.
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
