package main

import (
	"fmt"
	"strings"
)

const (
	scopeOpenID        = "openid"
	scopeProfile       = "profile"
	scopeEmail         = "email"
	scopeGroups        = "groups"
	scopeOfflineAccess = "offline_access"
)

var supportedAuthorizationScopes = map[string]bool{ //nolint:gochecknoglobals // Static protocol vocabulary.
	scopeOpenID:        true,
	scopeProfile:       true,
	scopeEmail:         true,
	scopeGroups:        true,
	scopeOfflineAccess: true,
}

var defaultClientAllowedScopes = []string{scopeOpenID, scopeProfile, scopeEmail, scopeGroups} //nolint:gochecknoglobals // Static default copied before mutation.

func normalizeClientScopePolicy(c *Client) error {
	allowed, err := normalizeClientAllowedScopes(c.AllowedScopes, c.AllowOfflineAccess)
	if err != nil {
		return err
	}
	clientCredentialsScopes, err := normalizeClientCredentialsScopes(c.ClientCredentialsScopes)
	if err != nil {
		return err
	}
	c.AllowedScopes = allowed
	c.ClientCredentialsScopes = clientCredentialsScopes
	c.allowedScopeSet = scopeSet(allowed)
	c.clientCredentialsAllowedScopes = scopeSet(clientCredentialsScopes)
	return nil
}

func validateClientScopeConfig(c Client) error {
	return normalizeClientScopePolicy(&c)
}

func normalizeClientAllowedScopes(configured []string, allowOfflineAccess bool) ([]string, error) {
	scopes := configured
	if len(scopes) == 0 {
		scopes = append([]string(nil), defaultClientAllowedScopes...)
	}
	normalized, err := normalizeScopeTokens(scopes)
	if err != nil {
		return nil, err
	}
	hasOffline := false
	for _, scope := range normalized {
		if !supportedAuthorizationScopes[scope] {
			return nil, fmt.Errorf("allowed_scopes contains unsupported scope %q", scope)
		}
		if scope == scopeOfflineAccess {
			hasOffline = true
		}
	}
	if hasOffline && !allowOfflineAccess {
		return nil, fmt.Errorf("offline_access requires allow_offline_access=true")
	}
	if allowOfflineAccess && !hasOffline {
		normalized = append(normalized, scopeOfflineAccess)
	}
	return normalized, nil
}

func normalizeClientCredentialsScopes(configured []string) ([]string, error) {
	normalized, err := normalizeScopeTokens(configured)
	if err != nil {
		return nil, err
	}
	for _, scope := range normalized {
		if scope == scopeOfflineAccess {
			return nil, fmt.Errorf("client_credentials_scopes must not include offline_access")
		}
	}
	return normalized, nil
}

func normalizeAppTokenScope(raw string) (string, error) {
	scopes, err := parseScopeString(raw)
	if err != nil {
		return "", err
	}
	for _, scope := range scopes {
		if !supportedAuthorizationScopes[scope] || scope == scopeOfflineAccess {
			return "", fmt.Errorf("app token scope %q is not supported", scope)
		}
	}
	return strings.Join(scopes, " "), nil
}

func validateAuthorizationScope(client Client, raw string) (string, error) {
	scopes, err := parseScopeString(raw)
	if err != nil {
		return "", err
	}
	allowed := clientAllowedScopeSet(client)
	for _, scope := range scopes {
		if !supportedAuthorizationScopes[scope] {
			return "", fmt.Errorf("unsupported scope %q", scope)
		}
		if scope == scopeOfflineAccess && !client.AllowOfflineAccess {
			return "", fmt.Errorf("scope offline_access is not allowed for this client")
		}
		if !allowed[scope] {
			return "", fmt.Errorf("scope %q is not allowed for this client", scope)
		}
	}
	return strings.Join(scopes, " "), nil
}

func validateClientCredentialsScope(client Client, raw string) (string, error) {
	scopes, err := parseScopeString(raw)
	if err != nil {
		return "", err
	}
	allowed := clientCredentialsScopeSet(client)
	for _, scope := range scopes {
		if !allowed[scope] {
			return "", fmt.Errorf("scope %q is not allowed for client_credentials", scope)
		}
	}
	return strings.Join(scopes, " "), nil
}

func clientAllowedScopeSet(client Client) map[string]bool {
	if len(client.allowedScopeSet) > 0 {
		return client.allowedScopeSet
	}
	allowed, err := normalizeClientAllowedScopes(client.AllowedScopes, client.AllowOfflineAccess)
	if err != nil {
		return map[string]bool{}
	}
	return scopeSet(allowed)
}

func clientCredentialsScopeSet(client Client) map[string]bool {
	if len(client.clientCredentialsAllowedScopes) > 0 {
		return client.clientCredentialsAllowedScopes
	}
	allowed, err := normalizeClientCredentialsScopes(client.ClientCredentialsScopes)
	if err != nil {
		return map[string]bool{}
	}
	return scopeSet(allowed)
}

func normalizeScopeTokens(values []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		for _, scope := range strings.Fields(value) {
			if !validScopeToken(scope) {
				return nil, fmt.Errorf("invalid scope %q", scope)
			}
			if seen[scope] {
				continue
			}
			seen[scope] = true
			out = append(out, scope)
		}
	}
	return out, nil
}

func parseScopeString(raw string) ([]string, error) {
	return normalizeScopeTokens([]string{raw})
}

func validScopeToken(scope string) bool {
	if scope == "" {
		return false
	}
	for i := 0; i < len(scope); i++ {
		c := scope[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x5b) || (c >= 0x5d && c <= 0x7e) {
			continue
		}
		return false
	}
	return true
}

func scopeSet(scopes []string) map[string]bool {
	if len(scopes) == 0 {
		return nil
	}
	out := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		out[scope] = true
	}
	return out
}
