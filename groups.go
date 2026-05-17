package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

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

// mappedAppTokenGroups applies an app token's group_mappings to user groups.
// Wrapping mappedClientGroups in a function keyed by the mapping map keeps the
// app-token codepath from awkwardly synthesizing a Client just to reuse the
// mapping logic.
func mappedAppTokenGroups(mappings map[string]string, userGroups []string) []string {
	return mappedClientGroups(Client{GroupMappings: mappings}, userGroups)
}
