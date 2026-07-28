package countries

import (
	"fmt"
	"sort"
	"strings"
)

// nameToCode is the reverse of codeToName, keyed by lowercase country name.
var nameToCode = func() map[string]string {
	m := make(map[string]string, len(codeToName))
	for code, name := range codeToName {
		m[strings.ToLower(name)] = code
	}
	return m
}()

// Name returns the Gluetun country name for an ISO 3166-1 alpha-2 code.
// Unknown codes are returned uppercased, so an unexpected code from the Proton
// API degrades into a usable (if ugly) value instead of an empty string.
func Name(code string) (name string, known bool) {
	name, known = codeToName[strings.ToLower(strings.TrimSpace(code))]
	if !known {
		return strings.ToUpper(strings.TrimSpace(code)), false
	}
	return name, true
}

// Normalize resolves a user-provided country - either an alpha-2 code ("se")
// or a full name ("Sweden", case-insensitive) - to the canonical Gluetun
// country name. It exists so the COUNTRIES setting is forgiving about input
// while everything downstream only ever deals with canonical names.
func Normalize(input string) (name string, err error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", fmt.Errorf("empty country")
	}

	if name, ok := codeToName[strings.ToLower(trimmed)]; ok {
		return name, nil
	}
	if code, ok := nameToCode[strings.ToLower(trimmed)]; ok {
		return codeToName[code], nil
	}
	return "", fmt.Errorf("unknown country %q: expected an ISO 3166-1 alpha-2 code (e.g. SE) or a country name (e.g. Sweden)", input)
}

// AllNames returns every known country name, sorted. Used by the dashboard to
// offer a country picker.
func AllNames() (names []string) {
	names = make([]string, 0, len(codeToName))
	for _, name := range codeToName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
