package countries

import (
	"fmt"
	"sort"
	"strings"
)

// supplement holds codes Proton uses that Gluetun's map does not contain.
//
// Gluetun would render these as the bare code, so supplying a real name is
// strictly better: our servers.json defines the country values Gluetun accepts
// for filtering, so a readable name here becomes a usable filter value there.
//
// XK is the user-assigned code for Kosovo. It is not in ISO 3166-1, which is why
// Gluetun's list omits it, but Proton returns it.
var supplement = map[string]string{
	"xk": "Kosovo",
}

// nameToCode is the reverse of codeToName, keyed by lowercase country name.
var nameToCode = func() map[string]string {
	for code, name := range supplement {
		if _, exists := codeToName[code]; !exists {
			codeToName[code] = name
		}
	}

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
