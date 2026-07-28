package countries

import "testing"

// The names must match Gluetun's exactly, otherwise the country written into
// servers.json would not match what Gluetun accepts in SERVER_COUNTRIES.
func TestNameMatchesGluetunSpelling(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"se": "Sweden",
		"SE": "Sweden",
		"us": "United States",
		"gb": "United Kingdom",
		"nl": "Netherlands",
		"ch": "Switzerland",
	}

	for code, want := range tests {
		got, known := Name(code)
		if !known {
			t.Errorf("Name(%q) reported unknown", code)
		}
		if got != want {
			t.Errorf("Name(%q) = %q, want %q", code, got, want)
		}
	}
}

// An unrecognised code must degrade into something usable rather than an empty
// string, so an unexpected Proton value cannot produce a server with no country.
func TestNameUnknownCodeFallsBack(t *testing.T) {
	t.Parallel()

	got, known := Name("zz")
	if known {
		t.Error("zz should not be a known code")
	}
	if got != "ZZ" {
		t.Errorf("Name(zz) = %q, want ZZ", got)
	}
}

func TestNormalizeAcceptsCodesAndNames(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"se":             "Sweden",
		"SE":             "Sweden",
		"Sweden":         "Sweden",
		"sweden":         "Sweden",
		"  Netherlands ": "Netherlands",
		"united states":  "United States",
	}

	for input, want := range tests {
		got, err := Normalize(input)
		if err != nil {
			t.Errorf("Normalize(%q): %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("Normalize(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeRejectsUnknown(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"", "  ", "Atlantis", "zz"} {
		if _, err := Normalize(input); err == nil {
			t.Errorf("Normalize(%q) should have failed", input)
		}
	}
}

func TestAllNamesIsSortedAndComplete(t *testing.T) {
	t.Parallel()

	names := AllNames()
	if len(names) < 200 {
		t.Errorf("got %d countries, expected the full ISO list", len(names))
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("AllNames is not sorted at %d: %q > %q", i, names[i-1], names[i])
		}
	}
}
