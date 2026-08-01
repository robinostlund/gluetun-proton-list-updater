package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// setMinimal sets the two mandatory variables so each test only has to declare
// what it actually cares about. t.Setenv restores the environment afterwards.
func setMinimal(t *testing.T) {
	t.Helper()
	t.Setenv("PROTON_USERNAME", "user@example.com")
	t.Setenv("PROTON_PASSWORD", "secret")
}

func TestLoadDefaults(t *testing.T) {
	setMinimal(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	switch {
	case cfg.Servers.FilePath != "/gluetun/servers.json":
		t.Errorf("FilePath = %q", cfg.Servers.FilePath)
	case cfg.Servers.WriteMode != WriteModeUpdate:
		t.Errorf("WriteMode = %q", cfg.Servers.WriteMode)
	case cfg.Switch.Mode != ReconnectSettings:
		t.Errorf("Switch.Mode = %q", cfg.Switch.Mode)
	case cfg.Filter.MaxLoad != 90:
		t.Errorf("MaxLoad = %d", cfg.Filter.MaxLoad)
	case cfg.Filter.SecureCore != FilterExclude:
		t.Errorf("SecureCore = %q, want exclude by default", cfg.Filter.SecureCore)
	case !cfg.Latency.Enabled:
		t.Error("latency probing should be on by default")
	case cfg.Proton.RefreshInterval != 12*time.Hour:
		t.Errorf("RefreshInterval = %s", cfg.Proton.RefreshInterval)
	}
}

func TestLoadRequiresCredentials(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "")
	t.Setenv("PROTON_PASSWORD", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error without credentials")
	}
	// Both problems must be reported at once, so a misconfigured container does
	// not need several restarts to be fixed.
	for _, want := range []string{"PROTON_USERNAME", "PROTON_PASSWORD"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

// Docker secrets are files, so the _FILE indirection has to work.
func TestLoadReadsSecretsFromFiles(t *testing.T) {
	directory := t.TempDir()
	passwordPath := filepath.Join(directory, "password")
	if err := os.WriteFile(passwordPath, []byte("  file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PROTON_USERNAME", "user@example.com")
	t.Setenv("PROTON_PASSWORD_FILE", passwordPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proton.Password != "file-secret" {
		t.Errorf("Password = %q, want the trimmed file contents", cfg.Proton.Password)
	}
}

func TestLoadMissingSecretFileIsAnError(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "user@example.com")
	t.Setenv("PROTON_PASSWORD_FILE", filepath.Join(t.TempDir(), "absent"))

	if _, err := Load(); err == nil {
		t.Fatal("expected an error for a missing secret file")
	}
}

// Countries should accept codes and names, and normalise both to Gluetun's
// spelling.
func TestLoadNormalizesCountries(t *testing.T) {
	setMinimal(t)
	t.Setenv("FILTER_COUNTRIES", "se, netherlands ,DE,Sweden")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := []string{"Sweden", "Netherlands", "Germany"}
	if len(cfg.Filter.Countries) != len(want) {
		t.Fatalf("Countries = %v, want %v (duplicates removed)", cfg.Filter.Countries, want)
	}
	for i := range want {
		if cfg.Filter.Countries[i] != want[i] {
			t.Errorf("Countries = %v, want %v", cfg.Filter.Countries, want)
		}
	}
}

func TestLoadRejectsUnknownCountry(t *testing.T) {
	setMinimal(t)
	t.Setenv("FILTER_COUNTRIES", "Sweden,Atlantis")

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error for an unknown country")
	}
	if !strings.Contains(err.Error(), "Atlantis") {
		t.Errorf("error should name the offending value: %v", err)
	}
}

func TestLoadValidatesRanges(t *testing.T) {
	tests := map[string]map[string]string{
		"max load too high":       {"FILTER_MAX_LOAD": "150"},
		"zero weights":            {"SCORING_LOAD_WEIGHT": "0", "SCORING_LATENCY_WEIGHT": "0", "SCORING_PROTON_WEIGHT": "0"},
		"bad port":                {"LATENCY_PORT": "70000"},
		"smoothing out of range":  {"LATENCY_SMOOTHING": "2"},
		"refresh far too often":   {"PROTON_REFRESH_INTERVAL": "10s"},
		"loads far too often":     {"PROTON_LOAD_REFRESH_INTERVAL": "5s"},
		"bad reconnect mode":      {"SWITCHING_MODE": "teleport"},
		"bad boolean":             {"SWITCHING_AUTO": "perhaps"},
		"bad duration":            {"SWITCHING_COOLDOWN": "soon"},
		"dashboard half-auth":     {"DASHBOARD_USERNAME": "admin"},
		"both gluetun auth kinds": {"GLUETUN_API_KEY": "k", "GLUETUN_USERNAME": "u", "GLUETUN_PASSWORD": "p"},
		"bad gluetun url":         {"GLUETUN_URL": "gluetun:8000"},
		"switch candidates zero":  {"SWITCHING_CANDIDATES": "0"},
	}

	for name, env := range tests {
		t.Run(name, func(t *testing.T) {
			setMinimal(t)
			for key, value := range env {
				t.Setenv(key, value)
			}
			if _, err := Load(); err == nil {
				t.Errorf("expected an error for %s", name)
			}
		})
	}
}

func TestLoadOnlyAllowedCountriesNeedsCountries(t *testing.T) {
	setMinimal(t)
	t.Setenv("GLUETUN_SERVERS_ONLY_ALLOWED_COUNTRIES", "true")

	if _, err := Load(); err == nil {
		t.Fatal("expected an error when the option is set without COUNTRIES")
	}
}

func TestLoadAcceptsFullConfiguration(t *testing.T) {
	setMinimal(t)
	for key, value := range map[string]string{
		"FILTER_COUNTRIES":               "Sweden,Norway",
		"FILTER_EXCLUDE_COUNTRIES":       "Norway",
		"FILTER_CITIES":                  "Stockholm",
		"FILTER_MAX_LOAD":                "70",
		"FILTER_VPN_TYPE":                "wireguard",
		"FILTER_SECURE_CORE":             "only",
		"FILTER_TOR":                     "include",
		"FILTER_P2P":                     "only",
		"FILTER_FREE_TIER":               "exclude",
		"SCORING_LOAD_WEIGHT":            "2",
		"SCORING_LATENCY_WEIGHT":         "1.5",
		"SCORING_PROTON_WEIGHT":          "0.25",
		"SCORING_LATENCY_CEILING":        "120ms",
		"LATENCY_TOP_N":                  "40",
		"SWITCHING_AUTO":                 "false",
		"SWITCHING_MODE":                 "status",
		"SWITCHING_LOAD_TRIGGER":         "75",
		"GLUETUN_SERVERS_WRITE_MODE":     "replace",
		"GLUETUN_SERVERS_SCHEMA_VERSION": "5",
		"GLUETUN_SERVERS_INCLUDE_IPV6":   "yes",
		"DASHBOARD_USERNAME":             "admin",
		"DASHBOARD_PASSWORD":             "hunter2",
		"LOG_LEVEL":                      "debug",
		"LOG_FORMAT":                     "json",
		"PROTON_LOAD_REFRESH_INTERVAL":   "5m",
	} {
		t.Setenv(key, value)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	switch {
	case cfg.Filter.VPNType != "wireguard":
		t.Errorf("VPNType = %q", cfg.Filter.VPNType)
	case cfg.Filter.SecureCore != FilterOnly:
		t.Errorf("SecureCore = %q", cfg.Filter.SecureCore)
	case cfg.Score.LoadWeight != 2:
		t.Errorf("LoadWeight = %f", cfg.Score.LoadWeight)
	case cfg.Score.LatencyCeiling != 120*time.Millisecond:
		t.Errorf("LatencyCeiling = %s", cfg.Score.LatencyCeiling)
	case cfg.Servers.SchemaVersion != 5:
		t.Errorf("SchemaVersion = %d", cfg.Servers.SchemaVersion)
	case !cfg.Servers.IncludeIPv6:
		t.Error("IncludeIPv6 should be true")
	case cfg.Switch.Auto:
		t.Error("AutoSwitch should be false")
	case cfg.Switch.Mode != ReconnectStatus:
		t.Errorf("Switch.Mode = %q", cfg.Switch.Mode)
	case cfg.LogFormat != "json":
		t.Errorf("LogFormat = %q", cfg.LogFormat)
	}
}

// An explicitly empty variable should fall back to the default rather than
// producing an empty setting, because compose files often contain `KEY=`.
func TestEmptyVariableFallsBackToDefault(t *testing.T) {
	setMinimal(t)
	t.Setenv("GLUETUN_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Gluetun.BaseURL != "http://gluetun:8000" {
		t.Errorf("BaseURL = %q, want the default", cfg.Gluetun.BaseURL)
	}
}

// Thresholds are written the way people say rates. A value in bare bytes is
// unreadable and trivially wrong by three orders of magnitude, which for this setting
// is the difference between "never switch" and "always switch".
func TestByteRateParsing(t *testing.T) {
	t.Parallel()

	// Megabits per second, written as a plain number. One unit end to end: the sources
	// convert at their boundary, the engine carries bits, the dashboard displays bits.
	for _, testCase := range []struct {
		input string
		want  uint64
	}{
		{"16", 16_000_000},
		{"1", 1_000_000},
		{"0.5", 500_000},
		{"2.5", 2_500_000},
		{" 8 ", 8_000_000},
		{"0", 0},
		{"1000", 1_000_000_000},
	} {
		got, err := parseMegabits(testCase.input)
		if err != nil {
			t.Errorf("parseMegabits(%q): %v", testCase.input, err)
			continue
		}
		if got != testCase.want {
			t.Errorf("parseMegabits(%q) = %d, want %d", testCase.input, got, testCase.want)
		}
	}

	for _, bad := range []string{"", "lots", "-1", "16Mbit", "MB"} {
		if _, err := parseMegabits(bad); err == nil {
			t.Errorf("parseMegabits(%q) should have failed", bad)
		}
	}

	// The upgrade case, which must not be reinterpreted: "2MB" meant 2 megabytes per second,
	// and reading it as 2 megabits would quietly cut the threshold to an eighth. It is refused
	// with the arithmetic spelled out.
	_, err := parseMegabits("2MB")
	if err == nil {
		t.Fatal(`parseMegabits("2MB") should be refused rather than reinterpreted`)
	}
	for _, want := range []string{"plain number", "megabits", "2MB becomes 16"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q should mention %q", err, want)
		}
	}
}

// A half-configured qBittorrent is worse than none: it reads as enabled while never
// deferring anything, so every mistake has to be caught at startup.
func TestQBittorrentConfigurationIsValidated(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "url without a key",
			env:     map[string]string{"QBITTORRENT_URL": "http://qb:8080"},
			wantErr: "QBITTORRENT_API_KEY is required",
		},
		{
			name: "url without a scheme",
			env: map[string]string{
				"QBITTORRENT_URL": "qb:8080", "QBITTORRENT_API_KEY": "qbt_x",
			},
			wantErr: "must start with http",
		},
		{
			name: "both thresholds disabled",
			env: map[string]string{
				"QBITTORRENT_URL": "http://qb:8080", "QBITTORRENT_API_KEY": "qbt_x",
				"SWITCHING_BUSY_DOWNLOAD": "0", "SWITCHING_BUSY_UPLOAD": "0",
			},
			wantErr: "no transfer would ever defer a switch",
		},
		{
			name: "timeout not shorter than the interval",
			env: map[string]string{
				"QBITTORRENT_URL": "http://qb:8080", "QBITTORRENT_API_KEY": "qbt_x",
				"QBITTORRENT_TIMEOUT": "30s", "QBITTORRENT_INTERVAL": "15s",
			},
			wantErr: "must be shorter than",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("PROTON_USERNAME", "user")
			t.Setenv("PROTON_PASSWORD", "pass")
			for key, value := range testCase.env {
				t.Setenv(key, value)
			}
			_, err := Load()
			if err == nil {
				t.Fatalf("expected an error mentioning %q", testCase.wantErr)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, testCase.wantErr)
			}
		})
	}
}

// And the feature must stay off, with no validation at all, when it is not configured.
func TestQBittorrentIsOffByDefault(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "user")
	t.Setenv("PROTON_PASSWORD", "pass")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.QBittorrent.Enabled() {
		t.Error("qBittorrent should be disabled when QBITTORRENT_URL is unset")
	}
}

// "nan" and "inf" parse cleanly as floats and then defeat every range check, because
// NaN compares false against everything. Both settings this affects fail *open*, which
// is the dangerous direction: a NaN busy-threshold is never exceeded, so a typo would
// silently switch off the protection, and a NaN scoring weight makes every score NaN
// and the ranking meaningless.
func TestNonFiniteNumbersAreRejected(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"nan", "NaN", "inf", "+Inf", "-inf", "1e400"} {
		if _, err := parseMegabits(value); err == nil {
			t.Errorf("parseMegabits(%q) should have been rejected", value)
		}
	}
	// And a value that overflows uint64 once scaled to bits. Converting an out-of-range float
	// to an integer is undefined in Go, so this must be caught before the conversion.
	// MaxUint64 is about 1.845e19 bits, so anything above 1.845e13 megabits overflows.
	for _, value := range []string{"1e30", "2e13"} {
		if got, err := parseMegabits(value); err == nil {
			t.Errorf("parseMegabits(%q) = %d, should have been rejected as too large", value, got)
		}
	}
	// Something large but genuinely representable stays acceptable.
	for _, value := range []string{"10000", "1e12"} {
		if _, err := parseMegabits(value); err != nil {
			t.Errorf("parseMegabits(%q) should be accepted: %v", value, err)
		}
	}
}

// The same class of bug in the float reader, which the scoring weights use.
func TestNonFiniteScoringWeightsAreRejected(t *testing.T) {
	for _, key := range []string{"SCORING_LOAD_WEIGHT", "SCORING_LATENCY_WEIGHT", "SCORING_PROTON_WEIGHT"} {
		for _, value := range []string{"nan", "inf"} {
			t.Run(key+"="+value, func(t *testing.T) {
				t.Setenv("PROTON_USERNAME", "user")
				t.Setenv("PROTON_PASSWORD", "pass")
				t.Setenv(key, value)

				_, err := Load()
				if err == nil {
					t.Fatalf("%s=%s was accepted; every score would become NaN", key, value)
				}
				if !strings.Contains(err.Error(), "finite") {
					t.Errorf("error = %v, want it to say the value is not finite", err)
				}
			})
		}
	}
}

// A non-finite busy threshold has to be refused too, since it reaches the same
// conversion by a different route.
func TestANonFiniteBusyThresholdIsRejected(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "user")
	t.Setenv("PROTON_PASSWORD", "pass")
	t.Setenv("QBITTORRENT_URL", "http://qb:8080")
	t.Setenv("QBITTORRENT_API_KEY", "qbt_x")
	t.Setenv("SWITCHING_BUSY_DOWNLOAD", "nan")

	if _, err := Load(); err == nil {
		t.Fatal("SWITCHING_BUSY_DOWNLOAD=nan was accepted; it would never be exceeded")
	}
}

// A window shorter than the poll interval holds one sample, which is the very thing it
// exists to stop being decisive.
func TestTheBusyWindowMustHoldMoreThanOneSample(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "user")
	t.Setenv("PROTON_PASSWORD", "pass")
	t.Setenv("QBITTORRENT_URL", "http://qb:8080")
	t.Setenv("QBITTORRENT_API_KEY", "qbt_x")
	t.Setenv("QBITTORRENT_INTERVAL", "15s")
	t.Setenv("SWITCHING_BUSY_WINDOW", "5s")

	_, err := Load()
	if err == nil {
		t.Fatal("a window shorter than the interval was accepted")
	}
	if !strings.Contains(err.Error(), "averages a single reading") {
		t.Errorf("error = %v, want it to explain why", err)
	}
}

// Zero is the escape hatch and must stay allowed.
func TestAZeroBusyWindowIsAllowed(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "user")
	t.Setenv("PROTON_PASSWORD", "pass")
	t.Setenv("QBITTORRENT_URL", "http://qb:8080")
	t.Setenv("QBITTORRENT_API_KEY", "qbt_x")
	t.Setenv("SWITCHING_BUSY_WINDOW", "0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.QBittorrent.BusyWindow != 0 {
		t.Errorf("BusyWindow = %s, want 0", cfg.QBittorrent.BusyWindow)
	}
}

// The default has to be long enough to smooth real bursts.
func TestTheBusyWindowDefaultsToFiveMinutes(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "user")
	t.Setenv("PROTON_PASSWORD", "pass")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.QBittorrent.BusyWindow != 5*time.Minute {
		t.Errorf("BusyWindow = %s, want 5m", cfg.QBittorrent.BusyWindow)
	}
}

// The selection filters are FILTER_* now: scattered across the namespace they gave no
// hint of being one group, and names like TOR or P2P could collide with something else an
// operator sets.
func TestFilterVariablesUseTheFilterPrefix(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "user")
	t.Setenv("PROTON_PASSWORD", "pass")
	t.Setenv("FILTER_COUNTRIES", "Sweden")
	t.Setenv("FILTER_MAX_LOAD", "70")
	t.Setenv("FILTER_IPV6", "only")
	t.Setenv("FILTER_P2P", "exclude")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Filter.Countries; len(got) != 1 || got[0] != "Sweden" {
		t.Errorf("Countries = %v", got)
	}
	if cfg.Filter.MaxLoad != 70 {
		t.Errorf("MaxLoad = %d, want 70", cfg.Filter.MaxLoad)
	}
	if cfg.Filter.IPv6 != FilterOnly {
		t.Errorf("IPv6 = %q, want only", cfg.Filter.IPv6)
	}
	if cfg.Filter.P2P != FilterExclude {
		t.Errorf("P2P = %q, want exclude", cfg.Filter.P2P)
	}
}

// The error messages have to name the variable an operator now sets, or the fix is a
// guess.
func TestValidationErrorsNameTheCurrentVariable(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "user")
	t.Setenv("PROTON_PASSWORD", "pass")
	t.Setenv("FILTER_MAX_LOAD", "500")

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "FILTER_MAX_LOAD") {
		t.Errorf("error = %v, want it to name FILTER_MAX_LOAD", err)
	}
}

// The rename is a hard break, and a removed name is refused rather than ignored.
//

// Every variable belongs to a named group, so its prefix says what it configures.
//
// This was not always so: the selection filters were bare names (COUNTRIES, TOR, P2P) and
// the server-data settings were SERVERS_*, which read as though they described servers in
// general rather than the data written for Gluetun. Both are grouped now, and this keeps
// the next addition from drifting back.
func TestEveryVariableBelongsToAGroup(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}

	groups := []string{
		"PROTON_",      // the Proton API and account
		"GLUETUN_",     // the Gluetun container, including the data written for it
		"FILTER_",      // which servers may be selected
		"SCORING_",     // how survivors are ranked
		"LATENCY_",     // the latency prober
		"SWITCHING_",   // when the tunnel may be moved
		"QBITTORRENT_", // transfer awareness
		"DASHBOARD_",   // the web UI
		"LOG_",         // logging
	}
	// Standalone names that belong to no group because there is only ever one of them.
	standalone := map[string]bool{
		"STATE_DIR": true, "TZ": true,
	}

	var ungrouped []string
	seen := map[string]bool{}
	pattern := `r\.(?:str|choice|integer|boolean|duration|float|csv|required|megabits)\("([A-Z_0-9]+)"`
	for _, match := range regexp.MustCompile(pattern).FindAllSubmatch(source, -1) {
		name := string(match[1])
		if seen[name] || standalone[name] {
			continue
		}
		seen[name] = true
		grouped := false
		for _, prefix := range groups {
			if strings.HasPrefix(name, prefix) {
				grouped = true
				break
			}
		}
		if !grouped {
			ungrouped = append(ungrouped, name)
		}
	}
	sort.Strings(ungrouped)
	if len(ungrouped) > 0 {
		t.Errorf("these variables belong to no group: %v\n"+
			"prefix each with one of %v, or add it to the standalone list with a reason",
			ungrouped, groups)
	}
	if len(seen) < 60 {
		t.Fatalf("only found %d variables; the pattern is wrong", len(seen))
	}

	// The server-data settings are Gluetun's, and named so.
	for _, name := range []string{
		"GLUETUN_SERVERS_FILE", "GLUETUN_SERVERS_DIR", "GLUETUN_SERVERS_WRITE_MODE",
		"GLUETUN_SERVERS_PREFERRED", "GLUETUN_SERVERS_SCHEMA_VERSION",
		"GLUETUN_SERVERS_ONLY_ALLOWED_COUNTRIES", "GLUETUN_SERVERS_INCLUDE_IPV6",
	} {
		if !seen[name] {
			t.Errorf("%s is not read; the rename left something behind", name)
		}
	}
	// And the old bare names are gone entirely.
	if regexp.MustCompile(`r\.\w+\("SERVERS_`).Match(source) {
		t.Error("a bare SERVERS_* variable is back")
	}
}

// The new names are what actually configure the writer.
func TestGluetunServersVariablesAreRead(t *testing.T) {
	t.Setenv("PROTON_USERNAME", "user")
	t.Setenv("PROTON_PASSWORD", "pass")
	t.Setenv("GLUETUN_SERVERS_FILE", "/gluetun/custom.json")
	t.Setenv("GLUETUN_SERVERS_DIR", "/gluetun/custom-servers")
	t.Setenv("GLUETUN_SERVERS_WRITE_MODE", "replace")
	t.Setenv("GLUETUN_SERVERS_PREFERRED", "false")
	t.Setenv("GLUETUN_SERVERS_INCLUDE_IPV6", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Servers.FilePath != "/gluetun/custom.json" {
		t.Errorf("FilePath = %q", cfg.Servers.FilePath)
	}
	if cfg.Servers.DirPath != "/gluetun/custom-servers" {
		t.Errorf("DirPath = %q", cfg.Servers.DirPath)
	}
	if cfg.Servers.WriteMode != WriteModeReplace {
		t.Errorf("WriteMode = %q", cfg.Servers.WriteMode)
	}
	if cfg.Servers.Preferred {
		t.Error("Preferred should be false")
	}
	if !cfg.Servers.IncludeIPv6 {
		t.Error("IncludeIPv6 should be true")
	}
}

// Every variable name that appears in the documentation, the dashboard or a message an
// operator will read has to be one that actually exists.
//
// This is not hypothetical: renaming the SWITCH_* and SCORE_* variables into groups left
// stale names behind in the README, in two dashboard tooltips and in a validation error
// telling operators to set a variable that had ceased to exist. Nothing failed, because
// nothing was checking.
func TestNoDocumentedVariableNameIsUnknown(t *testing.T) {
	t.Parallel()

	// The definitions in config.go are the authority on what exists, read the same way
	// TestEveryVariableBelongsToAGroup reads them.
	source, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	definition := regexp.MustCompile(
		`(?:r\.(?:str|choice|integer|boolean|duration|float|csv|required|megabits)|` +
			`parseLevel|parseFormat)\(r?,? ?"([A-Z_0-9]+)"`)
	for _, match := range definition.FindAllSubmatch(source, -1) {
		name := string(match[1])
		known[name] = true
		// Every variable also accepts a _FILE form, which is how a secret is passed
		// without putting it in the environment.
		known[name+"_FILE"] = true
	}
	if len(known) < 40 {
		t.Fatalf("only found %d variable definitions; the pattern has stopped matching", len(known))
	}
	// Variables belonging to other programs, which legitimately appear in the compose
	// file and the documentation.
	for _, name := range []string{
		"TZ", "WIREGUARD_PRIVATE_KEY", "SERVER_COUNTRIES", "SERVER_CITIES", "SERVER_NAMES",
		"VPN_SERVICE_PROVIDER", "VPN_TYPE", "VPN_PORT_FORWARDING", "PORT_FORWARD_ONLY",
		"HTTP_CONTROL_SERVER_ADDRESS", "HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE",
		"UPDATER_PERIOD", "UPDATER_PROTONVPN_EMAIL", "UPDATER_PROTONVPN_PASSWORD",
		"STORAGE_SERVERS_ENABLED", "HEALTH_RESTART_VPN", "COUNTRIES", "DOCKER_BUILDKIT",
		// Makefile variables, which configure a build or a test run rather than the tool.
		"GLUETUN_VERSION", "GLUETUN_IMAGE",
		"CGO_ENABLED", "GOFLAGS", "GOOS", "GOARCH", "GOCACHE", "GOPATH",
		"QBT_SID", "SID",
	} {
		known[name] = true
	}

	// A name is only a claim about this tool's configuration when it looks like one:
	// upper snake case with a prefix this tool uses.
	prefixes := []string{"FILTER_", "SWITCH", "SCOR", "GLUETUN_", "PROTON_", "LATENCY_",
		"QBITTORRENT_", "DASHBOARD_", "LOG_", "STATE_", "SERVERS_"}
	// The integration harness has its own variables, which configure the test rather
	// than the tool.
	exempt := []string{"GLUETUN_ITEST_"}
	pattern := regexp.MustCompile(`\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b`)

	// The repository root, not the package's parent: the README and the compose file
	// are the documents most likely to keep a name a rename left behind, and an earlier
	// version of this test walked only internal/ and so proved nothing about them.
	root := "../.."
	var offenders []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "dist" {
				return fs.SkipDir
			}
			return nil
		}
		// The Dockerfile is scanned too. It sets environment variables like any other
		// configuration, and being excluded from this scan is how it came to keep setting a
		// servers-file variable long after that name was replaced - the image configuring
		// something the program no longer read, with nothing to notice.
		//
		// Note the wording: naming the dead variable here would make this test fail on its own
		// comment, which is exactly the point of scanning comments in the first place.
		switch {
		case entry.Name() == "Dockerfile":
		default:
			switch filepath.Ext(entry.Name()) {
			case ".go", ".md", ".js", ".html", ".yml", ".yaml":
			default:
				return nil
			}
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, name := range pattern.FindAllString(string(content), -1) {
			if known[name] {
				continue
			}
			var claimed bool
			for _, prefix := range prefixes {
				if strings.HasPrefix(name, prefix) {
					claimed = true
					break
				}
			}
			for _, prefix := range exempt {
				if strings.HasPrefix(name, prefix) {
					claimed = false
					break
				}
			}
			if claimed {
				offenders = append(offenders, fmt.Sprintf("%s: %s", path, name))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("these look like this tool's variables but are not defined:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// Every variable this tool reads must appear in the reported configuration.
//
// "How is this configured" is not answerable from the subset somebody remembered to add to
// a list, which is what the dashboard's settings panel used to be. Recording happens while
// parsing, so this test is what proves no accessor was left out of that.
func TestEveryVariableIsReported(t *testing.T) {
	setMinimal(t)

	source, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	reported := make(map[string]Variable, len(cfg.Variables))
	for _, variable := range cfg.Variables {
		if _, duplicate := reported[variable.Name]; duplicate {
			t.Errorf("%s is reported twice", variable.Name)
		}
		reported[variable.Name] = variable
	}

	definition := regexp.MustCompile(
		`(?:r\.(?:str|choice|integer|boolean|duration|float|csv|required|megabits)|` +
			`parseLevel|parseFormat)\(r?,? ?"([A-Z_0-9]+)"`)
	var missing []string
	for _, match := range definition.FindAllSubmatch(source, -1) {
		if _, found := reported[string(match[1])]; !found {
			missing = append(missing, string(match[1]))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("these variables are read but never reported: %s", strings.Join(missing, ", "))
	}
	if len(cfg.Variables) < 60 {
		t.Errorf("only %d variables reported; the tool reads more than that", len(cfg.Variables))
	}

	// Defaults are reported too, marked as defaults. A value in effect that nobody chose is
	// exactly what an operator needs to see, and it is also not a decision.
	if plan, found := reported["PROTON_API_URL"]; !found || plan.Configured {
		t.Errorf("an unset variable is missing or marked as configured: %+v", plan)
	}
	if username, found := reported["PROTON_USERNAME"]; !found || !username.Configured {
		t.Errorf("a set variable is missing or marked as a default: %+v", username)
	}
}

// A credential's value must never leave the process. This is the test that would have to
// fail for one to leak, so it checks the values rather than the labelling.
func TestNoSecretValueIsEverReported(t *testing.T) {
	const (
		password = "NotAPasswordAnybodyElseUses1!"
		totp     = "TOTPSECRETVALUE234567"
		apiKey   = "qbt_secretsecretsecretsecrets"
		gluetun  = "gluetun-api-key-value"
		dashpass = "dashboard-password-value"
	)
	setMinimal(t)
	t.Setenv("PROTON_PASSWORD", password)
	t.Setenv("PROTON_TOTP_SECRET", totp)
	t.Setenv("QBITTORRENT_URL", "http://qbittorrent:8080")
	t.Setenv("QBITTORRENT_API_KEY", apiKey)
	t.Setenv("SWITCHING_BUSY_DOWNLOAD", "16")
	t.Setenv("GLUETUN_API_KEY", gluetun)
	// Both halves, since the config rejects one without the other.
	t.Setenv("DASHBOARD_USERNAME", "admin")
	t.Setenv("DASHBOARD_PASSWORD", dashpass)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// The whole reported list, as the dashboard would receive it.
	encoded, err := json.Marshal(cfg.Variables)
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string]string{
		"PROTON_PASSWORD": password, "PROTON_TOTP_SECRET": totp,
		"QBITTORRENT_API_KEY": apiKey, "GLUETUN_API_KEY": gluetun,
		"DASHBOARD_PASSWORD": dashpass,
	} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Errorf("the value of %s appears in the reported configuration", name)
		}
	}

	// And each is still reported as present, because whether a credential is set is
	// diagnostic and withholding that only makes misconfiguration harder to find.
	for _, name := range []string{"PROTON_PASSWORD", "QBITTORRENT_API_KEY", "GLUETUN_API_KEY"} {
		var found bool
		for _, variable := range cfg.Variables {
			if variable.Name != name {
				continue
			}
			found = true
			if !variable.Secret {
				t.Errorf("%s is not marked secret", name)
			}
			if variable.Value != "set" {
				t.Errorf("%s = %q, want \"set\"", name, variable.Value)
			}
		}
		if !found {
			t.Errorf("%s is not reported at all", name)
		}
	}

	// A password is also the one value most likely to be pasted into a bug report, so the
	// guard covers the shape of the whole config too, not just the variable list.
	whole, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(whole, []byte(password)) {
		t.Log("note: Config itself still carries the password, which is expected - it is " +
			"needed to log in. What must never be serialised to the dashboard is Variables.")
	}
}

// The README's reference table states the defaults, so it has to agree with them.
//
// It drifted the moment the threshold unit changed: the table still said `1MiB` while the code
// had moved to megabits, which is the one place someone checks when their setting does not
// behave as expected.
func TestTheDocumentedDefaultsMatchTheCode(t *testing.T) {
	t.Parallel()

	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}

	// Every variable the reference table documents with a default, against what config.go
	// actually passes as one. Only the simple literal defaults: anything computed is out of
	// scope for a text comparison and would produce noise rather than findings.
	rows := regexp.MustCompile(`(?m)^\| ` + "`" + `([A-Z_0-9]+)` + "`" + ` \| ` + "`" + `([^` + "`" + `]+)` + "`")
	definitions := regexp.MustCompile(
		`r\.(?:str|choice|integer|boolean|duration|float|megabits)\("([A-Z_0-9]+)", *([^),]+)\)`)

	actual := map[string]string{}
	for _, match := range definitions.FindAllSubmatch(source, -1) {
		actual[string(match[1])] = strings.TrimSpace(string(match[2]))
	}

	var checked int
	for _, row := range rows.FindAllSubmatch(readme, -1) {
		name, documented := string(row[1]), string(row[2])
		code, found := actual[name]
		if !found {
			continue
		}
		// Compare only where the code's default is a plain number or a quoted string, which
		// is what a table cell can be checked against without interpreting Go.
		normalised := strings.Trim(code, `"`)
		if strings.ContainsAny(normalised, "*<+/(") {
			continue
		}
		checked++
		if documented != normalised && documented != normalised+"s" {
			t.Errorf("README documents %s as %q, but the code defaults to %q",
				name, documented, normalised)
		}
	}
	if checked < 15 {
		t.Fatalf("only compared %d defaults; the scan is not working", checked)
	}
	t.Logf("compared %d documented defaults against the code", checked)
}
