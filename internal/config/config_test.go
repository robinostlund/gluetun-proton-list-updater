package config

import (
	"os"
	"path/filepath"
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
	t.Setenv("COUNTRIES", "se, netherlands ,DE,Sweden")

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
	t.Setenv("COUNTRIES", "Sweden,Atlantis")

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
		"max load too high":       {"MAX_LOAD": "150"},
		"zero weights":            {"SCORE_LOAD_WEIGHT": "0", "SCORE_LATENCY_WEIGHT": "0", "SCORE_PROTON_WEIGHT": "0"},
		"bad port":                {"LATENCY_PORT": "70000"},
		"smoothing out of range":  {"LATENCY_SMOOTHING": "2"},
		"refresh far too often":   {"PROTON_REFRESH_INTERVAL": "10s"},
		"loads far too often":     {"PROTON_LOAD_REFRESH_INTERVAL": "5s"},
		"bad reconnect mode":      {"RECONNECT_MODE": "teleport"},
		"bad boolean":             {"AUTO_SWITCH": "perhaps"},
		"bad duration":            {"SWITCH_COOLDOWN": "soon"},
		"dashboard half-auth":     {"DASHBOARD_USERNAME": "admin"},
		"both gluetun auth kinds": {"GLUETUN_API_KEY": "k", "GLUETUN_USERNAME": "u", "GLUETUN_PASSWORD": "p"},
		"bad gluetun url":         {"GLUETUN_URL": "gluetun:8000"},
		"switch candidates zero":  {"SWITCH_CANDIDATES": "0"},
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
	t.Setenv("SERVERS_ONLY_ALLOWED_COUNTRIES", "true")

	if _, err := Load(); err == nil {
		t.Fatal("expected an error when the option is set without COUNTRIES")
	}
}

func TestLoadAcceptsFullConfiguration(t *testing.T) {
	setMinimal(t)
	for key, value := range map[string]string{
		"COUNTRIES":                    "Sweden,Norway",
		"EXCLUDE_COUNTRIES":            "Norway",
		"CITIES":                       "Stockholm",
		"MAX_LOAD":                     "70",
		"VPN_TYPE":                     "wireguard",
		"SECURE_CORE":                  "only",
		"TOR":                          "include",
		"P2P":                          "only",
		"FREE_TIER":                    "exclude",
		"SCORE_LOAD_WEIGHT":            "2",
		"SCORE_LATENCY_WEIGHT":         "1.5",
		"SCORE_PROTON_WEIGHT":          "0.25",
		"SCORE_LATENCY_CEILING":        "120ms",
		"LATENCY_TOP_N":                "40",
		"AUTO_SWITCH":                  "false",
		"RECONNECT_MODE":               "status",
		"SWITCH_LOAD_TRIGGER":          "75",
		"SERVERS_WRITE_MODE":           "replace",
		"SERVERS_SCHEMA_VERSION":       "5",
		"SERVERS_INCLUDE_IPV6":         "yes",
		"DASHBOARD_USERNAME":           "admin",
		"DASHBOARD_PASSWORD":           "hunter2",
		"LOG_LEVEL":                    "debug",
		"LOG_FORMAT":                   "json",
		"PROTON_LOAD_REFRESH_INTERVAL": "5m",
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

	for _, testCase := range []struct {
		input string
		want  uint64
	}{
		{"1MB", 1_000_000},
		{"1mb", 1_000_000},
		{"1 MB", 1_000_000},
		{"1MB/s", 1_000_000},
		{"500KB", 500_000},
		{"1MiB", 1 << 20},
		{"2MiB", 2 << 20},
		{"1GB", 1_000_000_000},
		{"1.5MB", 1_500_000},
		{"2M", 2_000_000},
		{"1024", 1024}, // a bare number is bytes per second
		{"0", 0},
		{"1024B", 1024},
	} {
		got, err := parseByteRate(testCase.input)
		if err != nil {
			t.Errorf("parseByteRate(%q): %v", testCase.input, err)
			continue
		}
		if got != testCase.want {
			t.Errorf("parseByteRate(%q) = %d, want %d", testCase.input, got, testCase.want)
		}
	}

	for _, bad := range []string{"", "lots", "-1MB", "MB", "1XB"} {
		if _, err := parseByteRate(bad); err == nil {
			t.Errorf("parseByteRate(%q) should have failed", bad)
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
				"SWITCH_BUSY_DOWNLOAD": "0", "SWITCH_BUSY_UPLOAD": "0",
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
		if _, err := parseByteRate(value); err == nil {
			t.Errorf("parseByteRate(%q) should have been rejected", value)
		}
	}
	// And a value that overflows uint64 once scaled. Converting an out-of-range float
	// to an integer is undefined in Go, so this must be caught before the conversion.
	// 2e19 is above MaxUint64 (~1.845e19); 1e19 is below it and must stay acceptable.
	for _, value := range []string{"99999999999999999999TB", "1e30MB", "2e19"} {
		if got, err := parseByteRate(value); err == nil {
			t.Errorf("parseByteRate(%q) = %d, should have been rejected as too large", value, got)
		}
	}
	// Something large but genuinely representable stays acceptable.
	for _, value := range []string{"10GB", "1e19"} {
		if _, err := parseByteRate(value); err != nil {
			t.Errorf("parseByteRate(%q) should be accepted: %v", value, err)
		}
	}
}

// The same class of bug in the float reader, which the scoring weights use.
func TestNonFiniteScoringWeightsAreRejected(t *testing.T) {
	for _, key := range []string{"SCORE_LOAD_WEIGHT", "SCORE_LATENCY_WEIGHT", "SCORE_PROTON_WEIGHT"} {
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
	t.Setenv("SWITCH_BUSY_DOWNLOAD", "nan")

	if _, err := Load(); err == nil {
		t.Fatal("SWITCH_BUSY_DOWNLOAD=nan was accepted; it would never be exceeded")
	}
}
