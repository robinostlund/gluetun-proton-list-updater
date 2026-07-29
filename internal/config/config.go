// Package config reads and validates the whole runtime configuration from
// environment variables. It is the only place that touches os.Getenv, so every
// other package receives a validated, immutable Config value.
package config

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/countries"
)

// Filter values for tri-state server categories.
const (
	FilterInclude = "include" // keep both kinds of server
	FilterExclude = "exclude" // drop servers with the feature
	FilterOnly    = "only"    // keep only servers with the feature
)

// Reconnect strategies, in order of decreasing preference.
const (
	// ReconnectSettings pins the chosen hostname through
	// PUT /v1/vpn/settings, which makes Gluetun reconnect to exactly that
	// server. This is the only mode that guarantees the selected server.
	ReconnectSettings = "settings"
	// ReconnectStatus stops and starts the tunnel through
	// PUT /v1/vpn/status. Gluetun then picks a server itself from the
	// filters it was started with, so the outcome is not guaranteed.
	ReconnectStatus = "status"
	// ReconnectNone never touches the tunnel; the tool only maintains
	// servers.json.
	ReconnectNone = "none"
)

// Servers file write modes.
const (
	// WriteModeUpdate rewrites only the protonvpn section and preserves every
	// other key already present in servers.json.
	WriteModeUpdate = "update"
	// WriteModeReplace writes a file containing only the protonvpn section.
	WriteModeReplace = "replace"
	// WriteModeNone disables writing entirely.
	WriteModeNone = "none"
)

// Config is the fully validated runtime configuration.
type Config struct {
	Proton    Proton
	Gluetun   Gluetun
	Servers   Servers
	Filter    Filter
	Score     Score
	Latency   Latency
	Switch    Switch
	Dashboard Dashboard

	// StateDir holds the Proton session, the cached server list and the
	// selection history. It must be writable and should be a volume so a
	// restart does not force a fresh Proton login.
	StateDir string
	LogLevel slog.Level
	// LogFormat is "text" or "json".
	LogFormat string
}

// Proton holds credentials and refresh cadence for the Proton API.
type Proton struct {
	Username string
	Password string
	// TOTPSecret is the base32 shared secret of the account's authenticator
	// app. When set, two-factor login is fully automatic. When empty and the
	// account requires 2FA, the tool waits for a code to be submitted from
	// the dashboard.
	TOTPSecret string
	// APIBaseURL defaults to Proton's VPN API host.
	APIBaseURL string
	// AppVersion is sent as x-pm-appversion. Proton rejects versions it
	// considers too old, so this may need bumping over time.
	AppVersion string
	UserAgent  string
	// RefreshInterval is how often the full logical server list is fetched.
	RefreshInterval time.Duration
	// LoadRefreshInterval is how often the much cheaper /vpn/v1/loads
	// endpoint is polled to update utilisation figures.
	LoadRefreshInterval time.Duration
	// RequestTimeout bounds a single HTTP request to the Proton API.
	RequestTimeout time.Duration
}

// Gluetun describes how to reach the Gluetun control server.
type Gluetun struct {
	BaseURL string
	// APIKey, Username and Password cover Gluetun's control server auth
	// methods. Leave all empty when the control server uses auth = "none".
	APIKey   string
	Username string
	Password string
	// RequestTimeout bounds read-only requests to Gluetun.
	RequestTimeout time.Duration
	// MutationTimeout bounds requests that change the tunnel state. Gluetun does
	// not answer those until its VPN loop has restarted, which takes seconds
	// normally and far longer while a tunnel is unhealthy, so this must be
	// generous.
	MutationTimeout time.Duration
	// HealthInterval is how often Gluetun's status and public IP are polled.
	HealthInterval time.Duration
	// RefreshServersOnReject asks Gluetun to run its own server-list updater
	// when it rejects every hostname we offer.
	//
	// Gluetun only reads servers.json at startup and validates pinned hostnames
	// against that in-memory list, so a server Proton added since then is
	// unusable no matter how current our file is. Triggering Gluetun's updater
	// refreshes that in-memory list without restarting the container. It needs
	// UPDATER_PROTONVPN_EMAIL and UPDATER_PROTONVPN_PASSWORD set on the Gluetun
	// container; without them Gluetun skips the update and this is a no-op.
	RefreshServersOnReject bool
	// UpdaterTimeout bounds waiting for Gluetun's updater to finish.
	UpdaterTimeout time.Duration
}

// Servers describes how the server data Gluetun reads is produced.
type Servers struct {
	// FilePath is Gluetun's legacy single servers file, /gluetun/servers.json by
	// default. Used by Gluetun up to and including v3.41.1.
	FilePath string
	// DirPath is Gluetun's servers directory, /gluetun/servers/ by default.
	// Current Gluetun versions keep one file per provider there, and read the
	// legacy file only when the directory's manifest.json is absent - so writing
	// only the legacy file to a current Gluetun has no effect at all.
	//
	// Which layout is in use is detected at runtime; this is only the location.
	DirPath string
	// Preferred sets Gluetun's "preferred" flag on our servers, which makes
	// Gluetun use them regardless of timestamps. It removes the timestamp race
	// entirely. Gluetun versions that predate the flag ignore it harmlessly.
	Preferred bool
	// WriteMode is one of WriteModeUpdate, WriteModeReplace, WriteModeNone.
	WriteMode string
	// SchemaVersion is the per-provider version Gluetun expects. Gluetun
	// discards a servers file whose version does not match its built-in one.
	// Zero means "detect from the existing file, falling back to
	// DefaultSchemaVersion".
	SchemaVersion uint16
	// OnlyAllowedCountries restricts the written file to the countries in
	// Filter.Countries. Keeping the full list (the default) means a manual
	// override to another country still works.
	OnlyAllowedCountries bool
	// IncludeIPv6 adds Proton's IPv6 entry addresses to the servers written.
	IncludeIPv6 bool
}

// DefaultSchemaVersion is the protonvpn servers schema version used by Gluetun
// v3.41.x. It is only a fallback: the real version is read from the servers
// file Gluetun itself wrote.
const DefaultSchemaVersion = 4

// Filter narrows the Proton server list down to acceptable candidates.
type Filter struct {
	// Countries is the allow-list of canonical Gluetun country names. Empty
	// means every country is allowed.
	Countries []string
	// ExcludeCountries is applied after Countries.
	ExcludeCountries []string
	// Cities, when set, further restricts candidates.
	Cities []string
	// MaxLoad drops servers reporting a higher utilisation percentage.
	MaxLoad int
	// SecureCore, Tor, P2P, Stream and Free are tri-state filters.
	SecureCore string
	Tor        string
	P2P        string
	Stream     string
	Free       string
	// VPNType is "auto", "wireguard" or "openvpn". "auto" asks Gluetun which
	// protocol it is configured for and follows it.
	VPNType string
}

// Score weights the candidate ranking. Lower scores win.
type Score struct {
	// LoadWeight applies to load/100.
	LoadWeight float64
	// LatencyWeight applies to min(latency, LatencyCeiling)/LatencyCeiling.
	LatencyWeight float64
	// ProtonScoreWeight applies to Proton's own server score, normalised
	// against the best score in the candidate set.
	ProtonScoreWeight float64
	// LatencyCeiling is the round-trip time that scores a full latency
	// penalty of 1.0.
	LatencyCeiling time.Duration
	// UnknownLatencyPenalty is the normalised latency value assumed for a
	// server that has not been probed yet, so unprobed servers are neither
	// unfairly favoured nor excluded.
	UnknownLatencyPenalty float64
}

// Latency configures active round-trip probing of Proton entry IPs.
type Latency struct {
	Enabled bool
	// Port is TCP-dialled to measure the round trip. 443 is served by every
	// Proton entry node for OpenVPN/TCP.
	Port int
	// Samples per server; the minimum round trip is kept, which filters out
	// scheduler and queueing noise.
	Samples int
	// Timeout bounds a single dial.
	Timeout time.Duration
	// Concurrency bounds parallel dials.
	Concurrency int
	// Interval is how often probing runs.
	Interval time.Duration
	// TopN limits probing to the N most promising candidates, keeping probe cost
	// proportional to what can realistically be selected. Zero probes all.
	//
	// Candidates are chosen by load, never by score: including latency in that
	// choice would mean an unprobed server's latency penalty kept it out of the
	// probe budget, so it could never become probed.
	TopN int
	// SmoothingFactor is the EWMA weight given to a new measurement
	// (0 < f <= 1). Lower values make scores steadier across runs.
	SmoothingFactor float64
}

// Switch controls when the tunnel is actually moved to another server.
type Switch struct {
	// Auto enables autonomous switching. When false, switching only happens
	// when triggered from the dashboard.
	Auto bool
	// Mode is one of ReconnectSettings, ReconnectStatus, ReconnectNone.
	Mode string
	// MinImprovement is the score gap the challenger must beat the current
	// server by. It is the main defence against reconnect flapping.
	MinImprovement float64
	// Cooldown is the minimum time between two automatic switches.
	Cooldown time.Duration
	// MinInterval is a hard floor between automatic switches that nothing
	// bypasses - not even LoadTrigger. Cooldown is the normal spacing;
	// MinInterval is the guarantee that a pathological situation (every server
	// overloaded, so every evaluation wants to move) cannot turn into a
	// reconnect loop that tears down connections repeatedly.
	MinInterval time.Duration
	// LoadTrigger forces a switch when the current server's load exceeds this
	// percentage, regardless of MinImprovement. Zero disables it.
	LoadTrigger int
	// Interval is how often the current server is re-evaluated.
	Interval time.Duration
	// VerifyTimeout bounds waiting for the tunnel to come back up after a
	// switch.
	VerifyTimeout time.Duration
	// Candidates is how many of the best servers are tried before giving up
	// on a switch.
	Candidates int
}

// Dashboard configures the built-in web UI.
type Dashboard struct {
	Enabled bool
	Address string
	// Username and Password enable HTTP basic auth when both are set.
	Username string
	Password string
}

// Load reads the configuration from the environment.
func Load() (cfg Config, err error) {
	r := &reader{}

	cfg.StateDir = r.str("STATE_DIR", "/data")
	cfg.LogFormat = r.choice("LOG_FORMAT", "text", "text", "json")
	cfg.LogLevel = parseLevel(r, "LOG_LEVEL", slog.LevelInfo)

	cfg.Proton = Proton{
		Username:            r.required("PROTON_USERNAME"),
		Password:            r.required("PROTON_PASSWORD"),
		TOTPSecret:          strings.ReplaceAll(r.str("PROTON_TOTP_SECRET", ""), " ", ""),
		APIBaseURL:          strings.TrimSuffix(r.str("PROTON_API_URL", "https://vpn-api.proton.me"), "/"),
		AppVersion:          r.str("PROTON_APP_VERSION", "linux-vpn-cli@4.15.2"),
		UserAgent:           r.str("PROTON_USER_AGENT", "ProtonVPN/4.15.2 (Linux)"),
		RefreshInterval:     r.duration("PROTON_REFRESH_INTERVAL", 12*time.Hour),
		LoadRefreshInterval: r.duration("PROTON_LOAD_REFRESH_INTERVAL", 15*time.Minute),
		RequestTimeout:      r.duration("PROTON_REQUEST_TIMEOUT", 30*time.Second),
	}

	cfg.Gluetun = Gluetun{
		BaseURL:                strings.TrimSuffix(r.str("GLUETUN_URL", "http://gluetun:8000"), "/"),
		APIKey:                 r.str("GLUETUN_API_KEY", ""),
		Username:               r.str("GLUETUN_USERNAME", ""),
		Password:               r.str("GLUETUN_PASSWORD", ""),
		RequestTimeout:         r.duration("GLUETUN_REQUEST_TIMEOUT", 10*time.Second),
		MutationTimeout:        r.duration("GLUETUN_MUTATION_TIMEOUT", 2*time.Minute),
		HealthInterval:         r.duration("GLUETUN_HEALTH_INTERVAL", 30*time.Second),
		RefreshServersOnReject: r.boolean("GLUETUN_REFRESH_SERVERS_ON_REJECT", true),
		UpdaterTimeout:         r.duration("GLUETUN_UPDATER_TIMEOUT", 3*time.Minute),
	}

	cfg.Servers = Servers{
		FilePath:             r.str("SERVERS_FILE", "/gluetun/servers.json"),
		DirPath:              r.str("SERVERS_DIR", "/gluetun/servers"),
		Preferred:            r.boolean("SERVERS_PREFERRED", true),
		WriteMode:            r.choice("SERVERS_WRITE_MODE", WriteModeUpdate, WriteModeUpdate, WriteModeReplace, WriteModeNone),
		SchemaVersion:        uint16(r.integer("SERVERS_SCHEMA_VERSION", 0)), //nolint:gosec // range checked below
		OnlyAllowedCountries: r.boolean("SERVERS_ONLY_ALLOWED_COUNTRIES", false),
		IncludeIPv6:          r.boolean("SERVERS_INCLUDE_IPV6", false),
	}

	cfg.Filter = Filter{
		Countries:        r.csv("COUNTRIES"),
		ExcludeCountries: r.csv("EXCLUDE_COUNTRIES"),
		Cities:           r.csv("CITIES"),
		MaxLoad:          r.integer("MAX_LOAD", 90),
		SecureCore:       r.choice("SECURE_CORE", FilterExclude, FilterInclude, FilterExclude, FilterOnly),
		Tor:              r.choice("TOR", FilterExclude, FilterInclude, FilterExclude, FilterOnly),
		P2P:              r.choice("P2P", FilterInclude, FilterInclude, FilterExclude, FilterOnly),
		Stream:           r.choice("STREAM", FilterInclude, FilterInclude, FilterExclude, FilterOnly),
		Free:             r.choice("FREE_TIER", FilterExclude, FilterInclude, FilterExclude, FilterOnly),
		VPNType:          r.choice("VPN_TYPE", "auto", "auto", "wireguard", "openvpn"),
	}

	cfg.Score = Score{
		LoadWeight:            r.float("SCORE_LOAD_WEIGHT", 1.0),
		LatencyWeight:         r.float("SCORE_LATENCY_WEIGHT", 0.7),
		ProtonScoreWeight:     r.float("SCORE_PROTON_WEIGHT", 0.0),
		LatencyCeiling:        r.duration("SCORE_LATENCY_CEILING", 150*time.Millisecond),
		UnknownLatencyPenalty: r.float("SCORE_UNKNOWN_LATENCY_PENALTY", 0.5),
	}

	cfg.Latency = Latency{
		Enabled:         r.boolean("LATENCY_ENABLED", true),
		Port:            r.integer("LATENCY_PORT", 443),
		Samples:         r.integer("LATENCY_SAMPLES", 3),
		Timeout:         r.duration("LATENCY_TIMEOUT", 2*time.Second),
		Concurrency:     r.integer("LATENCY_CONCURRENCY", 24),
		Interval:        r.duration("LATENCY_INTERVAL", 30*time.Minute),
		TopN:            r.integer("LATENCY_TOP_N", 150),
		SmoothingFactor: r.float("LATENCY_SMOOTHING", 0.5),
	}

	cfg.Switch = Switch{
		Auto:           r.boolean("AUTO_SWITCH", true),
		Mode:           r.choice("RECONNECT_MODE", ReconnectSettings, ReconnectSettings, ReconnectStatus, ReconnectNone),
		MinImprovement: r.float("SWITCH_MIN_IMPROVEMENT", 0.10),
		Cooldown:       r.duration("SWITCH_COOLDOWN", 15*time.Minute),
		MinInterval:    r.duration("SWITCH_MIN_INTERVAL", 5*time.Minute),
		LoadTrigger:    r.integer("SWITCH_LOAD_TRIGGER", 85),
		Interval:       r.duration("SWITCH_EVALUATION_INTERVAL", 5*time.Minute),
		VerifyTimeout:  r.duration("SWITCH_VERIFY_TIMEOUT", 90*time.Second),
		Candidates:     r.integer("SWITCH_CANDIDATES", 3),
	}

	cfg.Dashboard = Dashboard{
		Enabled:  r.boolean("DASHBOARD_ENABLED", true),
		Address:  r.str("DASHBOARD_ADDRESS", ":8080"),
		Username: r.str("DASHBOARD_USERNAME", ""),
		Password: r.str("DASHBOARD_PASSWORD", ""),
	}

	cfg.normalizeAndValidate(r)

	if len(r.errs) > 0 {
		return Config{}, fmt.Errorf("invalid configuration:\n  - %s",
			strings.Join(errorStrings(r.errs), "\n  - "))
	}
	return cfg, nil
}

func (cfg *Config) normalizeAndValidate(r *reader) {
	cfg.Filter.Countries = normalizeCountries(r, "COUNTRIES", cfg.Filter.Countries)
	cfg.Filter.ExcludeCountries = normalizeCountries(r, "EXCLUDE_COUNTRIES", cfg.Filter.ExcludeCountries)

	if cfg.Filter.MaxLoad < 1 || cfg.Filter.MaxLoad > 100 {
		r.errorf("MAX_LOAD: %d must be between 1 and 100", cfg.Filter.MaxLoad)
	}
	if cfg.Servers.OnlyAllowedCountries && len(cfg.Filter.Countries) == 0 {
		r.errorf("SERVERS_ONLY_ALLOWED_COUNTRIES requires COUNTRIES to be set")
	}
	if cfg.Latency.Port < 1 || cfg.Latency.Port > 65535 {
		r.errorf("LATENCY_PORT: %d is not a valid port", cfg.Latency.Port)
	}
	if cfg.Latency.Samples < 1 {
		r.errorf("LATENCY_SAMPLES: must be at least 1")
	}
	if cfg.Latency.Concurrency < 1 {
		r.errorf("LATENCY_CONCURRENCY: must be at least 1")
	}
	if cfg.Latency.SmoothingFactor <= 0 || cfg.Latency.SmoothingFactor > 1 {
		r.errorf("LATENCY_SMOOTHING: must be greater than 0 and at most 1")
	}
	if cfg.Latency.TopN < 0 {
		r.errorf("LATENCY_TOP_N: must not be negative")
	}
	if cfg.Score.LoadWeight < 0 || cfg.Score.LatencyWeight < 0 || cfg.Score.ProtonScoreWeight < 0 {
		r.errorf("score weights must not be negative")
	}
	if cfg.Score.LoadWeight+cfg.Score.LatencyWeight+cfg.Score.ProtonScoreWeight == 0 {
		r.errorf("at least one of SCORE_LOAD_WEIGHT, SCORE_LATENCY_WEIGHT, SCORE_PROTON_WEIGHT must be greater than 0")
	}
	if cfg.Score.LatencyCeiling <= 0 {
		r.errorf("SCORE_LATENCY_CEILING: must be greater than 0")
	}
	if cfg.Switch.Candidates < 1 {
		r.errorf("SWITCH_CANDIDATES: must be at least 1")
	}
	if cfg.Switch.LoadTrigger < 0 || cfg.Switch.LoadTrigger > 100 {
		r.errorf("SWITCH_LOAD_TRIGGER: must be between 0 and 100")
	}
	if cfg.Servers.SchemaVersion > 0 && cfg.Servers.SchemaVersion > 1000 {
		r.errorf("SERVERS_SCHEMA_VERSION: %d looks implausible", cfg.Servers.SchemaVersion)
	}
	if (cfg.Dashboard.Username == "") != (cfg.Dashboard.Password == "") {
		r.errorf("DASHBOARD_USERNAME and DASHBOARD_PASSWORD must be set together")
	}
	if cfg.Gluetun.APIKey != "" && cfg.Gluetun.Username != "" {
		r.errorf("set either GLUETUN_API_KEY or GLUETUN_USERNAME/GLUETUN_PASSWORD, not both")
	}
	if (cfg.Gluetun.Username == "") != (cfg.Gluetun.Password == "") {
		r.errorf("GLUETUN_USERNAME and GLUETUN_PASSWORD must be set together")
	}
	if !strings.HasPrefix(cfg.Gluetun.BaseURL, "http://") && !strings.HasPrefix(cfg.Gluetun.BaseURL, "https://") {
		r.errorf("GLUETUN_URL: %q must start with http:// or https://", cfg.Gluetun.BaseURL)
	}

	// A load refresh cheaper than the full refresh is the point of having
	// two intervals; warn-by-error if they are inverted, as that is almost
	// certainly a mistake that would hammer the API.
	if cfg.Proton.LoadRefreshInterval > 0 && cfg.Proton.LoadRefreshInterval < time.Minute {
		r.errorf("PROTON_LOAD_REFRESH_INTERVAL: %s is too aggressive, use at least 1m", cfg.Proton.LoadRefreshInterval)
	}
	if cfg.Proton.RefreshInterval > 0 && cfg.Proton.RefreshInterval < 15*time.Minute {
		r.errorf("PROTON_REFRESH_INTERVAL: %s is too aggressive, use at least 15m", cfg.Proton.RefreshInterval)
	}
}

func normalizeCountries(r *reader, key string, inputs []string) (names []string) {
	if len(inputs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(inputs))
	names = make([]string, 0, len(inputs))
	for _, input := range inputs {
		name, err := countries.Normalize(input)
		if err != nil {
			r.errorf("%s: %s", key, err)
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func parseLevel(r *reader, key string, defaultLevel slog.Level) slog.Level {
	value, isSet := r.lookup(key)
	if !isSet {
		return defaultLevel
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(value)); err != nil {
		r.errorf("%s: %q is not a log level (debug, info, warn, error)", key, value)
		return defaultLevel
	}
	return level
}

func errorStrings(errs []error) (strs []string) {
	strs = make([]string, len(errs))
	for i, err := range errs {
		strs[i] = err.Error()
	}
	return strs
}
