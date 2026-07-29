package engine

import (
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/catalog"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/latency"
)

// Snapshot is the complete, JSON-serialisable view of the engine. The dashboard
// renders nothing but this, which keeps the UI and the engine decoupled: there
// is exactly one place where internal state becomes external.
type Snapshot struct {
	At        time.Time `json:"at"`
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
	// Activity names the task currently running, empty when idle. It exists so
	// a click on "Refresh" gives immediate feedback.
	Activity string `json:"activity"`

	Proton    ProtonStatus    `json:"proton"`
	Gluetun   GluetunStatus   `json:"gluetun"`
	Servers   ServersStatus   `json:"servers_file"`
	Selection SelectionStatus `json:"selection"`

	Stats   catalog.Stats   `json:"stats"`
	Latency latency.Summary `json:"latency"`

	// Candidates is the ranked shortlist, capped so the payload stays small
	// enough to push over SSE every few seconds.
	//
	// It ends with any Blocked entries: servers Gluetun's own filters rule out,
	// listed for diagnosis but never selectable.
	Candidates      []CandidateView `json:"candidates"`
	CandidatesTotal int             `json:"candidates_total"`
	// CandidatesBlocked counts the blocked servers, which are not part of
	// CandidatesTotal.
	CandidatesBlocked int `json:"candidates_blocked"`

	History  []SwitchRecord    `json:"history"`
	NextRuns map[string]string `json:"next_runs"`
	Settings SettingsView      `json:"settings"`
}

// ProtonStatus reports the state of the Proton API side.
type ProtonStatus struct {
	LoggedIn bool   `json:"logged_in"`
	Session  string `json:"session"`
	// NeedsTOTP is true when a login is blocked waiting for a two-factor code
	// to be submitted from the dashboard.
	NeedsTOTP        bool      `json:"needs_totp"`
	LastFetch        time.Time `json:"last_fetch"`
	LastFetchError   string    `json:"last_fetch_error,omitempty"`
	LastLoadRefresh  time.Time `json:"last_load_refresh"`
	LastLoadError    string    `json:"last_load_error,omitempty"`
	LogicalsCount    int       `json:"logicals_count"`
	ListLastModified time.Time `json:"list_last_modified"`
	// FromCache is true when the current list came from disk because Proton
	// could not be reached.
	FromCache bool `json:"from_cache"`
	// AccountTier is the highest server tier this account may connect to: 0 is
	// free, 2 is Plus. Servers above it are excluded, because Proton refuses them.
	AccountTier *uint8 `json:"account_tier,omitempty"`
	AccountPlan string `json:"account_plan,omitempty"`
	AccountFree bool   `json:"account_free"`
	// MaxConnections is how many simultaneous sessions the plan allows.
	MaxConnections uint8 `json:"max_connections,omitempty"`
	// AccountDelinquent warns that Proton considers the account behind on payment,
	// a plausible cause of otherwise inexplicable connection refusals.
	AccountDelinquent bool `json:"account_delinquent"`
	// CacheStale is true when that cached list is older than
	// PROTON_CACHE_MAX_AGE. It is still used - a stale list beats none - but the
	// utilisation figures behind every decision may be well out of date.
	CacheStale bool `json:"cache_stale"`
}

// GluetunStatus is everything this tool reads from Gluetun's control server,
// surfaced as-is. It is deliberately complete: when something is wrong, the
// answer is almost always visible in one of these values, and having to reach
// for curl to see them is a poor experience.
type GluetunStatus struct {
	Reachable bool   `json:"reachable"`
	Status    string `json:"status"`
	// Version, Commit and Created come from GET /v1/version. The version also
	// determines the storage layout and schema version, so it is load-bearing.
	Version  string `json:"version"`
	Commit   string `json:"commit,omitempty"`
	Created  string `json:"created,omitempty"`
	VPNType  string `json:"vpn_type"`
	Provider string `json:"provider"`
	// Exit is Gluetun's own view of where traffic comes out, from
	// GET /v1/publicip/ip.
	Exit ExitInfo `json:"exit"`
	// ForwardedPorts is what Proton forwarded, from GET /v1/portforward.
	ForwardedPorts []uint16 `json:"forwarded_ports,omitempty"`
	// ExitCurrent is false when Exit and ForwardedPorts are the last values seen
	// rather than current ones, because the tunnel is not running right now. They
	// are deliberately kept: a poll landing mid-reconnect must not make a working
	// port forward read as "none".
	ExitCurrent bool `json:"exit_current"`
	// ExitObservedAt is when those values were last confirmed.
	ExitObservedAt time.Time `json:"exit_observed_at"`
	// PortForwardingEnabled distinguishes "no port yet" from "not requested".
	PortForwardingEnabled *bool `json:"port_forwarding_enabled,omitempty"`
	// DNSStatus is Gluetun's DNS-over-TLS resolver state, from
	// GET /v1/dns/status.
	DNSStatus string `json:"dns_status,omitempty"`
	// UpdaterStatus is Gluetun's own server-list updater state, from
	// GET /v1/updater/status.
	UpdaterStatus string `json:"updater_status,omitempty"`
	// Selection is the filter set Gluetun is currently applying, which is often
	// the reason a particular server was refused.
	Selection map[string][]string `json:"selection,omitempty"`
	// RequirementsAdopted lists the "only" filters this tool has taken on from
	// Gluetun, so it only ever picks servers Gluetun can actually use. They are
	// kept once seen: pinning a server clears them in Gluetun by design, so a
	// later "off" reading is our own doing rather than a change of intent.
	RequirementsAdopted []string `json:"requirements_adopted,omitempty"`
	// PortForwardRequirementFrom names the Gluetun setting behind the P2P
	// restriction: "PORT_FORWARD_ONLY" when Gluetun enforces it, or
	// "VPN_PORT_FORWARDING" when it only asked for a port and Proton forwards ports
	// on P2P servers alone.
	PortForwardRequirementFrom string `json:"port_forward_requirement_from,omitempty"`
	// KnownHostnames is how many servers Gluetun said it can actually use, the last
	// time it refused one. Zero means it has not refused anything, not that it knows
	// nothing. A value well below the candidate count means Gluetun is running on its
	// own built-in list and has to be restarted to pick up the one written here.
	KnownHostnames int       `json:"known_hostnames,omitempty"`
	LastCheck      time.Time `json:"last_check"`
	LastError      string    `json:"last_error,omitempty"`
	// ProviderMismatch warns that Gluetun is not configured for ProtonVPN, in
	// which case none of this tool's work can take effect.
	ProviderMismatch bool `json:"provider_mismatch"`
	// SettingsReadable is false when GET /v1/vpn/settings is refused, which
	// happens with Gluetun's default control-server role and also means
	// hostname pinning will be refused.
	SettingsReadable bool `json:"settings_readable"`
}

// ExitInfo is Gluetun's public-IP report.
type ExitInfo struct {
	IP           string `json:"ip,omitempty"`
	Country      string `json:"country,omitempty"`
	Region       string `json:"region,omitempty"`
	City         string `json:"city,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	Location     string `json:"location,omitempty"`
	Organization string `json:"organization,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	Timezone     string `json:"timezone,omitempty"`
}

// ServersStatus reports what was last written for Gluetun to read.
type ServersStatus struct {
	// Path is the configured legacy file, kept for display.
	Path      string `json:"path"`
	WriteMode string `json:"write_mode"`
	// Layout is the Gluetun storage layout that was detected: "directory" for
	// current versions, "legacy" for v3.41.2, "both" when Gluetun has
	// not written anything yet.
	Layout string `json:"layout"`
	// Paths lists the files actually written.
	Paths []string `json:"paths,omitempty"`
	// Preferred reports whether Gluetun's "preferred" flag was set, which makes
	// it use our servers regardless of timestamps.
	Preferred     bool      `json:"preferred"`
	SchemaVersion uint16    `json:"schema_version"`
	LastWrite     time.Time `json:"last_write"`
	ServerCount   int       `json:"server_count"`
	PreservedKeys []string  `json:"preserved_keys,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	// Ignored is true when Gluetun is running but keeps no server data on disk,
	// so nothing written here can have any effect. Server switching still works,
	// but only across the servers Gluetun has built in.
	Ignored bool `json:"ignored"`
	// IgnoredReason explains what to change.
	IgnoredReason string `json:"ignored_reason,omitempty"`
}

// SelectionStatus reports the current and desired server.
type SelectionStatus struct {
	AutoSwitch bool   `json:"auto_switch"`
	Mode       string `json:"mode"`
	// Current is the server the tunnel is believed to be on, identified either
	// by the hostname this tool pinned or by matching Gluetun's public IP
	// against Proton's exit addresses.
	Current *CandidateView `json:"current"`
	// CurrentSource explains how Current was determined: "pinned", "public-ip"
	// or "unknown".
	CurrentSource string         `json:"current_source"`
	Best          *CandidateView `json:"best"`
	// Improvement is how much better Best scores than Current; positive means
	// switching would help.
	Improvement       float64   `json:"improvement"`
	MinImprovement    float64   `json:"min_improvement"`
	LastEvaluation    time.Time `json:"last_evaluation"`
	LastSwitchAt      time.Time `json:"last_switch_at"`
	CooldownRemaining string    `json:"cooldown_remaining,omitempty"`
	// Explanation is why the last evaluation did *not* switch, in the same words the
	// decision was made in - "cooldown active for another 4m", "best server only
	// 0.021 better than current, need 0.050".
	//
	// It is published because "nothing is happening" is the state an operator most
	// often needs explained, and it was previously only visible at debug level in the
	// log. Empty when a switch did happen, or when none has been evaluated yet.
	Explanation string `json:"explanation,omitempty"`
	LastError   string `json:"last_error,omitempty"`
	// NeedsGluetunRestart is set when Gluetun refused every hostname we offered,
	// which means it is running with an older server list than the one now in
	// servers.json and must be restarted to pick it up.
	NeedsGluetunRestart bool `json:"needs_gluetun_restart"`
}

// CandidateView is one ranked server, flattened for the UI.
type CandidateView struct {
	Rank        int     `json:"rank"`
	Hostname    string  `json:"hostname"`
	ServerName  string  `json:"server_name"`
	Country     string  `json:"country"`
	City        string  `json:"city"`
	EntryIP     string  `json:"entry_ip"`
	ExitIP      string  `json:"exit_ip,omitempty"`
	Load        uint8   `json:"load"`
	RTTMS       float64 `json:"rtt_ms"`
	RTTKnown    bool    `json:"rtt_known"`
	Score       float64 `json:"score"`
	LoadPart    float64 `json:"score_load"`
	LatencyPart float64 `json:"score_latency"`
	ProtonPart  float64 `json:"score_proton"`
	SecureCore  bool    `json:"secure_core"`
	Tor         bool    `json:"tor"`
	P2P         bool    `json:"p2p"`
	Stream      bool    `json:"stream"`
	Free        bool    `json:"free"`
	Wireguard   bool    `json:"wireguard"`
	IsCurrent   bool    `json:"is_current"`
	// Excluded marks a server that is not in the allowed candidate set. It is
	// only ever set on the current server, to explain why it has no rank.
	Excluded bool `json:"excluded,omitempty"`
	// Blocked marks a server Gluetun's own filters rule out. It is shown but not
	// selectable, and BlockedBy names the Gluetun settings responsible.
	Blocked   bool     `json:"blocked,omitempty"`
	BlockedBy []string `json:"blocked_by,omitempty"`
}

// SettingsView exposes the effective configuration, so the dashboard can show
// why the tool behaves the way it does without the operator digging through
// compose files.
type SettingsView struct {
	Countries        []string `json:"countries"`
	ExcludeCountries []string `json:"exclude_countries,omitempty"`
	Cities           []string `json:"cities,omitempty"`
	MaxLoad          int      `json:"max_load"`
	VPNType          string   `json:"vpn_type"`
	SecureCore       string   `json:"secure_core"`
	Tor              string   `json:"tor"`
	P2P              string   `json:"p2p"`
	Stream           string   `json:"stream"`
	FreeTier         string   `json:"free_tier"`

	LoadWeight     float64 `json:"load_weight"`
	LatencyWeight  float64 `json:"latency_weight"`
	ProtonWeight   float64 `json:"proton_weight"`
	LatencyCeiling string  `json:"latency_ceiling"`

	RefreshInterval     string `json:"refresh_interval"`
	LoadRefreshInterval string `json:"load_refresh_interval"`
	LatencyInterval     string `json:"latency_interval"`
	EvaluationInterval  string `json:"evaluation_interval"`
	SwitchCooldown      string `json:"switch_cooldown"`
	SwitchMinInterval   string `json:"switch_min_interval"`
	LoadTrigger         int    `json:"load_trigger"`
	LatencyEnabled      bool   `json:"latency_enabled"`
	LatencyTopN         int    `json:"latency_top_n"`
}
