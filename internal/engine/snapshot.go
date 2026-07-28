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
	Candidates      []CandidateView `json:"candidates"`
	CandidatesTotal int             `json:"candidates_total"`

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
}

// GluetunStatus reports the state of the Gluetun side.
type GluetunStatus struct {
	Reachable     bool      `json:"reachable"`
	Status        string    `json:"status"`
	Version       string    `json:"version"`
	VPNType       string    `json:"vpn_type"`
	Provider      string    `json:"provider"`
	PublicIP      string    `json:"public_ip"`
	Country       string    `json:"country"`
	City          string    `json:"city"`
	ForwardedPort uint16    `json:"forwarded_port"`
	LastCheck     time.Time `json:"last_check"`
	LastError     string    `json:"last_error,omitempty"`
	// ProviderMismatch warns that Gluetun is not configured for ProtonVPN, in
	// which case none of this tool's work can take effect.
	ProviderMismatch bool `json:"provider_mismatch"`
}

// ServersStatus reports what was last written to servers.json.
type ServersStatus struct {
	Path          string    `json:"path"`
	WriteMode     string    `json:"write_mode"`
	SchemaVersion uint16    `json:"schema_version"`
	LastWrite     time.Time `json:"last_write"`
	ServerCount   int       `json:"server_count"`
	PreservedKeys []string  `json:"preserved_keys,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
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
	LastError         string    `json:"last_error,omitempty"`
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
