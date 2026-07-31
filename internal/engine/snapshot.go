package engine

import (
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/catalog"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
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

	// Transfer is what qBittorrent reports moving through the tunnel, when it is
	// configured. Zero value with Configured false means the feature is off.
	Transfer TransferStatus `json:"transfer"`

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
	// TunnelIPv4 and TunnelIPv6 list the tunnel interface's own addresses. Showing both
	// is what makes "IPv4 only" a statement rather than an inference from a blank row.
	//
	// This is the only IPv6 fact Gluetun exposes. Its public-IP endpoint returns a
	// single address, so there is no separate public IPv6 exit to report; whether the
	// tunnel carries IPv6 at all is the answerable question.
	TunnelIPv4 []string `json:"tunnel_ipv4,omitempty"`
	TunnelIPv6 []string `json:"tunnel_ipv6,omitempty"`
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
	// current versions, "legacy" for v3.41.3 and earlier, "both" when Gluetun has
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
	// OnCurrentSince is when the tunnel arrived on the server it is on, zero when that
	// is not known.
	//
	// It is only set when the current server is the one this tool pinned: if Gluetun
	// moved on its own, or the tunnel was already up when this container started, the
	// arrival time is genuinely unknown and a number would be a guess.
	OnCurrentSince time.Time `json:"on_current_since,omitempty"`
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

// TransferStatus is the traffic currently flowing, and what the engine does about it.
//
// It exists so a switch can be deferred rather than interrupting a transfer: tearing
// the tunnel down takes every connection through it with it.
type TransferStatus struct {
	// Configured is false when QBITTORRENT_URL is unset. Distinguishing that from
	// "configured and idle" matters: one means no information, the other means no
	// traffic, and only the second is a reason to allow a switch.
	Configured bool `json:"configured"`
	// Reachable is false when the last read failed. The rates below are then the
	// last known values, not current ones.
	Reachable bool `json:"reachable"`
	// HasReading is false until qBittorrent has answered at least once.
	//
	// It is distinct from Busy being false, and the difference matters: with no
	// reading at all, "not busy" means "unmeasured", not "idle". Reporting the second
	// would be a claim about traffic nobody has looked at.
	HasReading bool   `json:"has_reading"`
	LastError  string `json:"last_error,omitempty"`
	// Source names where the rates came from, because it changes what they cover: a torrent
	// client reports its own traffic, while a source inside the tunnel would report all of it.
	Source string `json:"source,omitempty"`
	// DownloadSpeed and UploadSpeed are the latest reading, in bits per second.
	//
	// Bits throughout: sources convert at the boundary, the thresholds are configured in
	// megabits, and the dashboard displays bits - so nothing in between multiplies by
	// anything. Volumes stay in bytes, which is the unit a volume belongs in.
	DownloadSpeed uint64 `json:"download_speed"`
	UploadSpeed   uint64 `json:"upload_speed"`
	// AverageDownload and AverageUpload are the mean over BusyWindow, and are what the
	// thresholds are actually compared against.
	//
	// Published separately from the latest reading because the two differ, and the one
	// that decides is the one worth showing next to the threshold: a card that showed
	// only the instantaneous rate would appear to contradict its own verdict every
	// time traffic dipped.
	AverageDownload uint64 `json:"average_download"`
	AverageUpload   uint64 `json:"average_upload"`
	// BusyWindow is the averaging period, and Samples how many readings are in it.
	BusyWindow string `json:"busy_window,omitempty"`
	Samples    int    `json:"samples"`
	// DownloadTotal and UploadTotal are bytes moved this qBittorrent session.
	DownloadTotal uint64 `json:"download_total"`
	UploadTotal   uint64 `json:"upload_total"`
	// DownloadLimit and UploadLimit are qBittorrent's configured caps, 0 for
	// unlimited. They give the rates context.
	DownloadLimit uint64 `json:"download_limit"`
	UploadLimit   uint64 `json:"upload_limit"`
	// ConnectionStatus is qBittorrent's own peer connectivity view: "connected",
	// "firewalled" or "disconnected".
	//
	// Note what this is *not*: it says nothing about whether this tool can reach
	// qBittorrent. That is Reachable. Presenting this one as "qBittorrent is
	// connected" conflated the two and was actively misleading.
	ConnectionStatus string `json:"connection_status,omitempty"`
	// ListenPort is the port qBittorrent accepts incoming peer connections on, and
	// RandomPort whether it re-chooses that port on every start.
	ListenPort uint16 `json:"listen_port,omitempty"`
	RandomPort bool   `json:"random_port,omitempty"`
	// ListenPortError is why ListenPort is unknown, when it is. The settings are read
	// separately from the rates and can fail on their own - an API key that is refused
	// for /api/v2/app/preferences, for instance - and an "unknown" with no reason
	// attached is not actionable.
	ListenPortError string `json:"listen_port_error,omitempty"`
	// PortForwarding is the verdict on whether a forwarded port actually reaches
	// qBittorrent: "working", "unreachable", "mismatch", "not requested" or
	// "unknown". PortForwardingDetail explains it in a sentence.
	//
	// It is computed rather than reported, because no single source knows the answer:
	// Gluetun knows which port Proton forwarded, qBittorrent knows which port it
	// listens on and whether anything is arriving, and only comparing the two catches
	// the common case where forwarding "works" while every incoming connection goes
	// nowhere.
	PortForwarding       string `json:"port_forwarding,omitempty"`
	PortForwardingDetail string `json:"port_forwarding_detail,omitempty"`
	// Busy is true when either rate is above its threshold, which is what defers a
	// switch.
	Busy bool `json:"busy"`
	// BusySince is when the tunnel last became busy, so the dashboard can show how
	// long switching has been deferred.
	BusySince time.Time `json:"busy_since,omitempty"`
	// DeferredFor is how long switching has been held off, formatted for display.
	DeferredFor string `json:"deferred_for,omitempty"`
	// Thresholds are the configured limits, echoed so the dashboard can show the
	// rates against them rather than as bare numbers.
	BusyDownloadThreshold uint64    `json:"busy_download_threshold"`
	BusyUploadThreshold   uint64    `json:"busy_upload_threshold"`
	MaxDefer              string    `json:"max_defer,omitempty"`
	LastCheck             time.Time `json:"last_check"`
	// Version is qBittorrent's reported version, proof the credentials work.
	Version string `json:"version,omitempty"`
}

// CandidateView is one ranked server, flattened for the UI.
type CandidateView struct {
	Rank       int    `json:"rank"`
	Hostname   string `json:"hostname"`
	ServerName string `json:"server_name"`
	Country    string `json:"country"`
	City       string `json:"city"`
	// Region is Proton's own grouping, which it fills in for some servers and not
	// others. Shown in the detail panel rather than the table, where it would be an
	// empty column most of the time.
	Region string `json:"region,omitempty"`
	// LogicalID identifies the logical server to Proton. It is what a Proton support
	// conversation or a raw API query needs, and nothing else in the UI can supply it.
	LogicalID string `json:"logical_id,omitempty"`
	EntryIP   string `json:"entry_ip"`
	// EntryIPv6 is only recorded when GLUETUN_SERVERS_INCLUDE_IPV6 is on, so its
	// absence says nothing about whether the server supports IPv6 - that is the IPv6
	// flag below.
	EntryIPv6 string `json:"entry_ipv6,omitempty"`
	ExitIP    string `json:"exit_ip,omitempty"`
	// ProtonScore is Proton's own routing preference, lower better, exactly as Proton
	// reported it. ProtonPart below is what that becomes after weighting; this is the
	// input, and the two are worth being able to compare.
	ProtonScore float64 `json:"proton_score"`
	// Tier is the plan level the server requires: 0 free, 2 Plus. Nil when Proton did
	// not say, which is reported as unknown rather than guessed at.
	Tier        *uint8  `json:"tier,omitempty"`
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
	IPv6        bool    `json:"ipv6"`
	Wireguard   bool    `json:"wireguard"`
	IsCurrent   bool    `json:"is_current"`
	// Excluded marks a server that is not in the allowed candidate set. It is
	// only ever set on the current server, to explain why it has no rank.
	Excluded bool `json:"excluded,omitempty"`
	// Blocked marks a server Gluetun's own filters rule out. It is shown but not
	// selectable, and BlockedBy names the Gluetun settings responsible.
	Blocked   bool     `json:"blocked,omitempty"`
	BlockedBy []string `json:"blocked_by,omitempty"`
	// Stats is what has been observed about this server over time, or nil if nothing has
	// been. Nil rather than a zeroed record, because "never measured" and "measured as
	// zero" are different facts.
	Stats *ServerStatsView `json:"stats,omitempty"`
}

// ServerStatsView is the dashboard's view of what has been measured about one server.
//
// Reduced to extremes, totals and counts rather than a series of readings. Those answer
// the questions a graph was being read for - is this server reliably quiet, has it ever
// been slow, how much have I pulled through it - without a state file that grows with
// every server and every hour.
//
// "Lowest" and "highest" rather than "best" and "worst": reading those requires knowing
// which direction is good. For load and latency lowest is best, and the dashboard labels
// them accordingly.
type ServerStatsView struct {
	// Load as Proton last reported it, and the extremes ever seen. 0-100.
	LoadLast    uint8 `json:"load,omitempty"`
	LoadLowest  uint8 `json:"load_lowest,omitempty"`
	LoadHighest uint8 `json:"load_highest,omitempty"`
	// Latency in whole milliseconds, and its extremes. Zero means never measured: the
	// prober only covers LATENCY_TOP_N servers, so that is a normal state.
	RTTLastMS    uint16 `json:"rtt_ms,omitempty"`
	RTTLowestMS  uint16 `json:"rtt_lowest_ms,omitempty"`
	RTTHighestMS uint16 `json:"rtt_highest_ms,omitempty"`
	// TransferKnown says whether the four transfer figures below mean anything. Without
	// the qBittorrent integration nothing measures throughput at all, and a zero would
	// otherwise read as "this server carried nothing".
	TransferKnown bool `json:"transfer_known,omitempty"`
	// DownloadedBytes and UploadedBytes are every byte ever moved through this server.
	// Never reset by a reconnect or a return visit.
	DownloadedBytes uint64 `json:"downloaded,omitempty"`
	UploadedBytes   uint64 `json:"uploaded,omitempty"`
	// MaxDownloadRate and MaxUploadRate are the fastest it was seen to go, in bits per
	// second.
	MaxDownloadRate uint64 `json:"max_download,omitempty"`
	MaxUploadRate   uint64 `json:"max_upload,omitempty"`
	// The timestamps are always serialised, zero included, and the dashboard recognises a
	// zero time by its value. Not `omitzero`: that option arrived in Go 1.24 and this module
	// targets 1.23, where encoding/json ignores it silently - while the container image is
	// built with 1.24, where it works. The same code produced different JSON depending on
	// which toolchain compiled it, which is a trap regardless of how small the difference
	// looked.
	LastTransferAt time.Time `json:"last_transfer_at"`
	// Samples counts load and latency observations; TransferReadings counts qBittorrent
	// polls attributed to this server. Two counters, because they come from different
	// sources on different cycles and one number would misrepresent both.
	Samples          int       `json:"samples,omitempty"`
	TransferReadings int       `json:"transfer_readings,omitempty"`
	Visits           int       `json:"visits,omitempty"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	// Current marks the server being measured right now, so a figure that is still
	// moving is not read as a final verdict.
	Current bool `json:"current,omitempty"`
}

// SettingsView exposes the effective configuration, so the dashboard can show
// why the tool behaves the way it does without the operator digging through
// compose files.
type SettingsView struct {
	// Variables is every configuration variable as it actually resolved, including the
	// ones left at their defaults, in the order they were read.
	//
	// The panel used to be a hand-written list of about half of them, which drifted every
	// time one was added or renamed. This cannot drift: it is recorded while the
	// configuration is parsed. Secret values are never present - see config.Variable.
	Variables        []config.Variable `json:"variables,omitempty"`
	Countries        []string          `json:"countries"`
	ExcludeCountries []string          `json:"exclude_countries,omitempty"`
	Cities           []string          `json:"cities,omitempty"`
	MaxLoad          int               `json:"max_load"`
	VPNType          string            `json:"vpn_type"`
	SecureCore       string            `json:"secure_core"`
	Tor              string            `json:"tor"`
	P2P              string            `json:"p2p"`
	Stream           string            `json:"stream"`
	FreeTier         string            `json:"free_tier"`
	IPv6Filter       string            `json:"ipv6_filter"`

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
