// Package catalog turns Proton's logical server list into the two things the
// rest of the tool needs: a flat list of connectable candidates to rank, and
// the server entries Gluetun expects in servers.json.
//
// One Proton "logical server" (SE#42) is backed by one or more physical
// machines. Gluetun connects to a physical machine by hostname, so a candidate
// here is one physical machine, carrying the load and score of the logical
// server it belongs to.
package catalog

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/countries"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/serversfile"
)

// VPN protocol names, matching Gluetun's values.
const (
	VPNWireguard = "wireguard"
	VPNOpenVPN   = "openvpn"
)

// Candidate is one physical Proton server that Gluetun could connect to.
type Candidate struct {
	// Hostname is Proton's Domain field and the value Gluetun pins on.
	Hostname string
	// ServerName is the human label, e.g. "SE#42".
	ServerName string
	// LogicalID lets a cheap /vpn/v1/loads refresh update this candidate
	// without re-fetching the whole list.
	LogicalID string
	Country   string
	Region    string
	City      string
	// EntryIP is the address Gluetun connects to and the address latency is
	// measured against.
	EntryIP   netip.Addr
	EntryIPv6 netip.Addr
	// ExitIP is the address the internet sees. It is what makes it possible to
	// identify which server Gluetun is currently on: Gluetun reports its public
	// IP, and that matches exactly one candidate's exit address.
	ExitIP netip.Addr
	// WgPubKey is empty when the machine has no WireGuard key, which makes it
	// unusable for WireGuard.
	WgPubKey string
	// Load is the utilisation percentage Proton reports for the logical server.
	Load uint8
	// ProtonScore is Proton's own preference value; lower is better.
	ProtonScore float64
	Free        bool
	SecureCore  bool
	Tor         bool
	P2P         bool
	Stream      bool
	// IPv6 is Proton's own capability flag for the logical server, independent of
	// whether IncludeIPv6 caused an EntryIPv6 to be recorded above. The two answer
	// different questions: "does this server support IPv6" and "are we offering
	// Gluetun its v6 entry address".
	IPv6 bool
}

// Stats records how the Proton list was reduced, for the dashboard and logs.
// Every "kept" figure is counted after filtering, so the pair explains exactly
// why a candidate list is smaller than expected.
type Stats struct {
	LogicalsTotal    int `json:"logicals_total"`
	LogicalsKept     int `json:"logicals_kept"`
	PhysicalTotal    int `json:"physical_total"`
	PhysicalKept     int `json:"physical_kept"`
	DisabledSkipped  int `json:"disabled_skipped"`
	DuplicateSkipped int `json:"duplicate_skipped"`
	// AboveTierSkipped counts servers the Proton account is not entitled to use.
	AboveTierSkipped int      `json:"above_tier_skipped"`
	SecureCoreTotal  int      `json:"secure_core_total"`
	TorTotal         int      `json:"tor_total"`
	P2PTotal         int      `json:"p2p_total"`
	StreamTotal      int      `json:"stream_total"`
	FreeTotal        int      `json:"free_total"`
	IPv6Total        int      `json:"ipv6_total"`
	UnknownCountries []string `json:"unknown_countries,omitempty"`
}

// Options controls which servers survive into the catalog.
type Options struct {
	// Countries is an allow-list of canonical country names; empty allows all.
	Countries []string
	// ExcludeCountries is applied after Countries.
	ExcludeCountries []string
	// Cities is an allow-list of city names, case-insensitive; empty allows all.
	Cities []string
	// MaxLoad drops servers above this utilisation percentage. Zero disables.
	MaxLoad int
	// Tri-state feature filters, using config.FilterInclude/Exclude/Only.
	SecureCore string
	Tor        string
	P2P        string
	Stream     string
	Free       string
	IPv6       string
	// VPNType restricts candidates to machines that support this protocol.
	// Empty accepts both.
	VPNType string
	// IncludeIPv6 keeps Proton's IPv6 entry addresses.
	IncludeIPv6 bool
	// MaxTier is the highest server tier the Proton account may connect to, or nil
	// when it is not known.
	//
	// Proton's list includes servers above the account's entitlement: they look
	// ordinary but refuse the connection, so selecting one wastes a reconnect and
	// leaves the tunnel down. Nil means "unknown", and nothing is filtered - a
	// missing answer must not empty the candidate list.
	MaxTier *uint8
	// Require narrows candidates to those satisfying filters Gluetun itself is
	// enforcing. Gluetun ANDs its "only" filters with a pinned hostname, so a
	// server that fails one of them cannot be connected to - it leaves Gluetun
	// with nothing matching, which crashes its VPN loop.
	Require Requirements
}

// Requirements mirrors the "only" filters a Gluetun instance is enforcing.
type Requirements struct {
	PortForward bool
	SecureCore  bool
	Tor         bool
	Stream      bool
	Free        bool
	Premium     bool
}

// None reports whether no requirement is in force.
func (r Requirements) None() bool {
	return r == Requirements{}
}

// Unmet names the requirements a candidate fails, in Gluetun's own setting names
// so the answer points at the setting to change.
//
// It takes a Candidate rather than a logical server because the caller that needs
// it - the dashboard, explaining why a listed server is not selectable - is working
// with the flattened set.
func (r Requirements) Unmet(candidate Candidate) (names []string) {
	for _, check := range []struct {
		required bool
		has      bool
		name     string
	}{
		{r.PortForward, candidate.P2P, "port_forward_only"},
		{r.SecureCore, candidate.SecureCore, "secure_core_only"},
		{r.Tor, candidate.Tor, "tor_only"},
		{r.Stream, candidate.Stream, "stream_only"},
		{r.Free, candidate.Free, "free_only"},
		{r.Premium, !candidate.Free, "premium_only"},
	} {
		if check.required && !check.has {
			names = append(names, check.name)
		}
	}
	return names
}

// satisfied reports whether a logical server meets every requirement.
func (r Requirements) satisfied(logical proton.LogicalServer) bool {
	switch {
	case r.PortForward && !logical.P2P():
		return false
	case r.SecureCore && !logical.SecureCore():
		return false
	case r.Tor && !logical.Tor():
		return false
	case r.Stream && !logical.Streaming():
		return false
	case r.Free && !logical.Free():
		return false
	case r.Premium && logical.Free():
		return false
	default:
		return true
	}
}

// secureCoreNamePattern extracts the exit country from a Secure Core server
// name such as "IS-US#1", where the first code is the entry country.
var secureCoreNamePattern = regexp.MustCompile(`^[A-Z]{2}-([A-Z]{2})`)

// Build flattens and filters Proton's logical servers into candidates.
//
// Filtering happens here rather than at selection time so the dashboard can
// show precisely how many servers each rule removed.
func Build(logicals []proton.LogicalServer, opts Options) (candidates []Candidate, stats Stats) {
	allowedCountries := toSet(opts.Countries)
	excludedCountries := toSet(opts.ExcludeCountries)
	allowedCities := toLowerSet(opts.Cities)
	unknownCountries := map[string]struct{}{}

	// entryIPToIndex deduplicates physical machines. Proton exposes the same
	// machine under several logical servers; Gluetun would otherwise list the
	// same IP many times. Secure Core is exempt because one entry node
	// legitimately backs several different exit countries.
	//
	// The index (rather than a plain set) is what lets a duplicate with a lower
	// load replace the one already kept: since load is the primary ranking
	// signal, keeping whichever entry happened to arrive first would sometimes
	// discard the better of two identical machines.
	entryIPToIndex := make(map[string]int, len(logicals))

	candidates = make([]Candidate, 0, len(logicals))

	for _, logical := range logicals {
		stats.LogicalsTotal++
		stats.PhysicalTotal += len(logical.Servers)

		if logical.SecureCore() {
			stats.SecureCoreTotal++
		}
		if logical.Tor() {
			stats.TorTotal++
		}
		if logical.P2P() {
			stats.P2PTotal++
		}
		if logical.Streaming() {
			stats.StreamTotal++
		}
		if logical.Free() {
			stats.FreeTotal++
		}
		if hasIPv6(logical) {
			stats.IPv6Total++
		}

		if !logical.Enabled() {
			stats.DisabledSkipped += len(logical.Servers)
			continue
		}
		if !featureAllowed(opts.SecureCore, logical.SecureCore()) ||
			!featureAllowed(opts.Tor, logical.Tor()) ||
			!featureAllowed(opts.P2P, logical.P2P()) ||
			!featureAllowed(opts.Stream, logical.Streaming()) ||
			!featureAllowed(opts.Free, logical.Free()) ||
			!featureAllowed(opts.IPv6, logical.IPv6()) {
			continue
		}
		if opts.MaxLoad > 0 && int(logical.Load) > opts.MaxLoad {
			continue
		}
		if !opts.Require.satisfied(logical) {
			continue
		}
		if aboveTier(logical, opts.MaxTier) {
			stats.AboveTierSkipped++
			continue
		}

		country, known := resolveCountry(logical)
		if !known {
			unknownCountries[country] = struct{}{}
		}
		if len(allowedCountries) > 0 {
			if _, allowed := allowedCountries[country]; !allowed {
				continue
			}
		}
		if _, excluded := excludedCountries[country]; excluded {
			continue
		}

		city := derefString(logical.City)
		if len(allowedCities) > 0 {
			if _, allowed := allowedCities[strings.ToLower(city)]; !allowed {
				continue
			}
		}

		keptFromLogical := 0
		for _, physical := range logical.Servers {
			if !physical.Enabled() {
				stats.DisabledSkipped++
				continue
			}
			if !physical.EntryIP.IsValid() {
				continue
			}
			if opts.VPNType == VPNWireguard && physical.X25519PublicKey == "" {
				continue
			}

			candidate := Candidate{
				Hostname:    physical.Domain,
				ServerName:  logical.Name,
				LogicalID:   logical.ID,
				Country:     country,
				Region:      derefString(logical.Region),
				City:        city,
				EntryIP:     physical.EntryIP,
				ExitIP:      physical.ExitIP,
				WgPubKey:    physical.X25519PublicKey,
				Load:        logical.Load,
				ProtonScore: logical.Score,
				Free:        logical.Free(),
				SecureCore:  logical.SecureCore(),
				Tor:         logical.Tor(),
				P2P:         logical.P2P(),
				Stream:      logical.Streaming(),
				IPv6:        logical.IPv6(),
			}
			if opts.IncludeIPv6 && physical.EntryIPv6 != "" {
				if address, err := netip.ParseAddr(physical.EntryIPv6); err == nil && address.Is6() {
					candidate.EntryIPv6 = address
				}
			}

			if logical.SecureCore() {
				candidates = append(candidates, candidate)
				keptFromLogical++
				continue
			}

			key := physical.EntryIP.String()
			existingIndex, duplicate := entryIPToIndex[key]
			if !duplicate {
				entryIPToIndex[key] = len(candidates)
				candidates = append(candidates, candidate)
				keptFromLogical++
				continue
			}

			stats.DuplicateSkipped++
			if candidate.Load < candidates[existingIndex].Load {
				// Same machine, better logical server: keep the quieter one.
				candidates[existingIndex] = candidate
			}
		}

		if keptFromLogical > 0 {
			stats.LogicalsKept++
		}
	}

	stats.PhysicalKept = len(candidates)
	stats.UnknownCountries = setToSlice(unknownCountries)
	return candidates, stats
}

// ToGluetunServers renders candidates as Gluetun server entries. Each candidate
// yields an OpenVPN entry and, when it has a WireGuard key, a WireGuard entry -
// the same shape Gluetun's built-in ProtonVPN updater produces.
func ToGluetunServers(candidates []Candidate) (servers []serversfile.Server) {
	const protocolsPerCandidate = 2
	servers = make([]serversfile.Server, 0, protocolsPerCandidate*len(candidates))

	for _, candidate := range candidates {
		ips := []netip.Addr{candidate.EntryIP}
		if candidate.EntryIPv6.IsValid() {
			ips = append(ips, candidate.EntryIPv6)
		}

		base := serversfile.Server{
			Country:    candidate.Country,
			Region:     candidate.Region,
			City:       candidate.City,
			ServerName: candidate.ServerName,
			Hostname:   candidate.Hostname,
			Free:       candidate.Free,
			Stream:     candidate.Stream,
			SecureCore: candidate.SecureCore,
			Tor:        candidate.Tor,
			// Gluetun's port_forward flag maps onto Proton's P2P feature:
			// Proton only forwards ports on P2P-enabled servers.
			PortForward: candidate.P2P,
			IPs:         ips,
		}

		openvpn := base
		openvpn.VPN = VPNOpenVPN
		openvpn.TCP = true
		openvpn.UDP = true
		servers = append(servers, openvpn)

		if candidate.WgPubKey != "" {
			wireguard := base
			wireguard.VPN = VPNWireguard
			wireguard.WgPubKey = candidate.WgPubKey
			servers = append(servers, wireguard)
		}
	}
	return servers
}

// ApplyLoads updates candidates in place from a cheap loads refresh and reports
// how many were matched. Candidates whose logical server has since been
// disabled are reported so the caller can drop them.
func ApplyLoads(candidates []Candidate, loads []proton.ServerLoad) (updated int, disabled map[string]struct{}) {
	byID := make(map[string]proton.ServerLoad, len(loads))
	for _, load := range loads {
		byID[load.ID] = load
	}
	disabled = make(map[string]struct{})

	for i := range candidates {
		load, ok := byID[candidates[i].LogicalID]
		if !ok {
			continue
		}
		candidates[i].Load = load.Load
		candidates[i].ProtonScore = load.Score
		updated++
		if load.Status == 0 {
			disabled[candidates[i].Hostname] = struct{}{}
		}
	}
	return updated, disabled
}

// resolveCountry determines the exit country of a logical server.
//
// ExitCountry is authoritative, but Secure Core names encode entry and exit as
// "IS-US#1"; parsing the name is used as a cross-check and as a fallback when
// ExitCountry is missing.
func resolveCountry(logical proton.LogicalServer) (name string, known bool) {
	code := strings.TrimSpace(logical.ExitCountry)
	if code == "" && logical.SecureCore() {
		if match := secureCoreNamePattern.FindStringSubmatch(logical.Name); match != nil {
			code = match[1]
		}
	}
	if code == "" && len(logical.Name) >= 2 {
		code = logical.Name[:2]
	}
	return countries.Name(code)
}

// aboveTier reports whether a server needs a higher tier than the account has.
// An unknown tier on either side is treated as usable, since refusing on missing
// information would be worse than attempting a connection.
func aboveTier(logical proton.LogicalServer, maxTier *uint8) bool {
	if maxTier == nil || logical.Tier == nil {
		return false
	}
	return *logical.Tier > *maxTier
}

// featureAllowed applies a tri-state filter to a boolean feature.
func featureAllowed(filter string, has bool) bool {
	switch filter {
	case config.FilterOnly:
		return has
	case config.FilterExclude:
		return !has
	default: // FilterInclude, or unset
		return true
	}
}

func hasIPv6(logical proton.LogicalServer) bool {
	for _, physical := range logical.Servers {
		if physical.EntryIPv6 != "" {
			return true
		}
	}
	return false
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func toSet(values []string) (set map[string]struct{}) {
	if len(values) == 0 {
		return nil
	}
	set = make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func toLowerSet(values []string) (set map[string]struct{}) {
	if len(values) == 0 {
		return nil
	}
	set = make(map[string]struct{}, len(values))
	for _, value := range values {
		set[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	return set
}

func setToSlice(set map[string]struct{}) (values []string) {
	if len(set) == 0 {
		return nil
	}
	values = make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	return values
}
