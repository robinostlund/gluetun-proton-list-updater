package catalog

import (
	"fmt"
	"strings"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
)

// Explanation says what happened to one server between Proton's response and the
// candidate list.
//
// It exists because "why is server X not in the list?" is otherwise very hard to
// answer: a server can be dropped by any of a dozen rules, and the aggregate
// statistics say how many were dropped without saying which, or why.
type Explanation struct {
	// ServerName is Proton's logical name, e.g. "SE#444".
	ServerName string `json:"server_name"`
	Country    string `json:"country"`
	City       string `json:"city"`
	Load       uint8  `json:"load"`
	Tier       *uint8 `json:"tier,omitempty"`

	SecureCore bool `json:"secure_core"`
	Tor        bool `json:"tor"`
	P2P        bool `json:"p2p"`
	Stream     bool `json:"stream"`
	Free       bool `json:"free"`
	// Enabled is Proton's own status for the logical server.
	Enabled bool `json:"enabled"`

	// Physical lists the machines behind this logical server.
	Physical []PhysicalExplanation `json:"physical"`

	// Included is true when at least one physical machine became a candidate.
	Included bool `json:"included"`
	// Reasons explains every exclusion, one per rule that rejected it. Empty when
	// Included is true.
	Reasons []string `json:"reasons,omitempty"`
	// Notes carry findings that are not exclusions, such as a machine being listed
	// under a sibling logical name.
	Notes []string `json:"notes,omitempty"`
}

// PhysicalExplanation is the per-machine part of an explanation.
type PhysicalExplanation struct {
	Hostname  string `json:"hostname"`
	EntryIP   string `json:"entry_ip"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Enabled   bool   `json:"enabled"`
	Wireguard bool   `json:"wireguard"`
	Included  bool   `json:"included"`
	Reason    string `json:"reason,omitempty"`
	// DeduplicatedBy names the server kept instead, when this machine was dropped
	// as a duplicate.
	DeduplicatedBy string `json:"deduplicated_by,omitempty"`
	// SameMachineAs names the sibling logical server this machine is listed under.
	//
	// Proton groups one physical machine under several logical names (SE#148 and
	// SE#444 can be the same box). Gluetun connects by hostname, so the machine is
	// usable either way - it just appears in the candidate list under whichever
	// name won. This is the usual reason a name seen on Proton's portal seems to be
	// missing here.
	SameMachineAs string `json:"same_machine_as,omitempty"`
}

// Explain reports what happened to every logical server matching query.
//
// The query is matched case-insensitively against the logical name and against
// each physical hostname, as a substring, so "SE#444", "se#444" and
// "node-se-12" all work.
func Explain(logicals []proton.LogicalServer, opts Options, query string) (explanations []Explanation) {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return nil
	}

	// The candidate set is built first so dedup outcomes can be reported: which
	// machine won an entry IP is only knowable by running the same selection.
	candidates, _ := Build(logicals, opts)
	byEntryIP := make(map[string]Candidate, len(candidates))
	for _, candidate := range candidates {
		byEntryIP[candidate.EntryIP.String()] = candidate
	}

	allowedCountries := toSet(opts.Countries)
	excludedCountries := toSet(opts.ExcludeCountries)
	allowedCities := toLowerSet(opts.Cities)

	for _, logical := range logicals {
		if !matches(logical, query) {
			continue
		}

		country, _ := resolveCountry(logical)
		city := derefString(logical.City)

		explanation := Explanation{
			ServerName: logical.Name,
			Country:    country,
			City:       city,
			Load:       logical.Load,
			Tier:       logical.Tier,
			SecureCore: logical.SecureCore(),
			Tor:        logical.Tor(),
			P2P:        logical.P2P(),
			Stream:     logical.Streaming(),
			Free:       logical.Free(),
			Enabled:    logical.Enabled(),
		}

		// Logical-level rules, in the order Build applies them.
		if !logical.Enabled() {
			explanation.Reasons = append(explanation.Reasons,
				"Proton reports this server as disabled (Status 0)")
		}
		explanation.Reasons = append(explanation.Reasons,
			featureReasons(logical, opts)...)
		if opts.MaxLoad > 0 && int(logical.Load) > opts.MaxLoad {
			explanation.Reasons = append(explanation.Reasons,
				sprintf("load %d%% is above MAX_LOAD=%d", logical.Load, opts.MaxLoad))
		}
		if !opts.Require.satisfied(logical) {
			explanation.Reasons = append(explanation.Reasons,
				"does not satisfy a filter Gluetun itself enforces "+requirementNames(opts.Require))
		}
		if aboveTier(logical, opts.MaxTier) {
			explanation.Reasons = append(explanation.Reasons, sprintf(
				"needs Proton tier %d, and this account is tier %d - it would refuse the connection",
				*logical.Tier, *opts.MaxTier))
		}
		if len(allowedCountries) > 0 {
			if _, allowed := allowedCountries[country]; !allowed {
				explanation.Reasons = append(explanation.Reasons,
					sprintf("country %q is not in COUNTRIES", country))
			}
		}
		if _, excluded := excludedCountries[country]; excluded {
			explanation.Reasons = append(explanation.Reasons,
				sprintf("country %q is in EXCLUDE_COUNTRIES", country))
		}
		if len(allowedCities) > 0 {
			if _, allowed := allowedCities[strings.ToLower(city)]; !allowed {
				explanation.Reasons = append(explanation.Reasons,
					sprintf("city %q is not in CITIES", city))
			}
		}

		logicalRejected := len(explanation.Reasons) > 0

		for _, physical := range logical.Servers {
			entry := PhysicalExplanation{
				Hostname:  physical.Domain,
				EntryIP:   physical.EntryIP.String(),
				Enabled:   physical.Enabled(),
				Wireguard: physical.X25519PublicKey != "",
			}
			if physical.ExitIP.IsValid() {
				entry.ExitIP = physical.ExitIP.String()
			}

			switch {
			case logicalRejected:
				entry.Reason = "excluded with its logical server"
			case !physical.Enabled():
				entry.Reason = "Proton reports this machine as disabled (Status 0)"
			case !physical.EntryIP.IsValid():
				entry.Reason = "no usable entry IP"
			case opts.VPNType == VPNWireguard && physical.X25519PublicKey == "":
				entry.Reason = "no WireGuard key, and the tunnel uses WireGuard"
			default:
				kept, present := byEntryIP[physical.EntryIP.String()]
				switch {
				case present && kept.LogicalID == logical.ID:
					entry.Included = true
				case present && kept.Hostname == physical.Domain:
					// The same machine, reached under a sibling logical name.
					// Proton groups one machine under several logical servers;
					// Gluetun connects by hostname, so this machine *is* usable -
					// it simply appears in the list under the other name. Nothing
					// is lost, which is worth saying plainly.
					entry.Included = true
					entry.SameMachineAs = kept.ServerName
				case present:
					// A different machine won this entry IP. Dedup keeps the
					// quieter of two servers sharing one address.
					entry.Reason = "deduplicated: another server shares this entry IP"
					entry.DeduplicatedBy = kept.ServerName + " (" + kept.Hostname + ")"
				default:
					entry.Reason = "excluded, but not by a rule reported here - please open an issue"
				}
			}

			if entry.Included {
				explanation.Included = true
			}
			explanation.Physical = append(explanation.Physical, entry)
		}

		for _, physical := range explanation.Physical {
			if physical.SameMachineAs != "" {
				explanation.Notes = append(explanation.Notes, sprintf(
					"usable: %s is the same machine as %s (%s), so it appears in the list under that name",
					logical.Name, physical.SameMachineAs, physical.Hostname))
			}
		}

		if !explanation.Included && len(explanation.Reasons) == 0 {
			for _, physical := range explanation.Physical {
				if physical.Reason != "" {
					explanation.Reasons = append(explanation.Reasons, physical.Reason)
				}
			}
		}
		if explanation.Included {
			explanation.Reasons = nil
		}

		explanations = append(explanations, explanation)
	}
	return explanations
}

func matches(logical proton.LogicalServer, query string) bool {
	if strings.Contains(strings.ToLower(logical.Name), query) {
		return true
	}
	for _, physical := range logical.Servers {
		if strings.Contains(strings.ToLower(physical.Domain), query) {
			return true
		}
	}
	return false
}

// featureReasons reports every tri-state filter that rejects the server.
func featureReasons(logical proton.LogicalServer, opts Options) (reasons []string) {
	checks := []struct {
		name   string
		filter string
		has    bool
	}{
		{"SECURE_CORE", opts.SecureCore, logical.SecureCore()},
		{"TOR", opts.Tor, logical.Tor()},
		{"P2P", opts.P2P, logical.P2P()},
		{"STREAM", opts.Stream, logical.Streaming()},
		{"FREE_TIER", opts.Free, logical.Free()},
	}

	for _, check := range checks {
		switch check.filter {
		case config.FilterExclude:
			if check.has {
				reasons = append(reasons, sprintf("%s=exclude and this server has that feature", check.name))
			}
		case config.FilterOnly:
			if !check.has {
				reasons = append(reasons, sprintf("%s=only and this server lacks that feature", check.name))
			}
		}
	}
	return reasons
}

func requirementNames(require Requirements) string {
	var names []string
	for name, required := range map[string]bool{
		"port_forward_only": require.PortForward,
		"secure_core_only":  require.SecureCore,
		"tor_only":          require.Tor,
		"stream_only":       require.Stream,
		"free_only":         require.Free,
		"premium_only":      require.Premium,
	} {
		if required {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "(" + strings.Join(names, ", ") + ")"
}

// sprintf is a local alias so this file needs no fmt import churn.
func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
