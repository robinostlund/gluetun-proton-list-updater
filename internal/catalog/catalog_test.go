package catalog

import (
	"net/netip"
	"testing"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
)

func tier(value uint8) *uint8 { return &value }

func str(value string) *string { return &value }

// logical builds a one-machine logical server for tests.
func logical(name, exitCountry string, load uint8, features uint16, opts ...func(*proton.LogicalServer)) proton.LogicalServer {
	server := proton.LogicalServer{
		ID:          "id-" + name,
		Name:        name,
		ExitCountry: exitCountry,
		City:        str("Stockholm"),
		Load:        load,
		Status:      1,
		Tier:        tier(2),
		Features:    features,
		Servers: []proton.PhysicalServer{{
			ID:              "p-" + name,
			EntryIP:         netip.MustParseAddr("10.0.0.1"),
			ExitIP:          netip.MustParseAddr("20.0.0.1"),
			Domain:          name + ".protonvpn.net",
			Status:          1,
			X25519PublicKey: "pubkey",
		}},
	}
	for _, opt := range opts {
		opt(&server)
	}
	return server
}

func withEntryIP(ip string) func(*proton.LogicalServer) {
	return func(server *proton.LogicalServer) {
		server.Servers[0].EntryIP = netip.MustParseAddr(ip)
	}
}

func TestBuildFlattensAndMapsFields(t *testing.T) {
	t.Parallel()

	logicals := []proton.LogicalServer{
		logical("se-01", "SE", 12, proton.FeatureP2P|proton.FeatureStreaming),
	}

	candidates, stats := Build(logicals, Options{})
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(candidates))
	}

	candidate := candidates[0]
	switch {
	case candidate.Country != "Sweden":
		t.Errorf("Country = %q, want Sweden", candidate.Country)
	case candidate.Hostname != "se-01.protonvpn.net":
		t.Errorf("Hostname = %q", candidate.Hostname)
	case candidate.Load != 12:
		t.Errorf("Load = %d, want 12", candidate.Load)
	case !candidate.P2P:
		t.Error("P2P should be set from the feature bits")
	case !candidate.Stream:
		t.Error("Stream should be set from the feature bits")
	case candidate.SecureCore:
		t.Error("SecureCore should not be set")
	case candidate.Free:
		t.Error("tier 2 is not free")
	}
	if stats.PhysicalKept != 1 || stats.LogicalsKept != 1 {
		t.Errorf("stats = %+v, want one kept logical and physical", stats)
	}
}

func TestBuildFiltersCountries(t *testing.T) {
	t.Parallel()

	logicals := []proton.LogicalServer{
		logical("se-01", "SE", 10, 0),
		logical("de-01", "DE", 10, 0, withEntryIP("10.0.0.2")),
		logical("nl-01", "NL", 10, 0, withEntryIP("10.0.0.3")),
	}

	candidates, _ := Build(logicals, Options{
		Countries:        []string{"Sweden", "Germany"},
		ExcludeCountries: []string{"Germany"},
	})

	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(candidates))
	}
	if candidates[0].Country != "Sweden" {
		t.Errorf("Country = %q, want Sweden", candidates[0].Country)
	}
}

func TestBuildAppliesMaxLoad(t *testing.T) {
	t.Parallel()

	logicals := []proton.LogicalServer{
		logical("se-01", "SE", 30, 0),
		logical("se-02", "SE", 95, 0, withEntryIP("10.0.0.2")),
	}

	candidates, _ := Build(logicals, Options{MaxLoad: 80})
	if len(candidates) != 1 || candidates[0].Load != 30 {
		t.Fatalf("got %+v, want only the 30%% server", candidates)
	}
}

func TestBuildTriStateFeatureFilters(t *testing.T) {
	t.Parallel()

	logicals := []proton.LogicalServer{
		logical("plain", "SE", 10, 0),
		logical("sc", "SE", 10, proton.FeatureSecureCore, withEntryIP("10.0.0.2")),
		logical("tor", "SE", 10, proton.FeatureTor, withEntryIP("10.0.0.3")),
	}

	tests := map[string]struct {
		opts      Options
		wantNames []string
	}{
		"secure core excluded by default": {
			opts:      Options{SecureCore: config.FilterExclude, Tor: config.FilterExclude},
			wantNames: []string{"plain"},
		},
		"secure core only": {
			opts:      Options{SecureCore: config.FilterOnly},
			wantNames: []string{"sc"},
		},
		"include everything": {
			opts:      Options{SecureCore: config.FilterInclude, Tor: config.FilterInclude},
			wantNames: []string{"plain", "sc", "tor"},
		},
		"tor only": {
			opts:      Options{Tor: config.FilterOnly},
			wantNames: []string{"tor"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			candidates, _ := Build(logicals, test.opts)
			got := make([]string, 0, len(candidates))
			for _, candidate := range candidates {
				got = append(got, candidate.ServerName)
			}
			if len(got) != len(test.wantNames) {
				t.Fatalf("got %v, want %v", got, test.wantNames)
			}
			for i := range got {
				if got[i] != test.wantNames[i] {
					t.Fatalf("got %v, want %v", got, test.wantNames)
				}
			}
		})
	}
}

// Proton exposes one machine under several logical servers; without
// deduplication the same IP would be written many times.
func TestBuildDeduplicatesByEntryIP(t *testing.T) {
	t.Parallel()

	logicals := []proton.LogicalServer{
		logical("se-01", "SE", 10, 0),
		logical("se-02", "SE", 20, 0), // same entry IP
	}

	candidates, stats := Build(logicals, Options{})
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(candidates))
	}
	if stats.DuplicateSkipped != 1 {
		t.Errorf("DuplicateSkipped = %d, want 1", stats.DuplicateSkipped)
	}
	if stats.PhysicalKept != 1 {
		t.Errorf("PhysicalKept = %d, want 1", stats.PhysicalKept)
	}
}

// When duplicates share a machine, the quieter logical server must win: load is
// the primary ranking signal, so keeping whichever arrived first would sometimes
// throw away the better of two identical servers.
func TestBuildDeduplicationKeepsTheLowestLoad(t *testing.T) {
	t.Parallel()

	// Busy first, then quiet: the later, better entry must replace the earlier.
	candidates, _ := Build([]proton.LogicalServer{
		logical("busy", "SE", 85, 0),
		logical("quiet", "SE", 4, 0),
	}, Options{})

	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(candidates))
	}
	if candidates[0].Load != 4 || candidates[0].ServerName != "quiet" {
		t.Errorf("kept %+v, want the quiet server", candidates[0])
	}

	// And the other way round, so the result does not depend on API ordering.
	candidates, _ = Build([]proton.LogicalServer{
		logical("quiet", "SE", 4, 0),
		logical("busy", "SE", 85, 0),
	}, Options{})
	if candidates[0].Load != 4 {
		t.Errorf("kept load %d, want 4 regardless of input order", candidates[0].Load)
	}
}

// A Secure Core entry node legitimately backs several exit countries, so it must
// not be deduplicated away.
func TestBuildKeepsSecureCoreSharingAnEntryIP(t *testing.T) {
	t.Parallel()

	logicals := []proton.LogicalServer{
		logical("IS-SE#1", "SE", 10, proton.FeatureSecureCore),
		logical("IS-US#1", "US", 10, proton.FeatureSecureCore),
	}

	candidates, _ := Build(logicals, Options{SecureCore: config.FilterInclude})
	if len(candidates) != 2 {
		t.Fatalf("got %d candidates, want 2", len(candidates))
	}
}

func TestBuildSkipsDisabledServers(t *testing.T) {
	t.Parallel()

	disabledLogical := logical("se-01", "SE", 10, 0)
	disabledLogical.Status = 0

	disabledPhysical := logical("se-02", "SE", 10, 0, withEntryIP("10.0.0.2"))
	disabledPhysical.Servers[0].Status = 0

	candidates, stats := Build([]proton.LogicalServer{disabledLogical, disabledPhysical}, Options{})
	if len(candidates) != 0 {
		t.Fatalf("got %d candidates, want 0", len(candidates))
	}
	if stats.DisabledSkipped != 2 {
		t.Errorf("DisabledSkipped = %d, want 2", stats.DisabledSkipped)
	}
}

func TestBuildRequiresWireguardKeyForWireguard(t *testing.T) {
	t.Parallel()

	noKey := logical("se-01", "SE", 10, 0)
	noKey.Servers[0].X25519PublicKey = ""

	candidates, _ := Build([]proton.LogicalServer{noKey}, Options{VPNType: VPNWireguard})
	if len(candidates) != 0 {
		t.Fatalf("got %d candidates, want 0 for wireguard without a key", len(candidates))
	}

	candidates, _ = Build([]proton.LogicalServer{noKey}, Options{VPNType: VPNOpenVPN})
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1 for openvpn", len(candidates))
	}
}

func TestBuildFreeTierDetection(t *testing.T) {
	t.Parallel()

	free := logical("se-free", "SE", 10, 0)
	free.Tier = tier(0)

	unknownTier := logical("se-unknown", "SE", 10, 0, withEntryIP("10.0.0.2"))
	unknownTier.Tier = nil

	candidates, _ := Build([]proton.LogicalServer{free, unknownTier}, Options{Free: config.FilterInclude})
	if len(candidates) != 2 {
		t.Fatalf("got %d candidates, want 2", len(candidates))
	}
	if !candidates[0].Free {
		t.Error("tier 0 should be free")
	}
	if candidates[1].Free {
		t.Error("a missing tier must be treated as paid")
	}
}

func TestToGluetunServersEmitsBothProtocols(t *testing.T) {
	t.Parallel()

	candidates := []Candidate{{
		Hostname: "se-01.protonvpn.net", ServerName: "SE#1", Country: "Sweden",
		EntryIP: netip.MustParseAddr("10.0.0.1"), WgPubKey: "key", P2P: true,
	}, {
		Hostname: "se-02.protonvpn.net", ServerName: "SE#2", Country: "Sweden",
		EntryIP: netip.MustParseAddr("10.0.0.2"), // no WireGuard key
	}}

	servers := ToGluetunServers(candidates)
	if len(servers) != 3 {
		t.Fatalf("got %d servers, want 3 (2 for the first candidate, 1 for the second)", len(servers))
	}

	if servers[0].VPN != VPNOpenVPN || !servers[0].TCP || !servers[0].UDP {
		t.Errorf("first entry should be OpenVPN with both protocols: %+v", servers[0])
	}
	if servers[1].VPN != VPNWireguard || servers[1].WgPubKey != "key" {
		t.Errorf("second entry should be WireGuard: %+v", servers[1])
	}
	// Proton only forwards ports on P2P servers, which is what Gluetun's
	// port_forward flag means.
	if !servers[0].PortForward {
		t.Error("P2P should map to port_forward")
	}
	if servers[2].VPN != VPNOpenVPN {
		t.Errorf("keyless candidate should only produce OpenVPN: %+v", servers[2])
	}
}

func TestApplyLoadsUpdatesAndDetectsDisabled(t *testing.T) {
	t.Parallel()

	candidates := []Candidate{
		{Hostname: "a", LogicalID: "id-a", Load: 10},
		{Hostname: "b", LogicalID: "id-b", Load: 20},
		{Hostname: "c", LogicalID: "id-c", Load: 30},
	}

	updated, disabled := ApplyLoads(candidates, []proton.ServerLoad{
		{ID: "id-a", Load: 55, Score: 1.5, Status: 1},
		{ID: "id-b", Load: 5, Status: 0},
	})

	if updated != 2 {
		t.Errorf("updated = %d, want 2", updated)
	}
	if candidates[0].Load != 55 {
		t.Errorf("candidate a load = %d, want 55", candidates[0].Load)
	}
	if candidates[2].Load != 30 {
		t.Errorf("candidate c should keep its load, got %d", candidates[2].Load)
	}
	if _, ok := disabled["b"]; !ok {
		t.Error("candidate b should be reported as disabled")
	}
}

func TestResolveCountryFallsBackToServerName(t *testing.T) {
	t.Parallel()

	secureCore := logical("IS-US#1", "", 10, proton.FeatureSecureCore)
	candidates, _ := Build([]proton.LogicalServer{secureCore}, Options{SecureCore: config.FilterInclude})
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(candidates))
	}
	// "IS-US#1" enters in Iceland and exits in the United States; the exit is
	// what matters for routing.
	if candidates[0].Country != "United States" {
		t.Errorf("Country = %q, want United States", candidates[0].Country)
	}
}

func TestBuildIncludesIPv6WhenAsked(t *testing.T) {
	t.Parallel()

	withIPv6 := logical("se-01", "SE", 10, 0)
	withIPv6.Servers[0].EntryIPv6 = "2001:db8::1"

	candidates, _ := Build([]proton.LogicalServer{withIPv6}, Options{IncludeIPv6: true})
	if !candidates[0].EntryIPv6.IsValid() {
		t.Fatal("EntryIPv6 should be populated")
	}

	servers := ToGluetunServers(candidates)
	if len(servers[0].IPs) != 2 {
		t.Errorf("expected both IPv4 and IPv6 addresses, got %v", servers[0].IPs)
	}

	candidates, _ = Build([]proton.LogicalServer{withIPv6}, Options{})
	if candidates[0].EntryIPv6.IsValid() {
		t.Error("EntryIPv6 should be dropped when IncludeIPv6 is false")
	}
}
