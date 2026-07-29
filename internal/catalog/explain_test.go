package catalog

import (
	"strings"
	"testing"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
)

func reasonsContain(reasons []string, substring string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, substring) {
			return true
		}
	}
	return false
}

func TestExplainReportsInclusion(t *testing.T) {
	t.Parallel()

	logicals := []proton.LogicalServer{logical("SE#444", "SE", 12, proton.FeatureP2P)}

	explanations := Explain(logicals, Options{}, "SE#444")
	if len(explanations) != 1 {
		t.Fatalf("got %d explanations, want 1", len(explanations))
	}
	got := explanations[0]
	if !got.Included {
		t.Errorf("SE#444 should be included, reasons: %v", got.Reasons)
	}
	if len(got.Reasons) != 0 {
		t.Errorf("an included server needs no reasons, got %v", got.Reasons)
	}
	if got.Load != 12 || got.Country != "Sweden" || !got.P2P {
		t.Errorf("explanation does not describe the server: %+v", got)
	}
	if len(got.Physical) != 1 || !got.Physical[0].Included {
		t.Errorf("physical detail = %+v", got.Physical)
	}
}

// Every rule that can drop a server must be able to say so by name.
func TestExplainNamesTheRuleThatExcluded(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		logical proton.LogicalServer
		opts    Options
		want    string
	}{
		"max load": {
			logical: logical("SE#444", "SE", 95, 0),
			opts:    Options{MaxLoad: 80},
			want:    "MAX_LOAD=80",
		},
		"country not allowed": {
			logical: logical("NO#1", "NO", 10, 0),
			opts:    Options{Countries: []string{"Sweden"}},
			want:    "not in COUNTRIES",
		},
		"country excluded": {
			logical: logical("SE#444", "SE", 10, 0),
			opts:    Options{ExcludeCountries: []string{"Sweden"}},
			want:    "in EXCLUDE_COUNTRIES",
		},
		"city not allowed": {
			logical: logical("SE#444", "SE", 10, 0),
			opts:    Options{Cities: []string{"Gothenburg"}},
			want:    "not in CITIES",
		},
		"feature excluded": {
			logical: logical("SE#444", "SE", 10, proton.FeatureTor),
			opts:    Options{Tor: config.FilterExclude},
			want:    "TOR=exclude",
		},
		"feature required": {
			logical: logical("SE#444", "SE", 10, 0),
			opts:    Options{SecureCore: config.FilterOnly},
			want:    "SECURE_CORE=only",
		},
		"gluetun requirement": {
			logical: logical("SE#444", "SE", 10, 0),
			opts:    Options{Require: Requirements{PortForward: true}},
			want:    "Gluetun itself enforces",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			explanations := Explain([]proton.LogicalServer{test.logical}, test.opts, test.logical.Name)
			if len(explanations) != 1 {
				t.Fatalf("got %d explanations", len(explanations))
			}
			got := explanations[0]
			if got.Included {
				t.Fatal("server should have been excluded")
			}
			if !reasonsContain(got.Reasons, test.want) {
				t.Errorf("reasons = %v, want one containing %q", got.Reasons, test.want)
			}
		})
	}
}

// Disabled servers are the least obvious exclusion, since nothing the operator
// configured caused it.
func TestExplainReportsProtonDisabledServers(t *testing.T) {
	t.Parallel()

	disabled := logical("SE#444", "SE", 5, 0)
	disabled.Status = 0

	explanations := Explain([]proton.LogicalServer{disabled}, Options{}, "SE#444")
	if explanations[0].Included {
		t.Fatal("a disabled server must not be a candidate")
	}
	if !reasonsContain(explanations[0].Reasons, "disabled") {
		t.Errorf("reasons = %v, want the disabled status named", explanations[0].Reasons)
	}
}

// The subtlest case, and the one hardest to work out from the outside: the server
// was fine, but another sharing its machine was kept instead.
func TestExplainReportsDeduplication(t *testing.T) {
	t.Parallel()

	// Both on the same entry IP; the quieter one wins.
	logicals := []proton.LogicalServer{
		logical("SE#444", "SE", 40, 0),
		logical("SE#148", "SE", 5, 0),
	}

	explanations := Explain(logicals, Options{}, "SE#")
	if len(explanations) != 2 {
		t.Fatalf("got %d explanations, want 2", len(explanations))
	}

	byName := map[string]Explanation{}
	for _, explanation := range explanations {
		byName[explanation.ServerName] = explanation
	}

	if !byName["SE#148"].Included {
		t.Errorf("the quieter server should be kept: %+v", byName["SE#148"])
	}
	loser := byName["SE#444"]
	if loser.Included {
		t.Error("SE#444 shares an entry IP with a quieter server, so it is deduplicated")
	}
	if !reasonsContain(loser.Reasons, "deduplicated") {
		t.Errorf("reasons = %v, want deduplication named", loser.Reasons)
	}
	if got := loser.Physical[0].DeduplicatedBy; !strings.Contains(got, "SE#148") {
		t.Errorf("DeduplicatedBy = %q, want the winner named", got)
	}
}

func TestExplainMatchesHostnameAndIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	logicals := []proton.LogicalServer{logical("SE#444", "SE", 10, 0)}

	for _, query := range []string{"se#444", "SE#444", "  SE#444  ", "se#444.protonvpn.net", "protonvpn.net"} {
		if got := Explain(logicals, Options{}, query); len(got) != 1 {
			t.Errorf("query %q matched %d servers, want 1", query, len(got))
		}
	}
	if got := Explain(logicals, Options{}, "NO#9"); len(got) != 0 {
		t.Errorf("a non-matching query returned %d results", len(got))
	}
	if got := Explain(logicals, Options{}, "  "); got != nil {
		t.Errorf("an empty query returned %v", got)
	}
}

// A WireGuard tunnel cannot use a machine with no key, which is easy to miss.
func TestExplainReportsMissingWireguardKey(t *testing.T) {
	t.Parallel()

	noKey := logical("SE#444", "SE", 10, 0)
	noKey.Servers[0].X25519PublicKey = ""

	explanations := Explain([]proton.LogicalServer{noKey}, Options{VPNType: VPNWireguard}, "SE#444")
	if explanations[0].Included {
		t.Fatal("a keyless machine cannot serve WireGuard")
	}
	if !reasonsContain(explanations[0].Reasons, "WireGuard key") {
		t.Errorf("reasons = %v", explanations[0].Reasons)
	}
}

// The usual reason a name from Proton's portal seems missing: Proton groups one
// machine under several logical names, and Gluetun connects by hostname - so the
// machine is usable, listed under whichever name won.
func TestExplainReportsSiblingLogicalNames(t *testing.T) {
	t.Parallel()

	// Same hostname and entry IP, two logical names, different loads.
	sibling := logical("SE#148", "SE", 9, 0)
	sibling.Servers[0].Domain = "node-se-12.protonvpn.net"
	target := logical("SE#444", "SE", 14, 0)
	target.Servers[0].Domain = "node-se-12.protonvpn.net"

	explanations := Explain([]proton.LogicalServer{sibling, target}, Options{}, "SE#444")
	if len(explanations) != 1 {
		t.Fatalf("got %d explanations", len(explanations))
	}
	got := explanations[0]

	// It is usable: pinning that hostname reaches this machine.
	if !got.Included {
		t.Errorf("the machine is usable, so this must not read as excluded: %+v", got)
	}
	if got.Physical[0].SameMachineAs != "SE#148" {
		t.Errorf("SameMachineAs = %q, want SE#148", got.Physical[0].SameMachineAs)
	}
	if !reasonsContain(got.Notes, "same machine as SE#148") {
		t.Errorf("notes = %v, want the sibling explained", got.Notes)
	}
}
