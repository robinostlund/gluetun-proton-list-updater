package scoring

import (
	"net/netip"
	"testing"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/catalog"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/latency"
)

func testScore() config.Score {
	return config.Score{
		LoadWeight:            1.0,
		LatencyWeight:         1.0,
		LatencyCeiling:        100 * time.Millisecond,
		UnknownLatencyPenalty: 0.5,
	}
}

func candidate(hostname string, load uint8, ip string) catalog.Candidate {
	return catalog.Candidate{
		Hostname: hostname,
		Load:     load,
		EntryIP:  netip.MustParseAddr(ip),
	}
}

func TestRankPrefersLowerLoadAndLatency(t *testing.T) {
	t.Parallel()

	candidates := []catalog.Candidate{
		candidate("busy", 90, "10.0.0.1"),
		candidate("quiet", 10, "10.0.0.2"),
		candidate("middling", 50, "10.0.0.3"),
	}
	latencies := map[string]latency.Result{
		"10.0.0.1": {RTT: 10 * time.Millisecond},
		"10.0.0.2": {RTT: 10 * time.Millisecond},
		"10.0.0.3": {RTT: 10 * time.Millisecond},
	}

	ranked := Rank(candidates, latencies, testScore())
	if ranked[0].Candidate.Hostname != "quiet" {
		t.Errorf("best = %q, want quiet", ranked[0].Candidate.Hostname)
	}
	if ranked[2].Candidate.Hostname != "busy" {
		t.Errorf("worst = %q, want busy", ranked[2].Candidate.Hostname)
	}

	// load 10/100 * 1.0 + 10ms/100ms * 1.0 = 0.2
	if got := ranked[0].Score; got < 0.199 || got > 0.201 {
		t.Errorf("score = %f, want ~0.2", got)
	}
}

// A nearby busy server can legitimately beat an idle server on another
// continent; the weights are what express that trade-off.
func TestRankLatencyCanOutweighLoad(t *testing.T) {
	t.Parallel()

	candidates := []catalog.Candidate{
		candidate("far-idle", 5, "10.0.0.1"),
		candidate("near-busy", 45, "10.0.0.2"),
	}
	latencies := map[string]latency.Result{
		"10.0.0.1": {RTT: 90 * time.Millisecond}, // 0.90 penalty
		"10.0.0.2": {RTT: 8 * time.Millisecond},  // 0.08 penalty
	}

	ranked := Rank(candidates, latencies, testScore())
	if ranked[0].Candidate.Hostname != "near-busy" {
		t.Errorf("best = %q, want near-busy", ranked[0].Candidate.Hostname)
	}
}

// An unprobed server must be neither favoured (which would let it win on a zero
// latency) nor excluded.
func TestRankTreatsUnknownLatencyAsNeutral(t *testing.T) {
	t.Parallel()

	candidates := []catalog.Candidate{candidate("unprobed", 0, "10.0.0.1")}
	ranked := Rank(candidates, map[string]latency.Result{}, testScore())

	if ranked[0].LatencyKnown {
		t.Error("LatencyKnown should be false")
	}
	if got := ranked[0].LatencyPenalty; got != 0.5 {
		t.Errorf("LatencyPenalty = %f, want the configured 0.5 default", got)
	}
}

// A failed probe must not read as "instant".
func TestRankIgnoresFailedProbes(t *testing.T) {
	t.Parallel()

	candidates := []catalog.Candidate{candidate("unreachable", 0, "10.0.0.1")}
	latencies := map[string]latency.Result{"10.0.0.1": {Err: latency.ErrUnreachable}}

	ranked := Rank(candidates, latencies, testScore())
	if ranked[0].LatencyKnown {
		t.Error("a failed probe must not count as a known latency")
	}
}

func TestRankClampsLatencyAtCeiling(t *testing.T) {
	t.Parallel()

	candidates := []catalog.Candidate{candidate("slow", 0, "10.0.0.1")}
	latencies := map[string]latency.Result{"10.0.0.1": {RTT: 10 * time.Second}}

	ranked := Rank(candidates, latencies, testScore())
	if got := ranked[0].LatencyPenalty; got != 1.0 {
		t.Errorf("LatencyPenalty = %f, want it clamped to 1.0", got)
	}
}

// Ties must break the same way every time, or two consecutive evaluations could
// disagree and reconnect for nothing.
func TestRankIsDeterministic(t *testing.T) {
	t.Parallel()

	candidates := []catalog.Candidate{
		candidate("bbb", 20, "10.0.0.1"),
		candidate("aaa", 20, "10.0.0.2"),
	}
	latencies := map[string]latency.Result{
		"10.0.0.1": {RTT: 20 * time.Millisecond},
		"10.0.0.2": {RTT: 20 * time.Millisecond},
	}

	first := Rank(candidates, latencies, testScore())
	for range 20 {
		again := Rank(candidates, latencies, testScore())
		for i := range first {
			if first[i].Candidate.Hostname != again[i].Candidate.Hostname {
				t.Fatalf("ranking is not stable: %q vs %q",
					first[i].Candidate.Hostname, again[i].Candidate.Hostname)
			}
		}
	}
	if first[0].Candidate.Hostname != "aaa" {
		t.Errorf("tie should break on hostname, got %q", first[0].Candidate.Hostname)
	}
}

func TestRankProtonScoreWeight(t *testing.T) {
	t.Parallel()

	candidates := []catalog.Candidate{
		{Hostname: "preferred", Load: 20, ProtonScore: 1.0, EntryIP: netip.MustParseAddr("10.0.0.1")},
		{Hostname: "shunned", Load: 20, ProtonScore: 9.0, EntryIP: netip.MustParseAddr("10.0.0.2")},
	}

	cfg := testScore()
	cfg.LatencyWeight = 0
	cfg.ProtonScoreWeight = 1.0

	ranked := Rank(candidates, map[string]latency.Result{}, cfg)
	if ranked[0].Candidate.Hostname != "preferred" {
		t.Errorf("best = %q, want preferred", ranked[0].Candidate.Hostname)
	}
	if ranked[0].ProtonPenalty != 0 || ranked[1].ProtonPenalty != 1 {
		t.Errorf("proton penalties = %f/%f, want 0 and 1 after normalisation",
			ranked[0].ProtonPenalty, ranked[1].ProtonPenalty)
	}
}

func TestRankEmptyInput(t *testing.T) {
	t.Parallel()
	if ranked := Rank(nil, nil, testScore()); len(ranked) != 0 {
		t.Errorf("expected no results, got %d", len(ranked))
	}
}

func TestFindAndTopN(t *testing.T) {
	t.Parallel()

	candidates := []catalog.Candidate{
		candidate("a", 10, "10.0.0.1"),
		candidate("b", 20, "10.0.0.2"),
		candidate("c", 30, "10.0.0.3"),
	}
	ranked := Rank(candidates, map[string]latency.Result{}, testScore())

	if _, found := Find(ranked, "b"); !found {
		t.Error("Find should locate b")
	}
	if _, found := Find(ranked, "missing"); found {
		t.Error("Find should not invent results")
	}
	if got := len(TopN(ranked, 2)); got != 2 {
		t.Errorf("TopN(2) returned %d entries", got)
	}
	if got := len(TopN(ranked, 99)); got != 3 {
		t.Errorf("TopN beyond the end returned %d entries, want 3", got)
	}
	if got := len(TopN(ranked, 0)); got != 3 {
		t.Errorf("TopN(0) should return everything, got %d", got)
	}
}
