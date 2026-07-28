// Package scoring ranks candidate servers. Lower scores are better.
//
// The score is a weighted sum of normalised penalties, each in [0,1]:
//
//	load     load / 100
//	latency  min(rtt, ceiling) / ceiling
//	proton   Proton's own score, normalised across the candidate set
//
// Absolute normalisation (a fixed latency ceiling) is used rather than
// normalising latency across the candidate set, because a relative scale makes
// scores jump around as the set changes and would cause reconnect flapping.
// With a fixed ceiling, a server's score only changes when the server changes.
package scoring

import (
	"math"
	"sort"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/catalog"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/latency"
)

// Scored is a candidate with its computed score and the components behind it,
// so the dashboard can explain why a server ranks where it does.
type Scored struct {
	Candidate catalog.Candidate

	Score float64
	// LoadPenalty, LatencyPenalty and ProtonPenalty are the weighted
	// contributions that sum to Score.
	LoadPenalty    float64
	LatencyPenalty float64
	ProtonPenalty  float64

	// RTT is the measured round trip; zero when unmeasured.
	RTT time.Duration
	// LatencyKnown distinguishes "measured as very fast" from "never probed",
	// which otherwise look identical in the score.
	LatencyKnown bool
}

// Rank scores every candidate and returns them sorted best first.
//
// latencies is keyed by entry IP string, as returned by latency.Prober.
func Rank(candidates []catalog.Candidate, latencies map[string]latency.Result, cfg config.Score) (ranked []Scored) {
	ranked = make([]Scored, 0, len(candidates))
	if len(candidates) == 0 {
		return ranked
	}

	// Proton's score has no fixed range, so it is normalised against the best
	// and worst values present. When the weight is zero this is skipped
	// entirely - the common case, since load and latency are the better signals.
	bestProton, worstProton := protonScoreRange(candidates)
	protonSpan := worstProton - bestProton

	ceiling := float64(cfg.LatencyCeiling)
	if ceiling <= 0 {
		ceiling = float64(150 * time.Millisecond)
	}

	for _, candidate := range candidates {
		scored := Scored{Candidate: candidate}

		scored.LoadPenalty = cfg.LoadWeight * clamp01(float64(candidate.Load)/100)

		normalisedLatency := cfg.UnknownLatencyPenalty
		if result, ok := latencies[candidate.EntryIP.String()]; ok && result.OK() {
			scored.RTT = result.RTT
			scored.LatencyKnown = true
			normalisedLatency = clamp01(float64(result.RTT) / ceiling)
		}
		scored.LatencyPenalty = cfg.LatencyWeight * clamp01(normalisedLatency)

		if cfg.ProtonScoreWeight > 0 && protonSpan > 0 {
			scored.ProtonPenalty = cfg.ProtonScoreWeight *
				clamp01((candidate.ProtonScore-bestProton)/protonSpan)
		}

		scored.Score = scored.LoadPenalty + scored.LatencyPenalty + scored.ProtonPenalty
		ranked = append(ranked, scored)
	}

	sortRanked(ranked)
	return ranked
}

// sortRanked orders by score, breaking ties deterministically. Determinism
// matters: with random tie-breaking, two consecutive evaluations could disagree
// on the winner and reconnect for no reason.
func sortRanked(ranked []Scored) {
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		switch {
		case a.Score != b.Score:
			return a.Score < b.Score
		case a.Candidate.Load != b.Candidate.Load:
			return a.Candidate.Load < b.Candidate.Load
		default:
			return a.Candidate.Hostname < b.Candidate.Hostname
		}
	})
}

// Find returns the scored entry for a hostname.
func Find(ranked []Scored, hostname string) (scored Scored, found bool) {
	for _, entry := range ranked {
		if entry.Candidate.Hostname == hostname {
			return entry, true
		}
	}
	return Scored{}, false
}

// TopN returns at most n entries from the front of the ranking.
func TopN(ranked []Scored, n int) (top []Scored) {
	if n <= 0 || n >= len(ranked) {
		return ranked
	}
	return ranked[:n]
}

func protonScoreRange(candidates []catalog.Candidate) (best, worst float64) {
	best, worst = math.Inf(1), math.Inf(-1)
	for _, candidate := range candidates {
		if candidate.ProtonScore < best {
			best = candidate.ProtonScore
		}
		if candidate.ProtonScore > worst {
			worst = candidate.ProtonScore
		}
	}
	if math.IsInf(best, 1) {
		return 0, 0
	}
	return best, worst
}

func clamp01(value float64) float64 {
	switch {
	case math.IsNaN(value):
		return 0
	case value < 0:
		return 0
	case value > 1:
		return 1
	default:
		return value
	}
}
