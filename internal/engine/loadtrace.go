package engine

import (
	"time"
)

// recordCurrentLoad appends the current server's utilisation to the persisted trace.
//
// Sampling is driven by the loads refresh rather than a clock of its own, so the trace
// has exactly the resolution the figures do - there is nothing to be gained from
// recording the same number twice between refreshes.
func (e *Engine) recordCurrentLoad() {
	hostname, _ := e.currentHostname()
	if hostname == "" {
		return
	}
	candidate, found := e.lookupCandidate(hostname)
	if !found {
		return
	}

	sample := LoadSample{At: time.Now(), Hostname: hostname, Load: candidate.Load}
	if err := e.state.update(func(state *persistedState) {
		// Replace rather than append when the newest sample is for the same server and
		// carries the same figure from the same refresh: a load refresh that found no
		// change should not stretch the trace with duplicates.
		if last := len(state.LoadSamples) - 1; last >= 0 {
			previous := state.LoadSamples[last]
			if previous.Hostname == sample.Hostname && previous.Load == sample.Load &&
				time.Since(previous.At) < time.Second {
				state.LoadSamples[last] = sample
				return
			}
		}
		state.LoadSamples = append(state.LoadSamples, sample)
	}); err != nil {
		// Losing a sample is not a reason to interrupt anything.
		e.logger.Debug("could not persist a load sample", "error", err)
	}
}

// loadTrace returns the utilisation history for the server the tunnel is on.
//
// Only the contiguous tail for that hostname. Earlier samples belong to servers the
// tunnel has since left, and drawing them as one line would show a trend that never
// happened - a switch from a busy server to a quiet one would look like the busy server
// recovering.
func (e *Engine) loadTrace(hostname string) (trace []LoadPoint) {
	if hostname == "" {
		return nil
	}
	samples := e.state.snapshot().LoadSamples

	start := len(samples)
	for start > 0 && samples[start-1].Hostname == hostname {
		start--
	}
	if start == len(samples) {
		return nil
	}

	trace = make([]LoadPoint, 0, len(samples)-start)
	for _, sample := range samples[start:] {
		trace = append(trace, LoadPoint{At: sample.At, Load: sample.Load})
	}
	return trace
}

// onCurrentSince reports when the tunnel arrived on the server it is on.
//
// Zero unless the current server is the one this tool pinned. If Gluetun moved on its
// own, or the tunnel was already up when this container started, the arrival time is
// genuinely unknown, and showing the last switch time regardless would attribute someone
// else's reconnect to us.
func (e *Engine) onCurrentSince(hostname string) time.Time {
	persisted := e.state.snapshot()
	if hostname == "" || hostname != persisted.PinnedHostname {
		return time.Time{}
	}
	return persisted.LastSwitchAt
}
