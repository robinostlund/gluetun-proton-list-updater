// This file holds what has been *measured* about individual servers, as opposed to what
// Proton says about them.
//
// Load, latency and Proton's own score all describe a server before it is used, and all
// are replaced wholesale on every refresh. What is here instead accumulates from
// observation and survives restarts, so it is the only record of how a server actually
// behaved. Throughput is the first such record; anything else of that kind - persisted
// smoothed latency, connection failures, how often a server had to be abandoned -
// belongs beside it, keyed by the same hostname.
//
// Kept in one place because these records share their rules rather than merely their
// shape: a reading must be attributed to the server that earned it, a measurement that
// was never taken must read as absent rather than as zero, and a record must be dropped
// when Proton retires the server.
package engine

import (
	"math"
	"sort"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
)

// maxThroughputRecords bounds the persisted per-server throughput history.
//
// Proton has thousands of servers but a filtered candidate set is a few hundred at
// most, and only servers the tunnel has actually been on get a record, so this is far
// more than a normal deployment accumulates. The oldest are dropped first.
const maxThroughputRecords = 200

// stayGap decides when a reading belongs to a new stay on a server rather than a
// continuation of the last one.
//
// It only matters across a restart: while running, a change of server is observed
// directly. On startup the tunnel is usually still on the server this tool left it on,
// and discarding that server's figures because the process bounced would lose exactly
// the measurement being taken. A gap longer than this means too much happened
// unobserved to keep claiming the numbers describe one continuous stay.
const stayGap = 10 * time.Minute

// ThroughputRecord is what a server was observed to deliver while the tunnel was on it.
//
// It describes the most recent stay, not all time. A server that was fast once, months
// ago, on an empty swarm, is not evidence about the server now - and "what did this one
// give me last time I used it" is the question worth answering.
type ThroughputRecord struct {
	// StartedAt is when the current or most recent stay on this server began, as far
	// as this tool observed it.
	StartedAt time.Time `json:"started_at"`
	// LastReading is when traffic was last attributed to this server. It doubles as
	// the age of the whole record.
	LastReading time.Time `json:"last_reading"`
	// PeakDownload and PeakUpload are the highest single readings, in bytes per
	// second: the fastest this server was ever seen to go on this stay.
	PeakDownload uint64 `json:"peak_download,omitempty"`
	PeakUpload   uint64 `json:"peak_upload,omitempty"`
	// SustainedDownload and SustainedUpload are the highest *windowed averages*.
	//
	// These are the figures worth comparing between servers. A peak is one reading and
	// a torrent client will spike well above what it can hold; the highest average
	// over SWITCHING_BUSY_WINDOW is a rate the server actually maintained. They are
	// only recorded once the whole window has been on this server, so they never
	// splice two servers' rates together.
	SustainedDownload uint64 `json:"sustained_download,omitempty"`
	SustainedUpload   uint64 `json:"sustained_upload,omitempty"`
	// Readings counts only readings with traffic in them.
	//
	// Idle polls are excluded on purpose: a server the tunnel sat on all night with
	// nothing running would otherwise accumulate thousands of readings and a peak of
	// zero, which reads as "this server is slow" when it means "nothing was
	// downloading". With no active readings there is no measurement, and the dashboard
	// says so rather than showing a zero.
	Readings int `json:"readings"`
	// Visits counts the stays on this server that have been measured, across the
	// resets above. It is the one cumulative figure kept, because "first time here"
	// and "the tenth time here" are worth telling apart.
	Visits int `json:"visits"`
}

// measured reports whether anything was actually observed flowing.
func (r ThroughputRecord) measured() bool {
	return r.Readings > 0 && (r.PeakDownload > 0 || r.PeakUpload > 0)
}

// recordThroughput attributes the latest reading to the server the tunnel is on.
//
// Called after each successful qBittorrent poll. Every guard here exists to keep one
// server's figures from being credited to another, which is the only way this data can
// mislead rather than inform.
func (e *Engine) recordThroughput(download, upload uint64) {
	hostname, _ := e.currentHostname()
	if hostname == "" {
		return
	}
	// Nothing flows through a tunnel that is not up, and whatever qBittorrent reports
	// while it is down describes the moments before it fell over.
	if status := e.Snapshot().Gluetun.Status; status != "" && status != "running" {
		return
	}
	// An idle poll is not a measurement. Recording it would inflate Readings without
	// telling anyone anything.
	if download == 0 && upload == 0 {
		return
	}

	// A reading covers the interval before it, so the first one after a switch is
	// partly the previous server's traffic. Waiting one poll interval attributes it to
	// whichever server actually carried it.
	if since := e.onCurrentSince(hostname); !since.IsZero() {
		if settle := e.cfg.QBittorrent.Interval; settle > 0 && time.Since(since) < settle {
			return
		}
	}

	// The averages are only this server's once the whole window has been on it. Before
	// that they still contain the previous server's rates, and a slow server would
	// inherit a fast one's figures.
	sustainedDownload, sustainedUpload := uint64(0), uint64(0)
	if e.windowIsEntirelyOn(hostname) {
		sustainedDownload, sustainedUpload = e.averageRates()
	}

	now := time.Now()
	newStay := hostname != e.throughputHost
	if err := e.state.update(func(state *persistedState) {
		if state.Throughput == nil {
			state.Throughput = make(map[string]ThroughputRecord)
		}
		record := state.Throughput[hostname]

		// A stay ends when the tunnel leaves, and across a restart when the gap is too
		// long to claim continuity. Starting a fresh stay is what keeps the figures
		// describing "last time I used this server".
		if newStay && (e.throughputHost != "" || record.LastReading.IsZero() ||
			now.Sub(record.LastReading) > stayGap) {
			record = ThroughputRecord{StartedAt: now, Visits: record.Visits + 1}
		}
		if record.StartedAt.IsZero() {
			record.StartedAt = now
		}
		record.Visits = max(record.Visits, 1)
		record.Readings++
		record.LastReading = now
		record.PeakDownload = max(record.PeakDownload, download)
		record.PeakUpload = max(record.PeakUpload, upload)
		record.SustainedDownload = max(record.SustainedDownload, sustainedDownload)
		record.SustainedUpload = max(record.SustainedUpload, sustainedUpload)

		state.Throughput[hostname] = record
		pruneThroughput(state.Throughput)
	}); err != nil {
		// Losing a reading is not a reason to interrupt anything.
		e.logger.Debug("could not persist a throughput reading", "error", err)
	}

	if newStay {
		if e.throughputHost != "" {
			e.logger.Debug("throughput measurement moved to a new server",
				"from", e.throughputHost, "to", hostname)
		}
		e.throughputHost = hostname
	}
}

// windowIsEntirelyOn reports whether every sample in the averaging window was taken
// while the tunnel was on this server.
func (e *Engine) windowIsEntirelyOn(hostname string) bool {
	window := e.cfg.QBittorrent.BusyWindow
	if window <= 0 {
		// No averaging: the average is the latest reading, which the caller has
		// already established belongs to this server.
		return true
	}
	if len(e.transferSamples) == 0 {
		return false
	}
	// The oldest sample still in the window has to postdate the arrival on this
	// server. Without a known arrival time - Gluetun moved on its own, or the tunnel
	// was already up when this container started - there is nothing to check against,
	// so the conservative answer is no.
	since := e.onCurrentSince(hostname)
	if since.IsZero() {
		return false
	}
	return e.transferSamples[0].at.After(since)
}

// pruneThroughput drops the least recently measured records once the map is over the
// cap, so a long-running deployment that has wandered across many servers does not
// grow the state file without bound.
func pruneThroughput(records map[string]ThroughputRecord) {
	for len(records) > maxThroughputRecords {
		var oldestHost string
		var oldest time.Time
		for hostname, record := range records {
			if oldestHost == "" || record.LastReading.Before(oldest) {
				oldestHost, oldest = hostname, record.LastReading
			}
		}
		delete(records, oldestHost)
	}
}

// forgetRetiredThroughput drops records for servers Proton no longer lists.
//
// Proton retires servers, and a record for a hostname that no longer exists is dead
// weight in the state file: nothing can ever display it, because it will never appear
// as a candidate again.
//
// Three rules keep this from deleting live data, which is the only way it could do harm:
//
//   - it runs on a *fresh* list only. A cached list is what this tool falls back to when
//     Proton is unreachable, and treating "I could not ask" as "Proton has retired it"
//     would delete records during an outage.
//   - it compares against every physical server in every logical Proton returned -
//     before any filtering. A server excluded by FILTER_MAX_LOAD, sitting in
//     maintenance, or outside FILTER_COUNTRIES is still a server that exists, and
//     Proton puts servers into maintenance routinely. Comparing against the candidate
//     set instead would erase the history of every server the current filters happen to
//     exclude today.
//   - it refuses to act on an implausibly short list. Every server with a record was in
//     Proton's list when it was measured, so a list shorter than the number of records
//     held is not a retirement - it is a truncated or otherwise wrong response, and
//     acting on it would wipe good data.
func (e *Engine) forgetRetiredThroughput(logicals []proton.LogicalServer) {
	records := e.state.snapshot().Throughput
	if len(records) == 0 {
		return
	}

	listed := make(map[string]bool, len(logicals))
	for _, logical := range logicals {
		for _, physical := range logical.Servers {
			listed[physical.Domain] = true
		}
	}
	if len(listed) < len(records) {
		e.logger.Warn("not pruning measured throughput: proton's list is implausibly short",
			"servers_listed", len(listed), "records_held", len(records),
			"consequence", "records for any retired server are kept until the cap evicts them")
		return
	}

	var retired []string
	for hostname := range records {
		if !listed[hostname] {
			retired = append(retired, hostname)
		}
	}
	if len(retired) == 0 {
		return
	}
	sort.Strings(retired)

	if err := e.state.update(func(state *persistedState) {
		for _, hostname := range retired {
			delete(state.Throughput, hostname)
		}
	}); err != nil {
		e.logger.Debug("could not prune measured throughput", "error", err)
		return
	}
	// Worth an info line rather than a debug one: it is the disappearance of data an
	// operator may have been comparing servers on.
	e.logger.Info("forgot measured throughput for servers proton no longer lists",
		"servers", retired)
}

// recordReadings samples the servers worth keeping a history for.
//
// Driven by the loads refresh rather than a clock of its own, so the series has exactly
// the resolution Proton's figures do: there is nothing to be gained from recording the
// same number twice between refreshes. Latency is carried along at whatever the prober
// last measured, which is a slower cycle - a reading with no latency yet is stored as
// zero and drawn as a gap rather than as a fast server.
func (e *Engine) recordReadings() {
	targets := e.seriesTargets()
	if len(targets) == 0 {
		return
	}

	now := time.Now().Unix()
	readings := make(map[string]Reading, len(targets))
	for _, hostname := range targets {
		candidate, found := e.lookupCandidate(hostname)
		if !found {
			continue
		}
		reading := Reading{At: now, Load: candidate.Load}
		if result, ok := e.prober.Lookup(candidate.EntryIP); ok && result.Err == nil {
			// Whole milliseconds, saturating rather than wrapping: a 70-second RTT is
			// not a fast server, and uint16 arithmetic would make it look like one.
			if milliseconds := result.RTT.Milliseconds(); milliseconds > 0 {
				reading.RTTMS = uint16(min(milliseconds, math.MaxUint16))
			}
		}
		readings[hostname] = reading
	}
	if len(readings) == 0 {
		return
	}

	if err := e.state.update(func(state *persistedState) {
		if state.Series == nil {
			state.Series = make(map[string][]Reading, len(readings))
		}
		for hostname, reading := range readings {
			series := state.Series[hostname]
			// Replace rather than append when the newest reading is from the same
			// refresh: a refresh that found nothing changed should not stretch the
			// series with duplicates.
			if last := len(series) - 1; last >= 0 && series[last].At == reading.At {
				series[last] = reading
			} else {
				series = append(series, reading)
			}
			if len(series) > maxSeriesReadings {
				series = series[len(series)-maxSeriesReadings:]
			}
			state.Series[hostname] = series
		}
		pruneSeries(state.Series)
	}); err != nil {
		// Losing a sample is not a reason to interrupt anything.
		e.logger.Debug("could not persist server readings", "error", err)
	}
}

// seriesTargets is the set of servers worth spending state-file space on.
//
// Not every candidate: there are hundreds, and a history for a server that will never
// be chosen is bytes rewritten several times an hour for nothing. Three kinds are worth
// keeping, for three different reasons:
//
//   - the server the tunnel is on, because its trend is what answers "is this getting
//     worse?";
//   - the best few candidates, because their trend answers "is that alternative
//     reliably quieter, or quiet just at this moment?" - which is the question the load
//     figure alone cannot answer;
//   - anything already measured for throughput, so a server's records stay together
//     rather than one outliving the other.
func (e *Engine) seriesTargets() []string {
	const bestCandidates = 10

	targets := make([]string, 0, bestCandidates+len(e.state.snapshot().Throughput)+1)
	seen := make(map[string]bool)
	add := func(hostname string) {
		if hostname == "" || seen[hostname] {
			return
		}
		seen[hostname] = true
		targets = append(targets, hostname)
	}

	current, _ := e.currentHostname()
	add(current)
	for i, entry := range e.ranked {
		if i >= bestCandidates {
			break
		}
		add(entry.Candidate.Hostname)
	}
	for hostname := range e.state.snapshot().Throughput {
		add(hostname)
	}
	return targets
}

// pruneSeries bounds both dimensions of the history: how many servers have one, and how
// long each is. Least recently sampled servers go first.
func pruneSeries(series map[string][]Reading) {
	for hostname, readings := range series {
		if len(readings) > maxSeriesReadings {
			series[hostname] = readings[len(readings)-maxSeriesReadings:]
		}
		if len(readings) == 0 {
			delete(series, hostname)
		}
	}
	for len(series) > maxSeriesServers {
		var oldestHost string
		var oldest int64
		for hostname, readings := range series {
			last := readings[len(readings)-1].At
			if oldestHost == "" || last < oldest {
				oldestHost, oldest = hostname, last
			}
		}
		delete(series, oldestHost)
	}
}

// loadTrace returns the utilisation history for one server, for the sparkline on the
// current-server column.
//
// Keyed by hostname, so unlike the single global trace this replaced it cannot splice
// two servers' figures into one line.
func (e *Engine) loadTrace(hostname string) (trace []LoadPoint) {
	if hostname == "" {
		return nil
	}
	readings := e.state.snapshot().Series[hostname]
	if len(readings) == 0 {
		return nil
	}
	trace = make([]LoadPoint, 0, len(readings))
	for _, reading := range readings {
		trace = append(trace, LoadPoint{At: time.Unix(reading.At, 0), Load: reading.Load})
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

// ServerHistory is everything measured about one server, for the detail panel.
//
// Fetched per server on demand rather than published in the snapshot: the candidate list
// runs to hundreds of rows, and attaching a series to each would put tens of thousands of
// points on the wire on every update to show the handful anyone opens.
type ServerHistory struct {
	Hostname string `json:"hostname"`
	// Readings is oldest first. Load is always present; RTT is absent for readings
	// taken before latency was known.
	Readings []HistoryPoint `json:"readings"`
	// Throughput is what the server delivered, or nil if it was never measured.
	Throughput *ThroughputView `json:"throughput,omitempty"`
	// Interval is how often readings are taken, so the graph can say what it spans
	// rather than leaving the reader to guess from timestamps.
	Interval string `json:"interval,omitempty"`
	// Capacity is how many readings are kept at most, so a full series can say so.
	Capacity int `json:"capacity"`
}

// HistoryPoint is one reading, expanded from its compact stored form.
type HistoryPoint struct {
	At time.Time `json:"at"`
	// Load is Proton's utilisation percentage.
	Load uint8 `json:"load"`
	// RTTMS is 0 when latency was not known when this reading was taken, which is
	// drawn as a gap. RTTKnown says which of the two a zero means.
	RTTMS    uint16 `json:"rtt_ms,omitempty"`
	RTTKnown bool   `json:"rtt_known"`
}

// ServerHistory returns one server's measured history.
func (e *Engine) ServerHistory(hostname string) ServerHistory {
	history := ServerHistory{
		Hostname: hostname,
		Interval: e.cfg.Proton.LoadRefreshInterval.String(),
		Capacity: maxSeriesReadings,
		Readings: []HistoryPoint{},
	}
	for _, reading := range e.state.snapshot().Series[hostname] {
		history.Readings = append(history.Readings, HistoryPoint{
			At: time.Unix(reading.At, 0), Load: reading.Load,
			RTTMS: reading.RTTMS, RTTKnown: reading.RTTMS > 0,
		})
	}
	history.Throughput = e.throughputFor(hostname)
	return history
}

// throughputFor returns the record for a server, if it has been measured.
func (e *Engine) throughputFor(hostname string) (view *ThroughputView) {
	if e.qbittorrent == nil || hostname == "" {
		return nil
	}
	record, found := e.state.snapshot().Throughput[hostname]
	if !found || !record.measured() {
		return nil
	}
	return &ThroughputView{
		PeakDownload:      record.PeakDownload,
		PeakUpload:        record.PeakUpload,
		SustainedDownload: record.SustainedDownload,
		SustainedUpload:   record.SustainedUpload,
		Readings:          record.Readings,
		Visits:            record.Visits,
		StartedAt:         record.StartedAt,
		LastReading:       record.LastReading,
		Current:           hostname == e.throughputHost,
	}
}
