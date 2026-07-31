// This file holds what has been *measured* about individual servers, as opposed to what
// Proton says about them.
//
// Load, latency and Proton's own score all describe a server before it is used, and all
// are replaced wholesale on every refresh. What is here instead accumulates from
// observation and survives restarts, so it is the only record of how a server actually
// behaved.
//
// Everything is reduced to figures that do not grow with time - extremes, totals and
// counts - rather than kept as a series of readings. That is a deliberate trade: a series
// buys graphs at the cost of a state file that grows with every server and every hour,
// while a dozen fixed numbers answer what those graphs were being read for and cost the
// same whether a server has been used for a day or a year. It is also what makes this
// affordable for *every* candidate rather than a chosen few.
//
// Kept in one place because these records share their rules rather than merely their
// shape: an observation must be attributed to the server that earned it, something never
// measured must read as absent rather than as zero, and a record must be dropped when
// Proton retires the server.
package engine

import (
	"math"
	"sort"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/qbittorrent"
)

// stateFlushInterval is how often pending in-memory changes are written.
//
// The compromise between two failure modes. Writing on every qBittorrent poll - four times
// a minute, the whole file each time - is needless wear on hardware that may be an SD card.
// Writing only on the loads refresh, fifteen minutes apart, meant a restart could discard a
// quarter of an hour of counted bytes. A minute bounds the loss to something nobody will
// notice while cutting the writes by three quarters.
const stateFlushInterval = time.Minute

// flushState writes anything the fast path left in memory.
func (e *Engine) flushState(trigger string) {
	written, err := e.state.flush()
	if err != nil {
		e.logger.Warn("could not save state", "trigger", trigger, "error", err)
		return
	}
	if written {
		e.logger.Debug("saved pending state", "trigger", trigger)
	}
}

// recordSamples folds the current load and latency of every candidate into its statistics.
//
// Driven by the loads refresh rather than a clock of its own, so the figures have exactly
// the resolution Proton's do: there is nothing to be gained from recording the same number
// twice between refreshes.
//
// Every candidate, not a chosen few. A fixed-size record per server is cheap enough that
// narrowing it would only lose information - and "has this server ever been busy?" is most
// useful for the ones not currently in use.
func (e *Engine) recordSamples() {
	if len(e.ranked) == 0 {
		return
	}
	now := time.Now()

	if err := e.state.update(func(state *persistedState) {
		if state.Stats == nil {
			state.Stats = make(map[string]ServerStats, len(e.ranked))
		}
		for _, entry := range e.ranked {
			candidate := entry.Candidate
			stats := state.Stats[candidate.Hostname]
			stats.observeLoad(candidate.Load, now)
			if result, found := e.prober.Lookup(candidate.EntryIP); found && result.Err == nil {
				// Whole milliseconds, saturating rather than wrapping: a 70 second round
				// trip is not a fast server, and uint16 arithmetic would make it look
				// like one.
				if milliseconds := result.RTT.Milliseconds(); milliseconds > 0 {
					stats.observeRTT(uint16(min(milliseconds, math.MaxUint16)))
				}
			}
			state.Stats[candidate.Hostname] = stats
		}
	}); err != nil {
		// Losing a sample is not a reason to interrupt anything.
		e.logger.Debug("could not persist server statistics", "error", err)
	}
}

// recordTransfer attributes a qBittorrent reading to the server carrying the traffic.
//
// Called after each successful poll. Every guard here exists to keep one server's figures
// from being credited to another, which is the only way this data can mislead rather than
// inform.
func (e *Engine) recordTransfer(transfer qbittorrent.Transfer) {
	download, upload := transfer.DownloadSpeed, transfer.UploadSpeed

	// Every path that declines to attribute this reading must also drop the byte
	// baseline, or the next difference silently spans the gap and credits one server with
	// traffic that moved while something else was true. Deferred so no early return can
	// forget it.
	attributed := false
	defer func() {
		if !attributed {
			e.transferBaselineHost = ""
		}
	}()

	hostname, _ := e.currentHostname()
	if hostname == "" {
		return
	}
	// Nothing flows through a tunnel that is not up, and whatever qBittorrent reports
	// while it is down describes the moments before it fell over.
	if status := e.Snapshot().Gluetun.Status; status != "" && status != "running" {
		return
	}
	// A reading covers the interval before it, so the first one after a switch is partly
	// the previous server's traffic. Waiting one poll interval attributes it to whichever
	// server actually carried it.
	if since := e.onCurrentSince(hostname); !since.IsZero() {
		if settle := e.cfg.QBittorrent.Interval; settle > 0 && time.Since(since) < settle {
			return
		}
	}

	bytesDown, bytesUp := e.transferredSince(hostname, transfer)
	attributed = true

	// Nothing moved and nothing is moving: there is no measurement here, and creating a
	// record from it would put a server in the table on the strength of having been
	// connected rather than having carried anything. The baseline has already been
	// advanced above, which is the part that matters - an idle interval is a real zero,
	// so the next difference still covers it.
	if bytesDown == 0 && bytesUp == 0 && download == 0 && upload == 0 {
		return
	}

	// A stay is defined by where the tunnel is, so this comes from persisted state rather
	// than from memory: otherwise a restart would look like a fresh arrival and throw away
	// the rates measured so far on the server the tunnel never left.
	newStay := hostname != e.state.snapshot().MeasuringHost
	now := time.Now()

	// Deliberately mutate rather than update: this runs on every qBittorrent poll, and
	// rewriting the whole state file four times a minute for figures that rarely change is
	// pure wear. The loads refresh flushes it.
	e.state.mutate(func(state *persistedState) {
		if state.Stats == nil {
			state.Stats = make(map[string]ServerStats)
		}
		stats := state.Stats[hostname]

		// Visits counts stays during which this server actually carried something, which is
		// the useful reading of "how often have I used this one": a stay that moved nothing
		// tells you about your torrents, not about the server.
		if newStay {
			stats.Visits++
		}
		if stats.FirstSeenUnix == 0 {
			stats.FirstSeenUnix = now.Unix()
		}

		// Volume is counted even when the rates are zero, and separately from them. The
		// two are different measurements: a rate is what this instant looks like, so an
		// idle poll says nothing about it, while a volume is a difference between two
		// counters and an idle interval genuinely contributes nothing.
		if bytesDown > 0 || bytesUp > 0 {
			stats.DownloadedBytes += bytesDown
			stats.UploadedBytes += bytesUp
			stats.LastTransferUnix = now.Unix()
		}
		if download > 0 || upload > 0 {
			// The first reading of a new stay replaces the rates; the rest raise them.
			//
			// Volumes accumulate for ever and rates do not, because they are different
			// kinds of claim. "412 GB have gone through this server" only grows truer with
			// time. "This server does 14 MB/s" was true on one evening under one set of
			// conditions, and repeating it about a server that is busier now is worse than
			// saying nothing.
			//
			// Replacing on the first reading rather than clearing on arrival is what keeps
			// the previous stay's figure visible until there is something real to put in its
			// place - reconnecting does not blank the card and leave it blank until a
			// download happens to start.
			if newStay {
				stats.MaxDownloadRate, stats.MaxUploadRate = download, upload
			} else {
				stats.MaxDownloadRate = max(stats.MaxDownloadRate, download)
				stats.MaxUploadRate = max(stats.MaxUploadRate, upload)
			}
			stats.TransferReadings++
			stats.LastSeenUnix = now.Unix()
			// The stay is only established once it has a rate of its own, for the same
			// reason: until then the figure on display still belongs to the previous one.
			state.MeasuringHost = hostname
		}

		state.Stats[hostname] = stats
	})

	if newStay {
		if e.throughputHost != "" && e.throughputHost != hostname {
			e.logger.Debug("transfer measurement moved to a new server",
				"from", e.throughputHost, "to", hostname)
		}
		e.throughputHost = hostname
	}
}

// transferredSince returns how many bytes moved since the previous poll, attributed to
// this server.
//
// qBittorrent reports session totals, not per-server ones, so the only way to attribute
// them is by difference between consecutive polls. Three things make a difference
// meaningless, and each yields zero and a fresh baseline rather than a wrong number:
//
//   - no baseline yet, because this is the first poll, or the previous one was not
//     attributable. There is nothing to subtract from;
//   - the baseline belongs to another server. The bytes in that interval were carried by
//     that server, and it has already been credited with them;
//   - the counter went backwards, which means qBittorrent restarted. Its session totals
//     began again from zero, so the difference would be nonsense - and the bytes moved
//     before the restart within this interval are simply not recoverable.
//
// An idle interval is none of those. Nothing moved, which is a real zero rather than a
// gap, so the baseline moves forward through quiet periods instead of restarting.
func (e *Engine) transferredSince(hostname string, transfer qbittorrent.Transfer) (down, up uint64) {
	previousHost := e.transferBaselineHost
	previousDown, previousUp := e.transferBaselineDown, e.transferBaselineUp

	e.transferBaselineHost = hostname
	e.transferBaselineDown = transfer.DownloadTotal
	e.transferBaselineUp = transfer.UploadTotal

	if previousHost != hostname {
		return 0, 0
	}
	if transfer.DownloadTotal < previousDown || transfer.UploadTotal < previousUp {
		e.logger.Debug("qbittorrent's session counters went backwards; it has restarted",
			"consequence", "the bytes moved in this interval are not attributed")
		return 0, 0
	}
	return transfer.DownloadTotal - previousDown, transfer.UploadTotal - previousUp
}

// pruneStats bounds how many servers keep statistics, least recently seen first.
func pruneStats(stats map[string]ServerStats) {
	for len(stats) > maxServerStats {
		var oldestHost string
		var oldest int64
		for hostname, record := range stats {
			if oldestHost == "" || record.LastSeenUnix < oldest {
				oldestHost, oldest = hostname, record.LastSeenUnix
			}
		}
		delete(stats, oldestHost)
	}
}

// forgetRetiredServers drops the statistics of servers Proton no longer lists.
//
// Proton retires servers, and a record for a hostname that no longer exists is dead weight
// in the state file: nothing can ever display it, because it will never appear as a
// candidate again. This is also the only route by which a transferred total is deleted,
// which is why the guards below matter so much: those totals are meant to be kept
// indefinitely, and there is no recovering one discarded by mistake.
//
// Three rules keep it from deleting live data:
//
//   - it runs on a *fresh* list only. A cached list is what this tool falls back to when
//     Proton is unreachable, and treating "I could not ask" as "Proton has retired it"
//     would delete records during an outage;
//   - it compares against every physical server in every logical Proton returned, before
//     any filtering. A server excluded by FILTER_MAX_LOAD, sitting in maintenance, or
//     outside FILTER_COUNTRIES is still a server that exists, and Proton puts servers into
//     maintenance routinely. Comparing against the candidate set instead would erase the
//     history of every server the current filters happen to exclude today;
//   - it refuses to act on an implausibly short list. Every server with a record was in
//     Proton's list when it was measured, so a list shorter than the number of records
//     held is not a retirement - it is a truncated or otherwise wrong response, and acting
//     on it would wipe good data.
func (e *Engine) forgetRetiredServers(logicals []proton.LogicalServer) {
	held := e.state.snapshot().Stats
	if len(held) == 0 {
		return
	}

	listed := make(map[string]bool, len(logicals))
	for _, logical := range logicals {
		for _, physical := range logical.Servers {
			listed[physical.Domain] = true
		}
	}
	if len(listed) < len(held) {
		e.logger.Warn("not pruning server statistics: proton's list is implausibly short",
			"servers_listed", len(listed), "records_held", len(held),
			"consequence", "statistics for any retired server are kept for now")
		return
	}

	var retired []string
	for hostname := range held {
		if !listed[hostname] {
			retired = append(retired, hostname)
		}
	}
	if len(retired) == 0 {
		return
	}
	sort.Strings(retired)

	// What is being discarded, before it is discarded. A transferred total is meant to
	// last for the life of the server, so its removal is reported with the figure rather
	// than as a bare count of hostnames.
	for _, hostname := range retired {
		record := held[hostname]
		e.logger.Info("forgetting a server proton no longer lists",
			"hostname", hostname,
			"downloaded", formatBytes(record.DownloadedBytes),
			"uploaded", formatBytes(record.UploadedBytes),
			"visits", record.Visits)
	}

	if err := e.state.update(func(state *persistedState) {
		for _, hostname := range retired {
			delete(state.Stats, hostname)
		}
	}); err != nil {
		e.logger.Warn("could not prune the statistics of retired servers", "error", err)
	}
}

// onCurrentSince reports when the tunnel arrived on the server it is on.
//
// Zero unless the current server is the one this tool pinned. If Gluetun moved on its own,
// or the tunnel was already up when this container started, the arrival time is genuinely
// unknown, and showing the last switch time regardless would attribute someone else's
// reconnect to us.
func (e *Engine) onCurrentSince(hostname string) time.Time {
	persisted := e.state.snapshot()
	if hostname == "" || hostname != persisted.PinnedHostname {
		return time.Time{}
	}
	return persisted.LastSwitchAt
}

// statsFor returns the observed statistics for a server, or nil if nothing has been
// observed.
//
// Nil rather than a zeroed record: "never measured" and "measured as zero" are different
// facts, and the dashboard has to be able to say which.
func (e *Engine) statsFor(hostname string) (view *ServerStatsView) {
	if hostname == "" {
		return nil
	}
	record, found := e.state.snapshot().Stats[hostname]
	if !found || !record.measured() {
		return nil
	}

	view = &ServerStatsView{
		LoadLast:         record.LoadLast,
		LoadLowest:       record.LoadLowest,
		LoadHighest:      record.LoadHighest,
		RTTLastMS:        record.RTTLastMS,
		RTTLowestMS:      record.RTTLowestMS,
		RTTHighestMS:     record.RTTHighestMS,
		Samples:          record.Samples,
		TransferReadings: record.TransferReadings,
		Visits:           record.Visits,
		FirstSeen:        record.FirstSeen(),
		LastSeen:         record.LastSeen(),
		Current:          hostname == e.throughputHost,
	}
	// The transfer figures exist only with qBittorrent. Marked unknown rather than zeroed
	// when it is not configured, so the dashboard says "not measured" instead of implying
	// this server carried nothing.
	if e.qbittorrent != nil {
		view.TransferKnown = true
		view.DownloadedBytes = record.DownloadedBytes
		view.UploadedBytes = record.UploadedBytes
		view.MaxDownloadRate = record.MaxDownloadRate
		view.MaxUploadRate = record.MaxUploadRate
		view.LastTransferAt = record.LastTransferAt()
	}
	return view
}
