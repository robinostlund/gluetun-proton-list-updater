package engine

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/gluetunapi"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/qbittorrent"
)

// refreshTransfer reads the current transfer rates and works out whether the tunnel
// is too busy to be moved.
//
// A failed read never clears "busy". The purpose of this feature is to avoid
// interrupting a transfer, and treating "I could not find out" as "nothing is
// happening" would interrupt exactly the transfer it exists to protect. So the last
// known rates are kept, marked as not current, and they keep deferring switches until
// qBittorrent answers again.
func (e *Engine) refreshTransfer(ctx context.Context, trigger string) {
	if e.qbittorrent == nil {
		return
	}

	transfer, err := e.qbittorrent.Transfer(ctx)
	if err != nil {
		e.transferReachable = false
		// Logged at warn once and at debug thereafter: a qBittorrent that is down
		// stays down, and repeating the same line every fifteen seconds drowns the
		// log in it.
		if e.transferErr == "" {
			e.logger.Warn("could not read transfer rates from qbittorrent",
				"trigger", trigger, "error", err,
				"consequence", "the last known rates keep deferring switches until it answers again")
		} else {
			e.logger.Debug("qbittorrent still unreachable", "error", err)
		}
		e.transferErr = err.Error()
		// Neither of these will start working on its own, so they are logged as
		// errors rather than buried as transient failures - and named apart, because
		// the fixes are completely different.
		switch {
		case errors.Is(err, qbittorrent.ErrAddressRejected):
			e.logger.Error("qbittorrent refused the address, not the key; "+
				"transfer awareness is not working",
				"url", e.cfg.QBittorrent.URL,
				"fix", "point QBITTORRENT_URL at qBittorrent's own Web UI port",
				"error", err)
		case errors.Is(err, qbittorrent.ErrKeyRejected):
			e.logger.Error("qbittorrent rejected the API key; transfer awareness is not working",
				"error", err)
		}
		e.publishTransfer()
		return
	}

	if !e.transferReachable && e.transferErr != "" {
		e.logger.Info("qbittorrent is answering again")
	}
	e.transferReachable = true
	e.refreshQBittorrentPreferences(ctx)
	e.transferErr = ""
	e.transfer = transfer
	e.transferCheckedAt = time.Now()
	e.recordTransferSample(transfer)
	// Credit the reading to whichever server carried it, so there is a record of what each
	// one actually delivered.
	e.recordTransfer(transfer)

	// Track when the tunnel became busy, so the wait can be bounded and shown.
	busy := e.transferIsBusy()
	switch {
	case busy && e.transferBusySince.IsZero():
		e.transferBusySince = time.Now()
		averageDownload, averageUpload := e.averageRates()
		e.logger.Info("transfer in progress, automatic switching is on hold",
			"average_download", formatRate(averageDownload),
			"average_upload", formatRate(averageUpload),
			"window", e.cfg.QBittorrent.BusyWindow,
			"samples", len(e.transferSamples))
	case !busy && !e.transferBusySince.IsZero():
		e.logger.Info("transfer has quietened down, automatic switching is available again",
			"was_busy_for", time.Since(e.transferBusySince).Truncate(time.Second))
		e.transferBusySince = time.Time{}
	}

	e.publishTransfer()
}

// transferIsBusy reports whether either direction is above its threshold.
//
// The two are checked independently and deliberately: seeding at 5 MB/s and
// downloading at 5 MB/s are different situations, and an operator may want to protect
// one and not the other. A zero threshold disables that direction.
func (e *Engine) transferIsBusy() bool {
	limits := e.cfg.QBittorrent
	download, upload := e.averageRates()
	if limits.BusyDownload > 0 && download >= limits.BusyDownload {
		return true
	}
	return limits.BusyUpload > 0 && upload >= limits.BusyUpload
}

// transferSample is one reading, kept so the decision can be made on an average.
type transferSample struct {
	at       time.Time
	download uint64
	upload   uint64
}

// recordTransferSample appends a reading and drops the ones that have aged out.
//
// Pruning is relative to the newest sample rather than to now, which matters when
// qBittorrent stops answering: measured from now, the window would drain until the
// average fell below the threshold and a switch was allowed - silently undoing the
// fail-safe. Anchored to the last reading, the history simply stops moving.
func (e *Engine) recordTransferSample(transfer qbittorrent.Transfer) {
	window := e.cfg.QBittorrent.BusyWindow
	now := time.Now()
	if window <= 0 {
		// Averaging disabled: the latest reading is the whole history.
		e.transferSamples = []transferSample{{
			at: now, download: transfer.DownloadSpeed, upload: transfer.UploadSpeed,
		}}
		return
	}

	e.transferSamples = append(e.transferSamples, transferSample{
		at: now, download: transfer.DownloadSpeed, upload: transfer.UploadSpeed,
	})

	cutoff := now.Add(-window)
	kept := e.transferSamples[:0]
	for _, sample := range e.transferSamples {
		if !sample.at.Before(cutoff) {
			kept = append(kept, sample)
		}
	}
	e.transferSamples = kept
}

// averageRates returns the mean download and upload rate over the window.
//
// A mean, not the latest reading: traffic is bursty, and a torrent that is plainly
// active drops to nothing between pieces. A poll landing in one of those dips reported
// the tunnel idle and let a switch through mid-transfer, which is the exact
// interruption this feature exists to prevent.
//
// Not a peak either. A single spike should not hold the tunnel for a whole window; an
// average is what distinguishes "in use" from "was used once a few minutes ago".
func (e *Engine) averageRates() (download, upload uint64) {
	if len(e.transferSamples) == 0 {
		return e.transfer.DownloadSpeed, e.transfer.UploadSpeed
	}

	var totalDownload, totalUpload uint64
	for _, sample := range e.transferSamples {
		totalDownload += sample.download
		totalUpload += sample.upload
	}
	count := uint64(len(e.transferSamples))
	return totalDownload / count, totalUpload / count
}

// transferBlocksSwitch reports whether a switch should be deferred, and why.
//
// It answers for automatic switching only. A switch the operator asked for
// explicitly is their decision to make, and overriding it would be worse than a
// broken transfer.
func (e *Engine) transferBlocksSwitch() (blocked bool, reason string) {
	if e.qbittorrent == nil {
		return false, ""
	}
	// Three states, not two, and the middle one is the whole point of this block.
	//
	// Having had a reading and then losing contact falls safe: the last known rates keep
	// deferring, because a transfer that was running a moment ago is very likely still
	// running. That is handled below.
	//
	// Never having had a reading is split by *how long* that has been true:
	//
	//   - briefly, which is the normal state just after a restart. Both containers come up
	//     together and qBittorrent is often not answering yet, so the first poll fails.
	//     Treating that as "nothing is transferring" let a switch through during an active
	//     download on every restart - the exact interruption this feature exists to
	//     prevent, at the moment it is most likely to happen. So it waits.
	//   - persistently, which means a wrong URL, a wrong key, or qBittorrent genuinely not
	//     running. Then it falls open: holding the tunnel on a degrading server for ever
	//     because of a misconfiguration is a worse outcome than a switch, and the failure
	//     is reported loudly elsewhere rather than silently freezing selection.
	if e.transferCheckedAt.IsZero() {
		// Waiting is only defensible when there is something to protect, and the thing that
		// decides that is whether the *tunnel* is up - not whether this tool can name the
		// server it is on.
		//
		// Those were conflated here, and it is exactly the case that matters: on startup the
		// current server is routinely unidentifiable for a moment (Gluetun restarted and
		// discarded the pin, so nothing has been re-pinned yet) while the tunnel is up and
		// carrying a download at full speed. Treating that as "nothing to protect" switched
		// servers mid-transfer on every restart - the precise failure this whole feature
		// exists to prevent.
		if status := e.Snapshot().Gluetun.Status; status != "" && status != gluetunapi.StatusRunning {
			return false, ""
		}
		if waited := time.Since(e.startedAt); waited < firstReadingGrace {
			return true, fmt.Sprintf(
				"qbittorrent has not answered yet (%s since startup, waiting up to %s "+
					"before switching without knowing)",
				waited.Truncate(time.Second), firstReadingGrace)
		}
		// Said once, when the grace period runs out, rather than on every evaluation.
		if !e.transferGraceExpired {
			e.transferGraceExpired = true
			e.logger.Warn("qbittorrent has never answered; switching will no longer wait for it",
				"waited", firstReadingGrace,
				"consequence", "a switch can now interrupt a transfer, because there is no "+
					"way to tell whether one is running",
				"fix", "check QBITTORRENT_URL and QBITTORRENT_API_KEY")
		}
		return false, ""
	}
	if !e.transferIsBusy() {
		return false, ""
	}

	// A crashed tunnel is the one case where deferring is actively harmful. Whatever
	// qBittorrent last reported, nothing is flowing through a tunnel that is down, so
	// there is no transfer left to protect - only a recovery to delay.
	if e.Snapshot().Gluetun.Status == gluetunapi.StatusCrashed {
		return false, ""
	}

	// The safety valve. Without a bound, a permanently busy tunnel would never be
	// moved off a degrading server; with one, protecting the transfer wins until the
	// choice has been stale for too long.
	if maxDefer := e.cfg.QBittorrent.MaxDefer; maxDefer > 0 && !e.transferBusySince.IsZero() {
		if held := time.Since(e.transferBusySince); held > maxDefer {
			e.logger.Warn("switching has been deferred for longer than the limit, moving anyway",
				"deferred_for", held.Truncate(time.Second), "limit", maxDefer,
				"download", formatRate(e.transfer.DownloadSpeed),
				"upload", formatRate(e.transfer.UploadSpeed))
			return false, ""
		}
	}

	averageDownload, averageUpload := e.averageRates()
	reason = fmt.Sprintf("a transfer is in progress (%s down, %s up",
		formatRate(averageDownload), formatRate(averageUpload))
	if window := e.cfg.QBittorrent.BusyWindow; window > 0 {
		reason += fmt.Sprintf(" averaged over %s)", window)
	} else {
		reason += ")"
	}
	if !e.transferReachable {
		reason += ", from the last reading before qbittorrent stopped answering"
	}
	return true, reason
}

// preferencesInterval is how often the port settings are re-read. They change only
// when an operator changes them, so polling them as often as the rates would be waste.
//
// preferencesRetryInterval applies after a failure instead. The slow interval is right
// for a value that rarely changes but wrong for one that is missing: a single blip -
// qBittorrent still starting up when this tool polls it, say - would otherwise leave
// the listen port unknown, and the mismatch check unable to run, for five minutes.
const (
	preferencesInterval      = 5 * time.Minute
	preferencesRetryInterval = 20 * time.Second
)

// refreshQBittorrentPreferences re-reads the port settings when they are stale.
//
// A failure here is not fatal - the rates, the thing the feature exists for, are
// already in hand - but it is not silent either. Without these settings the listen
// port is unknown and the mismatch check cannot run, which is exactly the failure
// this tool exists to catch, so the reason is kept and reported rather than dropped
// at debug level where nobody would ever see it.
func (e *Engine) refreshQBittorrentPreferences(ctx context.Context) {
	interval := preferencesInterval
	if e.qbPreferencesErr != "" || e.qbPreferences.ListenPort == 0 || e.qbittorrentVersion == "" {
		interval = preferencesRetryInterval
	}
	if !e.qbPreferencesAt.IsZero() && time.Since(e.qbPreferencesAt) < interval {
		return
	}

	preferences, err := e.qbittorrent.Preferences(ctx)
	if err != nil {
		// Warned once, then kept quiet: this is polled every few minutes and a
		// permission problem does not change between polls.
		if e.qbPreferencesErr == "" {
			e.logger.Warn("could not read qbittorrent's port settings",
				"error", err,
				"consequence", "the listen port is unknown, so a forwarded port that "+
					"does not reach qBittorrent cannot be detected")
		} else {
			e.logger.Debug("qbittorrent's port settings are still unreadable", "error", err)
		}
		e.qbPreferencesErr = err.Error()
		// Stamped even on failure, so the retry is paced rather than attempted on
		// every rate poll.
		e.qbPreferencesAt = time.Now()
		return
	}
	if e.qbPreferencesErr != "" {
		e.logger.Info("qbittorrent's port settings are readable again",
			"listen_port", preferences.ListenPort)
		e.qbPreferencesErr = ""
	}

	// The version is read here rather than only at startup, and on the same paced cadence
	// as the settings for the same reason: it changes rarely, and reading it on every rate
	// poll would be waste.
	//
	// Only at startup was wrong in two ways. If qBittorrent was not running then - the
	// common case when both containers come up together - it stayed blank for ever; and
	// after a qBittorrent upgrade the dashboard reported the old version indefinitely.
	if e.qbittorrentVersion == "" {
		if version, err := e.qbittorrent.Version(ctx); err == nil {
			e.qbittorrentVersion = version
			e.logger.Info("identified qbittorrent", "version", version)
		} else {
			e.logger.Debug("could not read qbittorrent's version", "error", err)
		}
	}
	if preferences.ListenPort != e.qbPreferences.ListenPort && e.qbPreferences.ListenPort != 0 {
		e.logger.Info("qbittorrent's listen port changed",
			"from", e.qbPreferences.ListenPort, "to", preferences.ListenPort)
	}
	e.qbPreferences = preferences
	e.qbPreferencesAt = time.Now()
}

// portForwardingVerdict works out whether a forwarded port actually reaches
// qBittorrent.
//
// No single source knows this. Gluetun knows which port Proton forwarded; qBittorrent
// knows which port it listens on and whether anything is arriving. The failure worth
// catching is the one neither reports as a problem: forwarding succeeds, qBittorrent
// runs happily, and the two ports differ - so every incoming connection goes nowhere.
func (e *Engine) portForwardingVerdict(gluetun GluetunStatus) (verdict, detail string) {
	// Nothing to say before qBittorrent has answered.
	if e.transferCheckedAt.IsZero() {
		return "unknown", "qBittorrent has not answered yet."
	}

	requested := gluetun.PortForwardingEnabled
	if requested != nil && !*requested {
		return "not requested",
			"Gluetun is not asking Proton for a forwarded port, so no incoming connections are expected."
	}

	listen := e.qbPreferences.ListenPort
	forwarded := gluetun.ForwardedPorts

	// Without the listen port the mismatch check below cannot run, so a "working"
	// verdict from peer connectivity alone would be overstating what is known.
	if listen == 0 && e.qbPreferencesErr != "" {
		return "unknown", fmt.Sprintf(
			"qBittorrent's listening port could not be read, so it cannot be compared "+
				"with the forwarded port%s: %s",
			map[bool]string{true: " " + joinPorts(forwarded)}[len(forwarded) > 0],
			e.qbPreferencesErr)
	}

	// A mismatch is decisive, and takes precedence over anything qBittorrent reports
	// about peers: it explains the symptom and names the fix.
	if listen != 0 && len(forwarded) > 0 && !containsPort(forwarded, listen) {
		return "mismatch", fmt.Sprintf(
			"Gluetun forwarded port %s but qBittorrent is listening on %d, so nothing reaches it. "+
				"Set qBittorrent's listening port to the forwarded one%s.",
			joinPorts(forwarded), listen,
			map[bool]string{true: ", and turn off its random-port setting, which re-chooses the port on every start"}[e.qbPreferences.RandomPort])
	}
	if listen != 0 && e.qbPreferences.RandomPort {
		return "mismatch", fmt.Sprintf(
			"qBittorrent is set to use a random listening port (currently %d), so it will stop "+
				"matching the forwarded port the next time it starts.", listen)
	}

	switch e.transfer.ConnectionStatus {
	case "connected":
		if len(forwarded) > 0 {
			return "working", fmt.Sprintf(
				"Incoming connections are reaching qBittorrent on port %s.", joinPorts(forwarded))
		}
		return "working", "Incoming connections are reaching qBittorrent."
	case "firewalled":
		return "unreachable", fmt.Sprintf(
			"qBittorrent reports itself firewalled: no incoming connections are arriving%s. "+
				"Check that the forwarded port reaches it.",
			map[bool]string{true: fmt.Sprintf(" on port %s", joinPorts(forwarded))}[len(forwarded) > 0])
	case "disconnected":
		return "unknown", "qBittorrent is not connected to any peers, so nothing can be inferred yet."
	default:
		return "unknown", ""
	}
}

func containsPort(ports []uint16, port uint16) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func joinPorts(ports []uint16) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(int(port)))
	}
	return strings.Join(parts, ", ")
}

// transferView builds the published transfer block.
//
// It must be called *outside* mutateSnapshot: it reads the current snapshot to learn
// Gluetun's forwarded ports, and the snapshot mutex is not reentrant.
func (e *Engine) transferView() TransferStatus {
	limits := e.cfg.QBittorrent
	busy := e.transferIsBusy()

	deferredFor := ""
	if busy && !e.transferBusySince.IsZero() {
		deferredFor = formatDuration(time.Since(e.transferBusySince))
	}
	maxDefer := ""
	if limits.MaxDefer > 0 {
		maxDefer = limits.MaxDefer.String()
	}
	verdict, detail := e.portForwardingVerdict(e.Snapshot().Gluetun)
	averageDownload, averageUpload := e.averageRates()
	window := ""
	if limits.BusyWindow > 0 {
		window = limits.BusyWindow.String()
	}

	return TransferStatus{
		Configured:            true,
		Reachable:             e.transferReachable,
		HasReading:            !e.transferCheckedAt.IsZero(),
		LastError:             e.transferErr,
		DownloadSpeed:         e.transfer.DownloadSpeed,
		UploadSpeed:           e.transfer.UploadSpeed,
		AverageDownload:       averageDownload,
		AverageUpload:         averageUpload,
		BusyWindow:            window,
		Samples:               len(e.transferSamples),
		DownloadTotal:         e.transfer.DownloadTotal,
		UploadTotal:           e.transfer.UploadTotal,
		DownloadLimit:         e.transfer.DownloadLimit,
		UploadLimit:           e.transfer.UploadLimit,
		ConnectionStatus:      e.transfer.ConnectionStatus,
		ListenPort:            e.qbPreferences.ListenPort,
		ListenPortError:       e.qbPreferencesErr,
		RandomPort:            e.qbPreferences.RandomPort,
		PortForwarding:        verdict,
		PortForwardingDetail:  detail,
		Busy:                  busy,
		BusySince:             e.transferBusySince,
		DeferredFor:           deferredFor,
		BusyDownloadThreshold: limits.BusyDownload,
		BusyUploadThreshold:   limits.BusyUpload,
		MaxDefer:              maxDefer,
		LastCheck:             e.transferCheckedAt,
		Version:               e.qbittorrentVersion,
	}
}

// publishTransfer copies the transfer state into the snapshot.
func (e *Engine) publishTransfer() {
	view := e.transferView()
	e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Transfer = view })
}

// formatRate renders bytes per second the way people read it.
func formatRate(bytesPerSecond uint64) string {
	const unit = 1000
	if bytesPerSecond < unit {
		return fmt.Sprintf("%d B/s", bytesPerSecond)
	}
	value := float64(bytesPerSecond)
	for _, suffix := range []string{"kB/s", "MB/s", "GB/s", "TB/s"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f PB/s", value/unit)
}

// formatBytes renders a volume. Distinct from formatRate on purpose: logging a total as
// "12.4 MB/s" states a rate that was never measured, and the two are easy to confuse
// because they differ by three characters.
func formatBytes(total uint64) string {
	const unit = 1000
	if total < unit {
		return fmt.Sprintf("%d B", total)
	}
	value := float64(total)
	for _, suffix := range []string{"kB", "MB", "GB", "TB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1f PB", value/unit)
}

// firstReadingGrace is how long automatic switching waits for qBittorrent's first answer
// before proceeding without it.
//
// Long enough for qBittorrent to finish starting when both containers come up together,
// which is the case this exists for; short enough that a genuine misconfiguration does not
// freeze selection for long. Only the first reading is waited for - once one has arrived,
// the last known rates keep deferring on their own.
const firstReadingGrace = 5 * time.Minute

// transferInterval is how often to read the rates, zero when the feature is off so
// the ticker never fires.
func (e *Engine) transferInterval() time.Duration {
	if e.qbittorrent == nil {
		return 0
	}
	return e.cfg.QBittorrent.Interval
}

// identifyQBittorrent confirms once, at startup, that the API key works.
//
// Doing it eagerly turns a misconfiguration into a startup error the operator sees
// immediately, rather than a feature that silently never defers anything.
func (e *Engine) identifyQBittorrent(ctx context.Context) {
	if e.qbittorrent == nil {
		return
	}

	version, err := e.qbittorrent.Version(ctx)
	if err != nil {
		e.logger.Error("could not reach qbittorrent, so transfers cannot defer switching",
			"url", e.cfg.QBittorrent.URL, "error", err)
		e.transferErr = err.Error()
		e.publishTransfer()
		return
	}

	e.qbittorrentVersion = version
	e.logger.Info("transfer awareness enabled",
		"qbittorrent", version,
		"url", e.cfg.QBittorrent.URL,
		"busy_download", formatRate(e.cfg.QBittorrent.BusyDownload),
		"busy_upload", formatRate(e.cfg.QBittorrent.BusyUpload),
		"max_defer", e.cfg.QBittorrent.MaxDefer)
}
