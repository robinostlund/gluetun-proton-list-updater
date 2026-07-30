package engine

import (
	"context"
	"errors"
	"fmt"
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
		if errors.Is(err, qbittorrent.ErrUnauthorized) {
			// A rejected key will not start working on its own, so say so plainly
			// rather than burying it as a transient failure.
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
	e.transferErr = ""
	e.transfer = transfer
	e.transferCheckedAt = time.Now()

	// Track when the tunnel became busy, so the wait can be bounded and shown.
	busy := e.transferIsBusy()
	switch {
	case busy && e.transferBusySince.IsZero():
		e.transferBusySince = time.Now()
		e.logger.Info("transfer in progress, automatic switching is on hold",
			"download", formatRate(transfer.DownloadSpeed),
			"upload", formatRate(transfer.UploadSpeed))
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
	if limits.BusyDownload > 0 && e.transfer.DownloadSpeed >= limits.BusyDownload {
		return true
	}
	return limits.BusyUpload > 0 && e.transfer.UploadSpeed >= limits.BusyUpload
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
	// An unreachable qBittorrent keeps the last verdict rather than falling open.
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

	reason = fmt.Sprintf("a transfer is in progress (%s down, %s up)",
		formatRate(e.transfer.DownloadSpeed), formatRate(e.transfer.UploadSpeed))
	if !e.transferReachable {
		reason += ", from the last reading before qbittorrent stopped answering"
	}
	return true, reason
}

// publishTransfer copies the transfer state into the snapshot.
func (e *Engine) publishTransfer() {
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

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Transfer = TransferStatus{
			Configured:            true,
			Reachable:             e.transferReachable,
			LastError:             e.transferErr,
			DownloadSpeed:         e.transfer.DownloadSpeed,
			UploadSpeed:           e.transfer.UploadSpeed,
			DownloadTotal:         e.transfer.DownloadTotal,
			UploadTotal:           e.transfer.UploadTotal,
			DownloadLimit:         e.transfer.DownloadLimit,
			UploadLimit:           e.transfer.UploadLimit,
			ConnectionStatus:      e.transfer.ConnectionStatus,
			Busy:                  busy,
			BusySince:             e.transferBusySince,
			DeferredFor:           deferredFor,
			BusyDownloadThreshold: limits.BusyDownload,
			BusyUploadThreshold:   limits.BusyUpload,
			MaxDefer:              maxDefer,
			LastCheck:             e.transferCheckedAt,
			Version:               e.qbittorrentVersion,
		}
	})
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
