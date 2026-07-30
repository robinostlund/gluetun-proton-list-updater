package engine

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Command kinds the dashboard can issue.
const (
	commandRefreshList  = "refresh-list"
	commandRefreshLoads = "refresh-loads"
	commandProbe        = "probe-latency"
	commandEvaluate     = "evaluate"
	commandSwitchBest   = "switch-best"
	commandSwitchTo     = "switch-to"
	commandWriteServers = "write-servers"
	commandSetAuto      = "set-auto-switch"
	commandClearHistory = "clear-history"
	commandRunUpdater   = "run-updater"
	commandSetVPN       = "set-vpn"
	commandSetDNS       = "set-dns"
)

// command is a unit of work handed to the run loop. Results travel back over
// done, so callers can choose between fire-and-forget and waiting.
type command struct {
	kind     string
	hostname string
	enabled  bool
	// status carries a Gluetun lifecycle value ("running" or "stopped") for the
	// commands that start and stop one of its loops.
	status string
	done   chan error
}

// ErrBusy reports that the command queue is full, which means the engine is
// already working through a backlog.
var ErrBusy = errors.New("engine is busy, try again shortly")

// submit enqueues a command. When wait is true it blocks for the result, so the
// dashboard can report a real error instead of an optimistic "accepted".
func (e *Engine) submit(ctx context.Context, cmd command, wait bool) (err error) {
	if wait {
		cmd.done = make(chan error, 1)
	}

	select {
	case e.commands <- cmd:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
		return ErrBusy
	}

	if !wait {
		return nil
	}
	select {
	case err = <-cmd.done:
		return err
	case <-ctx.Done():
		// The command is still running in the loop; the caller just stops
		// waiting for it.
		return ctx.Err()
	}
}

// handleCommand executes a dashboard command inside the run loop, where it
// cannot race with the scheduled tasks.
func (e *Engine) handleCommand(ctx context.Context, cmd command) {
	var err error

	switch cmd.kind {
	case commandRefreshList:
		e.refreshServerList(ctx, "manual")
		e.evaluate(ctx, "after manual refresh", false)
	case commandRefreshLoads:
		e.refreshLoads(ctx, "manual")
	case commandProbe:
		if !e.cfg.Latency.Enabled {
			err = errors.New("latency probing is disabled (set LATENCY_ENABLED=true)")
			break
		}
		e.probeLatency(ctx, "manual")
	case commandEvaluate:
		e.evaluate(ctx, "manual", false)
	case commandSwitchBest:
		e.evaluate(ctx, "manual", true)
	case commandSwitchTo:
		err = e.switchTo(ctx, cmd.hostname)
	case commandWriteServers:
		e.writeServersFile()
		e.publish()
	case commandRunUpdater:
		// Reuses the reject-path helper, which also rewrites the servers file
		// afterwards - Gluetun's updater flushes its own fetch over it.
		if !e.refreshGluetunServerList(ctx) {
			err = errors.New("gluetun's updater did not complete; check its own log, and that " +
				"UPDATER_PROTONVPN_EMAIL and UPDATER_PROTONVPN_PASSWORD are set on that container")
		}
		e.checkGluetun(ctx)
		e.publish()
	case commandSetVPN:
		err = e.setTunnelStatus(ctx, cmd.status)
	case commandSetDNS:
		err = e.setDNSStatus(ctx, cmd.status)
	case commandClearHistory:
		err = e.state.update(func(state *persistedState) { state.History = nil })
		e.logger.Info("switch history cleared")
		e.publish()
	case commandSetAuto:
		enabled := cmd.enabled
		err = e.state.update(func(state *persistedState) { state.AutoSwitch = &enabled })
		e.logger.Info("automatic switching changed", "enabled", enabled)
		e.publish()
	default:
		err = fmt.Errorf("unknown command %q", cmd.kind)
	}

	if cmd.done != nil {
		cmd.done <- err
		close(cmd.done)
	}
}

// RefreshList triggers a full Proton server-list refresh.
func (e *Engine) RefreshList(ctx context.Context) error {
	return e.submit(ctx, command{kind: commandRefreshList}, false)
}

// RefreshLoads triggers a utilisation refresh.
func (e *Engine) RefreshLoads(ctx context.Context) error {
	return e.submit(ctx, command{kind: commandRefreshLoads}, false)
}

// ProbeLatency triggers a latency sweep.
func (e *Engine) ProbeLatency(ctx context.Context) error {
	return e.submit(ctx, command{kind: commandProbe}, false)
}

// Evaluate re-runs the switch decision without forcing it.
func (e *Engine) Evaluate(ctx context.Context) error {
	return e.submit(ctx, command{kind: commandEvaluate}, false)
}

// SwitchToBest reconnects to the best-ranked server, ignoring the cooldown and
// the auto-switch toggle.
func (e *Engine) SwitchToBest(ctx context.Context) error {
	return e.submit(ctx, command{kind: commandSwitchBest}, false)
}

// SwitchTo reconnects to a specific hostname and waits for the outcome, so the
// dashboard can show whether it worked.
func (e *Engine) SwitchTo(ctx context.Context, hostname string) error {
	return e.submit(ctx, command{kind: commandSwitchTo, hostname: hostname}, true)
}

// WriteServersFile rewrites servers.json from the current catalog.
func (e *Engine) WriteServersFile(ctx context.Context) error {
	return e.submit(ctx, command{kind: commandWriteServers}, false)
}

// ClearHistory discards the persisted switch history. It waits for the result, so
// the dashboard reports a failed write rather than showing rows that are still on
// disk.
func (e *Engine) ClearHistory(ctx context.Context) error {
	return e.submit(ctx, command{kind: commandClearHistory}, true)
}

// SetAutoSwitch turns automatic switching on or off; the choice is persisted.
func (e *Engine) SetAutoSwitch(ctx context.Context, enabled bool) error {
	return e.submit(ctx, command{kind: commandSetAuto, enabled: enabled}, true)
}

// Healthy reports whether the tool is doing its job, for a container health
// check.
//
// Deliberately lenient about the things it is built to survive: Gluetun being
// down or Proton being briefly unreachable do not make it unhealthy, because a
// cached list and a paused switch are working-as-intended.
//
// Strict about the three ways it is genuinely not doing its job: having no
// candidate servers, being unable to write the server data, and writing server
// data that Gluetun does not read. The last two matter because everything else
// can look fine while the tool has no effect at all.
//
// Note this cannot false-positive while Gluetun is down: the "ignored" condition
// is only ever set when Gluetun answers its control server, and Gluetun writes
// its server data before that server starts listening.
func (e *Engine) Healthy() (healthy bool, reason string) {
	snapshot := e.Snapshot()
	switch {
	case snapshot.CandidatesTotal == 0:
		return false, "no candidate servers available"
	case snapshot.Servers.LastError != "":
		return false, "cannot write server data: " + snapshot.Servers.LastError
	case snapshot.Servers.Ignored:
		return false, "gluetun is not reading the server data written here: " + snapshot.Servers.IgnoredReason
	default:
		return true, "ok"
	}
}

// RunUpdater asks Gluetun to run its own server-list updater, and waits for it.
//
// Exposed because the reject path only reaches it when a switch has already failed, and
// an operator who has just restarted Gluetun or added servers may want it now.
func (e *Engine) RunUpdater(ctx context.Context) error {
	return e.submit(ctx, command{kind: commandRunUpdater}, true)
}

// SetVPN starts or stops Gluetun's VPN loop.
func (e *Engine) SetVPN(ctx context.Context, status string) error {
	return e.submit(ctx, command{kind: commandSetVPN, status: status}, true)
}

// SetDNS starts or stops Gluetun's DNS-over-TLS resolver.
func (e *Engine) SetDNS(ctx context.Context, status string) error {
	return e.submit(ctx, command{kind: commandSetDNS, status: status}, true)
}
