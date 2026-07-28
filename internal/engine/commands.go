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
)

// command is a unit of work handed to the run loop. Results travel back over
// done, so callers can choose between fire-and-forget and waiting.
type command struct {
	kind     string
	hostname string
	enabled  bool
	done     chan error
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

// SetAutoSwitch turns automatic switching on or off; the choice is persisted.
func (e *Engine) SetAutoSwitch(ctx context.Context, enabled bool) error {
	return e.submit(ctx, command{kind: commandSetAuto, enabled: enabled}, true)
}

// Healthy reports whether the tool is doing its job, for a container health
// check.
//
// Deliberately lenient: Gluetun being down or Proton being unreachable are
// conditions this tool is built to survive, so they do not make it unhealthy.
// Only never having produced a usable server list does.
func (e *Engine) Healthy() (healthy bool, reason string) {
	snapshot := e.Snapshot()
	if snapshot.CandidatesTotal == 0 {
		return false, "no candidate servers available"
	}
	return true, "ok"
}
