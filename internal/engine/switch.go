package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/gluetunapi"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/scoring"
)

// decision is the outcome of evaluating whether to move the tunnel.
type decision struct {
	shouldSwitch bool
	reason       string
	// explanation is shown on the dashboard when no switch happens, so the
	// operator can see the tool is working rather than stuck.
	explanation string
}

// evaluate decides whether to switch and, if so, performs the switch.
//
// force skips the auto-switch toggle and the cooldown, which is what the
// dashboard's "reconnect to best" button uses.
func (e *Engine) evaluate(ctx context.Context, trigger string, force bool) {
	defer e.publish()

	e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Selection.LastEvaluation = time.Now() })

	if len(e.ranked) == 0 {
		e.logger.Debug("evaluation skipped: no candidates", "trigger", trigger)
		return
	}
	if e.cfg.Switch.Mode == config.ReconnectNone && !force {
		return
	}

	// Never fight the environment. If Gluetun cannot be reached there is nothing
	// to switch, and if the tunnel is deliberately stopped, starting it would
	// override an operator's decision.
	gluetun := e.Snapshot().Gluetun
	if !gluetun.Reachable {
		e.logger.Debug("evaluation skipped: gluetun unreachable", "trigger", trigger)
		e.mutateSnapshot(func(snapshot *Snapshot) {
			snapshot.Selection.LastError = "Gluetun is unreachable, so the tunnel cannot be moved"
		})
		return
	}
	// The tunnel status decides whether acting is safe or useful:
	//
	//	running   - normal case, evaluate as usual
	//	crashed   - Gluetun cannot connect with its current selection; moving to
	//	            another server is very likely what fixes it, so act
	//	starting,
	//	stopping  - mid-transition; a state-change request would block until the
	//	            transition finishes, so wait for the next evaluation
	//	stopped   - an operator's decision, never overridden
	switch gluetun.Status {
	case gluetunapi.StatusRunning:
	case gluetunapi.StatusCrashed:
		e.logger.Info("tunnel is crashed, trying to move it to another server", "trigger", trigger)
	default:
		if !force {
			e.logger.Debug("evaluation skipped: tunnel is not in a state that can be moved",
				"trigger", trigger, "status", gluetun.Status)
			return
		}
	}
	if gluetun.ProviderMismatch {
		e.logger.Debug("evaluation skipped: gluetun is not using protonvpn", "trigger", trigger)
		return
	}

	currentHostname, _ := e.currentHostname()
	current, haveCurrent := scoring.Find(e.ranked, currentHostname)
	best := e.ranked[0]

	verdict := e.decide(current, haveCurrent, best, force)
	e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Selection.LastError = "" })

	if !verdict.shouldSwitch {
		e.logger.Debug("staying on current server",
			"trigger", trigger, "reason", verdict.explanation, "current", currentHostname)
		return
	}

	e.logger.Info("switching server",
		"trigger", trigger,
		"reason", verdict.reason,
		"from", currentHostname,
		"to", best.Candidate.Hostname,
		"from_score", round(current.Score, 3),
		"to_score", round(best.Score, 3),
		"from_load", current.Candidate.Load,
		"to_load", best.Candidate.Load)

	e.performSwitch(ctx, currentHostname, current, haveCurrent, verdict.reason)
}

// decide applies the hysteresis rules. The goal is to switch when it clearly
// helps and to stay put otherwise: a VPN that reconnects every few minutes is
// worse than one on a slightly busier server.
func (e *Engine) decide(current scoring.Scored, haveCurrent bool, best scoring.Scored, force bool) decision {
	if force {
		return decision{shouldSwitch: true, reason: "manual"}
	}
	if !e.autoSwitchEnabled() {
		return decision{explanation: "automatic switching is disabled"}
	}
	if !haveCurrent {
		// Either the tunnel is on a server outside the allowed set, or it is
		// down. Either way, moving it to the best candidate is right.
		return decision{shouldSwitch: true, reason: "current server unknown or not allowed"}
	}
	if current.Candidate.Hostname == best.Candidate.Hostname {
		return decision{explanation: "already on the best server"}
	}

	// The hard floor comes first and nothing bypasses it. Every switch tears
	// down the tunnel and with it every connection through it, so the guarantee
	// worth having is an upper bound on how often that can happen.
	if remaining := e.minIntervalRemaining(); remaining > 0 {
		return decision{explanation: fmt.Sprintf(
			"minimum interval between switches not elapsed, %s to go",
			remaining.Truncate(time.Second))}
	}

	// An overloaded current server may skip the (longer) cooldown and the
	// improvement threshold - but only if moving would actually help. Without
	// that second condition, a night where every allowed server sits above the
	// trigger would reconnect on every evaluation and achieve nothing.
	overloaded := e.cfg.Switch.LoadTrigger > 0 &&
		int(current.Candidate.Load) > e.cfg.Switch.LoadTrigger &&
		int(best.Candidate.Load) <= e.cfg.Switch.LoadTrigger

	if remaining := e.cooldownRemaining(); remaining > 0 && !overloaded {
		return decision{explanation: fmt.Sprintf("cooldown active for another %s",
			remaining.Truncate(time.Second))}
	}

	if overloaded {
		return decision{
			shouldSwitch: true,
			reason: fmt.Sprintf("current server load %d%% exceeds trigger %d%% (best is %d%%)",
				current.Candidate.Load, e.cfg.Switch.LoadTrigger, best.Candidate.Load),
		}
	}

	improvement := current.Score - best.Score
	if improvement < e.cfg.Switch.MinImprovement {
		return decision{explanation: fmt.Sprintf(
			"best server only %.3f better than current, need %.3f",
			improvement, e.cfg.Switch.MinImprovement)}
	}

	return decision{
		shouldSwitch: true,
		reason:       fmt.Sprintf("score improves by %.3f", improvement),
	}
}

// performSwitch moves the tunnel, trying successive candidates when Gluetun
// refuses one.
//
// Gluetun validates a pinned hostname against the server list it loaded at
// startup. A hostname added to servers.json after Gluetun started is therefore
// rejected until Gluetun restarts - so a rejection is treated as "try the next
// candidate", and an all-rejected run raises a clear "restart Gluetun" flag
// rather than silently doing nothing.
func (e *Engine) performSwitch(ctx context.Context, previousHostname string,
	previous scoring.Scored, havePrevious bool, reason string,
) {
	candidates := scoring.TopN(e.ranked, e.cfg.Switch.Candidates)
	if len(candidates) == 0 {
		return
	}

	e.setActivity("switching server")
	defer e.setActivity("")

	if e.tryCandidates(ctx, candidates, previousHostname, previous, havePrevious, reason) {
		return
	}

	// Every candidate was refused, which means Gluetun is working from an older
	// server list than the one in servers.json. Ask it to refresh that list and
	// try once more before telling the operator to restart the container.
	if e.refreshGluetunServerList(ctx) &&
		e.tryCandidates(ctx, candidates, previousHostname, previous, havePrevious, reason) {
		return
	}
	e.flagGluetunRestartNeeded(len(candidates))
}

// tryCandidates attempts each candidate in turn and reports whether one stuck.
//
// A rejection is not a failure of the switch: it means Gluetun does not know
// that hostname, so the next candidate is tried. Any other error stops the
// attempt, because retrying against a struggling tunnel only makes things worse.
func (e *Engine) tryCandidates(ctx context.Context, candidates []scoring.Scored,
	previousHostname string, previous scoring.Scored, havePrevious bool, reason string,
) (switched bool) {
	// Any rejection means Gluetun is working from a list older than ours, even if
	// a later candidate succeeded. Left alone, that state persists: the best
	// servers stay unknown to Gluetun and every switch quietly settles for a worse
	// one. So a successful switch that had to skip a rejected candidate still
	// prompts a list refresh, for the benefit of the next switch.
	refreshAfter := false
	defer func() {
		if refreshAfter && switched {
			e.logger.Info("a candidate was refused before this switch succeeded, " +
				"refreshing gluetun's server list so the next one can use it")
			e.refreshGluetunServerList(ctx)
		}
	}()

	previousIP := e.Snapshot().Gluetun.Exit.IP
	rejections := 0

	for attempt, target := range candidates {
		if ctx.Err() != nil {
			return false
		}
		if havePrevious && target.Candidate.Hostname == previous.Candidate.Hostname {
			continue
		}

		outcome, err := e.applyTarget(ctx, target)
		switch {
		case errors.Is(err, gluetunapi.ErrRejected):
			rejections++
			refreshAfter = true
			e.logger.Warn("gluetun refused the server, trying the next candidate",
				"hostname", target.Candidate.Hostname, "attempt", attempt+1, "error", err)
			continue
		case errors.Is(err, gluetunapi.ErrTimedOut):
			// Gluetun answers these requests only once the VPN loop has actually
			// restarted, so a timeout means "still working", not "failed". Fall
			// through to verification: re-sending the request would risk a second,
			// pointless reconnect.
			e.logger.Warn("gluetun has not confirmed the change yet, verifying instead of retrying",
				"hostname", target.Candidate.Hostname, "error", err)
		case err != nil:
			e.recordSwitch(previousHostname, previous, havePrevious, target, reason, "", err)
			e.logger.Error("could not switch server",
				"hostname", target.Candidate.Hostname, "error", err)
			// Not a rejection, so a server-list refresh would not help: report
			// this as handled rather than letting the caller retry.
			return true
		}

		e.logger.Info("gluetun accepted the new server",
			"hostname", target.Candidate.Hostname, "outcome", outcome)

		publicIP, verifyErr := e.verifyTunnel(ctx, target, previousIP)
		if verifyErr != nil {
			// The tunnel did not come up on the new server in time. Report it
			// and stop: retrying immediately would only pile reconnects on top
			// of a struggling tunnel.
			e.recordSwitch(previousHostname, previous, havePrevious, target, reason, publicIP, verifyErr)
			e.logger.Error("tunnel did not come up after switching",
				"hostname", target.Candidate.Hostname, "error", verifyErr)
			e.mutateSnapshot(func(snapshot *Snapshot) {
				snapshot.Selection.LastError = verifyErr.Error()
			})
			return true
		}

		e.recordSwitch(previousHostname, previous, havePrevious, target, reason, publicIP, nil)
		e.mutateSnapshot(func(snapshot *Snapshot) {
			snapshot.Selection.NeedsGluetunRestart = false
			snapshot.Selection.LastError = ""
			snapshot.Gluetun.Exit.IP = publicIP
		})
		e.logger.Info("switched server",
			"hostname", target.Candidate.Hostname,
			"country", target.Candidate.Country,
			"city", target.Candidate.City,
			"load", target.Candidate.Load,
			"public_ip", publicIP)
		return true
	}

	// Nothing was applied. Only a run that ended in rejections is worth
	// retrying after a server-list refresh.
	return rejections == 0
}

// refreshGluetunServerList asks Gluetun to reload its own server list and
// reports whether a retry is worth attempting.
//
// This is the answer to "can Gluetun see a server we just added?". Gluetun
// reads servers.json only at startup, and there is no route to re-read it, so
// the only in-place remedy is to make Gluetun run its own updater, which
// replaces its in-memory list.
func (e *Engine) refreshGluetunServerList(ctx context.Context) (retryWorthwhile bool) {
	if !e.cfg.Gluetun.RefreshServersOnReject {
		return false
	}

	e.setActivity("asking gluetun to refresh its server list")
	defer e.setActivity("switching server")

	outcome, err := e.gluetun.TriggerUpdater(ctx)
	if err != nil {
		e.logger.Warn("could not trigger gluetun's server list updater", "error", err)
		return false
	}
	e.logger.Info("asked gluetun to refresh its own server list", "outcome", outcome)

	if err := e.gluetun.WaitForUpdater(ctx, e.cfg.Gluetun.UpdaterTimeout); err != nil {
		e.logger.Warn("gluetun's updater did not finish in time", "error", err)
		return false
	}
	return true
}

// flagGluetunRestartNeeded publishes the one situation this tool cannot resolve
// on its own.
func (e *Engine) flagGluetunRestartNeeded(candidates int) {
	message := "Gluetun rejected every candidate hostname, so it is running with an older server list than " +
		"servers.json. Restart the Gluetun container to load it."
	if e.cfg.Gluetun.RefreshServersOnReject {
		message += " Setting UPDATER_PROTONVPN_EMAIL and UPDATER_PROTONVPN_PASSWORD on the Gluetun container " +
			"lets it refresh its list in place instead."
	}

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Selection.NeedsGluetunRestart = true
		snapshot.Selection.LastError = message
	})
	e.logger.Error("gluetun rejected every candidate hostname",
		"candidates", candidates,
		"hint", "restart the gluetun container, or give it UPDATER_PROTONVPN_EMAIL/PASSWORD so it can refresh in place")
}

// applyTarget asks Gluetun to move to the target server.
func (e *Engine) applyTarget(ctx context.Context, target scoring.Scored) (outcome string, err error) {
	switch e.cfg.Switch.Mode {
	case config.ReconnectSettings:
		// The country and city travel with the hostname on purpose: Gluetun ANDs
		// every selection filter, so a hostname alone would still be intersected
		// with whatever SERVER_COUNTRIES the container was started with. A
		// mismatch there leaves no server matching both, which crashes Gluetun's
		// VPN loop and takes the tunnel down until the selection is fixed.
		outcome, err = e.gluetun.PinServer(ctx, gluetunapi.PinTarget{
			Hostname: target.Candidate.Hostname,
			Country:  target.Candidate.Country,
			City:     target.Candidate.City,
		})
		if err != nil {
			return "", err
		}
		if updateErr := e.state.update(func(state *persistedState) {
			state.PinnedHostname = target.Candidate.Hostname
		}); updateErr != nil {
			e.logger.Warn("could not persist pinned hostname", "error", updateErr)
		}

		// Gluetun stores the new selection but only restarts the VPN loop if it
		// was running. On a crashed or stopped loop it answers "already crashed" /
		// "already stopped" and the change sits unused until something restarts
		// it - so restart it explicitly rather than waiting out a retry backoff,
		// or worse, leaving the tunnel down.
		if outcomeMeansNotRestarted(outcome) {
			e.logger.Info("gluetun stored the selection without restarting, restarting explicitly",
				"outcome", outcome)
			restarted, err := e.gluetun.Reconnect(ctx)
			if err != nil {
				return "", fmt.Errorf("restarting after %q: %w", outcome, err)
			}
			outcome = restarted
		}
		return outcome, nil

	case config.ReconnectStatus:
		// Gluetun chooses the server itself in this mode, so the pin is
		// meaningless and must not be remembered as if it were honoured.
		outcome, err = e.gluetun.Reconnect(ctx)
		if err != nil {
			return "", err
		}
		if updateErr := e.state.update(func(state *persistedState) {
			state.PinnedHostname = ""
		}); updateErr != nil {
			e.logger.Warn("could not persist state", "error", updateErr)
		}
		return outcome, nil

	default:
		return "", fmt.Errorf("reconnect mode %q does not change the tunnel", e.cfg.Switch.Mode)
	}
}

// outcomeMeansNotRestarted reports whether Gluetun's answer indicates it kept the
// VPN loop as it was. Its outcome strings for those cases are of the form
// "already <status>".
func outcomeMeansNotRestarted(outcome string) bool {
	switch strings.TrimSpace(strings.ToLower(outcome)) {
	case "already crashed", "already stopped":
		return true
	default:
		return false
	}
}

// verifyTunnel waits for the tunnel to come back up and reports the public IP.
//
// Verification is what turns "we sent a request" into "the switch worked", but it
// has to accept the two ways a good switch can look:
//
//   - The public IP matches an exit address Proton lists for the pinned hostname.
//     This is conclusive.
//   - The public IP simply changed. This is accepted too, because Proton's exit
//     addresses are not always what the internet observes: a hostname can have
//     several physical machines with different exit addresses, and Proton reports
//     the server address rather than the NATed egress. Insisting on a match made
//     perfectly good switches record as failures, with the tunnel actually up and
//     running on the requested server.
func (e *Engine) verifyTunnel(ctx context.Context, target scoring.Scored, previousIP string) (publicIP string, err error) {
	deadline := time.Now().Add(e.cfg.Switch.VerifyTimeout)
	const pollInterval = 3 * time.Second

	// Every exit address Proton lists for this hostname, since a hostname can be
	// backed by more than one machine.
	expected := make(map[string]struct{})
	for _, candidate := range e.candidates {
		if candidate.Hostname == target.Candidate.Hostname && candidate.ExitIP.IsValid() {
			expected[candidate.ExitIP.String()] = struct{}{}
		}
	}

	// Once a changed address is seen, polling continues only briefly in case the
	// expected one appears - Gluetun caches the public IP for a moment, so the
	// first reading after a reconnect can still be the old one. Waiting out the
	// whole timeout for a match that may never come would leave every switch
	// looking unfinished for a minute and a half.
	const graceAfterChange = 9 * time.Second
	var changedAt time.Time

	var lastStatus, changedIP string
	var lastErr error

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}

		status, statusErr := e.gluetun.Status(ctx)
		if statusErr != nil {
			lastErr = statusErr
			continue
		}
		lastStatus = status
		if status != gluetunapi.StatusRunning {
			continue
		}

		ip, ipErr := e.gluetun.GetPublicIP(ctx)
		if ipErr != nil || ip.IP == "" {
			lastErr = ipErr
			continue
		}

		if _, matches := expected[ip.IP]; matches {
			return ip.IP, nil
		}
		if ip.IP != previousIP {
			if changedIP == "" {
				changedIP, changedAt = ip.IP, time.Now()
			}
			changedIP = ip.IP
			if time.Since(changedAt) >= graceAfterChange {
				break
			}
		}
	}

	if changedIP != "" {
		// The tunnel is up on a different address than before. Accept it, and say
		// that Proton's data did not line up so a mismatch is not mistaken for a
		// silent failure.
		e.logger.Info("tunnel verified by a changed public IP; it does not match Proton's exit address for this server",
			"hostname", target.Candidate.Hostname,
			"observed", changedIP,
			"proton_exit_addresses", expectedList(expected))
		return changedIP, nil
	}

	if lastErr != nil {
		return "", fmt.Errorf("tunnel not confirmed within %s (last status %q): %w",
			e.cfg.Switch.VerifyTimeout, lastStatus, lastErr)
	}
	return "", fmt.Errorf("tunnel not confirmed within %s (last status %q): the public IP never changed",
		e.cfg.Switch.VerifyTimeout, lastStatus)
}

func expectedList(expected map[string]struct{}) []string {
	list := make([]string, 0, len(expected))
	for address := range expected {
		list = append(list, address)
	}
	sort.Strings(list)
	return list
}

// recordSwitch appends to the persisted history.
//
// previousHostname is passed separately from previous, because the tunnel can be
// on a server that is not in the ranking at all (too busy, wrong country). The
// history should still say where the switch came from.
func (e *Engine) recordSwitch(previousHostname string, previous scoring.Scored, havePrevious bool,
	target scoring.Scored, reason, publicIP string, switchErr error,
) {
	record := SwitchRecord{
		At:          time.Now(),
		To:          target.Candidate.Hostname,
		Reason:      reason,
		ScoreAfter:  round(target.Score, 4),
		LoadAfter:   target.Candidate.Load,
		Country:     target.Candidate.Country,
		City:        target.Candidate.City,
		Succeeded:   switchErr == nil,
		Error:       errorText(switchErr),
		PublicIP:    publicIP,
		ScoreBefore: -1,
	}
	record.From = previousHostname
	if havePrevious {
		record.From = previous.Candidate.Hostname
		record.ScoreBefore = round(previous.Score, 4)
		record.LoadBefore = previous.Candidate.Load
	} else if candidate, found := e.lookupCandidate(previousHostname); found {
		// Not in the ranking, but its load is still worth recording.
		record.LoadBefore = candidate.Load
	}
	if target.LatencyKnown {
		record.RTTAfterMS = target.RTT.Milliseconds()
	}

	if err := e.state.update(func(state *persistedState) {
		state.History = append(state.History, record)
		if switchErr == nil {
			state.LastSwitchAt = record.At
		}
	}); err != nil {
		e.logger.Warn("could not persist switch history", "error", err)
	}
}

// switchTo moves the tunnel onto a specific hostname chosen from the dashboard.
func (e *Engine) switchTo(ctx context.Context, hostname string) (err error) {
	target, found := scoring.Find(e.ranked, hostname)
	if !found {
		return fmt.Errorf("server %q is not in the current candidate list", hostname)
	}

	currentHostname, _ := e.currentHostname()
	current, haveCurrent := scoring.Find(e.ranked, currentHostname)

	e.setActivity("switching to " + hostname)
	defer func() {
		e.setActivity("")
		e.publish()
	}()

	previousIP := e.Snapshot().Gluetun.Exit.IP
	outcome, err := e.applyTarget(ctx, target)
	if errors.Is(err, gluetunapi.ErrRejected) {
		// The operator picked a specific server, so rather than silently
		// choosing a different one, try to make Gluetun aware of this one.
		e.logger.Warn("gluetun does not know this server yet, refreshing its list",
			"hostname", hostname)
		if e.refreshGluetunServerList(ctx) {
			outcome, err = e.applyTarget(ctx, target)
		}
	}
	if err != nil {
		e.recordSwitch(currentHostname, current, haveCurrent, target, "manual", "", err)
		return err
	}
	e.logger.Info("gluetun accepted the requested server", "hostname", hostname, "outcome", outcome)

	publicIP, err := e.verifyTunnel(ctx, target, previousIP)
	e.recordSwitch(currentHostname, current, haveCurrent, target, "manual", publicIP, err)
	if err != nil {
		return err
	}

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.Exit.IP = publicIP
		snapshot.Selection.LastError = ""
	})
	e.logger.Info("switched to requested server", "hostname", hostname, "public_ip", publicIP)
	return nil
}
