package engine

import (
	"context"
	"errors"
	"fmt"
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

	// Every path out of here sets an explanation.
	//
	// Without that, an explanation set by an earlier evaluation stays on the
	// dashboard describing a situation that has since gone: "not switching while a
	// transfer is in progress" would still be showing long after the transfer
	// finished, if a later evaluation happened to bail out before deciding anything.
	explain := func(reason string) {
		e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Selection.Explanation = reason })
	}

	if len(e.ranked) == 0 {
		e.logger.Debug("evaluation skipped: no candidates", "trigger", trigger)
		explain("no candidate servers to choose from")
		return
	}
	if e.cfg.Switch.Mode == config.ReconnectNone && !force {
		explain(`reconnect mode is "none", so the tunnel is never moved`)
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
		explain("Gluetun is unreachable")
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
			explain(fmt.Sprintf("the tunnel is %q, which is not a state it can be moved from",
				gluetun.Status))
			return
		}
	}
	if gluetun.ProviderMismatch {
		e.logger.Debug("evaluation skipped: gluetun is not using protonvpn", "trigger", trigger)
		explain("Gluetun is not configured for ProtonVPN")
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
		explain(verdict.explanation)
		return
	}
	explain("")

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

	// An active transfer outranks every reason to move.
	//
	// This has to come before all of them, including "the current server is unknown"
	// and the load trigger. Switching tears the tunnel down and takes every
	// connection through it with it, so moving to a better server would inflict
	// exactly the interruption the better server is meant to avoid. A slow transfer
	// still beats a broken one, and an unidentified current server is no reason to
	// break a transfer that is demonstrably flowing.
	if blocked, reason := e.transferBlocksSwitch(); blocked {
		explanation := "not switching while " + reason
		if maxDefer := e.cfg.QBittorrent.MaxDefer; maxDefer > 0 {
			explanation += fmt.Sprintf("; will switch anyway after %s", maxDefer)
		}
		return decision{explanation: explanation}
	}

	// Checked before the floor below, because it is the more useful thing to say when both
	// are true: "already on the best server" is the answer, and the floor is incidental.
	if haveCurrent && current.Candidate.Hostname == best.Candidate.Hostname {
		return decision{explanation: "already on the best server"}
	}

	// The hard floor. Every switch tears down the tunnel and with it every connection
	// through it, so the guarantee worth having is an upper bound on how often that can
	// happen - and a guarantee with exceptions is not one.
	//
	// It used to sit below the "current server unknown" case while claiming in its own
	// comment that nothing bypassed it. That case bypassed it, which left a reconnect loop
	// reachable: anything that keeps the current server unidentifiable - Gluetun's settings
	// readable but reporting a hostname this tool does not recognise, an exit address that
	// matches no Proton server - would tear the tunnel down on every single evaluation, for
	// ever, with no floor at all. Only an explicit instruction bypasses it now, and that is
	// handled by the force branch at the top.
	if remaining := e.minIntervalRemaining(); remaining > 0 {
		return decision{explanation: fmt.Sprintf(
			"minimum interval between switches not elapsed, %s to go",
			remaining.Truncate(time.Second))}
	}

	if !haveCurrent {
		// Either the tunnel is on a server outside the allowed set, or it is
		// down. Either way, moving it to the best candidate is right.
		return decision{shouldSwitch: true, reason: "current server unknown or not allowed"}
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
	skipped := 0

	for attempt, target := range candidates {
		if ctx.Err() != nil {
			return false
		}
		if havePrevious && target.Candidate.Hostname == previous.Candidate.Hostname {
			continue
		}
		if !e.gluetunMightKnow(target.Candidate.Hostname) {
			skipped++
			e.logger.Debug("skipping a server gluetun has said it does not know",
				"hostname", target.Candidate.Hostname)
			continue
		}

		outcome, err := e.applyTarget(ctx, target)
		switch {
		case errors.Is(err, gluetunapi.ErrRejected):
			rejections++
			refreshAfter = true
			// The refusal enumerated everything Gluetun *would* accept. Remembering
			// that turns the remaining attempts from guesswork into a lookup: every
			// candidate outside the set is a wasted mutation request against a
			// tunnel that is already being restarted.
			e.learnGluetunHostnames(err)
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

		if outcome == "" {
			// Reached only via the ErrTimedOut case above: Gluetun took the request
			// and never answered, so whether it applied is genuinely unknown.
			// Calling that "accepted" was misleading in exactly the situation where
			// the log matters most.
			e.logger.Warn("gluetun never confirmed the change; verifying what actually happened",
				"hostname", target.Candidate.Hostname)
		} else {
			e.logger.Info("gluetun accepted the new server",
				"hostname", target.Candidate.Hostname, "outcome", outcome)
		}

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
		// A pin Gluetun accepted proves any list it disclosed earlier is out of date.
		e.forgetGluetunHostnames()
		e.mutateSnapshot(func(snapshot *Snapshot) {
			snapshot.Selection.NeedsGluetunRestart = false
			snapshot.Selection.LastError = ""
			snapshot.Gluetun.Exit.IP = publicIP
			// Gluetun's selection now names this hostname, because this is what was just
			// applied and Gluetun accepted it. Recording it here rather than waiting for the
			// next health check closes a window that produced a real double switch: the
			// snapshot still held the pre-switch selection, so the very next evaluation saw
			// readable settings naming no hostname, took that as proof the remembered pin
			// was stale - which it is, in general - and switched again four seconds later.
			if snapshot.Gluetun.Selection == nil {
				snapshot.Gluetun.Selection = map[string][]string{}
			}
			snapshot.Gluetun.Selection["hostnames"] = []string{target.Candidate.Hostname}
		})
		e.logger.Info("switched server",
			"hostname", target.Candidate.Hostname,
			"country", target.Candidate.Country,
			"city", target.Candidate.City,
			"load", target.Candidate.Load,
			"public_ip", publicIP)
		return true
	}

	// Nothing was applied. Report that as handled only when retrying could not
	// possibly help - otherwise the caller must go on to refresh Gluetun's list and,
	// failing that, tell the operator.
	//
	// Skips count here as much as rejections do. A learned hostname set that excludes
	// every candidate would otherwise end this loop with no attempts, no rejections
	// and no error, which the caller would read as success: the switch would silently
	// never happen, for as long as the process lived.
	if skipped > 0 {
		e.logger.Warn("every candidate is outside the server list gluetun disclosed",
			"skipped", skipped,
			"gluetun_knows", len(e.gluetunKnownHosts))
	}
	return rejections == 0 && skipped == 0
}

// refreshGluetunServerList asks Gluetun to reload its own server list and
// reports whether a retry is worth attempting.
//
// This is the answer to "can Gluetun see a server we just added?". Gluetun
// reads servers.json only at startup, and there is no route to re-read it, so
// the only in-place remedy is to make Gluetun run its own updater, which
// replaces its in-memory list.
//
// Two things about that updater are worth being explicit about, because they make it
// the wrong tool for anything other than this narrow case:
//
//   - It fetches from Proton's API. It does *not* re-read the file written here, so
//     triggering it cannot make Gluetun adopt the curated list - only its own.
//   - It persists what it fetched. Gluetun's SetServers calls flushToFile, which opens
//     the servers file with O_TRUNC, so running the updater overwrites the data written
//     here. That is why the file is rewritten immediately afterwards.
//
// Together they are also why this is never called after a successful write: doing so
// would replace the list just written with Gluetun's own.
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
	// Gluetun has replaced its in-memory list, so anything it disclosed before is out
	// of date. Keeping it would make the retry skip the very candidates the refresh
	// was meant to unlock.
	e.forgetGluetunHostnames()

	// The updater flushed its own fetch over the servers file, so restore the curated
	// data. Without this, the file stays Gluetun's until the next full Proton refresh -
	// up to PROTON_REFRESH_INTERVAL later - and a Gluetun restart in that window would
	// come up on an unfiltered, unpreferred list.
	e.writeServersFile()
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
	if err := e.waitForStableTunnel(ctx); err != nil {
		return "", err
	}

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

// verifyTunnel confirms the tunnel really moved to the requested server.
//
// It verifies Gluetun's own reported selection rather than the observed public IP,
// because Proton's exit addresses are not the addresses the internet sees. A
// server Proton lists at 62.93.166.123 can egress from 159.26.108.2, so requiring
// a match either failed outright or forced a weak "the address changed at least"
// fallback that proved nothing about *which* server was chosen.
//
// What Gluetun reports is authoritative and exact:
//
//   - the tunnel is running (not crashed, not mid-transition), and
//   - its server selection is still restricted to the hostname we asked for.
//
// Gluetun validated that hostname when it accepted the request, and its selection
// is the only thing that decides where the tunnel connects - so those two facts
// together mean it is on the requested server. The public IP is recorded for
// display, and never gates the result.
func (e *Engine) verifyTunnel(ctx context.Context, target scoring.Scored, previousIP string) (publicIP string, err error) {
	deadline := time.Now().Add(e.cfg.Switch.VerifyTimeout)
	const pollInterval = 2 * time.Second

	// Only a pinned selection can be confirmed. In status mode Gluetun chooses the
	// server itself, so there is nothing to compare against and a changed address
	// is the best available signal.
	pinned := e.cfg.Switch.Mode == config.ReconnectSettings

	var lastStatus string
	var lastErr error

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}

		status, statusErr := e.gluetun.Status(ctx)
		if statusErr != nil {
			lastErr = statusErr
		} else {
			lastStatus = status
			switch status {
			case gluetunapi.StatusCrashed:
				// No point waiting out the timeout: Gluetun cannot connect with
				// this selection and will keep retrying the same thing.
				return e.bestEffortPublicIP(ctx), fmt.Errorf(
					"gluetun could not connect to %s: its VPN loop crashed",
					target.Candidate.Hostname)

			case gluetunapi.StatusRunning:
				if !pinned {
					// Nothing to compare against, so fall back to the address
					// having changed.
					observed := e.bestEffortPublicIP(ctx)
					if observed != "" && observed != previousIP {
						return observed, nil
					}
					break
				}

				settings, settingsErr := e.gluetun.GetSettings(ctx)
				if settingsErr != nil {
					lastErr = settingsErr
					break
				}
				hostnames := settings.PinnedHostnames()
				if len(hostnames) == 1 && hostnames[0] == target.Candidate.Hostname {
					// Running, and restricted to exactly the server requested.
					return e.bestEffortPublicIP(ctx), nil
				}
				lastErr = fmt.Errorf("gluetun is running but its selection is %v, not %s",
					hostnames, target.Candidate.Hostname)
			}
		}

		if !time.Now().Before(deadline) {
			break
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("tunnel not confirmed within %s (last status %q): %w",
			e.cfg.Switch.VerifyTimeout, lastStatus, lastErr)
	}
	return "", fmt.Errorf("tunnel not confirmed within %s: it never reached the running state (last status %q)",
		e.cfg.Switch.VerifyTimeout, lastStatus)
}

// bestEffortPublicIP reads the exit address for display. A failure is not worth
// reporting: the address is informational, never a verification gate.
func (e *Engine) bestEffortPublicIP(ctx context.Context) (publicIP string) {
	ip, err := e.gluetun.GetPublicIP(ctx)
	if err != nil {
		return ""
	}
	return ip.IP
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
		// A blocked server is listed on the dashboard but must never be connected
		// to: Gluetun would refuse the selection and leave the tunnel down. Saying
		// which of its settings is responsible turns a dead end into an answer.
		for _, candidate := range e.blocked {
			if candidate.Hostname != hostname {
				continue
			}
			return fmt.Errorf("server %q cannot be used: gluetun enforces %s",
				hostname, strings.Join(e.requirements.Unmet(candidate), ", "))
		}
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
		e.learnGluetunHostnames(err)
		e.logger.Warn("gluetun does not know this server yet, refreshing its list",
			"hostname", hostname)
		if e.refreshGluetunServerList(ctx) {
			outcome, err = e.applyTarget(ctx, target)
		}
		if errors.Is(err, gluetunapi.ErrRejected) {
			// Refreshing did not help - it needs UPDATER_PROTONVPN_EMAIL and
			// UPDATER_PROTONVPN_PASSWORD on the Gluetun container, and is skipped
			// silently without them. Say what to do instead of repeating Gluetun's
			// complaint, and name the best server that would work right now.
			e.flagGluetunRestartNeeded(1)
			return fmt.Errorf("%w%s", err, e.knownAlternativeHint())
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

	e.forgetGluetunHostnames()
	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.Exit.IP = publicIP
		snapshot.Selection.LastError = ""
	})
	e.logger.Info("switched to requested server", "hostname", hostname, "public_ip", publicIP)
	return nil
}

// learnGluetunHostnames records the server list Gluetun revealed in a rejection.
//
// Gluetun keeps its server list in memory from startup and offers no route to read
// it. The one time it discloses that list is when it refuses a hostname, where it
// enumerates every name it would have accepted. Capturing it turns the remaining
// attempts from guesswork into a lookup, and makes the "restart Gluetun" advice
// specific: we can say which server would work right now instead.
//
// The set is replaced rather than merged: it is a snapshot of Gluetun's current
// state, and a Gluetun that has restarted has a different list. A later successful
// switch clears it, since a working pin proves it is out of date.
func (e *Engine) learnGluetunHostnames(err error) {
	hostnames, found := gluetunapi.KnownHostnames(err)
	if !found {
		return
	}

	known := make(map[string]struct{}, len(hostnames))
	for _, hostname := range hostnames {
		known[hostname] = struct{}{}
	}
	if len(known) == len(e.gluetunKnownHosts) && e.gluetunMightKnowAll(known) {
		return
	}

	e.gluetunKnownHosts = known
	e.logger.Warn("gluetun disclosed the server list it is actually using",
		"gluetun_knows", len(known),
		"we_offer", len(e.candidates),
		"consequence", "only servers in gluetun's list can be selected until it restarts")
}

// gluetunMightKnowAll reports whether the freshly disclosed set matches the one
// already held, so an unchanged list is not re-logged on every rejection.
func (e *Engine) gluetunMightKnowAll(known map[string]struct{}) bool {
	for hostname := range known {
		if _, present := e.gluetunKnownHosts[hostname]; !present {
			return false
		}
	}
	return true
}

// gluetunMightKnow reports whether a hostname is worth attempting.
//
// It answers "might" rather than "does" deliberately: with nothing learned yet the
// answer is yes, because an unproven assumption must never narrow the candidate set.
// Only a hostname Gluetun has explicitly excluded from its own list is skipped.
func (e *Engine) gluetunMightKnow(hostname string) bool {
	if len(e.gluetunKnownHosts) == 0 {
		return true
	}
	_, known := e.gluetunKnownHosts[hostname]
	return known
}

// forgetGluetunHostnames drops the learned set after a successful switch, since a
// pin Gluetun accepted proves the snapshot is stale.
func (e *Engine) forgetGluetunHostnames() {
	e.gluetunKnownHosts = nil
}

// knownAlternativeHint names the best server that would work right now.
//
// "Restart Gluetun" is correct but unsatisfying advice. When Gluetun has disclosed
// its list, there is usually a perfectly good server in it, and pointing at that
// gives the operator something to do in the meantime.
func (e *Engine) knownAlternativeHint() string {
	if len(e.gluetunKnownHosts) == 0 {
		return ""
	}
	for _, entry := range e.ranked {
		if e.gluetunMightKnow(entry.Candidate.Hostname) {
			return fmt.Sprintf(" - gluetun knows %d servers, of which %s (%s, %d%% load) "+
				"ranks highest and can be used right now",
				len(e.gluetunKnownHosts), entry.Candidate.ServerName,
				entry.Candidate.Hostname, entry.Candidate.Load)
		}
	}
	return fmt.Sprintf(" - none of the %d servers gluetun knows is an allowed candidate, "+
		"so gluetun must be restarted to load the list written here",
		len(e.gluetunKnownHosts))
}

// stableTunnelWait bounds how long to wait for Gluetun's VPN loop to settle before
// asking it to change server.
const stableTunnelWait = 45 * time.Second

// waitForStableTunnel holds off a settings change while Gluetun is mid-transition.
//
// Gluetun applies a selection synchronously: it stops the VPN loop, applies the
// change, starts it again and only then answers. So a request sent while the loop is
// already stopping or starting is queued behind that transition, and the HTTP call
// blocks for as long as it takes - up to the full mutation timeout, with nothing to
// show for it. Worse, Gluetun's health monitor restarts the loop on its own whenever
// the tunnel fails a check, so a struggling tunnel is in transition much of the time
// and the collision is likely rather than rare.
//
// This has been observed to wedge: a stop that never completed left the loop in
// "stopping" for minutes, the settings request timed out after two of them, and
// verification then failed on a tunnel that had never moved. Waiting for a stable
// state first turns that into either a clean switch or a fast, accurate error.
func (e *Engine) waitForStableTunnel(ctx context.Context) (err error) {
	const pollInterval = 2 * time.Second
	started := time.Now()
	deadline := started.Add(stableTunnelWait)

	// The caller has already published what it is doing ("switching server"), so
	// restore that rather than leaving the page describing a wait that has ended.
	callerActivity := e.Snapshot().Activity
	waited := false
	defer func() {
		if waited {
			e.setActivity(callerActivity)
		}
	}()

	var status string
	for {
		status, err = e.gluetun.Status(ctx)
		switch {
		case err != nil:
			// Unreachable is the caller's problem to classify; do not let a failed
			// pre-flight check become the reason a switch is abandoned.
			return nil
		case status != gluetunapi.StatusStopping && status != gluetunapi.StatusStarting:
			return nil
		case time.Now().After(deadline):
			return fmt.Errorf("%w: gluetun's vpn loop has been %q for over %s, so it cannot "+
				"apply a new server; this is a gluetun-side stall - restart the gluetun "+
				"container if it persists", gluetunapi.ErrUnavailable, status, stableTunnelWait)
		}

		e.logger.Debug("waiting for gluetun's vpn loop to settle before switching",
			"status", status)
		// Publish progress: without it the page simply looks idle for 45 seconds,
		// which is indistinguishable from the hang this is detecting.
		waited = true
		e.setActivity(fmt.Sprintf("waiting for gluetun's vpn loop to settle (%s for %s)",
			status, time.Since(started).Truncate(time.Second)))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
