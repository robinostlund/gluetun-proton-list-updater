package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/catalog"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/gluetunapi"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/serversfile"
)

// refreshServerList fetches Proton's logical servers, rebuilds the catalog and
// rewrites servers.json.
//
// Failure is survivable by design: the previously cached list stays in use, and
// servers.json is left exactly as it was. The tool keeps managing the tunnel
// with slightly stale data instead of falling over.
func (e *Engine) refreshServerList(ctx context.Context, trigger string) {
	e.setActivity("fetching Proton server list")
	defer func() {
		e.setActivity("")
		e.publish()
	}()

	started := time.Now()
	previousModified := e.Snapshot().Proton.ListLastModified

	// Ask what the account may actually use before applying the list, so the tier
	// limit is in place when candidates are built.
	e.refreshAccountInfo(ctx)

	logicals, lastModified, err := e.proton.Logicals(ctx, previousModified)
	switch {
	case errors.Is(err, proton.ErrNotModified):
		e.logger.Info("proton server list unchanged", "trigger", trigger)
		e.mutateSnapshot(func(snapshot *Snapshot) {
			snapshot.Proton.LastFetch = time.Now()
			snapshot.Proton.LastFetchError = ""
		})
		// The list is unchanged but servers.json may never have been written
		// (first run after a crash), so still make sure it is on disk.
		e.writeServersFile()
		return

	case errors.Is(err, proton.ErrTOTPRequired):
		e.logger.Warn("proton login needs a two-factor code",
			"hint", "submit it on the dashboard, or set PROTON_TOTP_SECRET for unattended operation")
		e.mutateSnapshot(func(snapshot *Snapshot) {
			snapshot.Proton.LastFetchError = err.Error()
			snapshot.Proton.NeedsTOTP = true
		})
		return

	case errors.Is(err, proton.ErrInvalidCredentials):
		// Retrying cannot help, so say so loudly rather than filling the log
		// with identical failures every refresh interval.
		e.logger.Error("proton rejected the credentials; fix PROTON_USERNAME/PROTON_PASSWORD", "error", err)
		e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Proton.LastFetchError = err.Error() })
		return

	case err != nil:
		e.logger.Error("could not fetch proton server list",
			"trigger", trigger, "error", err, "using_cache", len(e.candidates) > 0)
		e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Proton.LastFetchError = err.Error() })
		return
	}

	e.applyLogicals(logicals, false)

	if err := e.logicals.save(cachedLogicals{
		FetchedAt:    time.Now(),
		LastModified: lastModified,
		Servers:      logicals,
	}); err != nil {
		e.logger.Warn("could not cache proton server list", "error", err)
	}

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Proton.LastFetch = time.Now()
		snapshot.Proton.LastFetchError = ""
		snapshot.Proton.LogicalsCount = len(logicals)
		snapshot.Proton.ListLastModified = lastModified
		snapshot.Proton.FromCache = false
		snapshot.Proton.NeedsTOTP = false
	})

	e.logger.Info("fetched proton server list",
		"trigger", trigger,
		"logicals", len(logicals),
		"candidates", len(e.candidates),
		"took", time.Since(started).Truncate(time.Millisecond))

	e.writeServersFile()
}

// refreshAccountInfo learns the account's plan and its highest usable server
// tier.
//
// Proton's list contains servers above the account's entitlement, and they are
// indistinguishable from usable ones until the connection is refused. Knowing the
// tier turns that into a filter rather than a failed reconnect.
func (e *Engine) refreshAccountInfo(ctx context.Context) {
	info, err := e.proton.Account(ctx)
	if err != nil {
		// Not fatal: without it nothing is filtered by tier, which is how this
		// worked before the account was consulted at all.
		e.logger.Warn("could not read the proton account details", "error", err)
		return
	}

	tier := info.Tier
	changed := e.accountTier == nil || *e.accountTier != tier
	e.accountTier = &tier

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Proton.AccountTier = &tier
		snapshot.Proton.AccountPlan = info.PlanTitle
		if info.PlanTitle == "" {
			snapshot.Proton.AccountPlan = info.PlanName
		}
		snapshot.Proton.AccountFree = info.Free()
		snapshot.Proton.MaxConnections = info.MaxConnections
		snapshot.Proton.AccountDelinquent = info.Delinquent != 0
	})

	if changed {
		e.logger.Info("proton account details",
			"plan", info.PlanName, "tier", tier, "free", info.Free(),
			"max_connections", info.MaxConnections)
		if err := e.state.update(func(state *persistedState) {
			state.AccountTier = &tier
			state.AccountPlan = info.PlanName
		}); err != nil {
			e.logger.Warn("could not persist the proton account tier", "error", err)
		}
	}
	if info.Delinquent != 0 {
		e.logger.Warn("proton reports the account as delinquent, which can cause connections to be refused")
	}
}

// refreshLoads updates utilisation from the cheap loads endpoint. This is what
// makes "lowest utilised" mean "right now" rather than "twelve hours ago".
func (e *Engine) refreshLoads(ctx context.Context, trigger string) {
	if len(e.candidates) == 0 {
		return
	}

	e.setActivity("refreshing server loads")
	defer func() {
		e.setActivity("")
		e.publish()
	}()

	loads, err := e.proton.Loads(ctx)
	if err != nil {
		e.logger.Warn("could not refresh server loads", "trigger", trigger, "error", err)
		e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Proton.LastLoadError = err.Error() })
		return
	}

	e.latestLoads = loads
	before := len(e.candidates)
	updated := e.applyLoads(loads)
	dropped := before - len(e.candidates)
	e.rerank()
	e.recordSamples()

	// Persisted separately from the server list: a few kilobytes rewritten every
	// refresh, so a restart during a Proton outage resumes with recent
	// utilisation instead of whatever the last full fetch saw.
	if err := e.loads.save(cachedLoads{UpdatedAt: time.Now(), Loads: loads}); err != nil {
		e.logger.Warn("could not cache server loads", "error", err)
	}

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Proton.LastLoadRefresh = time.Now()
		snapshot.Proton.LastLoadError = ""
		snapshot.Proton.CacheStale = false
	})
	e.logger.Debug("refreshed server loads",
		"trigger", trigger, "updated", updated, "disabled", dropped)
}

// applyLoads refreshes utilisation across every set the dashboard shows.
//
// The blocked set matters as much as the selectable one here. Its whole purpose is
// comparison - "this quieter server exists but Gluetun cannot use it" - and that
// comparison is meaningless if one side is refreshed every few minutes while the
// other is frozen at whatever the last full list fetch said, hours ago.
func (e *Engine) applyLoads(loads []proton.ServerLoad) (updated int) {
	updated, disabled := catalog.ApplyLoads(e.candidates, loads)
	if len(disabled) > 0 {
		e.dropDisabled(disabled)
	}

	blockedUpdated, blockedDisabled := catalog.ApplyLoads(e.blocked, loads)
	if len(blockedDisabled) > 0 {
		kept := make([]catalog.Candidate, 0, len(e.blocked))
		for _, candidate := range e.blocked {
			if _, gone := blockedDisabled[candidate.Hostname]; gone {
				continue
			}
			kept = append(kept, candidate)
		}
		e.blocked = kept
	}
	return updated + blockedUpdated
}

// dropDisabled removes candidates Proton has taken out of service.
func (e *Engine) dropDisabled(disabled map[string]struct{}) {
	kept := make([]catalog.Candidate, 0, len(e.candidates))
	for _, candidate := range e.candidates {
		if _, gone := disabled[candidate.Hostname]; gone {
			continue
		}
		kept = append(kept, candidate)
	}
	e.logger.Info("dropped servers Proton disabled", "count", len(e.candidates)-len(kept))
	e.candidates = kept
}

// writeServersFile renders the catalog into Gluetun's servers.json.
func (e *Engine) writeServersFile() {
	if e.cfg.Servers.WriteMode == config.WriteModeNone {
		return
	}
	if len(e.candidates) == 0 {
		e.logger.Warn("not writing servers file because there are no candidates")
		return
	}

	// By default the file carries every country Proton offers, even those the
	// selector will not choose. That way a manual override, or a Gluetun
	// restart with different SERVER_COUNTRIES, still has servers to work with.
	servers := catalog.ToGluetunServers(e.serversForFile())

	// The layout is re-detected on every write: Gluetun can be upgraded (or
	// started for the first time) after this process began, which moves where
	// the data has to go.
	e.layout = serversfile.DetectLayout(e.serversPaths())

	result, err := serversfile.Write(servers, serversfile.Options{
		Paths:                  e.serversPaths(),
		Layout:                 e.layout,
		SchemaVersion:          e.schemaVersion,
		Preferred:              e.cfg.Servers.Preferred,
		PreserveOtherProviders: e.cfg.Servers.WriteMode == config.WriteModeUpdate,
	})
	if err != nil {
		e.logger.Error("could not write gluetun server data",
			"layout", string(e.layout), "error", err)
		e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Servers.LastError = err.Error() })
		return
	}

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Servers.LastWrite = result.Timestamp
		snapshot.Servers.ServerCount = result.ServerCount
		snapshot.Servers.SchemaVersion = result.SchemaVersion
		snapshot.Servers.PreservedKeys = result.PreservedKeys
		snapshot.Servers.Layout = string(result.Layout)
		snapshot.Servers.Paths = result.Written
		snapshot.Servers.Preferred = result.Preferred
		snapshot.Servers.LastError = ""
	})
	e.logger.Info("wrote gluetun server data",
		"layout", string(result.Layout),
		"paths", result.Written,
		"servers", result.ServerCount,
		"schema_version", result.SchemaVersion,
		"preferred", result.Preferred,
		"preserved", result.PreservedKeys)
}

// serversForFile decides which candidates end up in servers.json.
func (e *Engine) serversForFile() []catalog.Candidate {
	if e.cfg.Servers.OnlyAllowedCountries {
		return e.candidates
	}
	if len(e.fileCandidates) > 0 {
		return e.fileCandidates
	}
	// Fall back rather than write nothing: an unexpectedly empty wide set must
	// not cost Gluetun the servers we do have.
	return e.candidates
}

// probeLatency measures round-trip times for the most promising candidates.
//
// Only the top N by current ranking are probed: probing 1600 servers every
// half hour would be wasteful when only the best handful can ever be selected.
func (e *Engine) probeLatency(ctx context.Context, trigger string) {
	if !e.cfg.Latency.Enabled || len(e.candidates) == 0 {
		return
	}

	addresses := e.entryIPs(e.cfg.Latency.TopN)
	if len(addresses) == 0 {
		return
	}

	e.setActivity(fmt.Sprintf("probing latency of %d servers", len(addresses)))
	defer func() {
		e.setActivity("")
		e.publish()
	}()

	started := time.Now()
	results := e.prober.Probe(ctx, addresses)
	e.prober.Forget(e.allEntryIPs())
	e.rerank()

	failed := 0
	for _, result := range results {
		if !result.OK() {
			failed++
		}
	}
	summary := e.prober.Summarize()
	e.logger.Info("probed server latency",
		"trigger", trigger,
		"probed", len(results),
		"failed", failed,
		"best", summary.Best.Truncate(time.Millisecond),
		"median", summary.Median.Truncate(time.Millisecond),
		"took", time.Since(started).Truncate(time.Millisecond))
}

func (e *Engine) allEntryIPs() (addresses []netip.Addr) {
	addresses = make([]netip.Addr, 0, len(e.candidates))
	for _, candidate := range e.candidates {
		addresses = append(addresses, candidate.EntryIP)
	}
	return addresses
}

// checkGluetun polls Gluetun's status, public IP and forwarded port.
//
// Every failure here is non-fatal: Gluetun restarting is a normal event, and
// the tool must simply mark itself degraded and carry on.
func (e *Engine) checkGluetun(ctx context.Context) {
	// Remembered so a transition can be spotted: Gluetun coming up is worth acting
	// on at once rather than at the next evaluation, which may be minutes away.
	was := e.Snapshot().Gluetun

	status, err := e.gluetun.Status(ctx)
	if err != nil {
		e.mutateSnapshot(func(snapshot *Snapshot) {
			snapshot.Gluetun.Reachable = false
			snapshot.Gluetun.LastError = err.Error()
			snapshot.Gluetun.LastCheck = time.Now()
		})
		e.logger.Warn("gluetun control server unreachable", "error", err)
		return
	}

	settings, settingsErr := e.gluetun.GetSettings(ctx)
	if settingsErr == nil {
		if vpnType := settings.VPNType(); vpnType != "" {
			e.updateVPNType(vpnType)
		}
		e.updateRequirements(settings.Requirements())
	}

	// These are only queried while the tunnel is up: asking for the public IP
	// while it is down reports the real address, which is misleading.
	//
	// What must not happen is erasing what is already known. A poll that lands
	// while the tunnel is restarting - which, with switching enabled, is many of
	// them - would otherwise blank the forwarded port and the exit address until
	// the next poll, so the dashboard reads "none" for a port Gluetun is happily
	// forwarding. The previous values are kept and marked as not current instead.
	previous := e.Snapshot().Gluetun
	exit, ports := previous.Exit, previous.ForwardedPorts
	live := false

	if status == gluetunapi.StatusRunning {
		if ip, ipErr := e.gluetun.GetPublicIP(ctx); ipErr == nil && ip.IP != "" {
			exit = ExitInfo{
				IP: ip.IP, Country: ip.Country, Region: ip.Region, City: ip.City,
				Hostname: ip.Hostname, Location: ip.Location,
				Organization: ip.Organization, PostalCode: ip.PostalCode, Timezone: ip.Timezone,
			}
			live = true
		}
		if forwarded, portErr := e.gluetun.GetForwardedPorts(ctx); portErr == nil && len(forwarded) > 0 {
			ports = forwarded
		}
	}

	// These two are cheap and answer questions an operator otherwise has to use
	// curl for; a failure on either is not worth reporting as a problem.
	dnsStatus, _ := e.gluetun.DNSStatus(ctx)
	updaterStatus, _ := e.gluetun.UpdaterStatus(ctx)
	build, _ := e.gluetun.Version(ctx)

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.Reachable = true
		snapshot.Gluetun.Status = status
		snapshot.Gluetun.LastCheck = time.Now()
		snapshot.Gluetun.LastError = errorText(settingsErr)
		snapshot.Gluetun.Exit = exit
		snapshot.Gluetun.ForwardedPorts = ports
		if live {
			snapshot.Gluetun.ExitObservedAt = time.Now()
		}
		// Values shown while the tunnel is not running are the last ones seen, not
		// current facts, and the dashboard says so.
		snapshot.Gluetun.ExitCurrent = live
		snapshot.Gluetun.DNSStatus = dnsStatus
		snapshot.Gluetun.UpdaterStatus = updaterStatus
		if build.Version != "" {
			snapshot.Gluetun.Version = build.Version
			snapshot.Gluetun.Commit = build.Commit
			snapshot.Gluetun.Created = build.Created
		}

		snapshot.Gluetun.SettingsReadable = settingsErr == nil
		if settingsErr == nil {
			snapshot.Gluetun.VPNType = settings.VPNType()
			snapshot.Gluetun.Provider = settings.ProviderName()
			snapshot.Gluetun.ProviderMismatch = settings.ProviderName() != "" &&
				settings.ProviderName() != serversfile.Provider
			snapshot.Gluetun.Selection = settings.SelectionSummary()
			ipv4, ipv6 := settings.TunnelAddresses()
			snapshot.Gluetun.TunnelIPv4 = ipv4
			snapshot.Gluetun.TunnelIPv6 = ipv6
			if enabled, known := settings.PortForwardingEnabled(); known {
				snapshot.Gluetun.PortForwardingEnabled = &enabled
			}
		}
	})

	e.checkServerDataIsRead()

	if e.Snapshot().Gluetun.ProviderMismatch {
		e.logger.Warn("gluetun is not configured for protonvpn; this tool cannot affect it",
			"provider", e.Snapshot().Gluetun.Provider)
	}

	// Gluetun usually takes longer to start than this container does, so the first
	// few health checks find it unreachable. Waiting for the evaluation ticker
	// after that would leave the tunnel on whatever server Gluetun picked for
	// itself for up to SWITCHING_EVALUATION_INTERVAL - long enough that the obvious
	// reaction is to go and press the button by hand.
	if becameUsable(was, e.Snapshot().Gluetun) && len(e.ranked) > 0 {
		e.logger.Info("gluetun became usable, evaluating now rather than waiting for the next round",
			"status", status)
		e.evaluate(ctx, "gluetun became usable", false)
	}
}

// becameUsable reports whether Gluetun just reached a state the tunnel can be
// moved in. A crashed tunnel counts: moving it elsewhere is usually the fix.
func becameUsable(was, now GluetunStatus) bool {
	usable := func(state GluetunStatus) bool {
		return state.Reachable &&
			(state.Status == gluetunapi.StatusRunning || state.Status == gluetunapi.StatusCrashed)
	}
	return usable(now) && !usable(was)
}

// checkServerDataIsRead warns when the server data this tool writes cannot
// possibly be read.
//
// Gluetun with STORAGE_SERVERS_ENABLED=no keeps no server data on disk at all,
// and a container whose /gluetun volume is not shared with Gluetun looks
// identical. Either way the files are written into the void: the tool can still
// switch servers, but only among the ones Gluetun has built in, and none of the
// curated list matters. Silence here would be the worst outcome, since
// everything else reports success.
func (e *Engine) checkServerDataIsRead() {
	if e.cfg.Servers.WriteMode == config.WriteModeNone {
		return // not writing anything, so nothing to warn about
	}
	// Re-check first: Gluetun may have started after this process did, in which
	// case its data appears and there is nothing to warn about.
	e.refreshGluetunDataObservation()

	snapshot := e.Snapshot()
	if !snapshot.Gluetun.Reachable {
		return
	}
	if e.gluetunWroteServerData {
		// Clear a warning raised before Gluetun had written anything.
		if snapshot.Servers.Ignored {
			e.mutateSnapshot(func(snapshot *Snapshot) {
				snapshot.Servers.Ignored = false
				snapshot.Servers.IgnoredReason = ""
			})
		}
		return
	}
	if snapshot.Servers.Ignored {
		return // already reported
	}

	const reason = "Gluetun answers its control server but has written no server data of its own, " +
		"so it cannot be reading the data written here. This tool requires " +
		"STORAGE_SERVERS_ENABLED=yes on the Gluetun container (its default), and requires the same " +
		"/gluetun volume to be mounted into both containers - one of those two is not the case. " +
		"Server switching still works meanwhile, but only across the list Gluetun has built in. " +
		"If running without server storage is deliberate, set GLUETUN_SERVERS_WRITE_MODE=none here to stop " +
		"writing data nothing reads."

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Servers.Ignored = true
		snapshot.Servers.IgnoredReason = reason
	})
	e.logger.Warn("gluetun is not reading the server data written here",
		"servers_dir", e.cfg.Servers.DirPath,
		"legacy_file", e.cfg.Servers.FilePath,
		"hint", reason)
}

// updateRequirements adopts the "only" filters Gluetun is enforcing.
//
// Without this, the tool can pick a server Gluetun refuses to use: with
// PORT_FORWARD_ONLY=on, pinning a server that does not support port forwarding
// leaves Gluetun's filters matching nothing, and its VPN loop crashes instead of
// connecting. Adopting the requirements means the operator's intent is satisfied
// by the choice rather than fought over.
func (e *Engine) updateRequirements(from gluetunapi.Requirements) {
	// Requirements are only ever added, never dropped, and that is deliberate.
	//
	// Pinning a server clears these filters in Gluetun on purpose - they are
	// redundant next to an exact hostname, and Gluetun's built-in feature data can
	// disagree with Proton's, which crashes its VPN loop. The consequence is that
	// every pin makes Gluetun report them as off. Believing that would undo the
	// operator's intent: the requirement would be dropped, a server that fails it
	// would be chosen next time, and each flip would rebuild the whole catalog.
	//
	// So an observed "off" is assumed to be our own doing. A genuine change to off
	// is picked up when this container restarts.
	//
	// Asking Proton for a forwarded port counts as requiring P2P, even when Gluetun
	// is not enforcing PORT_FORWARD_ONLY itself.
	//
	// Proton forwards ports on P2P servers and nowhere else, so with
	// VPN_PORT_FORWARDING=on a non-P2P server connects perfectly and then never
	// produces a port. Picking the quietest server would therefore quietly break the
	// feature the operator switched on. Gluetun tolerates that combination; there is
	// no reason for this tool to walk into it.
	// Once the inferred requirement has been given up for lack of any P2P candidate,
	// it must not come straight back: Gluetun still reports port forwarding as on, so
	// re-deriving it here would restart the empty-then-drop cycle on every tick.
	inferred := from.PortForwardingRequested && !e.portForwardInferenceAbandoned
	wantsPortForward := from.PortForward || inferred
	requirements := catalog.Requirements{
		PortForward: wantsPortForward || e.requirements.PortForward,
		SecureCore:  from.SecureCore || e.requirements.SecureCore,
		Tor:         from.Tor || e.requirements.Tor,
		Stream:      from.Stream || e.requirements.Stream,
		Free:        from.Free || e.requirements.Free,
		Premium:     from.Premium || e.requirements.Premium,
	}

	// Record which setting is responsible, because "P2P only" is confusing when the
	// operator never set PORT_FORWARD_ONLY.
	switch {
	case from.PortForward:
		e.portForwardReason = "PORT_FORWARD_ONLY"
	case inferred && e.portForwardReason == "":
		e.portForwardReason = "VPN_PORT_FORWARDING"
	}

	if requirements == e.requirements {
		return
	}

	e.logger.Info("adopting the server requirements gluetun is enforcing",
		"port_forward_only", requirements.PortForward,
		"secure_core_only", requirements.SecureCore,
		"tor_only", requirements.Tor,
		"stream_only", requirements.Stream,
		"free_only", requirements.Free,
		"premium_only", requirements.Premium)
	if from.MultiHop || from.Owned {
		e.logger.Warn("gluetun enforces a filter ProtonVPN does not express, so it cannot be satisfied",
			"multi_hop_only", from.MultiHop, "owned_only", from.Owned)
	}

	e.requirements = requirements
	e.rebuildFromCache("gluetun requirements changed")
	e.publish()
}

// rebuildFromCache re-derives the catalog from the cached Proton list, used when
// something outside the list itself changes what counts as a candidate.
func (e *Engine) rebuildFromCache(reason string) {
	cached, found, err := e.logicals.load()
	if err != nil || !found {
		return
	}
	e.logger.Info("rebuilding candidate list", "reason", reason)
	e.applyLogicals(cached.Servers, true)
}

// updateVPNType reacts to Gluetun's configured protocol. When VPN_TYPE is auto
// and the protocol turns out to be WireGuard, candidates without a WireGuard key
// must be dropped, so the catalog is rebuilt.
func (e *Engine) updateVPNType(vpnType string) {
	if e.vpnType == vpnType {
		return
	}
	previous := e.effectiveVPNType()
	e.vpnType = vpnType
	if e.cfg.Filter.VPNType != "auto" || e.effectiveVPNType() == previous {
		return
	}

	e.rebuildFromCache("gluetun protocol detected: " + vpnType)
}

// currentHostname determines which server the tunnel is on.
//
// Two independent signals are used, in order of reliability:
//
//  1. the hostname this tool pinned, when Gluetun still reports it pinned;
//  2. Gluetun's public IP matched against Proton's exit addresses, which works
//     even when the tunnel was started by someone else.
func (e *Engine) currentHostname() (hostname, source string) {
	snapshot := e.Snapshot()

	// Gluetun's own reported selection comes first, because it is exact. When it
	// is restricted to a single hostname, that is where the tunnel is - Gluetun
	// validated the name and its selection is what decides the connection.
	if pinned := snapshot.Gluetun.Selection["hostnames"]; len(pinned) == 1 {
		return pinned[0], "pinned"
	}

	// Failing that, match Gluetun's exit address against Proton's. This is a
	// weaker signal than it looks: Proton publishes the server address, which is
	// often not the address the internet sees, so a miss here means nothing.
	if snapshot.Gluetun.Exit.IP != "" {
		if address, err := netip.ParseAddr(snapshot.Gluetun.Exit.IP); err == nil {
			// Search the wide set, not just the allowed one: a tunnel sitting on
			// an over-loaded or out-of-country server is exactly the case worth
			// reporting accurately, and it is what triggers a switch.
			for _, set := range [][]catalog.Candidate{e.fileCandidates, e.candidates} {
				for _, candidate := range set {
					if candidate.ExitIP.IsValid() && candidate.ExitIP == address {
						return candidate.Hostname, "public-ip"
					}
				}
			}
		}
	}

	// Last resort: what this tool last asked for. Used when Gluetun's settings
	// cannot be read at all.
	if remembered := e.state.snapshot().PinnedHostname; remembered != "" {
		return remembered, "remembered"
	}
	return "", "unknown"
}

// lookupCandidate finds a candidate by hostname in either set.
func (e *Engine) lookupCandidate(hostname string) (candidate catalog.Candidate, found bool) {
	if hostname == "" {
		return catalog.Candidate{}, false
	}
	for _, set := range [][]catalog.Candidate{e.candidates, e.fileCandidates} {
		for _, entry := range set {
			if entry.Hostname == hostname {
				return entry, true
			}
		}
	}
	return catalog.Candidate{}, false
}
