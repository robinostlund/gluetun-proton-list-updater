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

	updated, disabled := catalog.ApplyLoads(e.candidates, loads)
	if len(disabled) > 0 {
		e.dropDisabled(disabled)
	}
	e.rerank()

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Proton.LastLoadRefresh = time.Now()
		snapshot.Proton.LastLoadError = ""
	})
	e.logger.Debug("refreshed server loads",
		"trigger", trigger, "updated", updated, "disabled", len(disabled))
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

	result, err := serversfile.Write(servers, serversfile.Options{
		Path:                   e.cfg.Servers.FilePath,
		SchemaVersion:          e.schemaVersion,
		PreserveOtherProviders: e.cfg.Servers.WriteMode == config.WriteModeUpdate,
	})
	if err != nil {
		e.logger.Error("could not write servers file", "path", e.cfg.Servers.FilePath, "error", err)
		e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Servers.LastError = err.Error() })
		return
	}

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Servers.LastWrite = result.Timestamp
		snapshot.Servers.ServerCount = result.ServerCount
		snapshot.Servers.SchemaVersion = result.SchemaVersion
		snapshot.Servers.PreservedKeys = result.PreservedKeys
		snapshot.Servers.LastError = ""
	})
	e.logger.Info("wrote servers file",
		"path", result.Path,
		"servers", result.ServerCount,
		"schema_version", result.SchemaVersion,
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
	}

	// The public IP is only meaningful while the tunnel is up, and asking for it
	// while stopped produces a confusing "your real IP" answer.
	var publicIP gluetunapi.PublicIP
	var port uint16
	if status == gluetunapi.StatusRunning {
		if ip, ipErr := e.gluetun.GetPublicIP(ctx); ipErr == nil {
			publicIP = ip
		}
		if forwarded, portErr := e.gluetun.GetForwardedPort(ctx); portErr == nil {
			port = forwarded
		}
	}

	version, _ := e.gluetun.Version(ctx)

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.Reachable = true
		snapshot.Gluetun.Status = status
		snapshot.Gluetun.LastCheck = time.Now()
		snapshot.Gluetun.LastError = errorText(settingsErr)
		snapshot.Gluetun.PublicIP = publicIP.IP
		snapshot.Gluetun.Country = publicIP.Country
		snapshot.Gluetun.City = publicIP.City
		snapshot.Gluetun.ForwardedPort = port
		if version != "" {
			snapshot.Gluetun.Version = version
		}
		if settingsErr == nil {
			snapshot.Gluetun.VPNType = settings.VPNType()
			snapshot.Gluetun.Provider = settings.ProviderName()
			snapshot.Gluetun.ProviderMismatch = settings.ProviderName() != "" &&
				settings.ProviderName() != serversfile.Provider
		}
	})

	if e.Snapshot().Gluetun.ProviderMismatch {
		e.logger.Warn("gluetun is not configured for protonvpn; this tool cannot affect it",
			"provider", e.Snapshot().Gluetun.Provider)
	}
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

	e.logger.Info("gluetun protocol detected, rebuilding candidate list", "vpn", vpnType)
	cached, found, err := e.logicals.load()
	if err != nil || !found {
		return
	}
	e.applyLogicals(cached.Servers, true)
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

	if snapshot.Gluetun.PublicIP != "" {
		if address, err := netip.ParseAddr(snapshot.Gluetun.PublicIP); err == nil {
			// Search the wide set, not just the allowed one: a tunnel sitting on
			// an over-loaded or out-of-country server is exactly the case worth
			// reporting accurately, and it is what triggers a switch.
			for _, candidate := range e.fileCandidates {
				if candidate.ExitIP.IsValid() && candidate.ExitIP == address {
					return candidate.Hostname, "public-ip"
				}
			}
			for _, candidate := range e.candidates {
				if candidate.ExitIP.IsValid() && candidate.ExitIP == address {
					return candidate.Hostname, "public-ip"
				}
			}
		}
	}

	if pinned := e.state.snapshot().PinnedHostname; pinned != "" {
		return pinned, "pinned"
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
