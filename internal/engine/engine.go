// Package engine owns all the moving parts: it fetches Proton's server list,
// keeps servers.json current, probes latency, ranks candidates and moves the
// Gluetun tunnel onto the best one.
//
// Concurrency model: exactly one goroutine (Run) mutates engine state. Timers
// and dashboard commands both funnel into that goroutine's select loop, so
// there is no lock ordering to reason about and no possibility of two switches
// racing. The only shared state is the published Snapshot, guarded by a mutex
// and replaced wholesale.
package engine

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/catalog"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/gluetunapi"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/latency"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/qbittorrent"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/scoring"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/serversfile"
)

// maxCandidateViews caps how many ranked servers the snapshot carries. The
// dashboard shows a shortlist; sending 1600 rows several times a minute would
// waste far more bandwidth than it is worth.
const maxCandidateViews = 150

// maxBlockedViews caps the unselectable rows shown alongside them. They exist to
// answer "where did that server go?", and a couple of dozen answers that question
// as well as hundreds would.
const maxBlockedViews = 25

// Engine coordinates every periodic task.
type Engine struct {
	cfg     config.Config
	logger  *slog.Logger
	version string

	proton  *proton.Client
	gluetun *gluetunapi.Client
	prober  *latency.Prober
	manual  *proton.ManualCodeProvider // nil when a TOTP secret is configured

	state    *stateStore
	logicals *logicalsCache
	loads    *loadsCache

	// commands carries dashboard-initiated work into the run loop.
	commands chan command
	// subscribers are notified whenever the snapshot changes.
	subscribers *subscriberSet

	startedAt time.Time

	// Fields below are only touched by the run loop, except through snapshot.
	//
	// There are deliberately three candidate sets. candidates is fully filtered
	// and is what selection ranks. fileCandidates only drops servers that are
	// unusable (disabled, wrong protocol, unwanted features) and keeps every
	// country, because servers.json should give Gluetun the whole picture: a
	// manual override, or a Gluetun restart with different SERVER_COUNTRIES,
	// then still has servers to work with.
	//
	// blocked is the third: servers that pass every filter the operator chose but
	// fail one Gluetun itself enforces. They are never selectable - Gluetun would
	// refuse them - but they are shown, because "my quiet Stockholm server has
	// vanished from the list" is otherwise a mystery, and the answer is a setting
	// on the *other* container.
	candidates     []catalog.Candidate
	fileCandidates []catalog.Candidate
	blocked        []catalog.Candidate
	ranked         []scoring.Scored
	stats          catalog.Stats
	vpnType        string
	// requirements are the "only" filters Gluetun is enforcing. They are read from
	// Gluetun rather than configured here, because a candidate that fails one of
	// them cannot be connected to at all.
	requirements catalog.Requirements
	// portForwardInferenceAbandoned records that requiring P2P purely because a
	// forwarded port was requested has been given up, because it left no candidates.
	//
	// It has to be remembered, not just undone. The requirement is re-derived from
	// Gluetun's settings on every health check, and VPN_PORT_FORWARDING is still on -
	// so without this the requirement would be re-adopted, empty the catalog, be
	// dropped again, and rebuild the whole catalog on every tick, for ever. An
	// explicit PORT_FORWARD_ONLY is unaffected: that is Gluetun's own filter and is
	// always honoured.
	portForwardInferenceAbandoned bool
	// qbittorrent reads current transfer rates, nil when QBITTORRENT_URL is unset.
	// Its purpose is to keep a switch from interrupting an active transfer.
	qbittorrent        *qbittorrent.Client
	qbittorrentVersion string
	transfer           qbittorrent.Transfer
	// transferSamples is the recent rate history, used to average over
	// SWITCHING_BUSY_WINDOW rather than deciding on one reading.
	transferSamples []transferSample
	qbPreferences   qbittorrent.Preferences
	qbPreferencesAt time.Time
	// throughputHost is the server the last throughput reading was attributed to. A
	// change of hostname is what ends one stay's measurement and begins the next.
	throughputHost string
	// transferGraceExpired records that the wait for qBittorrent's first answer has been
	// given up on, so the warning is said once rather than on every evaluation.
	transferGraceExpired bool
	// throughputPeakDownload and throughputPeakUpload are the highest rates seen since
	// the last graph point was written, held in memory and cleared when it is.
	throughputPeakDownload uint64
	throughputPeakUpload   uint64
	// throughputBytesDown and throughputBytesUp are the volume moved since then, the
	// same way.
	throughputBytesDown uint64
	throughputBytesUp   uint64
	// transferBaseline* is qBittorrent's session counter at the previous poll, and the
	// server it was attributed to. Bytes are attributed by difference, so a baseline
	// from a different server - or from before a qBittorrent restart - must never be
	// subtracted from the current reading.
	transferBaselineHost string
	transferBaselineDown uint64
	transferBaselineUp   uint64
	// qbPreferencesErr is why the port settings could not be read. Kept rather than
	// discarded: without them the listen port is simply unknown, and an unexplained
	// "unknown" on the dashboard is not something an operator can act on.
	qbPreferencesErr  string
	transferReachable bool
	transferErr       string
	transferCheckedAt time.Time
	// transferBusySince is when the tunnel last became busy, zero when idle. It is
	// what bounds how long a switch can be deferred.
	transferBusySince time.Time
	// gluetunKnownHosts is the server list Gluetun disclosed the last time it
	// refused a hostname, empty when it has not refused one.
	//
	// Gluetun loads its servers at startup and exposes no route to read them back,
	// so this is the only way to know what it can actually be switched to. It is a
	// snapshot, not a fact: it is dropped as soon as a switch succeeds.
	gluetunKnownHosts map[string]struct{}
	// portForwardReason names the Gluetun setting that made P2P a requirement,
	// either "PORT_FORWARD_ONLY" or "VPN_PORT_FORWARDING". They are different
	// settings with the same consequence here, and saying which one applies is the
	// difference between an explicable restriction and a baffling one.
	portForwardReason string
	schemaVersion     uint16
	// layout is which storage layout the running Gluetun uses. It is detected
	// rather than configured, and re-detected on each write because Gluetun can
	// be upgraded underneath us.
	layout serversfile.Layout
	// accountTier is the highest server tier the Proton account may use, nil until
	// known. Servers above it refuse the connection, so they are not candidates.
	accountTier *uint8
	// latestLoads is the most recent utilisation figures seen, from either a
	// refresh or the cache.
	//
	// It exists because the catalog is rebuilt from the cached Proton list whenever
	// something outside that list changes what counts as a candidate - the VPN
	// protocol, or the filters Gluetun enforces. A rebuild would otherwise revert
	// every load to whatever the last full fetch saw, silently undoing up to a
	// refresh interval of updates.
	latestLoads []proton.ServerLoad
	// gluetunWroteServerData records whether Gluetun had written any server data
	// of its own before this process wrote anything.
	//
	// It is captured once, at startup, precisely because our own writes would
	// otherwise pollute the signal. Combined with "Gluetun answers its control
	// server", its absence means Gluetun is running but keeps no server data on
	// disk - either STORAGE_SERVERS_ENABLED=no, or the /gluetun volume is not
	// actually shared with this container. In both cases everything written here
	// is ignored, which is worth saying out loud.
	gluetunWroteServerData bool

	snapshotMu sync.RWMutex
	snapshot   Snapshot
}

// Options configures a new Engine.
type Options struct {
	Config  config.Config
	Logger  *slog.Logger
	Version string
	Proton  *proton.Client
	Gluetun *gluetunapi.Client
	// Manual is the dashboard-driven TOTP provider, if one is in use.
	Manual *proton.ManualCodeProvider
}

// New builds an Engine and restores persisted state. It does not perform any
// network I/O; that starts with Run.
func New(opts Options) (engine *Engine, err error) {
	if opts.Proton == nil || opts.Gluetun == nil {
		return nil, errors.New("engine: proton and gluetun clients are required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	engine = &Engine{
		cfg:     opts.Config,
		logger:  logger,
		version: opts.Version,
		proton:  opts.Proton,
		gluetun: opts.Gluetun,
		manual:  opts.Manual,
		prober: latency.New(latency.Options{
			Port:            opts.Config.Latency.Port,
			Samples:         opts.Config.Latency.Samples,
			Timeout:         opts.Config.Latency.Timeout,
			Concurrency:     opts.Config.Latency.Concurrency,
			SmoothingFactor: opts.Config.Latency.SmoothingFactor,
		}),
		state:       newStateStore(opts.Config.StateDir),
		logicals:    newLogicalsCache(opts.Config.StateDir),
		loads:       newLoadsCache(opts.Config.StateDir),
		commands:    make(chan command, 16),
		subscribers: newSubscriberSet(),
		startedAt:   time.Now(),
		vpnType:     opts.Config.Filter.VPNType,
	}

	if opts.Config.QBittorrent.Enabled() {
		engine.qbittorrent = qbittorrent.New(qbittorrent.Options{
			BaseURL: opts.Config.QBittorrent.URL,
			APIKey:  opts.Config.QBittorrent.APIKey,
			Timeout: opts.Config.QBittorrent.RequestTimeout,
		})
		if !qbittorrent.APIKeyLooksValid(opts.Config.QBittorrent.APIKey) {
			// Advisory: qBittorrent decides whether a key works, and the format
			// could change. But a value that is plainly not a key - a password, a
			// session cookie, a truncated paste - is worth catching here rather
			// than as a puzzling 401 later.
			logger.Warn("QBITTORRENT_API_KEY does not look like a qBittorrent API key",
				"expected", "a value beginning \"qbt_\", generated in Preferences -> Web UI -> API keys",
				"note", "it will still be tried")
		}
	}

	if err := engine.state.load(); err != nil {
		// Corrupt state must not prevent startup: the tool can rebuild
		// everything it needs from Proton and Gluetun.
		logger.Warn("could not load persisted state, starting fresh", "error", err)
	}
	// A remembered tier applies immediately, so a restart while Proton is
	// unreachable does not consider servers the account cannot use.
	engine.accountTier = engine.state.snapshot().AccountTier
	return engine, nil
}

// Explain reports what happened to every Proton server matching query, between
// Proton's response and the candidate list.
//
// It reads the cached raw server list rather than the candidates, because the
// whole point is to explain servers that are *not* candidates.
func (e *Engine) Explain(query string) (explanations []catalog.Explanation, err error) {
	cached, found, err := e.logicals.load()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("no cached Proton server list yet: wait for the first fetch to succeed")
	}
	return catalog.Explain(cached.Servers, e.catalogOptions(), query), nil
}

// SessionPath returns where the Proton session is stored, so main can wire the
// session store without duplicating path logic.
func SessionPath(stateDir string) string { return filepath.Join(stateDir, sessionFileName) }

// Run executes the engine until ctx is cancelled.
//
// Startup order matters: the server list is loaded (from cache first, then
// Proton) before anything tries to select a server, so a Proton outage at boot
// degrades to "use yesterday's list" rather than "do nothing".
func (e *Engine) Run(ctx context.Context) (err error) {
	e.logger.Info("starting engine",
		"version", e.version,
		"countries", e.cfg.Filter.Countries,
		"reconnect_mode", e.cfg.Switch.Mode,
		"auto_switch", e.autoSwitchEnabled(),
	)

	e.detectSchemaVersion()
	e.loadCachedLogicals()
	e.publish()

	// Kick off the first round of work immediately rather than waiting a full
	// interval, but do it inside the loop so a slow Proton API cannot delay
	// dashboard responsiveness.
	e.checkGluetun(ctx)
	e.identifyQBittorrent(ctx)
	e.refreshTransfer(ctx, "startup")
	e.refreshServerList(ctx, "startup")
	e.probeLatency(ctx, "startup")
	e.evaluate(ctx, "startup", false)

	listTicker := newTicker(e.cfg.Proton.RefreshInterval)
	defer listTicker.Stop()
	loadTicker := newTicker(e.cfg.Proton.LoadRefreshInterval)
	defer loadTicker.Stop()
	latencyTicker := newTicker(e.latencyInterval())
	defer latencyTicker.Stop()
	evaluateTicker := newTicker(e.cfg.Switch.Interval)
	defer evaluateTicker.Stop()
	healthTicker := newTicker(e.cfg.Gluetun.HealthInterval)
	defer healthTicker.Stop()
	// Disabled when qBittorrent is not configured, so an unused feature costs
	// nothing: newTicker treats a zero interval as "never fire".
	transferTicker := newTicker(e.transferInterval())
	defer transferTicker.Stop()
	// The per-server statistics are updated on every qBittorrent poll but written on a
	// timer, so a fifteen-second poll does not rewrite the whole state file. This is what
	// bounds how much that can lose.
	flushTicker := newTicker(stateFlushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Settle anything still in memory before going away. Without this a restart
			// inside the flush window discarded every byte counted since the last write,
			// which looked exactly like the figures not surviving a restart.
			e.flushState("shutdown")
			e.logger.Info("engine stopped")
			return nil

		case <-listTicker.C():
			e.refreshServerList(ctx, "scheduled")
			e.evaluate(ctx, "after list refresh", false)

		case <-loadTicker.C():
			e.refreshLoads(ctx, "scheduled")

		case <-latencyTicker.C():
			e.probeLatency(ctx, "scheduled")

		case <-evaluateTicker.C():
			e.evaluate(ctx, "scheduled", false)

		case <-healthTicker.C():
			e.checkGluetun(ctx)
			e.publish()

		case <-transferTicker.C():
			e.refreshTransfer(ctx, "scheduled")

		case <-flushTicker.C():
			e.flushState("scheduled")

		case cmd := <-e.commands:
			e.handleCommand(ctx, cmd)
		}
	}
}

// Snapshot returns the current published view.
func (e *Engine) Snapshot() Snapshot {
	e.snapshotMu.RLock()
	defer e.snapshotMu.RUnlock()
	return e.snapshot
}

// Subscribe registers for snapshot-change notifications. The returned function
// must be called to release the subscription.
func (e *Engine) Subscribe() (updates <-chan struct{}, cancel func()) {
	return e.subscribers.add()
}

// SubmitTOTP hands a two-factor code to a login that is waiting for one.
func (e *Engine) SubmitTOTP(code string) (accepted bool) {
	if e.manual == nil {
		return false
	}
	return e.manual.Submit(code)
}

// autoSwitchEnabled reports whether automatic switching is on, honouring a
// dashboard override stored in the state file.
func (e *Engine) autoSwitchEnabled() bool {
	if override := e.state.snapshot().AutoSwitch; override != nil {
		return *override
	}
	return e.cfg.Switch.Auto
}

func (e *Engine) latencyInterval() time.Duration {
	if !e.cfg.Latency.Enabled {
		return 0
	}
	return e.cfg.Latency.Interval
}

// detectSchemaVersion works out which protonvpn schema version the running
// Gluetun expects.
//
// Gluetun discards a servers file whose version differs from its built-in one,
// and that version changes between Gluetun releases. Reading it back from the
// file Gluetun itself wrote is far more robust than hardcoding a number that
// silently rots.
func (e *Engine) detectSchemaVersion() {
	e.refreshGluetunDataObservation()
	e.layout = serversfile.DetectLayout(e.serversPaths())
	e.logger.Info("detected gluetun storage layout",
		"layout", string(e.layout),
		"servers_dir", e.cfg.Servers.DirPath,
		"legacy_file", e.cfg.Servers.FilePath)

	if e.cfg.Servers.SchemaVersion > 0 {
		e.schemaVersion = e.cfg.Servers.SchemaVersion
		e.logger.Info("using configured servers schema version", "version", e.schemaVersion)
		return
	}

	version, source, err := serversfile.DetectSchemaVersion(e.serversPaths())
	switch {
	case err != nil:
		e.schemaVersion = config.DefaultSchemaVersion
		e.logger.Warn("could not read the schema version from Gluetun's server data, using default",
			"version", e.schemaVersion, "error", err)
	case version > 0:
		e.schemaVersion = version
		e.logger.Info("detected servers schema version from Gluetun's own data",
			"path", source, "version", version)
	default:
		e.schemaVersion = config.DefaultSchemaVersion
		e.logger.Info("Gluetun has not written server data yet, using the default schema version",
			"version", e.schemaVersion,
			"hint", "if Gluetun logs that servers were discarded, set GLUETUN_SERVERS_SCHEMA_VERSION to the version it reports")
	}
}

// refreshGluetunDataObservation notes whether Gluetun's own server data is
// present, remembering a positive result permanently.
func (e *Engine) refreshGluetunDataObservation() {
	if e.gluetunWroteServerData {
		return
	}
	if e.state.snapshot().GluetunHadServerData {
		e.gluetunWroteServerData = true
		return
	}
	if !serversfile.HasGluetunData(e.serversPaths()) {
		return
	}

	e.gluetunWroteServerData = true
	if err := e.state.update(func(state *persistedState) {
		state.GluetunHadServerData = true
	}); err != nil {
		e.logger.Warn("could not persist the gluetun server data observation", "error", err)
	}
}

// serversPaths locates both of Gluetun's storage layouts.
func (e *Engine) serversPaths() serversfile.Paths {
	return serversfile.Paths{
		Directory:  e.cfg.Servers.DirPath,
		LegacyFile: e.cfg.Servers.FilePath,
	}
}

// loadCachedLogicals seeds the catalog from disk so the tool is useful before
// the first successful Proton fetch.
func (e *Engine) loadCachedLogicals() {
	cached, found, err := e.logicals.load()
	if err != nil {
		e.logger.Warn("could not read cached server list", "error", err)
		return
	}
	if !found {
		return
	}

	e.applyLogicals(cached.Servers, true)

	age := time.Since(cached.FetchedAt)
	stale := e.cfg.Proton.CacheMaxAge > 0 && age > e.cfg.Proton.CacheMaxAge

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Proton.FromCache = true
		snapshot.Proton.LastFetch = cached.FetchedAt
		snapshot.Proton.ListLastModified = cached.LastModified
		snapshot.Proton.LogicalsCount = len(cached.Servers)
		snapshot.Proton.CacheStale = stale
	})

	if stale {
		// Still used: a stale list beats no list, and it is corrected as soon as
		// Proton answers. But choosing on week-old utilisation figures deserves
		// saying out loud rather than being buried in a startup line.
		e.logger.Warn("the cached server list is old; utilisation figures may be well out of date",
			"age", age.Truncate(time.Minute), "max_age", e.cfg.Proton.CacheMaxAge)
	}
	e.logger.Info("loaded server list from cache",
		"logicals", len(cached.Servers),
		"candidates", len(e.candidates),
		"age", age.Truncate(time.Second))

	// Utilisation is cached separately and refreshed far more often, so applying
	// it here recovers most of what a restart would otherwise lose.
	e.applyCachedLoads(cached.FetchedAt)

	// Write the server data from the cache as well.
	//
	// Otherwise a restart while Proton is unreachable leaves Gluetun with whatever
	// it had - possibly nothing, on a fresh volume - even though a perfectly usable
	// list is sitting right here. Writing cached data is strictly better than
	// writing none, and it is corrected as soon as Proton answers again.
	e.writeServersFile()
}

// applyCachedLoads overlays utilisation figures newer than the cached list.
func (e *Engine) applyCachedLoads(listFetchedAt time.Time) {
	cached, found, err := e.loads.load()
	switch {
	case err != nil:
		e.logger.Warn("could not read cached server loads", "error", err)
		return
	case !found:
		return
	case !cached.UpdatedAt.After(listFetchedAt):
		return // the list itself is at least as fresh
	}

	e.latestLoads = cached.Loads
	updated := e.applyLoads(cached.Loads)
	e.rerank()

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Proton.LastLoadRefresh = cached.UpdatedAt
	})
	e.logger.Info("applied cached server loads",
		"updated", updated,
		"age", time.Since(cached.UpdatedAt).Truncate(time.Second))
}

// applyLogicals rebuilds the catalog and ranking from a logical server list.
func (e *Engine) applyLogicals(logicals []proton.LogicalServer, fromCache bool) {
	candidates, stats := catalog.Build(logicals, e.catalogOptions())

	// Requiring P2P because a forwarded port was *requested* is an inference, not a
	// filter Gluetun enforces, so it must never be the reason the tunnel has nowhere
	// to go. If it empties the candidate list, drop it and say so: no port at all is
	// better than no connection at all, and Gluetun would have connected anyway.
	if len(candidates) == 0 && e.portForwardOnlyIsInferred() {
		e.logger.Warn("no port-forwarding server is available, so that preference is being ignored",
			"reason", "VPN_PORT_FORWARDING is on, but no P2P server survives the other filters",
			"consequence", "the tunnel will connect, but Proton will not forward a port")
		e.requirements.PortForward = false
		e.portForwardReason = ""
		e.portForwardInferenceAbandoned = true
		candidates, stats = catalog.Build(logicals, e.catalogOptions())
	}

	e.candidates = candidates
	e.stats = stats
	e.fileCandidates, _ = catalog.Build(logicals, e.fileCatalogOptions())
	e.blocked = e.buildBlocked(logicals)

	// Re-apply the newest utilisation figures over the freshly built candidates:
	// the list they came from can be hours older than the last loads refresh.
	if len(e.latestLoads) > 0 {
		updated := e.applyLoads(e.latestLoads)
		e.logger.Debug("re-applied the latest loads after rebuilding", "updated", updated)
	}
	e.rerank()

	if len(stats.UnknownCountries) > 0 {
		e.logger.Warn("proton returned country codes this build does not know",
			"codes", stats.UnknownCountries)
	}
	if len(candidates) == 0 {
		e.logger.Warn("no candidate servers survived filtering",
			"from_cache", fromCache,
			"hint", "check FILTER_COUNTRIES, FILTER_MAX_LOAD and the feature filters")
	}

	// A fresh list is the only authority on which servers still exist, so it is also
	// the only moment a retired server's measurements may be discarded.
	if !fromCache {
		e.forgetRetiredServers(logicals)
	}
}

// portForwardOnlyIsInferred reports whether the P2P requirement came from Gluetun
// merely asking for a forwarded port, rather than from PORT_FORWARD_ONLY. Only the
// inferred one may be given up.
func (e *Engine) portForwardOnlyIsInferred() bool {
	return e.requirements.PortForward && e.portForwardReason == "VPN_PORT_FORWARDING"
}

// buildBlocked lists the servers that only a Gluetun-enforced filter rejects.
//
// It is a set difference rather than a separate filter pass, so it cannot drift
// from what selection actually accepts: anything that survives the operator's
// filters but is absent from the real candidate list was removed by a requirement,
// by definition.
//
// Deliberately narrow. Servers dropped by COUNTRIES, MAX_LOAD or a feature filter
// are *not* included: the operator set those, the filtering statistics already
// count them, and listing them would bury the useful rows under hundreds of
// self-inflicted ones.
func (e *Engine) buildBlocked(logicals []proton.LogicalServer) (blocked []catalog.Candidate) {
	if e.requirements.None() {
		return nil
	}

	opts := e.catalogOptions()
	opts.Require = catalog.Requirements{}
	unrestricted, _ := catalog.Build(logicals, opts)

	selectable := make(map[string]struct{}, len(e.candidates))
	for _, candidate := range e.candidates {
		selectable[candidate.Hostname] = struct{}{}
	}

	for _, candidate := range unrestricted {
		if _, usable := selectable[candidate.Hostname]; usable {
			continue
		}
		blocked = append(blocked, candidate)
	}
	return blocked
}

// catalogOptions maps the configuration onto catalog filters.
func (e *Engine) catalogOptions() catalog.Options {
	return catalog.Options{
		Countries:        e.cfg.Filter.Countries,
		ExcludeCountries: e.cfg.Filter.ExcludeCountries,
		Cities:           e.cfg.Filter.Cities,
		MaxLoad:          e.cfg.Filter.MaxLoad,
		SecureCore:       e.cfg.Filter.SecureCore,
		Tor:              e.cfg.Filter.Tor,
		P2P:              e.cfg.Filter.P2P,
		IPv6:             e.cfg.Filter.IPv6,
		Stream:           e.cfg.Filter.Stream,
		Free:             e.cfg.Filter.Free,
		VPNType:          e.effectiveVPNType(),
		IncludeIPv6:      e.cfg.Servers.IncludeIPv6,
		Require:          e.requirements,
		MaxTier:          e.accountTier,
	}
}

// fileCatalogOptions is catalogOptions without the location and load
// restrictions, producing the wider set written to servers.json.
//
// Feature filters are kept: a Tor or Secure Core server the operator excluded
// should not be offered to Gluetun at all. Load is not a filter here, because a
// server being busy right now says nothing about whether it belongs in the list.
func (e *Engine) fileCatalogOptions() catalog.Options {
	opts := e.catalogOptions()
	opts.Countries = nil
	opts.ExcludeCountries = nil
	opts.Cities = nil
	opts.MaxLoad = 0
	// Gluetun applies its own "only" filters when choosing from this list, so it
	// should receive every server rather than a pre-narrowed set. The tier limit
	// stays, though: a server the account cannot connect to is of no use to Gluetun
	// either, and offering it only invites failed connections.
	opts.Require = catalog.Requirements{}
	return opts
}

// effectiveVPNType resolves "auto" against what Gluetun reported.
func (e *Engine) effectiveVPNType() string {
	if e.cfg.Filter.VPNType != "auto" {
		return e.cfg.Filter.VPNType
	}
	switch e.vpnType {
	case catalog.VPNWireguard, catalog.VPNOpenVPN:
		return e.vpnType
	default:
		// Not known yet: accept both, so nothing is filtered out prematurely.
		return ""
	}
}

func (e *Engine) rerank() {
	e.ranked = scoring.Rank(e.candidates, e.prober.Results(), e.cfg.Score)
}

// entryIPs lists the addresses worth probing, most promising first.
//
// The ordering deliberately ignores latency. Ranking by the full score would
// make probing self-reinforcing: an unprobed server carries the
// UnknownLatencyPenalty, which pushes it down the ranking, which keeps it
// outside the probe budget, so it stays unprobed forever - even when its load is
// better than that of servers being probed. Selecting on load (and Proton's own
// score) instead means a server's chance of being measured never depends on
// whether it has already been measured.
func (e *Engine) entryIPs(limit int) (addresses []netip.Addr) {
	latencyBlind := e.cfg.Score
	latencyBlind.LatencyWeight = 0
	ranked := scoring.Rank(e.candidates, nil, latencyBlind)

	if limit > 0 && limit < len(ranked) {
		ranked = ranked[:limit]
	}
	addresses = make([]netip.Addr, 0, len(ranked))
	seen := make(map[string]struct{}, len(ranked))
	for _, entry := range ranked {
		key := entry.Candidate.EntryIP.String()
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		addresses = append(addresses, entry.Candidate.EntryIP)
	}
	return addresses
}

// setActivity publishes what the engine is doing, so the dashboard can show a
// spinner instead of appearing frozen during a 90-second switch.
func (e *Engine) setActivity(activity string) {
	e.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Activity = activity })
}

// mutateSnapshot applies a change to the published snapshot and notifies
// subscribers.
func (e *Engine) mutateSnapshot(mutate func(snapshot *Snapshot)) {
	e.snapshotMu.Lock()
	mutate(&e.snapshot)
	e.snapshot.At = time.Now()
	e.snapshotMu.Unlock()
	e.subscribers.notify()
}

// publish rebuilds the derived parts of the snapshot from engine state.
func (e *Engine) publish() {
	persisted := e.state.snapshot()
	ranked := e.ranked
	currentHostname, currentSource := e.currentHostname()

	views := make([]CandidateView, 0, min(len(ranked), maxCandidateViews))
	for i, entry := range ranked {
		if i >= maxCandidateViews {
			break
		}
		views = append(views, toCandidateView(i+1, entry, entry.Candidate.Hostname == currentHostname))
	}
	views = append(views, e.blockedViews(currentHostname)...)
	// What has actually been observed about each server. Attached here rather than inside
	// toCandidateView because it comes from persisted state rather than from the scored
	// candidate.
	for i := range views {
		views[i].Stats = e.statsFor(views[i].Hostname)
	}

	var current, best *CandidateView
	switch scored, found := scoring.Find(ranked, currentHostname); {
	case found:
		view := toCandidateView(rankOf(ranked, currentHostname), scored, true)
		current = &view
	default:
		// The tunnel is on a server the filters exclude - too busy, wrong
		// country, unwanted feature. Showing it as "unknown" would hide the very
		// thing the operator needs to see, so report it and mark it excluded.
		if candidate, ok := e.lookupCandidate(currentHostname); ok {
			view := toCandidateView(0, scoring.Scored{Candidate: candidate}, true)
			view.Excluded = true
			current = &view
		}
	}
	if len(ranked) > 0 {
		view := toCandidateView(1, ranked[0], ranked[0].Candidate.Hostname == currentHostname)
		best = &view
	}
	if current != nil {
		current.Stats = e.statsFor(current.Hostname)
	}
	if best != nil {
		best.Stats = e.statsFor(best.Hostname)
	}

	improvement := 0.0
	if current != nil && best != nil {
		improvement = current.Score - best.Score
	}

	// nextRuns reads the published snapshot, so it must be computed before
	// taking the write lock: sync.RWMutex is not reentrant.
	nextRuns := e.nextRuns()
	onCurrentSince := e.onCurrentSince(currentHostname)

	// Same reason, and the same rule: transferView reads Gluetun's forwarded ports
	// out of the snapshot. Recomputing it here is what keeps the port-forwarding
	// verdict in step with Gluetun, whose port arrives on a different tick.
	var transfer *TransferStatus
	if e.qbittorrent != nil {
		view := e.transferView()
		transfer = &view
	}
	// Computed out here with the others, for the same reason. It happens to read only
	// configuration today, so calling it under the write lock is safe today - and it is one
	// natural edit away from reading the snapshot, which would deadlock the engine. The rule
	// is easier to keep than the exception, and TestNothingReadsTheSnapshotWhileWritingIt
	// keeps it.
	settings := e.settingsView()

	e.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Version = e.version
		snapshot.StartedAt = e.startedAt
		snapshot.Stats = e.stats
		snapshot.Latency = e.prober.Summarize()
		snapshot.Candidates = views
		snapshot.CandidatesTotal = len(ranked)
		snapshot.CandidatesBlocked = len(e.blocked)
		snapshot.History = reverseHistory(persisted.History)
		snapshot.Settings = settings
		snapshot.Servers.Path = e.cfg.Servers.FilePath
		snapshot.Servers.WriteMode = e.cfg.Servers.WriteMode
		snapshot.Servers.SchemaVersion = e.schemaVersion
		snapshot.Proton.LoggedIn = e.proton.LoggedIn()
		snapshot.Proton.Session = e.proton.SessionUID()
		snapshot.Proton.NeedsTOTP = e.manual != nil && e.manual.Waiting()
		snapshot.Gluetun.RequirementsAdopted = requirementLabels(e.requirements)
		snapshot.Gluetun.PortForwardRequirementFrom = e.portForwardReason
		snapshot.Gluetun.KnownHostnames = len(e.gluetunKnownHosts)
		if transfer != nil {
			snapshot.Transfer = *transfer
		}
		snapshot.Selection.AutoSwitch = e.autoSwitchEnabled()
		snapshot.Selection.Mode = e.cfg.Switch.Mode
		snapshot.Selection.Current = current
		snapshot.Selection.CurrentSource = currentSource
		snapshot.Selection.Best = best
		snapshot.Selection.Improvement = improvement
		snapshot.Selection.MinImprovement = e.cfg.Switch.MinImprovement
		snapshot.Selection.LastSwitchAt = persisted.LastSwitchAt
		snapshot.Selection.CooldownRemaining = formatDuration(e.cooldownRemaining())
		snapshot.Selection.OnCurrentSince = onCurrentSince

		snapshot.NextRuns = nextRuns
	})
}

// blockedViews renders the servers Gluetun's filters rule out.
//
// They are scored with the same weights as everything else - a blocked row is
// only useful if its load and latency are comparable with the rest of the table -
// but they carry no rank, because ranking implies selectability.
func (e *Engine) blockedViews(currentHostname string) (views []CandidateView) {
	if len(e.blocked) == 0 {
		return nil
	}

	scored := scoring.Rank(e.blocked, e.prober.Results(), e.cfg.Score)
	views = make([]CandidateView, 0, min(len(scored), maxBlockedViews))
	for i, entry := range scored {
		if i >= maxBlockedViews {
			break
		}
		view := toCandidateView(0, entry, entry.Candidate.Hostname == currentHostname)
		view.Blocked = true
		view.BlockedBy = e.requirements.Unmet(entry.Candidate)
		views = append(views, view)
	}
	return views
}

func (e *Engine) cooldownRemaining() time.Duration {
	return e.remainingSince(e.cfg.Switch.Cooldown)
}

// minIntervalRemaining is the hard floor between automatic switches. Unlike the
// cooldown, no trigger bypasses it: it is the guarantee that the tunnel - and
// every connection through it - cannot be torn down more often than this.
func (e *Engine) minIntervalRemaining() time.Duration {
	return e.remainingSince(e.cfg.Switch.MinInterval)
}

func (e *Engine) remainingSince(window time.Duration) time.Duration {
	last := e.state.snapshot().LastSwitchAt
	if last.IsZero() || window <= 0 {
		return 0
	}
	remaining := window - time.Since(last)
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (e *Engine) nextRuns() map[string]string {
	snapshot := e.Snapshot()
	runs := map[string]string{}
	add := func(name string, last time.Time, interval time.Duration) {
		if interval <= 0 {
			runs[name] = "disabled"
			return
		}
		if last.IsZero() {
			runs[name] = "pending"
			return
		}
		runs[name] = formatDuration(time.Until(last.Add(interval)))
	}
	add("server_list", snapshot.Proton.LastFetch, e.cfg.Proton.RefreshInterval)
	add("loads", snapshot.Proton.LastLoadRefresh, e.cfg.Proton.LoadRefreshInterval)
	add("latency", latencyLastRun(snapshot), e.latencyInterval())
	add("evaluation", snapshot.Selection.LastEvaluation, e.cfg.Switch.Interval)
	return runs
}

func latencyLastRun(snapshot Snapshot) time.Time {
	return snapshot.Latency.LastRun
}

func (e *Engine) settingsView() SettingsView {
	return SettingsView{
		Variables:           e.cfg.Variables,
		Countries:           e.cfg.Filter.Countries,
		ExcludeCountries:    e.cfg.Filter.ExcludeCountries,
		Cities:              e.cfg.Filter.Cities,
		MaxLoad:             e.cfg.Filter.MaxLoad,
		VPNType:             e.effectiveVPNTypeLabel(),
		SecureCore:          e.cfg.Filter.SecureCore,
		Tor:                 e.cfg.Filter.Tor,
		P2P:                 e.cfg.Filter.P2P,
		IPv6Filter:          e.cfg.Filter.IPv6,
		Stream:              e.cfg.Filter.Stream,
		FreeTier:            e.cfg.Filter.Free,
		LoadWeight:          e.cfg.Score.LoadWeight,
		LatencyWeight:       e.cfg.Score.LatencyWeight,
		ProtonWeight:        e.cfg.Score.ProtonScoreWeight,
		LatencyCeiling:      e.cfg.Score.LatencyCeiling.String(),
		RefreshInterval:     e.cfg.Proton.RefreshInterval.String(),
		LoadRefreshInterval: e.cfg.Proton.LoadRefreshInterval.String(),
		LatencyInterval:     formatInterval(e.latencyInterval()),
		EvaluationInterval:  e.cfg.Switch.Interval.String(),
		SwitchCooldown:      e.cfg.Switch.Cooldown.String(),
		SwitchMinInterval:   e.cfg.Switch.MinInterval.String(),
		LoadTrigger:         e.cfg.Switch.LoadTrigger,
		LatencyEnabled:      e.cfg.Latency.Enabled,
		LatencyTopN:         e.cfg.Latency.TopN,
	}
}

func (e *Engine) effectiveVPNTypeLabel() string {
	resolved := e.effectiveVPNType()
	if resolved == "" {
		return "auto (unknown)"
	}
	if e.cfg.Filter.VPNType == "auto" {
		return "auto (" + resolved + ")"
	}
	return resolved
}

func toCandidateView(rank int, scored scoring.Scored, isCurrent bool) CandidateView {
	candidate := scored.Candidate
	view := CandidateView{
		Rank:        rank,
		Hostname:    candidate.Hostname,
		ServerName:  candidate.ServerName,
		Country:     candidate.Country,
		City:        candidate.City,
		Region:      candidate.Region,
		LogicalID:   candidate.LogicalID,
		EntryIP:     candidate.EntryIP.String(),
		ProtonScore: round(candidate.ProtonScore, 4),
		Tier:        candidate.Tier,
		Load:        candidate.Load,
		RTTKnown:    scored.LatencyKnown,
		Score:       round(scored.Score, 4),
		LoadPart:    round(scored.LoadPenalty, 4),
		LatencyPart: round(scored.LatencyPenalty, 4),
		ProtonPart:  round(scored.ProtonPenalty, 4),
		SecureCore:  candidate.SecureCore,
		Tor:         candidate.Tor,
		P2P:         candidate.P2P,
		Stream:      candidate.Stream,
		IPv6:        candidate.IPv6,
		Free:        candidate.Free,
		Wireguard:   candidate.WgPubKey != "",
		IsCurrent:   isCurrent,
	}
	if candidate.ExitIP.IsValid() {
		view.ExitIP = candidate.ExitIP.String()
	}
	if candidate.EntryIPv6.IsValid() {
		view.EntryIPv6 = candidate.EntryIPv6.String()
	}
	if scored.LatencyKnown {
		view.RTTMS = round(float64(scored.RTT)/float64(time.Millisecond), 1)
	}
	return view
}

func rankOf(ranked []scoring.Scored, hostname string) int {
	for i, entry := range ranked {
		if entry.Candidate.Hostname == hostname {
			return i + 1
		}
	}
	return 0
}

func reverseHistory(history []SwitchRecord) (reversed []SwitchRecord) {
	reversed = make([]SwitchRecord, 0, len(history))
	for i := len(history) - 1; i >= 0; i-- {
		reversed = append(reversed, history[i])
	}
	return reversed
}

func round(value float64, decimals int) float64 {
	factor := 1.0
	for range decimals {
		factor *= 10
	}
	return float64(int64(value*factor+0.5)) / factor
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.Truncate(time.Second).String()
}

func formatInterval(d time.Duration) string {
	if d <= 0 {
		return "disabled"
	}
	return d.String()
}

// ticker wraps time.Ticker so a zero interval means "never fire" without the
// caller needing a nil check at every use.
type ticker struct {
	inner *time.Ticker
}

func newTicker(interval time.Duration) *ticker {
	if interval <= 0 {
		return &ticker{}
	}
	return &ticker{inner: time.NewTicker(interval)}
}

func (t *ticker) C() <-chan time.Time {
	if t.inner == nil {
		return nil // a nil channel blocks forever, which is exactly right
	}
	return t.inner.C
}

func (t *ticker) Stop() {
	if t.inner != nil {
		t.inner.Stop()
	}
}

// subscriberSet is a tiny fan-out for snapshot changes.
type subscriberSet struct {
	mu   sync.Mutex
	next int
	subs map[int]chan struct{}
}

func newSubscriberSet() *subscriberSet {
	return &subscriberSet{subs: make(map[int]chan struct{})}
}

func (s *subscriberSet) add() (updates <-chan struct{}, cancel func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.next
	s.next++
	// Buffered by one: a subscriber that is mid-render still learns that
	// something changed, and notify never blocks the run loop.
	channel := make(chan struct{}, 1)
	s.subs[id] = channel

	return channel, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if existing, ok := s.subs[id]; ok {
			delete(s.subs, id)
			close(existing)
		}
	}
}

func (s *subscriberSet) notify() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, channel := range s.subs {
		select {
		case channel <- struct{}{}:
		default: // already pending
		}
	}
}

// requirementLabels names the adopted requirements for display.
func requirementLabels(requirements catalog.Requirements) (labels []string) {
	for _, pair := range []struct {
		name     string
		required bool
	}{
		{"port_forward_only", requirements.PortForward},
		{"secure_core_only", requirements.SecureCore},
		{"tor_only", requirements.Tor},
		{"stream_only", requirements.Stream},
		{"free_only", requirements.Free},
		{"premium_only", requirements.Premium},
	} {
		if pair.required {
			labels = append(labels, pair.name)
		}
	}
	return labels
}

// errorText renders an error for the snapshot, where the zero value must be an
// empty string rather than "<nil>".
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
