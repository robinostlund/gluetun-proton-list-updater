package engine

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/atomicfile"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
)

// State file names inside the state directory.
const (
	stateFileName    = "state.json"
	sessionFileName  = "session.json"
	logicalsFileName = "logicals.json"
	loadsFileName    = "loads.json"
)

// maxHistory bounds the persisted switch history. Every file in the state
// directory is replaced in full rather than appended to, so this count cap is all
// that is needed to keep the state bounded.
const maxHistory = 100

// maxServerStats bounds how many servers keep statistics.
//
// One fixed-size record per server rather than a series of readings, which is what makes
// this affordable for every candidate instead of a chosen few: a record is a couple of
// hundred bytes and does not grow with time, so 600 of them is well under a megabyte and
// covers a filtered candidate set several times over.
//
// The transferred totals in a record are meant to last for the life of the server, so
// this cap is a backstop against a deployment left to wander across every server Proton
// offers - not a retention policy. The normal way a record goes away is Proton retiring
// the server. Least recently seen goes first, and it is logged, because a total
// disappearing is exactly the kind of silent loss these figures must not suffer.
const maxServerStats = 600

// SwitchRecord is one entry of the switch history shown on the dashboard.
type SwitchRecord struct {
	At   time.Time `json:"at"`
	From string    `json:"from,omitempty"`
	To   string    `json:"to"`
	// Reason explains what triggered the switch, e.g. "better score" or
	// "manual".
	Reason      string  `json:"reason"`
	ScoreBefore float64 `json:"score_before"`
	ScoreAfter  float64 `json:"score_after"`
	LoadBefore  uint8   `json:"load_before"`
	LoadAfter   uint8   `json:"load_after"`
	RTTAfterMS  int64   `json:"rtt_after_ms,omitempty"`
	Country     string  `json:"country,omitempty"`
	City        string  `json:"city,omitempty"`
	Succeeded   bool    `json:"succeeded"`
	Error       string  `json:"error,omitempty"`
	// PublicIP is the exit address observed after the switch, which is the
	// proof that the tunnel really moved.
	PublicIP string `json:"public_ip,omitempty"`
}

// ServerStats is what has been observed about one server, reduced to figures that do not
// grow with time.
//
// Deliberately not a history. A series of readings per server buys graphs at the cost of a
// state file that grows with every server and every hour; these dozen numbers answer the
// questions the graphs were actually being read for - is this server reliably quiet, has
// it ever been slow, how much have I pulled through it - in a fixed two hundred bytes.
//
// "Lowest" and "highest" rather than "best" and "worst", because reading those requires
// knowing which direction is good. For load and latency lowest is best; the dashboard
// says so, the field names do not have to imply it.
type ServerStats struct {
	// Load, as Proton reports it: 0-100.
	LoadLast    uint8 `json:"load,omitempty"`
	LoadLowest  uint8 `json:"load_lowest,omitempty"`
	LoadHighest uint8 `json:"load_highest,omitempty"`
	// Latency in whole milliseconds. Zero means never measured - the prober only covers
	// LATENCY_TOP_N servers, so that is a normal state, not an error. Whole milliseconds
	// because nothing here is decided on fractions of one.
	RTTLastMS    uint16 `json:"rtt_ms,omitempty"`
	RTTLowestMS  uint16 `json:"rtt_lowest_ms,omitempty"`
	RTTHighestMS uint16 `json:"rtt_highest_ms,omitempty"`
	// DownloadedBytes and UploadedBytes are every byte ever moved through this server.
	//
	// Never reset - not by a reconnect, not by returning after a month away. A rate is a
	// snapshot, but a volume is a fact that only accumulates, and the only thing that
	// removes one is Proton retiring the server. Requires the qBittorrent integration;
	// zero without it.
	DownloadedBytes uint64 `json:"downloaded,omitempty"`
	UploadedBytes   uint64 `json:"uploaded,omitempty"`
	// MaxDownloadRate and MaxUploadRate are the fastest this server was seen to go during
	// the current stay on it - or during the most recent one, for a server not in use.
	//
	// Not all-time, unlike the volumes above, because a rate is a claim about conditions
	// rather than a count: a server that managed 14 MB/s two months ago says nothing about
	// what it will do tonight, and quoting it invites exactly the wrong comparison.
	//
	// The replacement is lazy, which is the part that matters. Arriving on a server does not
	// clear these; the *first reading with traffic in it* replaces them, and readings after
	// that raise them. So the previous stay's figure stays visible until there is a real
	// measurement to put in its place, instead of the card going blank the moment you
	// reconnect and staying blank until you happen to start a download.
	MaxDownloadRate uint64 `json:"max_download,omitempty"`
	MaxUploadRate   uint64 `json:"max_upload,omitempty"`
	// Samples counts load and latency observations, TransferReadings counts qBittorrent
	// polls attributed to this server. Two counters because the two are collected on
	// different cycles from different sources, and a single number would misrepresent how
	// much evidence is behind either set of figures.
	Samples          int `json:"samples,omitempty"`
	TransferReadings int `json:"transfer_readings,omitempty"`
	// Visits counts the stays on this server, so "first time here" and "the tenth time"
	// can be told apart.
	Visits int `json:"visits,omitempty"`
	// The three timestamps are unix seconds rather than time.Time, which serialises as
	// RFC 3339.
	//
	// Not a micro-optimisation: three RFC 3339 timestamps and their key names are over
	// half of a record, and there is one record per server. Second resolution is more than
	// enough for figures whose fastest source is a fifteen-second poll, and nothing reads
	// this file but the program that wrote it.
	FirstSeenUnix int64 `json:"first_seen,omitempty"`
	LastSeenUnix  int64 `json:"last_seen,omitempty"`
	// LastTransferUnix is when the totals last increased, which is a different age from
	// LastSeenUnix: a server can be sampled for load long after it last carried traffic.
	LastTransferUnix int64 `json:"last_transfer,omitempty"`
}

// FirstSeen, LastSeen and LastTransferAt present the stored unix seconds as times. Zero
// stays zero, so "never" survives the conversion rather than becoming 1970.
func (s ServerStats) FirstSeen() time.Time      { return unixOrZero(s.FirstSeenUnix) }
func (s ServerStats) LastSeen() time.Time       { return unixOrZero(s.LastSeenUnix) }
func (s ServerStats) LastTransferAt() time.Time { return unixOrZero(s.LastTransferUnix) }

func unixOrZero(seconds int64) time.Time {
	if seconds == 0 {
		return time.Time{}
	}
	return time.Unix(seconds, 0)
}

// observeLoad folds a load reading in, maintaining the extremes.
func (s *ServerStats) observeLoad(load uint8, at time.Time) {
	s.LoadLast = load
	if s.LoadLowest == 0 || load < s.LoadLowest {
		s.LoadLowest = load
	}
	if load > s.LoadHighest {
		s.LoadHighest = load
	}
	s.Samples++
	if s.FirstSeenUnix == 0 {
		s.FirstSeenUnix = at.Unix()
	}
	s.LastSeenUnix = at.Unix()
}

// observeRTT folds a latency measurement in. A zero is "not measured" rather than "very
// fast", so it is ignored entirely.
func (s *ServerStats) observeRTT(milliseconds uint16) {
	if milliseconds == 0 {
		return
	}
	s.RTTLastMS = milliseconds
	if s.RTTLowestMS == 0 || milliseconds < s.RTTLowestMS {
		s.RTTLowestMS = milliseconds
	}
	if milliseconds > s.RTTHighestMS {
		s.RTTHighestMS = milliseconds
	}
}

// measured reports whether anything at all has been observed about this server.
func (s ServerStats) measured() bool {
	return s.Samples > 0 || s.TransferReadings > 0 ||
		s.DownloadedBytes > 0 || s.UploadedBytes > 0
}

// persistedState is what survives a restart.
type persistedState struct {
	// PinnedHostname is the server this tool last asked Gluetun to use. On
	// startup it is what lets the tool recognise that the tunnel is already
	// where it wants it, instead of reconnecting for no reason.
	PinnedHostname string    `json:"pinned_hostname,omitempty"`
	LastSwitchAt   time.Time `json:"last_switch_at"`
	AutoSwitch     *bool     `json:"auto_switch,omitempty"`
	// AccountTier is the Proton account's highest usable server tier, remembered so
	// a restart while Proton is unreachable still avoids servers the account cannot
	// connect to.
	AccountTier *uint8 `json:"account_tier,omitempty"`
	AccountPlan string `json:"account_plan,omitempty"`
	// GluetunHadServerData records that Gluetun's own server data was seen at
	// least once. It only ever goes from false to true: once Gluetun has proven it
	// keeps server data on disk, a later absence is far more likely to be a
	// transient read than a configuration change, and warning on it would be
	// noise.
	GluetunHadServerData bool           `json:"gluetun_had_server_data,omitempty"`
	History              []SwitchRecord `json:"history,omitempty"`
	// MeasuringHost is the server the transfer measurement currently belongs to.
	//
	// Persisted because a stay is defined by where the tunnel is, not by whether this
	// process has been running the whole time. Held only in memory, every restart would
	// look like a fresh arrival and discard the stay's measured rates.
	MeasuringHost string `json:"measuring_host,omitempty"`
	// Stats is what has been observed about each server, keyed by hostname.
	//
	// One record per server, fixed size. Load, latency and Proton's own score describe a
	// server before it is used and are replaced wholesale on every refresh; these figures
	// accumulate from observation and survive restarts, which makes them the only record
	// of how a server has actually behaved.
	Stats map[string]ServerStats `json:"stats,omitempty"`
}

// stateStore persists engine state atomically.
type stateStore struct {
	path string

	mu    sync.RWMutex
	state persistedState
	// dirty marks changes that are in memory but not yet on disk, made through mutate.
	// flush is what settles them.
	dirty bool
}

func newStateStore(directory string) *stateStore {
	return &stateStore{path: filepath.Join(directory, stateFileName)}
}

// load reads the state file. A missing file is not an error: it is the normal
// first run.
func (s *stateStore) load() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var state persistedState
	found, err := atomicfile.ReadJSON(s.path, &state)
	if err != nil {
		return err
	}
	if found {
		s.state = state
	}
	return nil
}

func (s *stateStore) snapshot() persistedState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// mutate applies a change in memory without writing the file.
//
// For changes that arrive far more often than they matter. The statistics are updated on
// every qBittorrent poll - every fifteen seconds by default - and the state file is
// rewritten in full, so persisting each one meant hundreds of kilobytes of writes a
// minute, indefinitely, on hardware that may well be an SD card. The next update() from
// any other path flushes it, and the loads refresh guarantees one every
// PROTON_LOAD_REFRESH_INTERVAL.
//
// The cost is bounded and worth naming: an unclean shutdown loses whatever arrived since
// the last write. For a peak rate and a byte count, that is the right trade.
func (s *stateStore) mutate(change func(state *persistedState)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	change(&s.state)
	s.trim()
	s.dirty = true
}

// flush writes the state if anything is waiting in memory, and reports whether it did.
//
// The counterpart to mutate, and the reason the deferred write is bounded rather than
// open-ended. Called on a short timer and again on shutdown: without the second, a restart
// inside the timer window lost every byte counted since the last write, which read as the
// figures not surviving a restart at all.
func (s *stateStore) flush() (written bool, err error) {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return false, nil
	}
	state := s.state
	s.dirty = false
	s.mu.Unlock()

	if err := atomicfile.WriteJSON(s.path, state, 0o600); err != nil {
		// Left dirty so the next flush tries again rather than dropping the change.
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return false, fmt.Errorf("saving state: %w", err)
	}
	return true, nil
}

// trim enforces every cap. Called from both mutation paths, so a change that only lives in
// memory for a while cannot grow past its bound in the meantime.
//
// The caller holds the lock.
func (s *stateStore) trim() {
	if len(s.state.History) > maxHistory {
		s.state.History = s.state.History[len(s.state.History)-maxHistory:]
	}
	pruneStats(s.state.Stats)
}

// update applies mutate to the state and writes it out. The write error is
// returned but callers generally only log it: losing history is not a reason to
// stop managing the tunnel.
func (s *stateStore) update(mutate func(state *persistedState)) (err error) {
	s.mu.Lock()
	mutate(&s.state)
	s.trim()
	state := s.state
	// This writes everything, including whatever mutate left pending.
	s.dirty = false
	s.mu.Unlock()

	if err := atomicfile.WriteJSON(s.path, state, 0o600); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return fmt.Errorf("saving state: %w", err)
	}
	return nil
}

// cachedLogicals is the on-disk copy of Proton's server list. It exists so the
// tool starts up useful even when Proton is unreachable, which is the most
// likely external failure.
type cachedLogicals struct {
	FetchedAt    time.Time              `json:"fetched_at"`
	LastModified time.Time              `json:"last_modified"`
	Servers      []proton.LogicalServer `json:"servers"`
}

type logicalsCache struct {
	path string
	mu   sync.Mutex
}

// cachedLoads is the on-disk copy of Proton's utilisation figures.
//
// It is deliberately separate from the server list. The list is several megabytes
// and changes twice a day; the loads are a few kilobytes and change every few
// minutes. Keeping them apart means a restart during a Proton outage resumes with
// utilisation figures minutes old rather than hours old - which matters for a tool
// whose entire purpose is picking the least utilised server.
type cachedLoads struct {
	UpdatedAt time.Time           `json:"updated_at"`
	Loads     []proton.ServerLoad `json:"loads"`
}

type loadsCache struct {
	path string
	mu   sync.Mutex
}

func newLoadsCache(directory string) *loadsCache {
	return &loadsCache{path: filepath.Join(directory, loadsFileName)}
}

func (c *loadsCache) load() (cached cachedLoads, found bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	found, err = atomicfile.ReadJSON(c.path, &cached)
	if err != nil {
		return cachedLoads{}, false, err
	}
	if !found || len(cached.Loads) == 0 {
		return cachedLoads{}, false, nil
	}
	return cached, true, nil
}

func (c *loadsCache) save(cached cachedLoads) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return atomicfile.WriteJSON(c.path, cached, 0o600)
}

func newLogicalsCache(directory string) *logicalsCache {
	return &logicalsCache{path: filepath.Join(directory, logicalsFileName)}
}

func (c *logicalsCache) load() (cached cachedLogicals, found bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	found, err = atomicfile.ReadJSON(c.path, &cached)
	if err != nil {
		return cachedLogicals{}, false, err
	}
	if !found || len(cached.Servers) == 0 {
		return cachedLogicals{}, false, nil
	}
	return cached, true, nil
}

func (c *logicalsCache) save(cached cachedLogicals) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return atomicfile.WriteJSON(c.path, cached, 0o600)
}
