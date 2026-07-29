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
}

// stateStore persists engine state atomically.
type stateStore struct {
	path string

	mu    sync.RWMutex
	state persistedState
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

// update applies mutate to the state and writes it out. The write error is
// returned but callers generally only log it: losing history is not a reason to
// stop managing the tunnel.
func (s *stateStore) update(mutate func(state *persistedState)) (err error) {
	s.mu.Lock()
	mutate(&s.state)
	if len(s.state.History) > maxHistory {
		s.state.History = s.state.History[len(s.state.History)-maxHistory:]
	}
	state := s.state
	s.mu.Unlock()

	if err := atomicfile.WriteJSON(s.path, state, 0o600); err != nil {
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
