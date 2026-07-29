package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/catalog"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/gluetunapi"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/scoring"
)

// fakeGluetun is a stand-in for Gluetun's control server. It tracks the pinned
// hostname and reports the matching exit IP afterwards, which is what the engine
// uses to verify that a switch really happened.
type fakeGluetun struct {
	mu sync.Mutex
	// exitIPByHostname lets the fake behave like a real reconnect.
	exitIPByHostname map[string]string
	publicIP         string
	pinned           []string
	status           string
	rejectHostnames  bool
	// updaterCalls counts PUT /v1/updater/status requests. Triggering Gluetun's
	// own updater is the only in-place way to make it aware of new servers.
	updaterCalls int
	// acceptAfterUpdate mimics Gluetun learning the hostnames once its updater
	// has run.
	acceptAfterUpdate bool
	// statusPuts records PUT /v1/vpn/status bodies in order, so the stop-then-
	// start sequence of a plain reconnect can be asserted.
	statusPuts []string
	// settingsDelay makes PUT /v1/vpn/settings answer slowly while still applying
	// the change, which is how a real Gluetun behaves while its VPN loop restarts.
	settingsDelay time.Duration
}

func newFakeGluetun(publicIP string, exitIPs map[string]string) *fakeGluetun {
	return &fakeGluetun{
		exitIPByHostname: exitIPs,
		publicIP:         publicIP,
		status:           gluetunapi.StatusRunning,
	}
}

func (f *fakeGluetun) pinnedHostnames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.pinned...)
}

func (f *fakeGluetun) statusWrites() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.statusPuts...)
}

func (f *fakeGluetun) updaterTriggered() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updaterCalls
}

func (f *fakeGluetun) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/vpn/status", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"status": f.status})
	})
	mux.HandleFunc("PUT /v1/vpn/status", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.mu.Lock()
		f.statusPuts = append(f.statusPuts, body.Status)
		f.status = body.Status
		if body.Status == gluetunapi.StatusRunning {
			// A plain reconnect lets Gluetun pick the server, so the exit address
			// changes to something we did not choose.
			f.publicIP = "81.0.0.9"
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"outcome": body.Status})
	})
	mux.HandleFunc("GET /v1/vpn/settings", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"type":"wireguard","provider":{"name":"protonvpn","server_selection":{"vpn":"wireguard"}}}`)
	})
	mux.HandleFunc("PUT /v1/vpn/settings", func(w http.ResponseWriter, r *http.Request) {
		var patch gluetunapi.Settings
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		hostnames := patch.PinnedHostnames()
		if len(hostnames) != 1 {
			http.Error(w, "expected exactly one hostname", http.StatusBadRequest)
			return
		}

		f.mu.Lock()
		delay := f.settingsDelay
		f.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}

		f.mu.Lock()
		defer f.mu.Unlock()
		if f.rejectHostnames {
			// This is how Gluetun answers for a hostname missing from the list
			// it loaded at startup.
			http.Error(w, "no server found for hostname", http.StatusBadRequest)
			return
		}
		f.pinned = append(f.pinned, hostnames[0])
		if ip, ok := f.exitIPByHostname[hostnames[0]]; ok {
			f.publicIP = ip
		}
		_, _ = io.WriteString(w, "VPN settings updated")
	})
	mux.HandleFunc("GET /v1/publicip/ip", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{
			"public_ip": f.publicIP, "country": "Sweden", "city": "Stockholm",
		})
	})
	mux.HandleFunc("GET /v1/portforward", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"port":51820}`)
	})
	mux.HandleFunc("GET /v1/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"version":"v3.41.1"}`)
	})
	mux.HandleFunc("GET /v1/updater/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"stopped"}`)
	})
	mux.HandleFunc("PUT /v1/updater/status", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.updaterCalls++
		if f.acceptAfterUpdate {
			f.rejectHostnames = false
		}
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"outcome":"running"}`)
	})
	return mux
}

// protonServer serves a logicals response describing three Swedish servers with
// different loads.
func protonServer(t *testing.T, failing bool) *httptest.Server {
	t.Helper()

	body := `{"Code":1000,"LogicalServers":[
	  {"ID":"l1","Name":"SE#1","ExitCountry":"SE","City":"Stockholm","Load":80,"Score":2.0,"Status":1,"Tier":2,"Features":4,
	   "Servers":[{"ID":"p1","EntryIP":"10.1.0.1","ExitIP":"81.0.0.1","Domain":"se-01.protonvpn.net","Status":1,"X25519PublicKey":"k1"}]},
	  {"ID":"l2","Name":"SE#2","ExitCountry":"SE","City":"Stockholm","Load":5,"Score":1.0,"Status":1,"Tier":2,"Features":4,
	   "Servers":[{"ID":"p2","EntryIP":"10.1.0.2","ExitIP":"81.0.0.2","Domain":"se-02.protonvpn.net","Status":1,"X25519PublicKey":"k2"}]},
	  {"ID":"l3","Name":"NO#1","ExitCountry":"NO","City":"Oslo","Load":1,"Score":1.0,"Status":1,"Tier":2,"Features":4,
	   "Servers":[{"ID":"p3","EntryIP":"10.1.0.3","ExitIP":"81.0.0.3","Domain":"no-01.protonvpn.net","Status":1,"X25519PublicKey":"k3"}]}
	]}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			http.Error(w, `{"Code":503,"Error":"Unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/vpn/v1/logicals":
			_, _ = io.WriteString(w, body)
		case "/vpn/v1/loads":
			_, _ = io.WriteString(w, `{"Code":1000,"LogicalServers":[
			  {"ID":"l1","Load":80,"Score":2.0,"Status":1},
			  {"ID":"l2","Load":5,"Score":1.0,"Status":1},
			  {"ID":"l3","Load":1,"Score":1.0,"Status":1}]}`)
		default:
			t.Errorf("unexpected proton request %s", r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// seedSession writes a valid Proton session so tests skip the SRP handshake.
func seedSession(t *testing.T, stateDir string) {
	t.Helper()
	session := proton.Session{
		UID: "uid-test", AccessToken: "access", RefreshToken: "refresh",
		Scopes: []string{"self", "vpn"}, CreatedAt: time.Now(),
	}
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SessionPath(stateDir), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

type harness struct {
	engine   *Engine
	gluetun  *fakeGluetun
	stateDir string
	filePath string
}

func newHarness(t *testing.T, protonFailing bool, mutate func(cfg *config.Config)) *harness {
	t.Helper()

	stateDir := t.TempDir()
	seedSession(t, stateDir)

	gluetunDir := t.TempDir()
	filePath := filepath.Join(gluetunDir, "servers.json")
	serversDir := filepath.Join(gluetunDir, "servers")

	// A real Gluetun writes its own server data on startup, covering every
	// provider it knows. Modelling that matters: its absence is how the engine
	// detects a Gluetun that keeps no server data on disk, and a fake that never
	// writes anything would make every test look like that case.
	if err := os.WriteFile(filePath,
		[]byte(`{"version":1,"mullvad":{"version":9,"timestamp":1,"servers":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := newFakeGluetun("81.0.0.1", map[string]string{
		"se-01.protonvpn.net": "81.0.0.1",
		"se-02.protonvpn.net": "81.0.0.2",
		"no-01.protonvpn.net": "81.0.0.3",
	})
	gluetunServer := httptest.NewServer(fake.handler())
	t.Cleanup(gluetunServer.Close)

	protonAPI := protonServer(t, protonFailing)

	cfg := config.Config{
		StateDir: stateDir,
		Proton: config.Proton{
			Username: "user@example.com", Password: "secret",
			APIBaseURL: protonAPI.URL, AppVersion: "test", UserAgent: "test",
			RefreshInterval: time.Hour, LoadRefreshInterval: time.Hour,
			RequestTimeout: 5 * time.Second,
		},
		Gluetun: config.Gluetun{
			BaseURL: gluetunServer.URL, RequestTimeout: 5 * time.Second,
			HealthInterval: time.Hour, UpdaterTimeout: 20 * time.Second,
			MutationTimeout: 30 * time.Second,
		},
		Servers: config.Servers{
			FilePath: filePath, DirPath: serversDir,
			WriteMode: config.WriteModeUpdate, Preferred: true,
		},
		Filter: config.Filter{
			Countries: []string{"Sweden"}, MaxLoad: 90, VPNType: "auto",
			SecureCore: config.FilterExclude, Tor: config.FilterExclude,
			P2P: config.FilterInclude, Stream: config.FilterInclude, Free: config.FilterExclude,
		},
		Score: config.Score{
			LoadWeight: 1, LatencyWeight: 0, LatencyCeiling: 100 * time.Millisecond,
		},
		// Latency probing is off: the entry IPs are unroutable documentation
		// addresses, and the test is about selection, not measurement.
		Latency: config.Latency{Enabled: false},
		Switch: config.Switch{
			Auto: true, Mode: config.ReconnectSettings, MinImprovement: 0.05,
			Interval: time.Hour, VerifyTimeout: 20 * time.Second, Candidates: 3,
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}

	protonClient, err := proton.New(proton.Options{
		BaseURL: cfg.Proton.APIBaseURL, AppVersion: "test", UserAgent: "test",
		Username: cfg.Proton.Username, Password: cfg.Proton.Password,
		SessionStore: proton.NewFileSessionStore(SessionPath(stateDir)),
		Logger:       quietLogger(),
		HTTPClient:   protonAPI.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}

	core, err := New(Options{
		Config: cfg, Logger: quietLogger(), Version: "test",
		Proton: protonClient,
		// Real timeouts rather than an injected client, so tests can exercise a
		// state change that does not answer in time.
		Gluetun: gluetunapi.New(gluetunapi.Options{
			BaseURL:         cfg.Gluetun.BaseURL,
			Timeout:         cfg.Gluetun.RequestTimeout,
			MutationTimeout: cfg.Gluetun.MutationTimeout,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	return &harness{engine: core, gluetun: fake, stateDir: stateDir, filePath: filePath}
}

// run starts the engine and returns once it has finished its startup work.
func (h *harness) run(t *testing.T, wait func() bool) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := h.engine.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	deadline := time.Now().Add(25 * time.Second)
	for !wait() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	satisfied := wait()

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("engine did not stop within 10s of cancellation")
	}

	if !satisfied {
		t.Fatalf("condition was never satisfied; snapshot: %+v", h.engine.Snapshot().Selection)
	}
}

// The whole point of the tool: identify the busy server the tunnel is on, and
// move it to the least utilised allowed one.
func TestEngineSwitchesToTheLeastUtilisedServer(t *testing.T) {
	harness := newHarness(t, false, nil)

	// Wait for the switch to be verified, not merely requested: verification
	// polls Gluetun for a few seconds after the request.
	harness.run(t, func() bool {
		history := harness.engine.Snapshot().History
		return len(history) > 0 && history[0].Succeeded
	})

	pinned := harness.gluetun.pinnedHostnames()
	// SE#2 has 5% load against SE#1's 80%; NO#1 is excluded by COUNTRIES.
	if pinned[0] != "se-02.protonvpn.net" {
		t.Errorf("pinned %v, want se-02.protonvpn.net first", pinned)
	}

	snapshot := harness.engine.Snapshot()
	if snapshot.Selection.Current == nil || snapshot.Selection.Current.Hostname != "se-02.protonvpn.net" {
		t.Errorf("current server = %+v, want se-02", snapshot.Selection.Current)
	}
	if snapshot.Selection.CurrentSource != "public-ip" {
		t.Errorf("CurrentSource = %q, want public-ip", snapshot.Selection.CurrentSource)
	}

	history := snapshot.History
	if len(history) == 0 || !history[0].Succeeded {
		t.Fatalf("expected a successful switch in the history, got %+v", history)
	}
	if history[0].To != "se-02.protonvpn.net" || history[0].From != "se-01.protonvpn.net" {
		t.Errorf("history entry = %+v", history[0])
	}
}

func TestEngineWritesServersFile(t *testing.T) {
	harness := newHarness(t, false, nil)

	harness.run(t, func() bool {
		return !harness.engine.Snapshot().Servers.LastWrite.IsZero()
	})

	var file struct {
		Version   uint16 `json:"version"`
		Protonvpn struct {
			Version   uint16 `json:"version"`
			Timestamp int64  `json:"timestamp"`
			Servers   []struct {
				VPN      string `json:"vpn"`
				Country  string `json:"country"`
				Hostname string `json:"hostname"`
			} `json:"servers"`
		} `json:"protonvpn"`
	}
	data, err := os.ReadFile(harness.filePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decoding servers file: %v\n%s", err, data)
	}

	if file.Protonvpn.Version != config.DefaultSchemaVersion {
		t.Errorf("schema version = %d, want the default %d",
			file.Protonvpn.Version, config.DefaultSchemaVersion)
	}
	// Gluetun merges by recency, so the timestamp has to be current.
	if age := time.Since(time.Unix(file.Protonvpn.Timestamp, 0)); age > time.Minute {
		t.Errorf("timestamp is %s old, Gluetun would prefer its built-in list", age)
	}
	if len(file.Protonvpn.Servers) == 0 {
		t.Fatal("no servers were written")
	}

	// The file carries every country by default, even ones the selector will not
	// choose, so a manual override or a Gluetun restart with different
	// SERVER_COUNTRIES still has servers to work with.
	countries := map[string]bool{}
	for _, server := range file.Protonvpn.Servers {
		countries[server.Country] = true
	}
	if !countries["Sweden"] || !countries["Norway"] {
		t.Errorf("countries written = %v, want both Sweden and Norway", countries)
	}
}

// With SERVERS_ONLY_ALLOWED_COUNTRIES the file is narrowed to the allow-list.
func TestEngineWritesOnlyAllowedCountriesWhenAsked(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Servers.OnlyAllowedCountries = true
	})

	harness.run(t, func() bool {
		return !harness.engine.Snapshot().Servers.LastWrite.IsZero()
	})

	var file struct {
		Protonvpn struct {
			Servers []struct {
				Country string `json:"country"`
			} `json:"servers"`
		} `json:"protonvpn"`
	}
	data, err := os.ReadFile(harness.filePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}

	if len(file.Protonvpn.Servers) == 0 {
		t.Fatal("no servers were written")
	}
	for _, server := range file.Protonvpn.Servers {
		if server.Country != "Sweden" {
			t.Errorf("unexpected country %q: only allowed countries were requested", server.Country)
		}
	}
}

// A tunnel sitting on a server the filters exclude must be reported, not hidden
// behind "unknown": that is precisely the state the operator needs to see.
func TestEngineReportsCurrentServerOutsideTheAllowedSet(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		// Only Norway is allowed, but the tunnel starts on the Swedish SE#1.
		cfg.Filter.Countries = []string{"Norway"}
	})

	harness.run(t, func() bool {
		snapshot := harness.engine.Snapshot()
		return snapshot.History != nil && len(snapshot.History) > 0
	})

	history := harness.engine.Snapshot().History
	if history[0].From != "se-01.protonvpn.net" {
		t.Errorf("switch came from %q, want the excluded se-01", history[0].From)
	}
	if history[0].To != "no-01.protonvpn.net" {
		t.Errorf("switched to %q, want the only allowed server", history[0].To)
	}
}

// The schema version must follow whatever Gluetun wrote, because it changes
// between Gluetun releases and a mismatch makes Gluetun discard our file.
func TestEngineDetectsSchemaVersionFromExistingFile(t *testing.T) {
	harness := newHarness(t, false, nil)

	existing := `{"version":1,"protonvpn":{"version":9,"timestamp":1,"servers":[]}}`
	if err := os.WriteFile(harness.filePath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	harness.run(t, func() bool {
		return harness.engine.Snapshot().Servers.LastWrite.IsZero() == false
	})

	if got := harness.engine.Snapshot().Servers.SchemaVersion; got != 9 {
		t.Errorf("schema version = %d, want 9 as read from the existing file", got)
	}
}

// Proton being unreachable must not stop the tool: it should fall back to the
// cached list and keep managing the tunnel.
func TestEngineUsesCachedListWhenProtonFails(t *testing.T) {
	// First run populates the cache.
	warm := newHarness(t, false, nil)
	warm.run(t, func() bool { return warm.engine.Snapshot().CandidatesTotal > 0 })

	cachePath := filepath.Join(warm.stateDir, logicalsFileName)
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected a cached server list at %s: %v", cachePath, err)
	}

	// Second run reuses the same state directory against a failing API.
	cold := newHarness(t, true, nil)
	if err := os.Rename(cachePath, filepath.Join(cold.stateDir, logicalsFileName)); err != nil {
		t.Fatal(err)
	}

	cold.run(t, func() bool { return cold.engine.Snapshot().CandidatesTotal > 0 })

	snapshot := cold.engine.Snapshot()
	if !snapshot.Proton.FromCache {
		t.Error("FromCache should be set when the list came from disk")
	}
	if snapshot.Proton.LastFetchError == "" {
		t.Error("the fetch failure should be recorded for the dashboard")
	}
	if healthy, _ := cold.engine.Healthy(); !healthy {
		t.Error("a Proton outage must not make the tool unhealthy: it can still work from cache")
	}
}

// When Gluetun refuses every hostname it is running an older list, and the
// operator needs to be told to restart it rather than left guessing.
func TestEngineFlagsGluetunRestartWhenEveryHostnameIsRejected(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.rejectHostnames = true

	harness.run(t, func() bool {
		return harness.engine.Snapshot().Selection.NeedsGluetunRestart
	})

	snapshot := harness.engine.Snapshot()
	if !snapshot.Selection.NeedsGluetunRestart {
		t.Fatal("NeedsGluetunRestart should be set")
	}
	if snapshot.Selection.LastError == "" {
		t.Error("an explanatory error should be published")
	}
}

// RECONNECT_MODE=status must issue a stop followed by a start, which is the
// fallback for a Gluetun whose control server does not allow PUT /v1/vpn/settings.
func TestEngineReconnectStatusModeStopsThenStarts(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.Mode = config.ReconnectStatus
	})

	harness.run(t, func() bool {
		return len(harness.gluetun.statusWrites()) >= 2
	})

	writes := harness.gluetun.statusWrites()
	if writes[0] != gluetunapi.StatusStopped || writes[1] != gluetunapi.StatusRunning {
		t.Errorf("status writes = %v, want [stopped running]", writes)
	}
	// Gluetun chooses the server itself in this mode, so no hostname is pinned
	// and nothing may be remembered as if it had been.
	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) != 0 {
		t.Errorf("status mode must not pin a hostname, got %v", pinned)
	}
	if hostname := harness.engine.state.snapshot().PinnedHostname; hostname != "" {
		t.Errorf("persisted pinned hostname = %q, want empty in status mode", hostname)
	}
}

// When Gluetun does not know a hostname, the tool should ask Gluetun to refresh
// its own server list and try again - that is the only in-place remedy, since
// Gluetun reads servers.json solely at startup.
func TestEngineAsksGluetunToRefreshItsServerList(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Gluetun.RefreshServersOnReject = true
	})
	harness.gluetun.rejectHostnames = true
	harness.gluetun.acceptAfterUpdate = true

	harness.run(t, func() bool {
		history := harness.engine.Snapshot().History
		return len(history) > 0 && history[0].Succeeded
	})

	if calls := harness.gluetun.updaterTriggered(); calls == 0 {
		t.Fatal("gluetun's own updater was never triggered")
	}
	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) == 0 {
		t.Fatal("the retry after the refresh should have pinned a hostname")
	}
	// Having recovered, the tool must not still be telling the operator to
	// restart Gluetun.
	if harness.engine.Snapshot().Selection.NeedsGluetunRestart {
		t.Error("NeedsGluetunRestart should be cleared after a successful retry")
	}
}

// With the refresh disabled, a rejection goes straight to the restart banner.
func TestEngineSkipsRefreshWhenDisabled(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Gluetun.RefreshServersOnReject = false
	})
	harness.gluetun.rejectHostnames = true

	harness.run(t, func() bool {
		return harness.engine.Snapshot().Selection.NeedsGluetunRestart
	})

	if calls := harness.gluetun.updaterTriggered(); calls != 0 {
		t.Errorf("updater was triggered %d times despite being disabled", calls)
	}
}

// The hard floor is what guarantees the tunnel cannot be torn down repeatedly.
// Not even an overloaded current server may bypass it.
func TestEngineMinIntervalBlocksEvenAnOverloadedServer(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.LoadTrigger = 50 // SE#1 is at 80%, so the trigger would fire
		cfg.Switch.MinInterval = time.Hour
		cfg.Switch.Cooldown = 0
	})

	// Pretend a switch just happened.
	if err := harness.engine.state.update(func(state *persistedState) {
		state.LastSwitchAt = time.Now()
	}); err != nil {
		t.Fatal(err)
	}

	harness.run(t, func() bool { return harness.engine.Snapshot().CandidatesTotal > 0 })

	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) != 0 {
		t.Errorf("the minimum interval must block the switch, but pinned %v", pinned)
	}
}

// The load trigger may skip the cooldown, but only when moving would actually
// help: if every server is overloaded, switching achieves nothing and would
// otherwise repeat on every evaluation.
func TestDecideLoadTriggerRequiresABetterCandidate(t *testing.T) {
	t.Parallel()

	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.LoadTrigger = 50
		cfg.Switch.Cooldown = time.Hour
		cfg.Switch.MinInterval = 0
	})
	engine := harness.engine

	// Simulate a switch a moment ago so the cooldown is active.
	if err := engine.state.update(func(state *persistedState) {
		state.LastSwitchAt = time.Now()
	}); err != nil {
		t.Fatal(err)
	}

	current := scoredWithLoad("busy-a", 90, 0.9)
	betterButStillOverloaded := scoredWithLoad("busy-b", 80, 0.8)
	genuinelyBetter := scoredWithLoad("quiet", 10, 0.1)

	if verdict := engine.decide(current, true, betterButStillOverloaded, false); verdict.shouldSwitch {
		t.Errorf("should not switch when the best candidate is also overloaded: %+v", verdict)
	}
	if verdict := engine.decide(current, true, genuinelyBetter, false); !verdict.shouldSwitch {
		t.Errorf("should switch when a candidate is below the trigger: %+v", verdict)
	}
}

func TestDecideRespectsCooldownAndImprovement(t *testing.T) {
	t.Parallel()

	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.LoadTrigger = 0 // isolate the improvement rule
		cfg.Switch.Cooldown = time.Hour
		cfg.Switch.MinInterval = 0
		cfg.Switch.MinImprovement = 0.2
	})
	engine := harness.engine

	current := scoredWithLoad("current", 40, 0.40)
	marginal := scoredWithLoad("marginal", 35, 0.35)
	clear := scoredWithLoad("clear", 5, 0.05)

	// No switch yet, so no cooldown: the improvement rule decides.
	if verdict := engine.decide(current, true, marginal, false); verdict.shouldSwitch {
		t.Errorf("a 0.05 gain must not trigger a switch when 0.2 is required: %+v", verdict)
	}
	if verdict := engine.decide(current, true, clear, false); !verdict.shouldSwitch {
		t.Errorf("a 0.35 gain should trigger a switch: %+v", verdict)
	}

	// With a recent switch, the cooldown blocks even a clear improvement.
	if err := engine.state.update(func(state *persistedState) {
		state.LastSwitchAt = time.Now()
	}); err != nil {
		t.Fatal(err)
	}
	verdict := engine.decide(current, true, clear, false)
	if verdict.shouldSwitch {
		t.Errorf("the cooldown should block the switch: %+v", verdict)
	}

	// A manual request ignores both.
	if verdict := engine.decide(current, true, clear, true); !verdict.shouldSwitch {
		t.Errorf("a forced switch must always proceed: %+v", verdict)
	}
}

func scoredWithLoad(hostname string, load uint8, score float64) scoring.Scored {
	return scoring.Scored{
		Candidate: catalog.Candidate{Hostname: hostname, Load: load},
		Score:     score,
	}
}

// An unreachable Gluetun is an expected condition, not a crash.
func TestEngineSurvivesUnreachableGluetun(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Gluetun.BaseURL = "http://127.0.0.1:1"
	})

	harness.run(t, func() bool {
		snapshot := harness.engine.Snapshot()
		return snapshot.CandidatesTotal > 0 && snapshot.Gluetun.LastError != ""
	})

	snapshot := harness.engine.Snapshot()
	if snapshot.Gluetun.Reachable {
		t.Error("Gluetun should be reported unreachable")
	}
	// servers.json is still the tool's job even when Gluetun is down.
	if _, err := os.Stat(harness.filePath); err != nil {
		t.Errorf("servers file should still have been written: %v", err)
	}
	if len(harness.gluetun.pinnedHostnames()) != 0 {
		t.Error("no switch should be attempted while Gluetun is unreachable")
	}
}

// Hysteresis: a marginal improvement must not cause a reconnect.
func TestEngineRespectsMinimumImprovement(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		// SE#1 at 80% and SE#2 at 5% differ by 0.75; require more than that.
		cfg.Switch.MinImprovement = 0.9
	})

	harness.run(t, func() bool { return harness.engine.Snapshot().CandidatesTotal > 0 })

	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) != 0 {
		t.Errorf("no switch should have happened, but pinned %v", pinned)
	}
}

func TestEngineHonoursAutoSwitchDisabled(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.Auto = false
	})

	harness.run(t, func() bool { return harness.engine.Snapshot().CandidatesTotal > 0 })

	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) != 0 {
		t.Errorf("automatic switching is off, but pinned %v", pinned)
	}
	if harness.engine.Snapshot().Selection.AutoSwitch {
		t.Error("the snapshot should report automatic switching as off")
	}
}

// Reconnect mode "none" means the tool only maintains servers.json.
func TestEngineReconnectModeNoneNeverTouchesTheTunnel(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.Mode = config.ReconnectNone
	})

	harness.run(t, func() bool {
		return !harness.engine.Snapshot().Servers.LastWrite.IsZero()
	})

	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) != 0 {
		t.Errorf("mode none must not change the tunnel, but pinned %v", pinned)
	}
}

func TestEngineDoesNotSwitchWhileTunnelIsStopped(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.status = gluetunapi.StatusStopped

	harness.run(t, func() bool { return harness.engine.Snapshot().CandidatesTotal > 0 })

	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) != 0 {
		t.Errorf("a deliberately stopped tunnel must be left alone, but pinned %v", pinned)
	}
}

// State must survive a restart, otherwise the cooldown and history are lost on
// every container update.
func TestStateStoreRoundTrip(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()

	store := newStateStore(directory)
	if err := store.load(); err != nil {
		t.Fatalf("load on an empty directory: %v", err)
	}

	now := time.Now().Truncate(time.Second)
	if err := store.update(func(state *persistedState) {
		state.PinnedHostname = "se-02.protonvpn.net"
		state.LastSwitchAt = now
		state.History = append(state.History, SwitchRecord{At: now, To: "se-02.protonvpn.net", Succeeded: true})
	}); err != nil {
		t.Fatalf("update: %v", err)
	}

	reloaded := newStateStore(directory)
	if err := reloaded.load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	state := reloaded.snapshot()
	if state.PinnedHostname != "se-02.protonvpn.net" {
		t.Errorf("PinnedHostname = %q", state.PinnedHostname)
	}
	if !state.LastSwitchAt.Equal(now) {
		t.Errorf("LastSwitchAt = %s, want %s", state.LastSwitchAt, now)
	}
	if len(state.History) != 1 {
		t.Errorf("History = %+v", state.History)
	}
}

// The history is bounded so a long-lived container cannot grow the state file
// without limit.
func TestStateStoreBoundsHistory(t *testing.T) {
	t.Parallel()

	store := newStateStore(t.TempDir())
	for i := range maxHistory + 20 {
		if err := store.update(func(state *persistedState) {
			state.History = append(state.History, SwitchRecord{To: fmt.Sprintf("host-%d", i)})
		}); err != nil {
			t.Fatal(err)
		}
	}

	history := store.snapshot().History
	if len(history) != maxHistory {
		t.Fatalf("history length = %d, want %d", len(history), maxHistory)
	}
	// The newest entries are the ones worth keeping.
	if want := fmt.Sprintf("host-%d", maxHistory+19); history[len(history)-1].To != want {
		t.Errorf("last entry = %q, want %q", history[len(history)-1].To, want)
	}
}

func TestSubscriberSetNotifiesAndUnsubscribes(t *testing.T) {
	t.Parallel()

	subscribers := newSubscriberSet()
	updates, cancel := subscribers.add()

	subscribers.notify()
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("subscriber was not notified")
	}

	// A second notify with nothing reading must not block.
	subscribers.notify()
	subscribers.notify()

	cancel()
	// Drain any pending notification, then confirm the channel is closed.
	for {
		if _, open := <-updates; !open {
			break
		}
	}
	// Cancelling twice must not panic on a double close.
	cancel()
}

// Probe selection must not depend on latency, or it becomes self-reinforcing:
// an unprobed server carries the unknown-latency penalty, which pushes it down
// the ranking, which keeps it outside the probe budget, so it never gets probed
// even when its load is better than that of servers being probed.
func TestProbeTargetsAreChosenWithoutLatencyBias(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Score.LatencyWeight = 0.7
		cfg.Score.UnknownLatencyPenalty = 0.5
	})
	engine := harness.engine

	// Two candidates: the quieter one has never been probed, the busier one has a
	// good measurement. By full score the busy-but-measured server wins, so a
	// score-ordered budget of one would keep probing it and never touch the other.
	quietUnprobed := catalog.Candidate{
		Hostname: "quiet.protonvpn.net", Load: 20,
		EntryIP: netip.MustParseAddr("10.9.0.1"),
	}
	busyProbed := catalog.Candidate{
		Hostname: "busy.protonvpn.net", Load: 45,
		EntryIP: netip.MustParseAddr("10.9.0.2"),
	}
	engine.candidates = []catalog.Candidate{quietUnprobed, busyProbed}
	engine.prober.Record(busyProbed.EntryIP, 5*time.Millisecond)
	engine.rerank()

	// Confirm the premise: by full score the measured, busier server ranks first.
	if engine.ranked[0].Candidate.Hostname != "busy.protonvpn.net" {
		t.Fatalf("premise failed: expected the probed server to rank first, got %q",
			engine.ranked[0].Candidate.Hostname)
	}

	// With a budget of one, the unprobed-but-quieter server must still be chosen.
	targets := engine.entryIPs(1)
	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0] != quietUnprobed.EntryIP {
		t.Errorf("probe target = %s, want the quieter unprobed server %s",
			targets[0], quietUnprobed.EntryIP)
	}
}

// STORAGE_SERVERS_ENABLED=yes is a requirement, so an unmet one has to be
// reported rather than warned about once and forgotten. The health check is what
// makes it visible to Docker and to any monitoring.
func TestHealthyReportsServerDataThatGluetunIgnores(t *testing.T) {
	t.Parallel()

	harness := newHarness(t, false, nil)
	engine := harness.engine

	// Give it candidates so the other health condition is satisfied.
	engine.mutateSnapshot(func(snapshot *Snapshot) { snapshot.CandidatesTotal = 5 })
	if healthy, reason := engine.Healthy(); !healthy {
		t.Fatalf("expected healthy, got %q", reason)
	}

	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Servers.Ignored = true
		snapshot.Servers.IgnoredReason = "storage disabled"
	})

	healthy, reason := engine.Healthy()
	if healthy {
		t.Error("writing server data nothing reads must be unhealthy")
	}
	if !strings.Contains(reason, "not reading") {
		t.Errorf("reason = %q, want it to explain the problem", reason)
	}
}

// The warning must not fire while Gluetun is merely down, which is a condition
// the tool is built to survive.
func TestIgnoredServerDataIsNotReportedWhileGluetunIsDown(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Gluetun.BaseURL = "http://127.0.0.1:1" // nothing listening
	})

	harness.run(t, func() bool { return harness.engine.Snapshot().CandidatesTotal > 0 })

	snapshot := harness.engine.Snapshot()
	if snapshot.Servers.Ignored {
		t.Error("an unreachable Gluetun must not be reported as ignoring the server data")
	}
	// And the tool stays healthy: a Gluetun outage is survivable by design.
	if healthy, reason := harness.engine.Healthy(); !healthy {
		t.Errorf("a Gluetun outage must not make the tool unhealthy, got %q", reason)
	}
}

// A crashed tunnel is actionable, not something to wait out: Gluetun cannot
// connect with its current selection, and moving to another server is usually
// what fixes it. Only a deliberately stopped tunnel is left alone.
func TestEngineMovesACrashedTunnel(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.status = gluetunapi.StatusCrashed

	harness.run(t, func() bool {
		return len(harness.gluetun.pinnedHostnames()) > 0
	})

	if pinned := harness.gluetun.pinnedHostnames(); pinned[0] != "se-02.protonvpn.net" {
		t.Errorf("pinned %v, want the best server", pinned)
	}
}

// Gluetun answers a state change only once its VPN loop has restarted, which can
// outlast any sane timeout. The outcome is then unknown rather than failed, so it
// must be verified instead of re-sent - re-sending would cause a second,
// pointless reconnect.
func TestEngineVerifiesInsteadOfRetryingAfterASlowStateChange(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Gluetun.MutationTimeout = 200 * time.Millisecond
	})
	// The request outlasts the timeout but still applies, exactly as Gluetun does.
	harness.gluetun.settingsDelay = 600 * time.Millisecond

	harness.run(t, func() bool {
		history := harness.engine.Snapshot().History
		return len(history) > 0 && history[0].Succeeded
	})

	// Verification, not a retry: the hostname must have been sent exactly once.
	pinned := harness.gluetun.pinnedHostnames()
	if len(pinned) != 1 {
		t.Errorf("pinned %v, want exactly one request - a timeout must not be re-sent", pinned)
	}
	if pinned[0] != "se-02.protonvpn.net" {
		t.Errorf("pinned %v, want se-02", pinned)
	}
}

// The other health failure: unable to write the server data at all.
func TestHealthyReportsAWriteFailure(t *testing.T) {
	t.Parallel()

	engine := newHarness(t, false, nil).engine
	engine.mutateSnapshot(func(snapshot *Snapshot) { snapshot.CandidatesTotal = 5 })

	if healthy, reason := engine.Healthy(); !healthy {
		t.Fatalf("expected healthy, got %q", reason)
	}

	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Servers.LastError = "permission denied"
	})

	healthy, reason := engine.Healthy()
	if healthy {
		t.Error("being unable to write the server data must be unhealthy")
	}
	if !strings.Contains(reason, "permission denied") {
		t.Errorf("reason = %q, want the underlying error", reason)
	}
}
