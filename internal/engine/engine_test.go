package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
	// rejectHostname refuses just one hostname, modelling a Gluetun that knows
	// most of our servers but not the newest one.
	rejectHostname string
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
	// portForwardOnly mirrors Gluetun's PORT_FORWARD_ONLY, which it ANDs with any
	// pinned hostname.
	portForwardOnly bool
	// knownHostnames is the list the fake claims to know, mirroring the list a real
	// Gluetun loads at startup. Empty means "knows everything", so existing tests
	// are unaffected.
	//
	// It matters because a real Gluetun *enumerates this list* when it refuses a
	// hostname, and the engine mines that for recovery. A fake that refused with a
	// bare "no server found" would leave that path untested.
	knownHostnames []string
	// portForwarding mirrors VPN_PORT_FORWARDING, a genuinely separate setting:
	// Gluetun asks Proton for a port but does not refuse servers that cannot give
	// one. Keeping it separate here is the whole point - a fake that reported both
	// from one flag made the two indistinguishable, and hid a real bug.
	portForwarding bool
	// statusAfterPin is the status reported once a hostname has been pinned, so a
	// test can model Gluetun failing to connect with the new selection.
	statusAfterPin string
	// applyOutcome overrides the answer to PUT /v1/vpn/settings. Gluetun answers
	// "already crashed" when its VPN loop was not running, meaning it stored the
	// selection without restarting.
	applyOutcome string
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
		status := f.status
		if f.statusAfterPin != "" && len(f.pinned) > 0 {
			status = f.statusAfterPin
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
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
		f.mu.Lock()
		portForwardOnly := f.portForwardOnly
		// Gluetun requires port forwarding to be on before PORT_FORWARD_ONLY has any
		// effect, so the "only" flag implies the request - but not the reverse.
		portForwarding := f.portForwarding || f.portForwardOnly
		// Real Gluetun reports back the selection it is enforcing, including any
		// pinned hostname. Verification depends on that, so the fake has to do it.
		hostnames := ""
		if len(f.pinned) > 0 {
			hostnames = fmt.Sprintf(`"hostnames":[%q],`, f.pinned[len(f.pinned)-1])
		}
		f.mu.Unlock()
		fmt.Fprintf(w, `{"type":"wireguard","provider":{"name":"protonvpn",`+
			`"server_selection":{"vpn":"wireguard",%s"port_forward_only":%t},`+
			`"port_forwarding":{"enabled":%t}}}`, hostnames, portForwardOnly, portForwarding)
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

		unknown := false
		if len(f.knownHostnames) > 0 {
			unknown = !slices.Contains(f.knownHostnames, hostnames[0])
		}
		if unknown {
			// Word for word how Gluetun answers for a hostname missing from the list
			// it loaded at startup - including the full enumeration of what it would
			// have accepted, which the engine mines to recover.
			http.Error(w, "provider settings: server selection: for VPN service provider "+
				"protonvpn: the hostname specified is not valid: value is not one of the "+
				"possible choices: none of "+hostnames[0]+" is one of the choices available "+
				strings.Join(f.knownHostnames, ", "), http.StatusBadRequest)
			return
		}
		if f.rejectHostnames || (f.rejectHostname != "" && hostnames[0] == f.rejectHostname) {
			// A blanket refusal, with no list attached. Gluetun does this for
			// rejections that are not about an unknown hostname, and it is also the
			// honest shape for "reject everything": a fake that refused every
			// hostname while claiming to know a specific one would be incoherent.
			http.Error(w, "no server found for hostname", http.StatusBadRequest)
			return
		}
		f.pinned = append(f.pinned, hostnames[0])
		if ip, ok := f.exitIPByHostname[hostnames[0]]; ok {
			f.publicIP = ip
		}
		if f.applyOutcome != "" {
			_, _ = io.WriteString(w, f.applyOutcome)
			return
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
		// The shape a real Gluetun returns, including the plural field.
		_, _ = io.WriteString(w, `{"port":55019,"ports":[55019]}`)
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
		case "/vpn/v2":
			// Tier 2 (Plus), matching the tier of the fake server list.
			_, _ = io.WriteString(w, `{"Code":1000,"VPN":{"Status":1,"PlanName":"vpn2022",`+
				`"PlanTitle":"VPN Plus","MaxTier":2,"MaxConnect":10}}`)
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
			MutationTimeout: 30 * time.Second, RefreshServersOnReject: true,
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

// Gluetun ANDs PORT_FORWARD_ONLY with any pinned hostname, so pinning a server
// that does not support port forwarding leaves nothing matching and crashes its
// VPN loop. The requirement has to be adopted into the selection.
func TestEngineAdoptsGluetunPortForwardRequirement(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwardOnly = true

	harness.run(t, func() bool { return harness.engine.Snapshot().CandidatesTotal > 0 })

	if got := harness.engine.requirements.PortForward; !got {
		t.Error("the engine should have adopted port_forward_only from Gluetun")
	}
	// The fake Proton list marks every server P2P (Features: 4), so all survive -
	// what matters is that the requirement reached the catalog options.
	if got := harness.engine.catalogOptions().Require.PortForward; !got {
		t.Error("the requirement should be applied when building the catalog")
	}
}

// Gluetun stores a new selection even when its VPN loop is not running, but then
// answers "already crashed" and does not restart - leaving the change unused. An
// explicit restart is needed, or the tunnel stays down.
func TestEngineRestartsWhenGluetunDidNotApplyTheSelection(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.applyOutcome = "already crashed"

	harness.run(t, func() bool {
		return len(harness.gluetun.statusWrites()) >= 2
	})

	writes := harness.gluetun.statusWrites()
	if writes[0] != gluetunapi.StatusStopped || writes[1] != gluetunapi.StatusRunning {
		t.Errorf("status writes = %v, want an explicit [stopped running] restart", writes)
	}
	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) == 0 {
		t.Error("the selection should still have been sent")
	}
}

func TestOutcomeMeansNotRestarted(t *testing.T) {
	t.Parallel()

	for outcome, want := range map[string]bool{
		"already crashed":      true,
		"already stopped":      true,
		"ALREADY CRASHED":      true,
		" already stopped ":    true,
		"running":              false,
		"VPN settings updated": false,
		"":                     false,
	} {
		if got := outcomeMeansNotRestarted(outcome); got != want {
			t.Errorf("outcomeMeansNotRestarted(%q) = %v, want %v", outcome, got, want)
		}
	}
}

// Utilisation is what the whole ranking rests on, so a restart during a Proton
// outage should resume with the figures from the last cheap refresh rather than
// whichever ones the last full fetch happened to see.
func TestEngineAppliesCachedLoadsAfterRestart(t *testing.T) {
	// First run: fetch the list and let a loads refresh persist fresher figures.
	warm := newHarness(t, false, nil)
	warm.run(t, func() bool { return warm.engine.Snapshot().CandidatesTotal > 0 })

	// Persist load figures that differ markedly from the list's own.
	if err := warm.engine.loads.save(cachedLoads{
		UpdatedAt: time.Now(),
		Loads: []proton.ServerLoad{
			{ID: "l1", Load: 3, Status: 1},  // SE#1 was 80% in the list
			{ID: "l2", Load: 91, Status: 1}, // SE#2 was 5%
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Second run against a failing Proton, reusing the same state directory.
	cold := newHarness(t, true, nil)
	for _, name := range []string{logicalsFileName, loadsFileName} {
		if err := os.Rename(filepath.Join(warm.stateDir, name),
			filepath.Join(cold.stateDir, name)); err != nil {
			t.Fatal(err)
		}
	}

	cold.run(t, func() bool { return cold.engine.Snapshot().CandidatesTotal > 0 })

	// The cached loads must have overridden the list's own figures, which flips
	// the ranking.
	best := cold.engine.Snapshot().Selection.Best
	if best == nil {
		t.Fatal("no best candidate")
	}
	if best.ServerName != "SE#1" {
		t.Errorf("best = %s (load %d%%), want SE#1 at 3%% from the cached loads",
			best.ServerName, best.Load)
	}
}

// A cached list past PROTON_CACHE_MAX_AGE is still used - stale beats nothing -
// but the staleness has to be reported rather than hidden.
func TestEngineReportsAStaleCache(t *testing.T) {
	warm := newHarness(t, false, nil)
	warm.run(t, func() bool { return warm.engine.Snapshot().CandidatesTotal > 0 })

	// Age the cached list well past the threshold.
	cached, found, err := warm.engine.logicals.load()
	if err != nil || !found {
		t.Fatalf("expected a cached list: %v", err)
	}
	cached.FetchedAt = time.Now().Add(-30 * 24 * time.Hour)
	if err := warm.engine.logicals.save(cached); err != nil {
		t.Fatal(err)
	}

	cold := newHarness(t, true, func(cfg *config.Config) {
		cfg.Proton.CacheMaxAge = 72 * time.Hour
	})
	if err := os.Rename(filepath.Join(warm.stateDir, logicalsFileName),
		filepath.Join(cold.stateDir, logicalsFileName)); err != nil {
		t.Fatal(err)
	}

	cold.run(t, func() bool { return cold.engine.Snapshot().CandidatesTotal > 0 })

	snapshot := cold.engine.Snapshot()
	if !snapshot.Proton.CacheStale {
		t.Error("a month-old cache should be reported as stale")
	}
	// Still used, because stale data beats no data.
	if snapshot.CandidatesTotal == 0 {
		t.Error("the stale cache should still have been used")
	}
}

// A rebuild of the catalog must not discard utilisation updates. The catalog is
// rebuilt from the cached Proton list whenever the VPN protocol or Gluetun's
// filters change, and that list can be hours older than the last loads refresh -
// so a naive rebuild silently reverts every load.
func TestRebuildKeepsTheLatestLoads(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().CandidatesTotal > 0 })
	engine := harness.engine

	// Fresher figures than the list carries, as a loads refresh would produce.
	engine.latestLoads = []proton.ServerLoad{
		{ID: "l1", Load: 7, Status: 1},  // SE#1 is 80% in the list
		{ID: "l2", Load: 88, Status: 1}, // SE#2 is 5%
	}

	engine.rebuildFromCache("test")

	byName := map[string]uint8{}
	for _, candidate := range engine.candidates {
		byName[candidate.ServerName] = candidate.Load
	}
	if byName["SE#1"] != 7 || byName["SE#2"] != 88 {
		t.Errorf("loads after rebuild = %v, want SE#1 at 7%% and SE#2 at 88%%", byName)
	}
	// And the ranking must follow.
	if best := engine.ranked[0].Candidate.ServerName; best != "SE#1" {
		t.Errorf("best after rebuild = %s, want SE#1", best)
	}
}

// A poll landing while the tunnel restarts must not erase what is known. Without
// this, a working port forward reads as "none" on the dashboard for as long as the
// tunnel is cycling - which, with switching enabled, is often.
func TestTransientTunnelStateDoesNotEraseTheForwardedPort(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool {
		return len(harness.engine.Snapshot().Gluetun.ForwardedPorts) > 0
	})

	snapshot := harness.engine.Snapshot()
	if got := snapshot.Gluetun.ForwardedPorts; len(got) != 1 || got[0] != 55019 {
		t.Fatalf("ForwardedPorts = %v, want [55019]", got)
	}
	if !snapshot.Gluetun.ExitCurrent {
		t.Error("values read from a running tunnel should be marked current")
	}
	observedIP := snapshot.Gluetun.Exit.IP

	// Now the tunnel goes into a transitional state, as it does on every reconnect.
	harness.gluetun.mu.Lock()
	harness.gluetun.status = gluetunapi.StatusStopping
	harness.gluetun.mu.Unlock()

	harness.engine.checkGluetun(context.Background())

	snapshot = harness.engine.Snapshot()
	if got := snapshot.Gluetun.ForwardedPorts; len(got) != 1 || got[0] != 55019 {
		t.Errorf("ForwardedPorts = %v after a transient state, want the port to be retained", got)
	}
	if snapshot.Gluetun.Exit.IP != observedIP {
		t.Errorf("exit IP = %q, want the last known %q retained", snapshot.Gluetun.Exit.IP, observedIP)
	}
	// But it must be honest that these are no longer current readings.
	if snapshot.Gluetun.ExitCurrent {
		t.Error("retained values must be marked as not current")
	}
}

// Proton publishes the server address, not the address the internet sees: a
// server listed at 62.93.166.123 can egress from 159.26.108.2. Verification must
// not depend on them matching - it did, and reported perfectly good switches as
// failures.
func TestSwitchIsVerifiedWhenTheObservedAddressDiffersFromProtons(t *testing.T) {
	harness := newHarness(t, false, nil)
	// Gluetun reports an address that appears nowhere in Proton's data.
	harness.gluetun.exitIPByHostname = map[string]string{
		"se-01.protonvpn.net": "81.0.0.1",
		"se-02.protonvpn.net": "159.26.108.2", // Proton claims 81.0.0.2
		"no-01.protonvpn.net": "159.26.108.3",
	}

	harness.run(t, func() bool {
		history := harness.engine.Snapshot().History
		return len(history) > 0 && history[0].Succeeded
	})

	record := harness.engine.Snapshot().History[0]
	if !record.Succeeded {
		t.Fatalf("the switch should verify from Gluetun's selection: %+v", record)
	}
	if record.To != "se-02.protonvpn.net" {
		t.Errorf("switched to %q, want se-02", record.To)
	}
	// The address is still recorded, just not used as the gate.
	if record.PublicIP != "159.26.108.2" {
		t.Errorf("PublicIP = %q, want the observed address recorded", record.PublicIP)
	}
}

// A crashed VPN loop will keep failing with the same selection, so waiting out the
// verification timeout achieves nothing.
func TestVerificationFailsFastOnACrashedTunnel(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.VerifyTimeout = 60 * time.Second // would be a long wait
	})
	harness.gluetun.statusAfterPin = gluetunapi.StatusCrashed

	started := time.Now()
	harness.run(t, func() bool {
		history := harness.engine.Snapshot().History
		return len(history) > 0 && !history[0].Succeeded
	})
	elapsed := time.Since(started)

	record := harness.engine.Snapshot().History[0]
	if record.Succeeded {
		t.Fatal("a crashed tunnel is not a successful switch")
	}
	if !strings.Contains(record.Error, "crashed") {
		t.Errorf("error = %q, want the crash named", record.Error)
	}
	if elapsed > 30*time.Second {
		t.Errorf("took %s: a crash should be reported without waiting out the timeout", elapsed)
	}
}

// A rejection means Gluetun's list is older than ours. Even when a later candidate
// works, the list should be refreshed - otherwise the best servers stay unknown to
// Gluetun and every switch settles for a worse one.
func TestRejectionTriggersARefreshEvenWhenASwitchSucceeds(t *testing.T) {
	// Norway is allowed too, so refusing the best candidate still leaves a
	// different server to fall back to rather than only the current one.
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Filter.Countries = []string{"Sweden", "Norway"}
	})
	harness.gluetun.rejectHostname = "no-01.protonvpn.net"

	harness.run(t, func() bool {
		history := harness.engine.Snapshot().History
		return len(history) > 0 && history[0].Succeeded
	})

	if calls := harness.gluetun.updaterTriggered(); calls == 0 {
		t.Error("a rejection during a successful switch should still refresh gluetun's list")
	}
}

// Pinning a server clears Gluetun's "only" filters by design, so Gluetun then
// reports them as off. Believing that would drop the operator's requirement, let a
// server that fails it be chosen next time, and rebuild the catalog on every flip.
func TestRequirementsAreNotDroppedWhenOurOwnPinClearsThem(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwardOnly = true

	// Waiting on the published snapshot rather than on engine internals: those are
	// owned by the run loop, and reading them while it runs is a data race.
	harness.run(t, func() bool {
		adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted
		return len(adopted) == 1 && adopted[0] == "port_forward_only"
	})
	engine := harness.engine

	// Gluetun now reports the filter as off, because the pin cleared it.
	harness.gluetun.mu.Lock()
	harness.gluetun.portForwardOnly = false
	harness.gluetun.mu.Unlock()

	// A rebuild replaces the candidate slice, so its identity reveals whether one
	// happened; Stats contains a slice and cannot be compared directly.
	before := &engine.candidates[0]
	engine.checkGluetun(context.Background())

	if !engine.requirements.PortForward {
		t.Error("the requirement must survive our own clearing of the filter")
	}
	// And no pointless rebuild: re-deriving the catalog reads a multi-megabyte
	// cache and throws away the loads applied since the last full fetch.
	if &engine.candidates[0] != before {
		t.Error("nothing changed, so the catalog should not have been rebuilt")
	}

	// A newly appearing requirement is still adopted.
	harness.gluetun.mu.Lock()
	harness.gluetun.portForwardOnly = true
	harness.gluetun.mu.Unlock()
	engine.checkGluetun(context.Background())
	if !engine.requirements.PortForward {
		t.Error("requirements should still be adoptable")
	}
}

// A restart while Proton is unreachable must still give Gluetun a server list.
// Loading the cache without writing it left Gluetun with whatever it had - on a
// fresh volume, nothing - while a perfectly usable list sat in the cache.
func TestServerDataIsWrittenFromTheCacheWhenProtonIsDown(t *testing.T) {
	warm := newHarness(t, false, nil)
	warm.run(t, func() bool { return !warm.engine.Snapshot().Servers.LastWrite.IsZero() })

	// Second run against a failing Proton, reusing the cached list but a fresh
	// Gluetun volume so nothing is pre-written.
	cold := newHarness(t, true, nil)
	if err := os.Rename(filepath.Join(warm.stateDir, logicalsFileName),
		filepath.Join(cold.stateDir, logicalsFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cold.filePath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	cold.run(t, func() bool { return !cold.engine.Snapshot().Servers.LastWrite.IsZero() })

	snapshot := cold.engine.Snapshot()
	if snapshot.Servers.ServerCount == 0 {
		t.Error("server data should have been written from the cached list")
	}
	if !snapshot.Proton.FromCache {
		t.Error("the run should be marked as using the cache")
	}
	// And the file really exists on disk.
	if _, err := os.Stat(cold.filePath); err != nil {
		t.Errorf("the servers file was not written: %v", err)
	}
}

// Gluetun usually takes longer to start than this container, so the first health
// checks find it unreachable. Waiting for the evaluation ticker after that leaves
// the tunnel wherever Gluetun put it for up to SWITCH_EVALUATION_INTERVAL - which
// is why reaching for the dashboard button felt necessary.
func TestEvaluationHappensAsSoonAsGluetunBecomesUsable(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		// Long enough that the ticker cannot be what triggers the switch.
		cfg.Switch.Interval = time.Hour
	})
	// Gluetun is up but the tunnel is deliberately down, so nothing may move yet.
	harness.gluetun.mu.Lock()
	harness.gluetun.status = gluetunapi.StatusStopped
	harness.gluetun.mu.Unlock()

	harness.run(t, func() bool { return harness.engine.Snapshot().CandidatesTotal > 0 })

	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) != 0 {
		t.Fatalf("a stopped tunnel must be left alone, but pinned %v", pinned)
	}

	// The tunnel comes up. The next health check must act on it immediately.
	harness.gluetun.mu.Lock()
	harness.gluetun.status = gluetunapi.StatusRunning
	harness.gluetun.mu.Unlock()

	harness.engine.checkGluetun(context.Background())

	if pinned := harness.gluetun.pinnedHostnames(); len(pinned) == 0 {
		t.Error("the tunnel became usable, so it should have been evaluated at once")
	}
}

func TestBecameUsable(t *testing.T) {
	t.Parallel()

	down := GluetunStatus{Reachable: false}
	stopped := GluetunStatus{Reachable: true, Status: gluetunapi.StatusStopped}
	running := GluetunStatus{Reachable: true, Status: gluetunapi.StatusRunning}
	crashed := GluetunStatus{Reachable: true, Status: gluetunapi.StatusCrashed}

	for name, test := range map[string]struct {
		was, now GluetunStatus
		want     bool
	}{
		"unreachable to running": {down, running, true},
		"stopped to running":     {stopped, running, true},
		"unreachable to crashed": {down, crashed, true},
		"running stays running":  {running, running, false},
		"running to unreachable": {running, down, false},
		"running to stopped":     {running, stopped, false},
		"unreachable to stopped": {down, stopped, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := becameUsable(test.was, test.now); got != test.want {
				t.Errorf("becameUsable = %v, want %v", got, test.want)
			}
		})
	}
}

// The account tier has to be known before candidates are built, and remembered so
// a restart while Proton is unreachable does not reconsider servers the account
// cannot use.
func TestAccountTierIsAppliedAndRemembered(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Proton.AccountTier != nil })

	snapshot := harness.engine.Snapshot()
	if got := *snapshot.Proton.AccountTier; got != 2 {
		t.Errorf("AccountTier = %d, want 2", got)
	}
	if snapshot.Proton.AccountPlan != "VPN Plus" {
		t.Errorf("AccountPlan = %q", snapshot.Proton.AccountPlan)
	}
	if snapshot.Proton.AccountFree {
		t.Error("tier 2 is not the free tier")
	}
	// The tier reaches the catalog, which is what actually excludes servers.
	if harness.engine.catalogOptions().MaxTier == nil {
		t.Error("the tier should be applied when building candidates")
	}

	// Persisted, so a restart without Proton still filters correctly.
	if tier := harness.engine.state.snapshot().AccountTier; tier == nil || *tier != 2 {
		t.Errorf("persisted tier = %v, want 2", tier)
	}

	cold := newHarness(t, true, nil)
	if err := os.Rename(filepath.Join(harness.stateDir, stateFileName),
		filepath.Join(cold.stateDir, stateFileName)); err != nil {
		t.Fatal(err)
	}
	cold2, err := New(Options{
		Config: cold.engine.cfg, Logger: quietLogger(), Version: "test",
		Proton: cold.engine.proton, Gluetun: cold.engine.gluetun,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tier := cold2.accountTier; tier == nil || *tier != 2 {
		t.Errorf("a restarted engine should remember the tier, got %v", tier)
	}
}

// The restriction to P2P servers must come from Gluetun asking for it, and only
// from that. Restricting when Gluetun has PORT_FORWARD_ONLY off would silently
// throw away most of the server list for no reason.
func TestNoP2PRestrictionUnlessGluetunAsksForIt(t *testing.T) {
	harness := newHarness(t, false, nil)
	// Gluetun does not enforce port forwarding.
	harness.gluetun.portForwardOnly = false

	harness.run(t, func() bool { return harness.engine.Snapshot().CandidatesTotal > 0 })

	if adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted; len(adopted) != 0 {
		t.Errorf("no requirement should be adopted, got %v", adopted)
	}
	if harness.engine.requirements.PortForward {
		t.Error("P2P must not be required when Gluetun does not ask for it")
	}
	if harness.engine.catalogOptions().Require.PortForward {
		t.Error("the catalog must not filter on P2P either")
	}
}

// "Reconnect to best" bypasses the cooldown and the improvement threshold, but it
// must not bypass what Gluetun can actually use: forcing a switch onto a non-P2P
// server while Gluetun requires port forwarding would connect without the port
// the operator asked for.
func TestForcedReconnectStillRespectsThePortForwardRequirement(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwardOnly = true
	harness.run(t, func() bool {
		adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted
		return len(adopted) == 1 && adopted[0] == "port_forward_only"
	})
	engine := harness.engine

	// A mixed list where the non-P2P server is much quieter, so it would win on
	// merit alone.
	p2pBusy := proton.LogicalServer{
		ID: "p2p", Name: "SE#P2P", ExitCountry: "SE", Load: 40, Status: 1,
		Tier: tierPtr(2), Features: proton.FeatureP2P,
		Servers: []proton.PhysicalServer{{
			EntryIP: netip.MustParseAddr("10.7.0.1"), ExitIP: netip.MustParseAddr("81.7.0.1"),
			Domain: "node-se-p2p.protonvpn.net", Status: 1, X25519PublicKey: "k1",
		}},
	}
	plainQuiet := proton.LogicalServer{
		ID: "plain", Name: "SE#PLAIN", ExitCountry: "SE", Load: 2, Status: 1,
		Tier: tierPtr(2), Features: 0,
		Servers: []proton.PhysicalServer{{
			EntryIP: netip.MustParseAddr("10.7.0.2"), ExitIP: netip.MustParseAddr("81.7.0.2"),
			Domain: "node-se-plain.protonvpn.net", Status: 1, X25519PublicKey: "k2",
		}},
	}
	engine.applyLogicals([]proton.LogicalServer{p2pBusy, plainQuiet}, false)

	// The non-P2P server must not even be a candidate, so nothing - forced or not -
	// can select it.
	for _, candidate := range engine.candidates {
		if !candidate.P2P {
			t.Errorf("non-P2P server %s should not be a candidate", candidate.ServerName)
		}
	}
	if len(engine.ranked) == 0 {
		t.Fatal("no candidates left")
	}
	if best := engine.ranked[0]; best.Candidate.ServerName != "SE#P2P" {
		t.Errorf("best = %s, want the P2P server despite being busier", best.Candidate.ServerName)
	}

	// And the forced decision picks exactly that.
	verdict := engine.decide(scoring.Scored{}, false, engine.ranked[0], true)
	if !verdict.shouldSwitch || verdict.reason != "manual" {
		t.Errorf("a forced reconnect should proceed: %+v", verdict)
	}
}

func tierPtr(value uint8) *uint8 { return &value }

// mixedP2PLogicals is a busy P2P server and a much quieter non-P2P one, so which
// of the two is chosen is never ambiguous.
func mixedP2PLogicals() []proton.LogicalServer {
	return []proton.LogicalServer{
		{
			ID: "p2p", Name: "SE#P2P", ExitCountry: "SE", Load: 40, Status: 1,
			Tier: tierPtr(2), Features: proton.FeatureP2P,
			Servers: []proton.PhysicalServer{{
				EntryIP: netip.MustParseAddr("10.8.0.1"), ExitIP: netip.MustParseAddr("81.8.0.1"),
				Domain: "node-se-p2p.protonvpn.net", Status: 1, X25519PublicKey: "k1",
			}},
		},
		{
			ID: "plain", Name: "SE#PLAIN", ExitCountry: "SE", Load: 2, Status: 1,
			Tier: tierPtr(2), Features: 0,
			Servers: []proton.PhysicalServer{{
				EntryIP: netip.MustParseAddr("10.8.0.2"), ExitIP: netip.MustParseAddr("81.8.0.2"),
				Domain: "node-se-plain.protonvpn.net", Status: 1, X25519PublicKey: "k2",
			}},
		},
	}
}

// Asking Proton for a forwarded port is asking for a P2P server, whether or not
// PORT_FORWARD_ONLY is also set: Proton forwards ports on P2P servers and nowhere
// else, so the quietest non-P2P server would connect and never get a port.
//
// This is a real bug that shipped: only PORT_FORWARD_ONLY was read, so
// VPN_PORT_FORWARDING=on alone left the best candidate on a server that could not
// possibly deliver the port the operator asked for.
func TestPortForwardingAloneIsEnoughToRequireP2P(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwarding = true // VPN_PORT_FORWARDING, *not* PORT_FORWARD_ONLY
	harness.gluetun.portForwardOnly = false
	harness.run(t, func() bool {
		adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted
		return len(adopted) == 1 && adopted[0] == "port_forward_only"
	})

	harness.engine.applyLogicals(mixedP2PLogicals(), false)
	harness.engine.publish()
	snapshot := harness.engine.Snapshot()

	best := snapshot.Selection.Best
	if best == nil {
		t.Fatal("no best candidate")
	}
	if !best.P2P {
		t.Errorf("best candidate is %s (p2p=%v); a non-P2P server cannot receive a forwarded port",
			best.ServerName, best.P2P)
	}
	if best.ServerName != "SE#P2P" {
		t.Errorf("best = %s, want SE#P2P despite it being busier", best.ServerName)
	}
	// The dashboard has to be able to say *which* setting caused this, because the
	// operator never set PORT_FORWARD_ONLY.
	if from := snapshot.Gluetun.PortForwardRequirementFrom; from != "VPN_PORT_FORWARDING" {
		t.Errorf("PortForwardRequirementFrom = %q, want VPN_PORT_FORWARDING", from)
	}
}

// With port forwarding off entirely, nothing is narrowed and the quiet server wins.
func TestNoP2PRequirementWhenPortForwardingIsOff(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwarding = false
	harness.gluetun.portForwardOnly = false
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })

	harness.engine.applyLogicals(mixedP2PLogicals(), false)
	harness.engine.publish()
	snapshot := harness.engine.Snapshot()

	if adopted := snapshot.Gluetun.RequirementsAdopted; len(adopted) != 0 {
		t.Errorf("adopted %v with port forwarding off; nothing should be required", adopted)
	}
	if best := snapshot.Selection.Best; best == nil || best.ServerName != "SE#PLAIN" {
		t.Errorf("best = %v, want the quieter non-P2P server", best)
	}
	if snapshot.CandidatesBlocked != 0 {
		t.Errorf("blocked = %d, want 0 when no requirement is in force", snapshot.CandidatesBlocked)
	}
}

// Servers Gluetun's filters rule out are still listed - otherwise "my quiet
// Stockholm server vanished" has no answer - but they must be visibly unusable and
// impossible to select.
func TestBlockedServersAreListedButNotSelectable(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwardOnly = true
	harness.run(t, func() bool {
		adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted
		return len(adopted) == 1 && adopted[0] == "port_forward_only"
	})

	harness.engine.applyLogicals(mixedP2PLogicals(), false)
	harness.engine.publish()
	snapshot := harness.engine.Snapshot()

	if snapshot.CandidatesBlocked != 1 {
		t.Fatalf("blocked = %d, want the one non-P2P server", snapshot.CandidatesBlocked)
	}
	if snapshot.CandidatesTotal != 1 {
		t.Errorf("candidates_total = %d; blocked servers must not inflate the selectable count",
			snapshot.CandidatesTotal)
	}

	var blocked *CandidateView
	for i, view := range snapshot.Candidates {
		if view.Blocked {
			blocked = &snapshot.Candidates[i]
		}
	}
	if blocked == nil {
		t.Fatal("the non-P2P server is not in the candidate views at all")
	}
	if blocked.ServerName != "SE#PLAIN" {
		t.Errorf("blocked server = %s, want SE#PLAIN", blocked.ServerName)
	}
	if got := blocked.BlockedBy; len(got) != 1 || got[0] != "port_forward_only" {
		t.Errorf("BlockedBy = %v, want [port_forward_only]", got)
	}
	if blocked.Rank != 0 {
		t.Errorf("rank = %d, want 0: a rank implies it can be chosen", blocked.Rank)
	}
	// Scored like everything else, so the row is comparable with the rest of the
	// table rather than an empty stub.
	if blocked.Load != 2 || blocked.Score <= 0 {
		t.Errorf("blocked row should still carry load and score, got load=%d score=%v",
			blocked.Load, blocked.Score)
	}

	// The decisive part: it cannot be switched to, and the error says why. This calls
	// the in-loop method directly, because the public SwitchTo queues a command and
	// the run loop has already been stopped by harness.run.
	err := harness.engine.switchTo(context.Background(), "node-se-plain.protonvpn.net")
	if err == nil {
		t.Fatal("switching to a blocked server succeeded; gluetun would have refused it")
	}
	if !strings.Contains(err.Error(), "port_forward_only") {
		t.Errorf("error %q should name the gluetun setting responsible", err)
	}
}

// The inferred requirement must never be the reason the tunnel has nowhere to go:
// Gluetun would have connected without it, so no port is better than no tunnel.
func TestInferredP2PRequirementIsGivenUpRatherThanStrandingTheTunnel(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwarding = true
	harness.run(t, func() bool {
		adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted
		return len(adopted) == 1 && adopted[0] == "port_forward_only"
	})

	// Only non-P2P servers exist, so requiring P2P would leave nothing at all.
	onlyPlain := mixedP2PLogicals()[1:]
	harness.engine.applyLogicals(onlyPlain, false)
	harness.engine.publish()
	snapshot := harness.engine.Snapshot()

	if best := snapshot.Selection.Best; best == nil || best.ServerName != "SE#PLAIN" {
		t.Fatalf("best = %v, want the only server available", best)
	}
	if adopted := snapshot.Gluetun.RequirementsAdopted; len(adopted) != 0 {
		t.Errorf("adopted %v; the inferred requirement should have been given up", adopted)
	}
}

// An explicit PORT_FORWARD_ONLY is Gluetun's own filter, not our inference, so it
// is kept even when it empties the list: Gluetun would refuse those servers too, and
// pretending otherwise just crashes its VPN loop.
func TestExplicitPortForwardOnlyIsNeverGivenUp(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwardOnly = true
	harness.run(t, func() bool {
		adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted
		return len(adopted) == 1 && adopted[0] == "port_forward_only"
	})

	harness.engine.applyLogicals(mixedP2PLogicals()[1:], false)
	harness.engine.publish()
	snapshot := harness.engine.Snapshot()

	if snapshot.Selection.Best != nil {
		t.Errorf("best = %v, want none: gluetun refuses every server here",
			snapshot.Selection.Best.ServerName)
	}
	if adopted := snapshot.Gluetun.RequirementsAdopted; len(adopted) != 1 {
		t.Errorf("adopted %v, want port_forward_only to be kept", adopted)
	}
}

// Gluetun keeps its server list in memory from startup and offers no route to read
// it back. The one moment it discloses that list is when it refuses a hostname, where
// it enumerates every name it would have accepted. Mining that turns a dead end into
// a working switch: instead of failing, the engine goes to the best server Gluetun
// does know.
func TestARejectionTeachesTheEngineWhichServersGluetunCanUse(t *testing.T) {
	harness := newHarness(t, false, nil)
	// Gluetun is running on an older list: it knows the busier server but not the
	// quiet one this tool would prefer.
	harness.gluetun.knownHostnames = []string{"node-se-known.protonvpn.net"}

	logicals := []proton.LogicalServer{
		{
			ID: "quiet", Name: "SE#QUIET", ExitCountry: "SE", Load: 1, Status: 1,
			Tier: tierPtr(2), Features: 0,
			Servers: []proton.PhysicalServer{{
				EntryIP: netip.MustParseAddr("10.9.0.1"), ExitIP: netip.MustParseAddr("81.9.0.1"),
				Domain: "node-se-unknown.protonvpn.net", Status: 1, X25519PublicKey: "k1",
			}},
		},
		{
			ID: "known", Name: "SE#KNOWN", ExitCountry: "SE", Load: 30, Status: 1,
			Tier: tierPtr(2), Features: 0,
			Servers: []proton.PhysicalServer{{
				EntryIP: netip.MustParseAddr("10.9.0.2"), ExitIP: netip.MustParseAddr("81.9.0.2"),
				Domain: "node-se-known.protonvpn.net", Status: 1, X25519PublicKey: "k2",
			}},
		},
	}

	// Reach a steady state first, then drive the switch directly: the run loop is
	// stopped by harness.run, but the fake Gluetun stays up for the rest of the test.
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	harness.engine.applyLogicals(logicals, false)
	harness.engine.evaluate(context.Background(), "manual", true)

	snapshot := harness.engine.Snapshot()
	if len(snapshot.History) == 0 {
		t.Fatal("no switch was recorded")
	}
	// The quiet server ranks first but Gluetun cannot use it, so the switch has to
	// land on the busier one it does know rather than failing.
	if to := snapshot.History[0].To; to != "node-se-known.protonvpn.net" {
		t.Errorf("switched to %q, want the server gluetun actually knows", to)
	}
	if !snapshot.History[0].Succeeded {
		t.Errorf("the switch failed: %s", snapshot.History[0].Error)
	}
}

// The learned list must be a stopgap, never a lasting restriction: it is a snapshot
// of one moment, and a Gluetun that has restarted knows more. A successful pin proves
// the snapshot is stale, so it is dropped.
func TestTheLearnedListIsDiscardedOnceASwitchSucceeds(t *testing.T) {
	harness := newHarness(t, false, nil)
	engine := harness.engine

	rejection := &gluetunapi.RejectionError{
		KnownHostnames: []string{"a.protonvpn.net", "b.protonvpn.net"},
	}
	engine.learnGluetunHostnames(rejection)
	if len(engine.gluetunKnownHosts) != 2 {
		t.Fatalf("learned %d hostnames, want 2", len(engine.gluetunKnownHosts))
	}
	if engine.gluetunMightKnow("c.protonvpn.net") {
		t.Error("a hostname gluetun excluded should not be attempted")
	}
	if !engine.gluetunMightKnow("a.protonvpn.net") {
		t.Error("a hostname gluetun listed should be attempted")
	}

	engine.forgetGluetunHostnames()
	if !engine.gluetunMightKnow("c.protonvpn.net") {
		t.Error("with nothing learned, every candidate must be attempted again")
	}
}

// Knowing nothing must never narrow the candidate set - that would turn a missing
// answer into a restriction.
func TestNothingLearnedMeansEveryCandidateIsAttempted(t *testing.T) {
	harness := newHarness(t, false, nil)
	if !harness.engine.gluetunMightKnow("anything.protonvpn.net") {
		t.Error("gluetunMightKnow should default to true")
	}
	// A rejection with no list attached teaches nothing, and must not be read as
	// "gluetun knows no servers".
	harness.engine.learnGluetunHostnames(errors.New("no server found for hostname"))
	if !harness.engine.gluetunMightKnow("anything.protonvpn.net") {
		t.Error("a rejection without a list must not restrict anything")
	}
}

// Gluetun applies a selection synchronously - stop, apply, start, then answer - so a
// request sent while its VPN loop is already mid-transition is queued behind that
// transition and the HTTP call blocks. Observed in a real deployment: the loop sat in
// "stopping" for minutes, the settings request timed out after two of them, and
// verification then failed on a tunnel that had never moved.
//
// Waiting for a stable state first turns a two-minute block into a fast, accurate
// error that names the cause.
func TestASwitchWaitsRatherThanPushingIntoAStallingTunnel(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })

	// The engine switches once on startup, so count from there rather than from zero.
	harness.gluetun.mu.Lock()
	pinsBefore := len(harness.gluetun.pinned)
	// Wedge the fake exactly as the real one wedged: permanently "stopping".
	harness.gluetun.status = gluetunapi.StatusStopping
	harness.gluetun.mu.Unlock()

	target := harness.engine.ranked[0]
	start := time.Now()
	_, err := harness.engine.applyTarget(context.Background(), target)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("applying a target to a stalled vpn loop should fail rather than appear to work")
	}
	if !errors.Is(err, gluetunapi.ErrUnavailable) {
		t.Errorf("error = %v, want it classified as unavailable so the engine keeps going", err)
	}
	for _, want := range []string{"stopping", "gluetun-side stall", "restart the gluetun"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
	// It must give up on its own rather than blocking for the mutation timeout.
	if elapsed > stableTunnelWait+10*time.Second {
		t.Errorf("waited %s, want it bounded by stableTunnelWait (%s)", elapsed, stableTunnelWait)
	}
	// And it must not have sent the doomed request.
	harness.gluetun.mu.Lock()
	sent := len(harness.gluetun.pinned) - pinsBefore
	harness.gluetun.mu.Unlock()
	if sent != 0 {
		t.Errorf("%d pin requests were sent into a stalled loop; none should have been", sent)
	}
}

// A transient transition must only delay the switch, never abandon it: Gluetun's own
// health monitor restarts the loop routinely, so treating "starting" as fatal would
// make switching unreliable on a busy tunnel.
func TestASwitchProceedsOnceTheTunnelSettles(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })

	harness.gluetun.mu.Lock()
	pinsBefore := len(harness.gluetun.pinned)
	harness.gluetun.status = gluetunapi.StatusStarting
	harness.gluetun.mu.Unlock()

	// Settle it shortly after the switch begins, the way a real transition ends.
	go func() {
		time.Sleep(3 * time.Second)
		harness.gluetun.mu.Lock()
		harness.gluetun.status = gluetunapi.StatusRunning
		harness.gluetun.mu.Unlock()
	}()

	target := harness.engine.ranked[0]
	if _, err := harness.engine.applyTarget(context.Background(), target); err != nil {
		t.Fatalf("applyTarget should have waited and then succeeded: %v", err)
	}
	harness.gluetun.mu.Lock()
	pinned := append([]string(nil), harness.gluetun.pinned[pinsBefore:]...)
	harness.gluetun.mu.Unlock()
	if len(pinned) != 1 || pinned[0] != target.Candidate.Hostname {
		t.Errorf("pinned since the wait = %v, want just the target once the loop settled", pinned)
	}
}

// Skipping every candidate is not success. A learned hostname set that excludes all
// of them would end tryCandidates with no attempts, no rejections and no error, which
// the caller reads as "handled" - so the switch silently never happens and nothing
// ever says why. Found by review, not by a failing deployment.
func TestSkippingEveryCandidateIsNotReportedAsSuccess(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	// Gluetun has disclosed a list containing none of our candidates.
	engine.learnGluetunHostnames(&gluetunapi.RejectionError{
		KnownHostnames: []string{"somewhere-else.protonvpn.net"},
	})
	// Refreshing Gluetun's own list is what the caller falls back to, so disable it
	// here to isolate the reporting decision.
	engine.cfg.Gluetun.RefreshServersOnReject = false

	switched := engine.tryCandidates(context.Background(),
		engine.ranked, "", scoring.Scored{}, false, "manual")
	if switched {
		t.Error("tryCandidates reported success having attempted nothing at all")
	}
}

// End to end: the operator must be told, rather than left with a button that appears
// to work and does nothing.
func TestEveryCandidateSkippedFlagsGluetunRestart(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	engine.learnGluetunHostnames(&gluetunapi.RejectionError{
		KnownHostnames: []string{"somewhere-else.protonvpn.net"},
	})
	engine.cfg.Gluetun.RefreshServersOnReject = false

	engine.performSwitch(context.Background(), "", scoring.Scored{}, false, "manual")

	if !engine.Snapshot().Selection.NeedsGluetunRestart {
		t.Error("nothing was attempted and nothing was flagged; the failure is invisible")
	}
}

// Refreshing Gluetun's own server list replaces its in-memory set, so anything it
// disclosed beforehand is stale. Keeping it would make the retry skip exactly the
// candidates the refresh was meant to unlock.
func TestRefreshingGluetunsListForgetsWhatItDisclosed(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	engine.learnGluetunHostnames(&gluetunapi.RejectionError{
		KnownHostnames: []string{"stale.protonvpn.net"},
	})
	if len(engine.gluetunKnownHosts) == 0 {
		t.Fatal("nothing was learned, so the test proves nothing")
	}

	if !engine.refreshGluetunServerList(context.Background()) {
		t.Fatal("the fake should accept an updater refresh")
	}
	if len(engine.gluetunKnownHosts) != 0 {
		t.Errorf("still holding %d disclosed hostnames after gluetun refreshed its list",
			len(engine.gluetunKnownHosts))
	}
}

// Giving up the inferred P2P requirement must be remembered. It is re-derived from
// Gluetun's settings on every health check and VPN_PORT_FORWARDING is still on, so
// without a latch it would be re-adopted, empty the catalog, be dropped again, and
// rebuild the whole catalog on every tick for ever.
func TestTheAbandonedPortForwardInferenceIsNotReadopted(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwarding = true
	harness.run(t, func() bool {
		adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted
		return len(adopted) == 1 && adopted[0] == "port_forward_only"
	})
	engine := harness.engine

	// Only non-P2P servers exist, so the inference has to be given up.
	engine.applyLogicals(mixedP2PLogicals()[1:], false)
	if engine.requirements.PortForward {
		t.Fatal("the inferred requirement should have been given up")
	}
	if !engine.portForwardInferenceAbandoned {
		t.Fatal("giving it up was not recorded")
	}

	// Now the next health check re-reads Gluetun's settings, which still say port
	// forwarding is on. That must not bring the requirement back.
	for tick := range 3 {
		engine.updateRequirements(gluetunapi.Requirements{PortForwardingRequested: true})
		if engine.requirements.PortForward {
			t.Fatalf("tick %d re-adopted the requirement, restarting the oscillation", tick+1)
		}
	}

	// An explicit PORT_FORWARD_ONLY is Gluetun's own filter, not our inference, and
	// must still be honoured even after the inference was abandoned.
	engine.updateRequirements(gluetunapi.Requirements{
		PortForward: true, PortForwardingRequested: true,
	})
	if !engine.requirements.PortForward {
		t.Error("an explicit PORT_FORWARD_ONLY must always be adopted")
	}
	if engine.portForwardReason != "PORT_FORWARD_ONLY" {
		t.Errorf("reason = %q, want PORT_FORWARD_ONLY", engine.portForwardReason)
	}
}

// Blocked rows exist to be compared against selectable ones, so their load must be as
// fresh. Loads were only ever applied to the candidate set, leaving blocked rows
// frozen at whatever the last full list fetch said - potentially hours stale next to
// figures refreshed every few minutes.
func TestBlockedServersGetLoadUpdatesToo(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwardOnly = true
	harness.run(t, func() bool {
		adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted
		return len(adopted) == 1 && adopted[0] == "port_forward_only"
	})
	engine := harness.engine

	engine.applyLogicals(mixedP2PLogicals(), false)
	if len(engine.blocked) != 1 {
		t.Fatalf("blocked = %d, want the one non-P2P server", len(engine.blocked))
	}
	if load := engine.blocked[0].Load; load != 2 {
		t.Fatalf("blocked load = %d, want the value from the list (2)", load)
	}

	// A loads refresh moves the blocked server from 2% to 77%.
	engine.applyLoads([]proton.ServerLoad{
		{ID: "plain", Load: 77, Status: 1},
		{ID: "p2p", Load: 41, Status: 1},
	})

	if load := engine.blocked[0].Load; load != 77 {
		t.Errorf("blocked load = %d after a refresh, want 77: the row is stale", load)
	}
	engine.publish()
	for _, view := range engine.Snapshot().Candidates {
		if view.Blocked && view.Load != 77 {
			t.Errorf("the published blocked row shows %d%%, want 77%%", view.Load)
		}
	}
}

// A disabled blocked server must leave the list, exactly as a disabled candidate does.
func TestDisabledBlockedServersAreDropped(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.gluetun.portForwardOnly = true
	harness.run(t, func() bool {
		adopted := harness.engine.Snapshot().Gluetun.RequirementsAdopted
		return len(adopted) == 1 && adopted[0] == "port_forward_only"
	})
	engine := harness.engine

	engine.applyLogicals(mixedP2PLogicals(), false)
	engine.applyLoads([]proton.ServerLoad{{ID: "plain", Load: 5, Status: 0}})
	if len(engine.blocked) != 0 {
		t.Errorf("blocked = %d, want 0: Proton took that server out of service", len(engine.blocked))
	}
}

// "Nothing is happening" is the state an operator most often needs explained, and the
// reasoning existed only as a debug log line. Publishing it is what lets the dashboard
// say why it stayed put.
func TestWhyNoSwitchHappenedIsPublished(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		// A threshold nothing can beat, so the decision is always "stay".
		cfg.Switch.MinImprovement = 99
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	engine.applyLogicals(mixedP2PLogicals(), false)
	// Put the tunnel on the busier server so a better one exists but is not better
	// enough - the case the improvement threshold is for.
	engine.state.update(func(state *persistedState) {
		state.PinnedHostname = "node-se-p2p.protonvpn.net"
	})
	engine.evaluate(context.Background(), "manual", false)

	explanation := engine.Snapshot().Selection.Explanation
	if explanation == "" {
		t.Fatal("no explanation was published, so the dashboard cannot say why nothing happened")
	}
	if !strings.Contains(explanation, "99.000") {
		t.Errorf("explanation = %q, want it to name the threshold that blocked the switch", explanation)
	}

	// And it must be cleared once a switch does happen, or the page keeps explaining
	// a decision that has been superseded.
	engine.evaluate(context.Background(), "manual", true)
	if got := engine.Snapshot().Selection.Explanation; got != "" {
		t.Errorf("explanation = %q after a forced switch, want it cleared", got)
	}
}

// The 45-second settle wait is invisible otherwise, and an idle-looking page during it
// is indistinguishable from the Gluetun hang it exists to detect.
func TestWaitingForTheTunnelToSettleIsVisible(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	harness.gluetun.mu.Lock()
	harness.gluetun.status = gluetunapi.StatusStopping
	harness.gluetun.mu.Unlock()

	engine.setActivity("switching server")

	observed := make(chan string, 1)
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if activity := engine.Snapshot().Activity; strings.Contains(activity, "settle") {
				observed <- activity
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		observed <- ""
	}()

	_, _ = engine.applyTarget(context.Background(), engine.ranked[0])

	activity := <-observed
	if activity == "" {
		t.Fatal("the settle wait was never published, so the page looks idle for 45s")
	}
	if !strings.Contains(activity, "stopping") {
		t.Errorf("activity = %q, want it to name the state being waited on", activity)
	}

	// The caller's own activity has to come back, not be left describing a finished wait.
	if got := engine.Snapshot().Activity; got != "switching server" {
		t.Errorf("activity = %q after the wait, want the caller's own restored", got)
	}
}

// fakeQBittorrent stands in for a qBittorrent Web API, so the busy/idle transitions
// can be driven precisely.
type fakeQBittorrent struct {
	mu       sync.Mutex
	down, up uint64
	failing  bool
	requests int
}

func (f *fakeQBittorrent) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/app/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "v5.2.2")
	})
	mux.HandleFunc("GET /api/v2/transfer/info", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		down, up, failing := f.down, f.up, f.failing
		f.requests++
		f.mu.Unlock()
		if failing {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"dl_info_speed":%d,"up_info_speed":%d,"dl_info_data":1,`+
			`"up_info_data":2,"connection_status":"connected"}`, down, up)
	})
	return mux
}

func (f *fakeQBittorrent) set(down, up uint64) {
	f.mu.Lock()
	f.down, f.up = down, up
	f.mu.Unlock()
}

func (f *fakeQBittorrent) fail(failing bool) {
	f.mu.Lock()
	f.failing = failing
	f.mu.Unlock()
}

// withQBittorrent attaches a fake qBittorrent to a harness and returns it.
func withQBittorrent(t *testing.T, cfg *config.Config, down, up uint64) *fakeQBittorrent {
	t.Helper()
	fake := &fakeQBittorrent{down: down, up: up}
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	cfg.QBittorrent = config.QBittorrent{
		URL:            server.URL,
		APIKey:         "qbt_" + strings.Repeat("k", 28),
		Interval:       50 * time.Millisecond,
		RequestTimeout: 2 * time.Second,
		BusyDownload:   1 << 20,
		BusyUpload:     1 << 20,
	}
	return fake
}

// The whole point: a switch must not interrupt a transfer in progress.
func TestATransferInProgressDefersSwitching(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 8<<20, 0) // 8 MB/s down, well over the threshold
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine

	engine.applyLogicals(mixedP2PLogicals(), false)
	engine.evaluate(context.Background(), "scheduled", false)

	explanation := engine.Snapshot().Selection.Explanation
	if !strings.Contains(explanation, "transfer is in progress") {
		t.Errorf("explanation = %q, want it to say a transfer deferred the switch", explanation)
	}
	transfer := engine.Snapshot().Transfer
	if !transfer.Busy {
		t.Error("Busy should be true at 8 MB/s against a 1 MiB/s threshold")
	}
	if transfer.DownloadSpeed != 8<<20 {
		t.Errorf("DownloadSpeed = %d, want %d", transfer.DownloadSpeed, uint64(8<<20))
	}
	if !transfer.Configured || !transfer.Reachable {
		t.Errorf("transfer should be configured and reachable: %+v", transfer)
	}
	_ = fake
}

// An explicit instruction is the operator's decision, and must not be overridden.
func TestAForcedSwitchIsNotDeferredByATransfer(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		withQBittorrent(t, cfg, 8<<20, 0)
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine

	verdict := engine.decide(scoring.Scored{}, false, engine.ranked[0], true)
	if !verdict.shouldSwitch || verdict.reason != "manual" {
		t.Errorf("a forced switch should proceed despite a transfer: %+v", verdict)
	}
}

// The two directions are independent: protecting uploads must not require protecting
// downloads, and vice versa.
func TestDownloadAndUploadThresholdsAreIndependent(t *testing.T) {
	for _, testCase := range []struct {
		name             string
		down, up         uint64
		busyDown, busyUp uint64
		wantBusy         bool
	}{
		{"download over, upload under", 5 << 20, 0, 1 << 20, 1 << 20, true},
		{"upload over, download under", 0, 5 << 20, 1 << 20, 1 << 20, true},
		{"both under", 100, 100, 1 << 20, 1 << 20, false},
		{"download over but download not a trigger", 5 << 20, 0, 0, 1 << 20, false},
		{"upload over but upload not a trigger", 0, 5 << 20, 1 << 20, 0, false},
		{"exactly at the threshold counts as busy", 1 << 20, 0, 1 << 20, 1 << 20, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newHarness(t, false, func(cfg *config.Config) {
				withQBittorrent(t, cfg, testCase.down, testCase.up)
				cfg.QBittorrent.BusyDownload = testCase.busyDown
				cfg.QBittorrent.BusyUpload = testCase.busyUp
			})
			harness.run(t, func() bool {
				return !harness.engine.Snapshot().Transfer.LastCheck.IsZero()
			})
			if got := harness.engine.Snapshot().Transfer.Busy; got != testCase.wantBusy {
				t.Errorf("Busy = %v, want %v (%d down / %d up against %d/%d)",
					got, testCase.wantBusy, testCase.down, testCase.up,
					testCase.busyDown, testCase.busyUp)
			}
		})
	}
}

// The fail-safe that matters most. "I could not find out" must never be treated as
// "nothing is happening", or the feature breaks the transfer it exists to protect.
func TestAnUnreachableQBittorrentKeepsDeferring(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 8<<20, 0)
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine

	// qBittorrent goes away while the transfer is still running.
	fake.fail(true)
	engine.refreshTransfer(context.Background(), "test")

	transfer := engine.Snapshot().Transfer
	if transfer.Reachable {
		t.Error("Reachable should be false after a failed read")
	}
	if !transfer.Busy {
		t.Fatal("Busy was cleared by a failed read; that would break the transfer")
	}

	blocked, reason := engine.transferBlocksSwitch()
	if !blocked {
		t.Error("switching should still be deferred on the last known rates")
	}
	if !strings.Contains(reason, "last reading") {
		t.Errorf("reason = %q, want it to admit the reading is stale", reason)
	}
}

// The safety valve: a permanently busy tunnel must not be stuck on a degrading server
// for ever, when the operator has asked for a bound.
func TestTheDeferralCanBeBounded(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		withQBittorrent(t, cfg, 8<<20, 0)
		cfg.QBittorrent.MaxDefer = time.Hour
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine

	if blocked, _ := engine.transferBlocksSwitch(); !blocked {
		t.Fatal("should be deferring while inside the bound")
	}

	// Pretend the transfer has been running longer than the bound allows.
	engine.transferBusySince = time.Now().Add(-2 * time.Hour)
	if blocked, _ := engine.transferBlocksSwitch(); blocked {
		t.Error("past MaxDefer the switch should proceed anyway")
	}
}

// With no bound configured, an active transfer always wins - which is the default,
// because "do not break the transfer" is the point.
func TestWithoutABoundATransferAlwaysWins(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		withQBittorrent(t, cfg, 8<<20, 0)
		cfg.QBittorrent.MaxDefer = 0
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine

	engine.transferBusySince = time.Now().Add(-72 * time.Hour)
	if blocked, _ := engine.transferBlocksSwitch(); !blocked {
		t.Error("with MaxDefer unset a transfer should defer switching indefinitely")
	}
}

// Not configured must mean not consulted: no requests, and nothing deferred.
func TestWithoutQBittorrentNothingIsDeferred(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	if blocked, _ := engine.transferBlocksSwitch(); blocked {
		t.Error("nothing should be deferred when qBittorrent is not configured")
	}
	if transfer := engine.Snapshot().Transfer; transfer.Configured {
		t.Error("Transfer.Configured should be false, so the dashboard hides the card")
	}
	if got := engine.transferInterval(); got != 0 {
		t.Errorf("transferInterval = %s, want 0 so the ticker never fires", got)
	}
}

// A transfer that quietens down must release the hold, or one busy moment would
// disable switching until a restart.
func TestSwitchingResumesWhenTheTransferFinishes(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 8<<20, 0)
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine

	fake.set(1024, 512) // the transfer finishes
	engine.refreshTransfer(context.Background(), "test")

	transfer := engine.Snapshot().Transfer
	if transfer.Busy {
		t.Error("Busy should clear once the rates drop below the thresholds")
	}
	if !transfer.BusySince.IsZero() {
		t.Error("BusySince should be reset, so a later transfer measures its own duration")
	}
	if blocked, _ := engine.transferBlocksSwitch(); blocked {
		t.Error("switching should no longer be deferred")
	}
}

func TestRateFormatting(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		bytes uint64
		want  string
	}{
		{0, "0 B/s"},
		{999, "999 B/s"},
		{1000, "1.0 kB/s"},
		{1_500_000, "1.5 MB/s"},
		{13_107_200, "13.1 MB/s"},
		{2_500_000_000, "2.5 GB/s"},
	} {
		if got := formatRate(testCase.bytes); got != testCase.want {
			t.Errorf("formatRate(%d) = %q, want %q", testCase.bytes, got, testCase.want)
		}
	}
}

// The gate has to come before every reason to move, not after some of them.
//
// "The current server is unknown" is a reason to switch, and it used to be evaluated
// first, so an active transfer was silently bypassed on exactly the path most likely
// to fire. An unidentified current server is no reason to break a transfer that is
// demonstrably flowing.
func TestAnUnknownCurrentServerDoesNotBypassTheTransferGate(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		withQBittorrent(t, cfg, 8<<20, 0)
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine

	// haveCurrent=false is the path that used to win outright.
	verdict := engine.decide(scoring.Scored{}, false, engine.ranked[0], false)
	if verdict.shouldSwitch {
		t.Errorf("switched with a transfer running: %+v", verdict)
	}
	if !strings.Contains(verdict.explanation, "transfer is in progress") {
		t.Errorf("explanation = %q, want the transfer to be the stated reason", verdict.explanation)
	}
}

// Nor may the load trigger bypass it: moving off an overloaded server is still an
// interruption, and a slow transfer beats a broken one.
func TestTheLoadTriggerDoesNotBypassTheTransferGate(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		withQBittorrent(t, cfg, 8<<20, 0)
		cfg.Switch.LoadTrigger = 50
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine
	engine.applyLogicals(mixedP2PLogicals(), false)

	busy := scoring.Scored{Candidate: catalog.Candidate{
		Hostname: "node-busy.protonvpn.net", ServerName: "SE#BUSY", Load: 95,
	}, Score: 0.9}
	quiet := engine.ranked[0]

	verdict := engine.decide(busy, true, quiet, false)
	if verdict.shouldSwitch {
		t.Errorf("the load trigger bypassed the transfer gate: %+v", verdict)
	}
}

// The one case where deferring is harmful: a crashed tunnel has no transfer left to
// protect, only a recovery to delay.
func TestACrashedTunnelIsNotDeferred(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		withQBittorrent(t, cfg, 8<<20, 0)
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine

	if blocked, _ := engine.transferBlocksSwitch(); !blocked {
		t.Fatal("should defer while the tunnel is running")
	}

	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.Status = gluetunapi.StatusCrashed
	})
	if blocked, _ := engine.transferBlocksSwitch(); blocked {
		t.Error("a crashed tunnel must not be held back: nothing is flowing through it")
	}
}
