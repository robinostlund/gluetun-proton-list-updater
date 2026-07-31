package engine

import (
	"bytes"
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
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/catalog"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/config"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/gluetunapi"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/proton"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/qbittorrent"
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
	// Identified from Gluetun's own selection, which is exact: the pin was applied and
	// accepted, so there is nothing to infer. This used to read "public-ip" - the exit
	// address matched, which is a weaker signal and a slower one, and it left a window in
	// which the tunnel's own server was unidentifiable straight after being chosen.
	if snapshot.Selection.CurrentSource != "pinned" {
		t.Errorf("CurrentSource = %q, want pinned", snapshot.Selection.CurrentSource)
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

// With GLUETUN_SERVERS_ONLY_ALLOWED_COUNTRIES the file is narrowed to the allow-list.
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
// the tunnel wherever Gluetun put it for up to SWITCHING_EVALUATION_INTERVAL - which
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
// manyLogicals builds count listed servers, so a test can control whether Proton's
// list is long enough to be plausible evidence about what still exists.
func manyLogicals(t *testing.T, count int) []proton.LogicalServer {
	t.Helper()
	logicals := make([]proton.LogicalServer, 0, count)
	for i := range count {
		logicals = append(logicals, proton.LogicalServer{
			ID: fmt.Sprintf("l%02d", i), Name: fmt.Sprintf("SE#%d", i),
			ExitCountry: "SE", Load: 30, Status: 1, Tier: tierPtr(2),
			Features: proton.FeatureP2P,
			Servers: []proton.PhysicalServer{{
				EntryIP: netip.MustParseAddr(fmt.Sprintf("10.9.%d.1", i)),
				ExitIP:  netip.MustParseAddr(fmt.Sprintf("81.9.%d.1", i)),
				Domain:  fmt.Sprintf("node-se-%02d.protonvpn.net", i),
				Status:  1, X25519PublicKey: "k",
			}},
		})
	}
	// The fixture the other tests use, so a seeded record can name a host that is
	// genuinely in the list.
	return append(logicals, mixedP2PLogicals()...)
}

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
	//
	// Gluetun has to agree that it is there, not just this tool's own memory of asking:
	// a readable Gluetun reporting no hostname selection disproves the remembered value,
	// which would make this "current server unknown" and switch regardless of any
	// threshold. That is the point of TestARestartedGluetunDoesNotLeaveAStaleCurrentServer.
	pinCurrent(t, engine, "node-se-p2p.protonvpn.net", time.Hour)
	engine.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Gluetun.SettingsReadable = true })
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
	// prefsFailing fails only the port-settings call. The two are separate requests
	// and fail independently in practice - a key refused for /api/v2/app/preferences
	// while the rates keep arriving - so the fake has to be able to do that too.
	prefsFailing bool
	prefsCalls   int
	requests     int
	listenPort   uint16
	randomPort   bool
	connection   string
}

func (f *fakeQBittorrent) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/app/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "v5.2.2")
	})
	mux.HandleFunc("GET /api/v2/app/preferences", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		listen, random, failing := f.listenPort, f.randomPort, f.prefsFailing
		f.prefsCalls++
		f.mu.Unlock()
		if failing {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, `{"listen_port":%d,"random_port":%t,"upnp":false}`, listen, random)
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
		f.mu.Lock()
		connection := f.connection
		f.mu.Unlock()
		if connection == "" {
			connection = "connected"
		}
		fmt.Fprintf(w, `{"dl_info_speed":%d,"up_info_speed":%d,"dl_info_data":1,`+
			`"up_info_data":2,"connection_status":%q}`, down, up, connection)
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
	fake := &fakeQBittorrent{down: down, up: up, listenPort: 6881}
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)

	cfg.QBittorrent = config.QBittorrent{
		URL:    server.URL,
		APIKey: "qbt_" + strings.Repeat("k", 28),
		// Deliberately a combination the real validation accepts: the timeout must be
		// shorter than the interval, or a slow answer delays the next reading.
		Interval:       200 * time.Millisecond,
		RequestTimeout: 100 * time.Millisecond,
		BusyDownload:   1 << 20,
		BusyUpload:     1 << 20,
	}
	return fake
}

// The whole point: a switch must not interrupt a transfer in progress.
func TestATransferInProgressDefersSwitching(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		withQBittorrent(t, cfg, 8<<20, 0) // 8 MB/s down, well over the threshold
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

// The two failure modes are deliberately asymmetric, and the difference is the whole
// safety argument, so it is pinned here.
//
// Never having had a reading falls open: a wrong URL or key must not freeze the tunnel
// on one server for ever. Having had one and then losing contact falls safe: a transfer
// running a moment ago is very likely still running.
func TestAQBittorrentThatNeverAnsweredFallsOpen(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 8<<20, 0)
	})
	// Broken from the very first request, so no reading is ever obtained.
	fake.fail(true)

	harness.run(t, func() bool {
		return harness.engine.Snapshot().Transfer.LastError != ""
	})
	engine := harness.engine

	transfer := engine.Snapshot().Transfer
	if transfer.HasReading {
		t.Error("HasReading should be false when qBittorrent has never answered")
	}
	if transfer.Busy {
		t.Error("Busy should be false with no reading at all")
	}
	// Switching does wait briefly for a first answer - see
	// TestSwitchingWaitsForQBittorrentsFirstAnswer, which is the case a restart hits - but
	// the wait is bounded, and what matters here is that it ends. A wrong URL or key must
	// not freeze selection for ever.
	engine.startedAt = time.Now().Add(-firstReadingGrace - time.Minute)
	if blocked, _ := engine.transferBlocksSwitch(); blocked {
		t.Error("a qBittorrent that never answered must not freeze switching indefinitely")
	}

	// And once it does answer with a transfer running, it starts deferring.
	fake.fail(false)
	engine.refreshTransfer(context.Background(), "test")
	if !engine.Snapshot().Transfer.HasReading {
		t.Error("HasReading should be true after a successful read")
	}
	if blocked, _ := engine.transferBlocksSwitch(); !blocked {
		t.Error("should defer once a transfer is actually observed")
	}
}

// "Not busy" and "never measured" must be distinguishable in the snapshot, or the
// dashboard has to claim the tunnel is idle when nobody has looked.
func TestNoReadingIsDistinguishableFromIdle(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		withQBittorrent(t, cfg, 100, 100) // well under the thresholds: genuinely idle
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })

	transfer := harness.engine.Snapshot().Transfer
	if transfer.Busy {
		t.Error("Busy should be false at 100 B/s")
	}
	if !transfer.HasReading {
		t.Error("HasReading should be true: this is a measured idle, not an unmeasured one")
	}
}

// A stale explanation misattributes. If an evaluation bails out before deciding
// anything, an explanation from an earlier, different situation would stay on the
// dashboard - "not switching while a transfer is in progress" long after the transfer
// finished. Every path out of evaluate has to set one.
func TestEveryEvaluationPathSetsAnExplanation(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		withQBittorrent(t, cfg, 8<<20, 0)
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.Busy })
	engine := harness.engine
	engine.applyLogicals(mixedP2PLogicals(), false)

	// Establish a deferral, so there is something stale to leak.
	engine.evaluate(context.Background(), "test", false)
	if got := engine.Snapshot().Selection.Explanation; !strings.Contains(got, "transfer is in progress") {
		t.Fatalf("expected a transfer deferral first, got %q", got)
	}

	for _, testCase := range []struct {
		name    string
		arrange func()
		want    string
	}{
		{
			name:    "gluetun unreachable",
			arrange: func() { engine.mutateSnapshot(func(s *Snapshot) { s.Gluetun.Reachable = false }) },
			want:    "unreachable",
		},
		{
			name: "tunnel mid-transition",
			arrange: func() {
				engine.mutateSnapshot(func(s *Snapshot) {
					s.Gluetun.Reachable = true
					s.Gluetun.Status = gluetunapi.StatusStopping
				})
			},
			want: "not a state it can be moved from",
		},
		{
			name: "provider mismatch",
			arrange: func() {
				engine.mutateSnapshot(func(s *Snapshot) {
					s.Gluetun.Status = gluetunapi.StatusRunning
					s.Gluetun.ProviderMismatch = true
				})
			},
			want: "not configured for ProtonVPN",
		},
		{
			name: "reconnect mode none",
			arrange: func() {
				engine.mutateSnapshot(func(s *Snapshot) { s.Gluetun.ProviderMismatch = false })
				engine.cfg.Switch.Mode = config.ReconnectNone
			},
			want: `mode is "none"`,
		},
		{
			name: "no candidates",
			arrange: func() {
				engine.cfg.Switch.Mode = config.ReconnectSettings
				engine.ranked = nil
			},
			want: "no candidate servers",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// Plant a stale explanation from a different situation each time.
			engine.mutateSnapshot(func(s *Snapshot) {
				s.Selection.Explanation = "STALE: a transfer that finished long ago"
			})
			testCase.arrange()
			engine.evaluate(context.Background(), "test", false)

			got := engine.Snapshot().Selection.Explanation
			if strings.Contains(got, "STALE") {
				t.Errorf("the stale explanation survived: %q", got)
			}
			if !strings.Contains(got, testCase.want) {
				t.Errorf("explanation = %q, want it to mention %q", got, testCase.want)
			}
		})
	}
}

// Whether a forwarded port actually reaches qBittorrent is not something either side
// reports on its own. Gluetun knows which port Proton forwarded; qBittorrent knows
// which port it listens on and whether anything is arriving. The case worth catching
// is the one neither calls a problem: forwarding succeeds, qBittorrent runs happily,
// and the ports differ - so every incoming connection goes nowhere.
func TestPortForwardingVerdict(t *testing.T) {
	enabled, disabled := true, false

	for _, testCase := range []struct {
		name        string
		listenPort  uint16
		randomPort  bool
		connection  string
		forwarded   []uint16
		pfEnabled   *bool
		wantVerdict string
		wantDetail  string
	}{
		{
			name: "ports agree and peers are arriving", listenPort: 55019,
			connection: "connected", forwarded: []uint16{55019}, pfEnabled: &enabled,
			wantVerdict: "working", wantDetail: "55019",
		},
		{
			name: "ports disagree - the silent failure", listenPort: 6881,
			connection: "connected", forwarded: []uint16{55019}, pfEnabled: &enabled,
			wantVerdict: "mismatch", wantDetail: "listening on 6881",
		},
		{
			name: "ports agree but nothing is arriving", listenPort: 55019,
			connection: "firewalled", forwarded: []uint16{55019}, pfEnabled: &enabled,
			wantVerdict: "unreachable", wantDetail: "firewalled",
		},
		{
			name: "random port will drift out of match", listenPort: 55019, randomPort: true,
			connection: "connected", forwarded: []uint16{55019}, pfEnabled: &enabled,
			wantVerdict: "mismatch", wantDetail: "random listening port",
		},
		{
			name: "gluetun is not asking for a port at all", listenPort: 6881,
			connection: "firewalled", pfEnabled: &disabled,
			wantVerdict: "not requested", wantDetail: "not asking",
		},
		{
			name: "no peers yet, so nothing can be inferred", listenPort: 55019,
			connection: "disconnected", forwarded: []uint16{55019}, pfEnabled: &enabled,
			wantVerdict: "unknown",
		},
		{
			name: "port forwarding on but no port yet", listenPort: 55019,
			connection: "firewalled", pfEnabled: &enabled,
			wantVerdict: "unreachable",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var fake *fakeQBittorrent
			harness := newHarness(t, false, func(cfg *config.Config) {
				fake = withQBittorrent(t, cfg, 0, 0)
			})
			fake.mu.Lock()
			fake.listenPort, fake.randomPort, fake.connection =
				testCase.listenPort, testCase.randomPort, testCase.connection
			fake.mu.Unlock()

			harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })
			engine := harness.engine

			engine.mutateSnapshot(func(snapshot *Snapshot) {
				snapshot.Gluetun.ForwardedPorts = testCase.forwarded
				snapshot.Gluetun.PortForwardingEnabled = testCase.pfEnabled
			})

			verdict, detail := engine.portForwardingVerdict(engine.Snapshot().Gluetun)
			if verdict != testCase.wantVerdict {
				t.Errorf("verdict = %q, want %q (detail: %s)", verdict, testCase.wantVerdict, detail)
			}
			if testCase.wantDetail != "" && !strings.Contains(detail, testCase.wantDetail) {
				t.Errorf("detail = %q, want it to mention %q", detail, testCase.wantDetail)
			}
		})
	}
}

// Before qBittorrent has answered there is nothing to say, and claiming otherwise
// would be the same unmeasured-assertion problem as reporting an idle tunnel.
func TestPortForwardingIsUnknownBeforeQBittorrentAnswers(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
	})
	fake.fail(true)
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.LastError != "" })

	verdict, detail := harness.engine.portForwardingVerdict(harness.engine.Snapshot().Gluetun)
	if verdict != "unknown" {
		t.Errorf("verdict = %q, want unknown before any reading", verdict)
	}
	if !strings.Contains(detail, "not answered yet") {
		t.Errorf("detail = %q, want it to say why", detail)
	}
}

// The verdict depends on Gluetun's forwarded port, which arrives on a different tick
// from the qBittorrent reading. If it were only recomputed when qBittorrent is polled,
// it would lag a newly forwarded port by up to a full interval.
func TestTheVerdictIsRecomputedWhenGluetunsPortChanges(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
	})
	fake.mu.Lock()
	fake.listenPort, fake.connection = 55019, "connected"
	fake.mu.Unlock()

	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })
	engine := harness.engine

	enabled := true
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.ForwardedPorts = []uint16{6881} // disagrees with qBittorrent
		snapshot.Gluetun.PortForwardingEnabled = &enabled
	})
	// publish() is what runs after a Gluetun health check.
	engine.publish()
	if got := engine.Snapshot().Transfer.PortForwarding; got != "mismatch" {
		t.Errorf("PortForwarding = %q, want mismatch after publish()", got)
	}

	// Now Gluetun's port comes to agree, without any new qBittorrent reading.
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.ForwardedPorts = []uint16{55019}
	})
	engine.publish()
	if got := engine.Snapshot().Transfer.PortForwarding; got != "working" {
		t.Errorf("PortForwarding = %q, want working once the ports agree", got)
	}
}

// The reason the window exists. Traffic is bursty: a torrent that is plainly active
// drops to nothing between pieces, and a poll landing in one of those dips used to
// report the tunnel idle and let a switch through mid-transfer.
func TestABurstyTransferStaysBusyThroughItsDips(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
		cfg.QBittorrent.BusyDownload = 2 << 20 // 2 MiB/s
		cfg.QBittorrent.BusyUpload = 0
		cfg.QBittorrent.BusyWindow = time.Hour // long enough that nothing ages out here
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })
	engine := harness.engine

	// A transfer running well above the threshold, sampled a few times.
	for range 4 {
		fake.set(8<<20, 0)
		engine.refreshTransfer(context.Background(), "test")
	}
	if !engine.Snapshot().Transfer.Busy {
		t.Fatal("should be busy at 8 MiB/s")
	}

	// Now a dip to nothing - the sample that used to clear the hold.
	fake.set(0, 0)
	engine.refreshTransfer(context.Background(), "test")

	if !engine.Snapshot().Transfer.Busy {
		t.Error("a single dip to 0 cleared the hold; that is the interruption this prevents")
	}
	if blocked, reason := engine.transferBlocksSwitch(); !blocked {
		t.Errorf("switching was allowed during a dip: %s", reason)
	}
	// The published average has to be the deciding figure, not the latest reading.
	transfer := engine.Snapshot().Transfer
	if transfer.DownloadSpeed != 0 {
		t.Errorf("DownloadSpeed = %d, want the latest reading (0)", transfer.DownloadSpeed)
	}
	if transfer.AverageDownload == 0 {
		t.Error("AverageDownload should still be well above zero")
	}
}

// A transfer that genuinely finishes must release the hold once its samples age out,
// or one busy moment would defer switching for ever.
func TestTheAverageFallsAwayOnceTheTransferReallyStops(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
		cfg.QBittorrent.BusyDownload = 2 << 20
		cfg.QBittorrent.BusyUpload = 0
		cfg.QBittorrent.BusyWindow = time.Hour
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })
	engine := harness.engine

	fake.set(8<<20, 0)
	engine.refreshTransfer(context.Background(), "test")
	if !engine.Snapshot().Transfer.Busy {
		t.Fatal("should be busy")
	}

	// Age the busy samples out of the window, then keep reading zeroes.
	for i := range engine.transferSamples {
		engine.transferSamples[i].at = time.Now().Add(-2 * time.Hour)
	}
	fake.set(0, 0)
	engine.refreshTransfer(context.Background(), "test")

	if engine.Snapshot().Transfer.Busy {
		t.Error("the hold should release once the busy samples have aged out")
	}
}

// Samples are pruned relative to the newest reading, not to now. Measured from now, an
// unreachable qBittorrent would drain the window until the average fell below the
// threshold and a switch was allowed - silently undoing the fail-safe.
func TestAnUnreachableQBittorrentDoesNotDrainTheWindow(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
		cfg.QBittorrent.BusyDownload = 2 << 20
		cfg.QBittorrent.BusyUpload = 0
		cfg.QBittorrent.BusyWindow = 500 * time.Millisecond // tiny, so "now" would drain it
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })
	engine := harness.engine

	fake.set(8<<20, 0)
	engine.refreshTransfer(context.Background(), "test")
	if !engine.Snapshot().Transfer.Busy {
		t.Fatal("should be busy")
	}
	samples := len(engine.transferSamples)

	// qBittorrent goes away. Well past the window, nothing may be dropped, because
	// nothing new has been measured.
	fake.fail(true)
	time.Sleep(600 * time.Millisecond)
	engine.refreshTransfer(context.Background(), "test")

	if got := len(engine.transferSamples); got != samples {
		t.Errorf("samples = %d, want %d kept: a failed read must not age the window out", got, samples)
	}
	if !engine.Snapshot().Transfer.Busy {
		t.Error("the hold was released by qBittorrent going away, not by the transfer ending")
	}
}

// A zero window is the escape hatch: decide on the latest reading alone.
func TestAZeroWindowUsesTheLatestReadingAlone(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
		cfg.QBittorrent.BusyDownload = 2 << 20
		cfg.QBittorrent.BusyUpload = 0
		cfg.QBittorrent.BusyWindow = 0
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })
	engine := harness.engine

	fake.set(8<<20, 0)
	engine.refreshTransfer(context.Background(), "test")
	if !engine.Snapshot().Transfer.Busy {
		t.Fatal("should be busy at 8 MiB/s")
	}
	if got := len(engine.transferSamples); got != 1 {
		t.Errorf("samples = %d, want exactly 1 with averaging disabled", got)
	}

	// With no averaging, one dip clears it immediately - the old behaviour, kept
	// deliberately available.
	fake.set(0, 0)
	engine.refreshTransfer(context.Background(), "test")
	if engine.Snapshot().Transfer.Busy {
		t.Error("with SWITCHING_BUSY_WINDOW=0 the latest reading should decide on its own")
	}
	if window := engine.Snapshot().Transfer.BusyWindow; window != "" {
		t.Errorf("BusyWindow = %q, want empty so the card can say it is not averaged", window)
	}
}

// The mean, not the peak: a single spike should not hold the tunnel for a whole window.
func TestAnIsolatedSpikeDoesNotHoldTheTunnel(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
		cfg.QBittorrent.BusyDownload = 2 << 20
		cfg.QBittorrent.BusyUpload = 0
		cfg.QBittorrent.BusyWindow = time.Hour
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })
	engine := harness.engine

	// One spike, then a long quiet stretch: the mean stays under the threshold.
	fake.set(20<<20, 0)
	engine.refreshTransfer(context.Background(), "test")
	for range 30 {
		fake.set(0, 0)
		engine.refreshTransfer(context.Background(), "test")
	}

	if engine.Snapshot().Transfer.Busy {
		down, _ := engine.averageRates()
		t.Errorf("still busy after one spike and 30 quiet readings (average %d B/s)", down)
	}
}

// Gluetun's own updater fetches from Proton and then *persists* what it fetched:
// SetServers calls flushToFile, which opens the servers file with O_TRUNC. So triggering
// it overwrites the curated list written here, and the file has to be rewritten
// afterwards - otherwise it stays Gluetun's until the next full Proton refresh, and a
// Gluetun restart in that window comes up on an unfiltered list.
func TestTheServerFileIsRewrittenAfterGluetunsUpdaterRuns(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	before := engine.Snapshot().Servers.LastWrite
	if before.IsZero() {
		t.Fatal("expected the servers file to have been written during startup")
	}

	// Stand in for Gluetun's updater having clobbered the file.
	time.Sleep(10 * time.Millisecond)
	if !engine.refreshGluetunServerList(context.Background()) {
		t.Fatal("the fake should accept an updater refresh")
	}

	after := engine.Snapshot().Servers.LastWrite
	if !after.After(before) {
		t.Error("the servers file was not rewritten after the updater ran; " +
			"Gluetun's own fetch would remain on disk")
	}
}

// And it must never be triggered as part of a normal write: that would ask Gluetun to
// replace the list just written with its own.
func TestTheUpdaterIsNotTriggeredByAWrite(t *testing.T) {
	var fake *fakeGluetun
	harness := newHarness(t, false, nil)
	fake = harness.gluetun
	harness.run(t, func() bool { return harness.engine.Snapshot().Servers.LastWrite.IsZero() == false })

	fake.mu.Lock()
	before := fake.updaterCalls
	fake.mu.Unlock()

	harness.engine.writeServersFile()

	fake.mu.Lock()
	after := fake.updaterCalls
	fake.mu.Unlock()
	if after != before {
		t.Errorf("writing the servers file triggered Gluetun's updater %d time(s); "+
			"that would overwrite the list just written", after-before)
	}
}

// "On this server" is only knowable when this tool made the switch. Reporting the last
// switch time regardless would attribute someone else's reconnect to us.
func TestOnCurrentSinceIsOnlyKnownWhenWePinnedTheServer(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	switched := time.Now().Add(-3 * time.Hour)
	if err := engine.state.update(func(state *persistedState) {
		state.PinnedHostname = "ours.protonvpn.net"
		state.LastSwitchAt = switched
	}); err != nil {
		t.Fatal(err)
	}

	if got := engine.onCurrentSince("ours.protonvpn.net"); !got.Equal(switched) {
		t.Errorf("onCurrentSince = %v, want the switch time %v", got, switched)
	}
	// Gluetun moved on its own, or the tunnel predates this container.
	if got := engine.onCurrentSince("someone-elses.protonvpn.net"); !got.IsZero() {
		t.Errorf("onCurrentSince = %v for a server we did not pin, want zero", got)
	}
	if got := engine.onCurrentSince(""); !got.IsZero() {
		t.Errorf("onCurrentSince = %v for an unknown server, want zero", got)
	}
}

// The dashboard shows the listen port as its own row, so it has to survive the trip
// into the published snapshot - not just be readable inside portForwardingVerdict,
// which is all the verdict tests above prove.
func TestTheListenPortReachesThePublishedSnapshot(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
	})
	fake.mu.Lock()
	fake.listenPort, fake.randomPort, fake.connection = 46566, false, "connected"
	fake.mu.Unlock()

	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })

	transfer := harness.engine.Snapshot().Transfer
	if transfer.ListenPort != 46566 {
		t.Errorf("ListenPort = %d, want 46566", transfer.ListenPort)
	}

	// And it has to survive JSON encoding under the name the script reads.
	encoded, err := json.Marshal(transfer)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if port, ok := decoded["listen_port"]; !ok {
		t.Errorf("listen_port is absent from the JSON: %s", encoded)
	} else if port != float64(46566) {
		t.Errorf("listen_port = %v, want 46566", port)
	}
}

// failPreferences switches the port-settings call on or off independently of the rates.
func (f *fakeQBittorrent) failPreferences(failing bool) {
	f.mu.Lock()
	f.prefsFailing = failing
	f.mu.Unlock()
}

func (f *fakeQBittorrent) preferenceCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.prefsCalls
}

// The port settings are a separate request from the rates and can fail on their own.
// When they do, the listen port is unknown - and an unexplained "unknown" is not
// something an operator can act on, so the reason has to survive into the snapshot
// instead of being dropped at debug level.
func TestAnUnreadableListenPortCarriesItsReason(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
	})
	fake.failPreferences(true)
	fake.mu.Lock()
	fake.connection = "connected"
	fake.mu.Unlock()

	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.ListenPortError != "" })
	engine := harness.engine

	transfer := engine.Snapshot().Transfer
	// The rates still work: only the settings failed, and the feature's actual job is
	// unaffected.
	if !transfer.Reachable || !transfer.HasReading {
		t.Errorf("the rates should still be read: %+v", transfer)
	}
	if transfer.ListenPort != 0 {
		t.Errorf("ListenPort = %d, want 0 when the settings could not be read", transfer.ListenPort)
	}
	if !strings.Contains(transfer.ListenPortError, "QBITTORRENT_API_KEY") {
		t.Errorf("ListenPortError = %q, want the reason from qBittorrent", transfer.ListenPortError)
	}

	// And the verdict must not claim "working" off peer connectivity alone: without the
	// listen port, the mismatch it exists to catch cannot be ruled out.
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		enabled := true
		snapshot.Gluetun.ForwardedPorts = []uint16{55019}
		snapshot.Gluetun.PortForwardingEnabled = &enabled
	})
	verdict, detail := engine.portForwardingVerdict(engine.Snapshot().Gluetun)
	if verdict != "unknown" {
		t.Errorf("verdict = %q, want unknown while the listen port is unreadable", verdict)
	}
	for _, want := range []string{"could not be read", "55019"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail = %q, want it to mention %q", detail, want)
		}
	}
}

// A blip must not cost five minutes of unknown port. The steady-state interval is
// right for a value that rarely changes and wrong for one that is missing, so a
// failure is retried on a much shorter cycle.
func TestTheListenPortIsRetriedQuicklyAfterAFailure(t *testing.T) {
	if preferencesRetryInterval >= preferencesInterval {
		t.Fatalf("the retry interval (%s) must be shorter than the steady-state one (%s)",
			preferencesRetryInterval, preferencesInterval)
	}

	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
	})
	fake.failPreferences(true)
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.ListenPortError != "" })
	engine := harness.engine

	// A failed read is stamped, so the retry is paced rather than attempted on every
	// rate poll - otherwise a refused key would be hammered several times a minute.
	if engine.qbPreferencesAt.IsZero() {
		t.Error("a failed read should still be stamped, or the retry becomes a hot loop")
	}
	before := fake.preferenceCalls()

	// Pretend the retry interval has elapsed and let qBittorrent answer again.
	engine.qbPreferencesAt = time.Now().Add(-preferencesRetryInterval - time.Second)
	fake.failPreferences(false)
	fake.mu.Lock()
	fake.listenPort = 46566
	fake.mu.Unlock()

	engine.refreshQBittorrentPreferences(context.Background())

	if fake.preferenceCalls() == before {
		t.Fatal("the settings were not retried after the short interval")
	}
	if engine.qbPreferences.ListenPort != 46566 {
		t.Errorf("ListenPort = %d, want 46566 after the retry succeeded", engine.qbPreferences.ListenPort)
	}
	if engine.qbPreferencesErr != "" {
		t.Errorf("the error should be cleared once it works: %q", engine.qbPreferencesErr)
	}

	// Having succeeded, it must fall back to the slow interval rather than polling
	// qBittorrent every twenty seconds forever.
	settled := fake.preferenceCalls()
	engine.qbPreferencesAt = time.Now().Add(-preferencesRetryInterval - time.Second)
	engine.refreshQBittorrentPreferences(context.Background())
	if fake.preferenceCalls() != settled {
		t.Error("a successful read should go back to the slow interval")
	}
}

// throughputHarness gives the engine a current server and a running tunnel, which is
// the state every attribution rule is written against.
func throughputHarness(t *testing.T, window time.Duration) (*harness, *fakeQBittorrent) {
	t.Helper()
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
		cfg.QBittorrent.BusyWindow = window
		// Nothing here should be deferred; these tests are about measurement.
		cfg.QBittorrent.BusyDownload = 0
		cfg.QBittorrent.BusyUpload = 0
	})
	engine := harness.engine
	engine.applyLogicals(mixedP2PLogicals(), false)
	engine.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Gluetun.Status = "running" })
	return harness, fake
}

// pinCurrent makes a hostname the current server, arrived at long enough ago that the
// settling and window rules are satisfied.
func pinCurrent(t *testing.T, engine *Engine, hostname string, arrivedAgo time.Duration) {
	t.Helper()
	if err := engine.state.update(func(state *persistedState) {
		state.PinnedHostname = hostname
		state.LastSwitchAt = time.Now().Add(-arrivedAgo)
	}); err != nil {
		t.Fatal(err)
	}
	// Gluetun's own single-hostname selection is what currentHostname trusts first,
	// and it is what a real pin leaves behind.
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.Selection = map[string][]string{"hostnames": {hostname}}
	})
}

// The point of the whole feature: what a server actually delivered, kept per server.
// Proton's load figure says how busy a server is, not how much bandwidth it will give,
// so this is the only measured answer.
func TestThroughputIsRecordedPerServer(t *testing.T) {
	harness, _ := throughputHarness(t, 0)
	engine := harness.engine

	pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)
	engine.recordTransfer(transferOf(5<<20, 1<<20))
	engine.recordTransfer(transferOf(9<<20, 512<<10)) // a higher peak down, a lower peak up
	engine.recordTransfer(transferOf(2<<20, 3<<20))   // and a higher peak up

	pinCurrent(t, engine, "se-02.protonvpn.net", time.Hour)
	engine.recordTransfer(transferOf(1<<20, 1<<10))

	records := engine.state.snapshot().Stats
	first, second := records["se-01.protonvpn.net"], records["se-02.protonvpn.net"]

	// The peak in each direction, tracked independently: a server can be fast one way
	// and slow the other, which is the difference worth seeing.
	if first.MaxDownloadRate != 9<<20 {
		t.Errorf("peak download = %d, want %d", first.MaxDownloadRate, uint64(9<<20))
	}
	if first.MaxUploadRate != 3<<20 {
		t.Errorf("peak upload = %d, want %d", first.MaxUploadRate, uint64(3<<20))
	}
	if first.TransferReadings != 3 {
		t.Errorf("readings = %d, want 3", first.TransferReadings)
	}
	// And the second server's slower reading must not have touched the first's figures.
	if second.MaxDownloadRate != 1<<20 || second.MaxUploadRate != 1<<10 {
		t.Errorf("the second server's record is wrong: %+v", second)
	}
}

// Every one of these would credit one server with another's traffic, or invent a
// measurement that was never taken. They are the only ways this data can mislead
// rather than inform, so each is checked on its own.
func TestThroughputIsNotAttributedToTheWrongServer(t *testing.T) {
	t.Run("an idle poll is not a measurement", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)

		engine.recordTransfer(transferOf(0, 0))

		if record, found := engine.state.snapshot().Stats["se-01.protonvpn.net"]; found {
			t.Errorf("an idle poll created a record: %+v", record)
		}
	})

	t.Run("nothing flows through a tunnel that is down", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)
		engine.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Gluetun.Status = "crashed" })

		engine.recordTransfer(transferOf(8<<20, 0))

		if _, found := engine.state.snapshot().Stats["se-01.protonvpn.net"]; found {
			t.Error("a reading was credited to a server while the tunnel was down")
		}
	})

	t.Run("the first reading after a switch belongs to the previous server", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		// Arrived just now: this reading covers the interval before the switch.
		pinCurrent(t, engine, "se-02.protonvpn.net", 0)

		engine.recordTransfer(transferOf(8<<20, 0))

		if _, found := engine.state.snapshot().Stats["se-02.protonvpn.net"]; found {
			t.Error("a reading spanning the switch was credited to the new server")
		}
	})

	t.Run("with no current server there is nothing to credit", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine

		engine.recordTransfer(transferOf(8<<20, 1<<20))

		if len(engine.state.snapshot().Stats) != 0 {
			t.Errorf("records were created with no current server: %+v",
				engine.state.snapshot().Stats)
		}
	})
}

// An unmeasured server must read as unmeasured, not as a slow one. This is the
// difference between "this server gave me nothing" and "nothing was downloading".
func TestAnUnmeasuredServerHasNoThroughputView(t *testing.T) {
	harness, _ := throughputHarness(t, 0)
	engine := harness.engine

	// A real candidate from the fixture, so the published list can be checked too.
	const hostname = "node-se-p2p.protonvpn.net"

	if view := engine.statsFor(hostname); view != nil {
		t.Errorf("an unused server has a view: %+v", view)
	}

	pinCurrent(t, engine, hostname, time.Hour)
	engine.recordTransfer(transferOf(7<<20, 1<<20))
	engine.publish()

	view := engine.statsFor(hostname)
	if view == nil {
		t.Fatal("a measured server should have a view")
	}
	if view.MaxDownloadRate != 7<<20 || !view.Current {
		t.Errorf("view = %+v, want the peak and Current set while it is being measured", view)
	}

	// And it has to reach the candidate list, which is where servers are compared.
	var found bool
	for _, candidate := range engine.Snapshot().Candidates {
		if candidate.Hostname == hostname {
			found = candidate.Stats != nil && candidate.Stats.MaxDownloadRate == 7<<20
		}
	}
	if !found {
		t.Error("the measured throughput did not reach the candidate list")
	}
	// The current server's own column reads from the same place.
	if current := engine.Snapshot().Selection.Current; current == nil ||
		current.Stats == nil || current.Stats.MaxDownloadRate != 7<<20 {
		t.Errorf("the current server's throughput is missing: %+v", current)
	}
}

// Without qBittorrent nothing measures throughput, so those figures must be marked
// unknown rather than reported as zero - a zero says this server carried nothing, which is
// a claim about the server rather than an admission about us.
//
// Load and latency are unaffected: they come from Proton and the prober, and are worth
// having whether or not a torrent client is involved.
func TestTransferFiguresAreUnknownWithoutQBittorrent(t *testing.T) {
	harness := newHarness(t, false, nil)
	engine := harness.engine
	if err := engine.state.update(func(state *persistedState) {
		state.Stats = map[string]ServerStats{
			"se-01.protonvpn.net": {
				// Figures a previous run with qBittorrent configured could have left
				// behind, which must not be presented as current.
				MaxDownloadRate: 1 << 20, DownloadedBytes: 9 << 30, TransferReadings: 4,
				LoadLast: 30, LoadLowest: 8, LoadHighest: 74, Samples: 12,
			},
		}
	}); err != nil {
		t.Fatal(err)
	}

	view := engine.statsFor("se-01.protonvpn.net")
	if view == nil {
		t.Fatal("load and latency statistics should be reported without qBittorrent")
	}
	if view.TransferKnown {
		t.Error("TransferKnown is set with no qBittorrent configured")
	}
	if view.DownloadedBytes != 0 || view.MaxDownloadRate != 0 {
		t.Errorf("stale transfer figures were published: %+v", view)
	}
	if view.LoadLowest != 8 || view.LoadHighest != 74 {
		t.Errorf("load statistics were lost: %+v", view)
	}
}

// The state file is rewritten in full on every update, so an unbounded map would grow
// the write with every server the tunnel ever touches.
func TestThroughputRecordsAreBounded(t *testing.T) {
	records := make(map[string]ServerStats, maxServerStats+50)
	for i := range maxServerStats + 50 {
		records[fmt.Sprintf("host-%03d", i)] = ServerStats{
			// Later hosts are more recent, so the early ones are the ones dropped.
			LastSeenUnix:    time.Now().Add(time.Duration(i) * time.Second).Unix(),
			MaxDownloadRate: 1 << 20, TransferReadings: 1,
		}
	}

	pruneStats(records)

	if len(records) != maxServerStats {
		t.Errorf("kept %d records, want %d", len(records), maxServerStats)
	}
	if _, found := records["host-000"]; found {
		t.Error("the least recently measured record should have been dropped first")
	}
	if _, found := records[fmt.Sprintf("host-%03d", maxServerStats+49)]; !found {
		t.Error("the most recent record must be kept")
	}
}

// seedThroughput gives a hostname a measured record.
func seedThroughput(t *testing.T, engine *Engine, hostnames ...string) {
	t.Helper()
	if err := engine.state.update(func(state *persistedState) {
		if state.Stats == nil {
			state.Stats = make(map[string]ServerStats)
		}
		for _, hostname := range hostnames {
			state.Stats[hostname] = ServerStats{
				MaxDownloadRate: 8 << 20, TransferReadings: 12, Visits: 1,
				FirstSeenUnix: time.Now().Add(-time.Hour).Unix(), LastSeenUnix: time.Now().Unix(),
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func throughputHosts(engine *Engine) []string {
	var hosts []string
	for hostname := range engine.state.snapshot().Stats {
		hosts = append(hosts, hostname)
	}
	slices.Sort(hosts)
	return hosts
}

// Proton retires servers. A record for a hostname that no longer exists can never be
// displayed again - it will never be a candidate - so it is dead weight in the state
// file.
func TestThroughputIsForgottenWhenProtonRetiresAServer(t *testing.T) {
	harness, _ := throughputHarness(t, 0)
	engine := harness.engine

	// One host in Proton's list, one that has been retired, and enough listed servers
	// for the plausibility check to be satisfied.
	seedThroughput(t, engine, "node-se-p2p.protonvpn.net", "node-se-gone.protonvpn.net")

	engine.applyLogicals(manyLogicals(t, 8), false)

	if got := throughputHosts(engine); strings.Join(got, ",") != "node-se-p2p.protonvpn.net" {
		t.Errorf("hosts = %v, want only the one Proton still lists", got)
	}
}

// Each of these is a way the pruning could delete data that is still good, which is the
// only way it can do harm.
func TestThroughputIsKeptWhenProtonsListIsNotEvidenceOfRetirement(t *testing.T) {
	t.Run("a cached list means proton was unreachable, not that servers are gone", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		seedThroughput(t, engine, "node-se-gone.protonvpn.net")

		// fromCache: exactly the fallback used during a Proton outage.
		engine.applyLogicals(manyLogicals(t, 8), true)

		if got := throughputHosts(engine); len(got) != 1 {
			t.Errorf("hosts = %v, want the record kept: a cache load proves nothing", got)
		}
	})

	t.Run("a server excluded by filters still exists", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		engine.cfg.Filter.MaxLoad = 1 // excludes essentially everything

		logicals := manyLogicals(t, 8)
		seedThroughput(t, engine, logicals[0].Servers[0].Domain)
		engine.applyLogicals(logicals, false)

		if got := throughputHosts(engine); len(got) != 1 {
			t.Errorf("hosts = %v, want the record kept: the filters exclude it, Proton does not", got)
		}
	})

	t.Run("a server in maintenance still exists", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine

		logicals := manyLogicals(t, 8)
		// Status 0 is Proton's maintenance flag, which servers move in and out of
		// routinely. Its history has to survive that.
		logicals[0].Status = 0
		logicals[0].Servers[0].Status = 0
		seedThroughput(t, engine, logicals[0].Servers[0].Domain)

		engine.applyLogicals(logicals, false)

		if got := throughputHosts(engine); len(got) != 1 {
			t.Errorf("hosts = %v, want the record kept through maintenance", got)
		}
	})

	t.Run("an implausibly short list is a bad response, not a mass retirement", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		hosts := make([]string, 0, 6)
		for i := range 6 {
			hosts = append(hosts, fmt.Sprintf("node-x%02d.protonvpn.net", i))
		}
		seedThroughput(t, engine, hosts...)

		// Fewer servers listed than records held: every one of them was in the list
		// when it was measured, so this cannot be a genuine retirement.
		engine.applyLogicals(manyLogicals(t, 2), false)

		if got := throughputHosts(engine); len(got) != len(hosts) {
			t.Errorf("kept %d of %d records; a short response must not wipe them",
				len(got), len(hosts))
		}
	})
}

// The state file is rewritten in full on every update, several times an hour, so its size
// at full capacity is a budget rather than an afterthought. This measures it instead of
// trusting the arithmetic in the comments.
//
// The limit is generous against the measured figure on purpose: it is here to catch a
// change that multiplies the cost - a wider cap, a per-server series, a new field on every
// record - not to police a few hundred bytes.
func TestTheStateFileStaysSmallAtFullCapacity(t *testing.T) {
	t.Parallel()

	state := persistedState{Stats: map[string]ServerStats{}}
	for server := range maxServerStats {
		// Worst-case values: every field at its widest.
		state.Stats[fmt.Sprintf("node-country-%03d.protonvpn.net", server)] = ServerStats{
			FirstSeenUnix: time.Now().Unix(), LastSeenUnix: time.Now().Unix(),
			LastTransferUnix: time.Now().Unix(),
			MaxDownloadRate:  1234567890, MaxUploadRate: 123456789,
			DownloadedBytes: 123456789012345, UploadedBytes: 12345678901234,
			LoadLast: 100, LoadLowest: 1, LoadHighest: 100,
			RTTLastMS: 65535, RTTLowestMS: 1, RTTHighestMS: 65535,
			Samples: 999999, TransferReadings: 999999, Visits: 999,
		}
	}
	// Plus every other bounded list, so this is the whole file and not just the new part.
	for i := range maxHistory {
		state.History = append(state.History, SwitchRecord{
			At: time.Now(), From: "node-country-001.protonvpn.net",
			To: "node-country-002.protonvpn.net", Reason: "better score",
			PublicIP: "203.0.113.99", Country: "Sweden", City: "Stockholm",
			Succeeded: true, ScoreBefore: 0.5, ScoreAfter: 0.4,
			LoadBefore: 80, LoadAfter: 10, RTTAfterMS: int64(i),
		})
	}

	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	// 320 KB, which at four writes an hour is about 1.25 MB an hour, or 30 MB a day. That
	// is the figure that matters rather than the file size alone: before a qBittorrent poll
	// stopped writing the file, a fraction of this data cost roughly a gigabyte a day.
	//
	// This is the absolute worst case - the cap saturated with 600 servers, every field at
	// its widest, and every other bounded list full. The realistic figure is measured
	// below.
	const limit = 320 << 10
	t.Logf("state.json at full capacity: %d bytes (%.1f KB)", len(encoded), float64(len(encoded))/1024)
	if len(encoded) > limit {
		t.Errorf("state.json would be %d bytes at capacity, over the %d byte budget; "+
			"it is rewritten in full several times an hour", len(encoded), limit)
	}

	// And the size a real deployment sees: a filtered candidate set of a few hundred
	// servers with ordinary values, where omitempty drops most of the zero fields. This is
	// the number worth quoting, and it is measured rather than estimated.
	realistic := persistedState{Stats: map[string]ServerStats{}}
	for server := range 300 {
		stats := ServerStats{
			LoadLast: 34, LoadLowest: 11, LoadHighest: 78,
			RTTLastMS: 31, RTTLowestMS: 24, RTTHighestMS: 96,
			Samples: 1440, FirstSeenUnix: 1785000000, LastSeenUnix: 1785900000,
		}
		// Only a handful of servers have ever carried traffic.
		if server < 20 {
			stats.DownloadedBytes = 412 << 30
			stats.UploadedBytes = 38 << 30
			stats.MaxDownloadRate = 11 << 20
			stats.MaxUploadRate = 2 << 20
			stats.TransferReadings = 5100
			stats.Visits = 6
			stats.LastTransferUnix = 1785899000
		}
		realistic.Stats[fmt.Sprintf("node-se-%03d.protonvpn.net", server)] = stats
	}
	realisticEncoded, err := json.Marshal(realistic)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("state.json for 300 candidates, 20 of them used: %d bytes (%.1f KB)",
		len(realisticEncoded), float64(len(realisticEncoded))/1024)
}

// A qBittorrent poll must not rewrite the state file. It runs every fifteen seconds, the
// file is written in full, and the peak it updates rarely changes - so persisting each
// one was a few hundred kilobytes a minute of writes for nothing, indefinitely, on
// hardware that may be an SD card.
func TestAThroughputPollDoesNotRewriteTheStateFile(t *testing.T) {
	harness, _ := throughputHarness(t, 0)
	engine := harness.engine
	pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)

	// Settle any writes the startup path had queued.
	if err := engine.state.update(func(*persistedState) {}); err != nil {
		t.Fatal(err)
	}
	path := engine.state.path
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 20 {
		engine.recordTransfer(transferOf(uint64(i+1)<<20, 1<<20))
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Error("a throughput poll wrote the state file; it should only mutate memory")
	}

	// But the reading is not lost: it is in memory, and the next real update flushes it.
	if got := engine.state.snapshot().Stats["se-01.protonvpn.net"].MaxDownloadRate; got != 20<<20 {
		t.Errorf("in-memory peak = %d, want %d", got, uint64(20<<20))
	}
	if err := engine.state.update(func(*persistedState) {}); err != nil {
		t.Fatal(err)
	}
	reloaded := newStateStore(filepath.Dir(path))
	if err := reloaded.load(); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.snapshot().Stats["se-01.protonvpn.net"].MaxDownloadRate; got != 20<<20 {
		t.Errorf("peak after the flush = %d, want it persisted", got)
	}
}

// transferOf builds a reading with the given rates. Session counters advance with the
// rates so a test that does not care about volumes still produces coherent deltas.
func transferOf(download, upload uint64) qbittorrent.Transfer {
	transferCounter.down += download
	transferCounter.up += upload
	return qbittorrent.Transfer{
		DownloadSpeed: download, UploadSpeed: upload,
		DownloadTotal: transferCounter.down, UploadTotal: transferCounter.up,
		ConnectionStatus: "connected",
	}
}

// transferCounter is the monotonic session total transferOf hands out. Package level
// because qBittorrent's counters are per instance, not per test, and every test in this
// package shares one fake.
var transferCounter struct{ down, up uint64 }

// transferAt builds a reading with explicit session counters, for the delta rules where
// the counter values are the whole point.
func transferAt(speedDown, speedUp, totalDown, totalUp uint64) qbittorrent.Transfer {
	return qbittorrent.Transfer{
		DownloadSpeed: speedDown, UploadSpeed: speedUp,
		DownloadTotal: totalDown, UploadTotal: totalUp,
		ConnectionStatus: "connected",
	}
}

// Volume is what accumulates into "how much have I pulled through this server", and it is
// derived by difference from qBittorrent's session counters. Every way that difference can
// be meaningless has to yield nothing rather than a wrong number, because these totals are
// kept indefinitely - a bad one never washes out.
func TestTransferredBytesAreAttributedByDifference(t *testing.T) {
	t.Run("the first reading establishes a baseline and credits nothing", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)

		// A session that has already moved 50 GB before this tool ever looked. None of it
		// is ours to attribute.
		engine.recordTransfer(transferAt(1<<20, 0, 50<<30, 5<<30))

		if got := engine.state.snapshot().Stats["se-01.protonvpn.net"].DownloadedBytes; got != 0 {
			t.Errorf("credited %d bytes from the first reading, want 0", got)
		}

		// The second reading credits only the difference.
		engine.recordTransfer(transferAt(1<<20, 0, 51<<30, 5<<30))

		if got := engine.state.snapshot().Stats["se-01.protonvpn.net"].DownloadedBytes; got != 1<<30 {
			t.Errorf("credited %d bytes, want the 1 GiB difference", got)
		}
	})

	t.Run("a qbittorrent restart is not a negative transfer", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)

		engine.recordTransfer(transferAt(1<<20, 0, 40<<30, 4<<30))
		engine.recordTransfer(transferAt(1<<20, 0, 41<<30, 4<<30)) // +1 GiB
		// qBittorrent restarts: session counters begin again.
		engine.recordTransfer(transferAt(1<<20, 0, 2<<30, 0))
		engine.recordTransfer(transferAt(1<<20, 0, 3<<30, 0)) // +1 GiB again

		record := engine.state.snapshot().Stats["se-01.protonvpn.net"]
		if record.DownloadedBytes != 2<<30 {
			t.Errorf("total = %d, want exactly the two 1 GiB differences (%d)",
				record.DownloadedBytes, uint64(2<<30))
		}
	})

	t.Run("bytes are never credited across a server change", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine

		pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)
		engine.recordTransfer(transferAt(1<<20, 0, 10<<30, 0))
		engine.recordTransfer(transferAt(1<<20, 0, 11<<30, 0)) // 1 GiB on the first server

		// Move, then a reading whose counter grew by 5 GiB. That growth happened partly
		// on the previous server, so the new one must not be credited with it.
		pinCurrent(t, engine, "se-02.protonvpn.net", time.Hour)
		engine.recordTransfer(transferAt(1<<20, 0, 16<<30, 0))

		records := engine.state.snapshot().Stats
		if got := records["se-01.protonvpn.net"].DownloadedBytes; got != 1<<30 {
			t.Errorf("first server = %d bytes, want 1 GiB", got)
		}
		if got := records["se-02.protonvpn.net"].DownloadedBytes; got != 0 {
			t.Errorf("second server credited %d bytes it did not carry", got)
		}

		// From here on it accumulates normally.
		engine.recordTransfer(transferAt(1<<20, 0, 18<<30, 0))
		if got := engine.state.snapshot().Stats["se-02.protonvpn.net"].DownloadedBytes; got != 2<<30 {
			t.Errorf("second server = %d bytes, want the 2 GiB it did carry", got)
		}
	})

	t.Run("a skipped reading drops the baseline", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)

		engine.recordTransfer(transferAt(1<<20, 0, 10<<30, 0))
		// The tunnel goes down: this reading is not attributable at all.
		engine.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Gluetun.Status = "crashed" })
		engine.recordTransfer(transferAt(1<<20, 0, 20<<30, 0))
		engine.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Gluetun.Status = "running" })
		// The counter has moved 15 GiB since the last attributable reading, but 10 of that
		// straddles a window nothing was accounting for.
		engine.recordTransfer(transferAt(1<<20, 0, 25<<30, 0))

		if got := engine.state.snapshot().Stats["se-01.protonvpn.net"].DownloadedBytes; got != 0 {
			t.Errorf("credited %d bytes across an unaccounted gap, want 0", got)
		}
	})

	t.Run("an idle interval still moves the baseline forward", func(t *testing.T) {
		harness, _ := throughputHarness(t, 0)
		engine := harness.engine
		pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)

		engine.recordTransfer(transferAt(0, 0, 10<<30, 0)) // idle: baseline only
		engine.recordTransfer(transferAt(0, 0, 10<<30, 0)) // still idle, nothing moved
		engine.recordTransfer(transferAt(1<<20, 0, 11<<30, 0))

		// The idle polls must not have dropped the baseline: if they had, this would be 0.
		if got := engine.state.snapshot().Stats["se-01.protonvpn.net"].DownloadedBytes; got != 1<<30 {
			t.Errorf("total = %d, want 1 GiB: an idle interval is a real zero, not a gap", got)
		}
	})
}

// The peaks describe the current stay; the totals describe all time. Returning to a
// server must reset the first and never the second.
func TestTransferredTotalsSurviveANewStay(t *testing.T) {
	harness, _ := throughputHarness(t, 0)
	engine := harness.engine

	pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)
	engine.recordTransfer(transferAt(50<<20, 0, 10<<30, 0))
	engine.recordTransfer(transferAt(50<<20, 0, 14<<30, 0)) // 4 GiB, peak 50 MB/s

	pinCurrent(t, engine, "se-02.protonvpn.net", time.Hour)
	engine.recordTransfer(transferAt(1<<20, 0, 15<<30, 0))

	pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)
	engine.recordTransfer(transferAt(3<<20, 0, 16<<30, 0))
	engine.recordTransfer(transferAt(3<<20, 0, 17<<30, 0)) // 1 GiB more, peak 3 MB/s

	record := engine.state.snapshot().Stats["se-01.protonvpn.net"]
	if record.DownloadedBytes != 5<<30 {
		t.Errorf("total = %d, want 5 GiB across both stays", record.DownloadedBytes)
	}
	// The maximum is all-time, like the totals: "the fastest this server has ever gone"
	// is the question, and an earlier stay is still evidence for it.
	if record.MaxDownloadRate != 50<<20 {
		t.Errorf("max rate = %d, want the all-time 50 MB/s", record.MaxDownloadRate)
	}
	if record.Visits != 2 {
		t.Errorf("visits = %d, want 2", record.Visits)
	}
}

// Retirement is the only route by which a transferred total is deleted, so everything about
// the server has to go at once - the totals, the rates, the load and latency extremes.
func TestRetiringAServerForgetsEverythingAboutIt(t *testing.T) {
	harness, _ := throughputHarness(t, 0)
	engine := harness.engine

	const gone = "node-se-gone.protonvpn.net"
	seedThroughput(t, engine, gone, "node-se-p2p.protonvpn.net")
	if err := engine.state.update(func(state *persistedState) {
		record := state.Stats[gone]
		record.DownloadedBytes = 900 << 30
		record.LoadLowest, record.LoadHighest = 4, 91
		record.RTTLowestMS, record.RTTHighestMS = 22, 180
		state.Stats[gone] = record
	}); err != nil {
		t.Fatal(err)
	}

	engine.applyLogicals(manyLogicals(t, 8), false)

	persisted := engine.state.snapshot()
	if record, found := persisted.Stats[gone]; found {
		t.Errorf("the retired server's statistics survived: %+v", record)
	}
	// And the server Proton still lists keeps all of its.
	if _, found := persisted.Stats["node-se-p2p.protonvpn.net"]; !found {
		t.Error("a listed server lost statistics it should have kept")
	}
}

// A volume logged as a rate states a measurement that was never taken, and the two differ
// by three characters.
func TestVolumesAndRatesAreFormattedDifferently(t *testing.T) {
	t.Parallel()

	if got := formatBytes(9663676416); got != "9.7 GB" {
		t.Errorf("formatBytes = %q, want 9.7 GB", got)
	}
	if got := formatRate(9663676416); got != "9.7 GB/s" {
		t.Errorf("formatRate = %q, want 9.7 GB/s", got)
	}
	if got := formatBytes(512); got != "512 B" {
		t.Errorf("formatBytes = %q, want 512 B", got)
	}
}

// The scenario worth being explicit about: qBittorrent's session counter runs continuously
// across a server switch and only resets when qBittorrent itself restarts. So a total is
// never read directly - every figure is a difference between consecutive polls, and a
// difference is only credited when both ends of it were on the same server.
//
// This walks a whole session across two switches and checks the arithmetic exactly.
func TestASessionSpanningSwitchesCreditsEachServerOnlyItsOwnBytes(t *testing.T) {
	harness, _ := throughputHarness(t, 0)
	engine := harness.engine

	// One continuous qBittorrent session. The counter only ever rises.
	session := uint64(100 << 30) // 100 GiB already moved before this tool started

	poll := func(hostname string, movedGiB uint64) {
		session += movedGiB << 30
		engine.recordTransfer(transferAt(1<<20, 0, session, 0))
	}

	pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)
	poll("se-01", 0) // first poll: baseline only, none of the 100 GiB is ours to claim
	poll("se-01", 3)
	poll("se-01", 2) // 5 GiB on the first server

	// Switch. The interval that straddles it moved 9 GiB, partly on each server, so it is
	// credited to neither - the alternative is crediting one of them with the other's
	// traffic, which is worse than a floor.
	pinCurrent(t, engine, "se-02.protonvpn.net", time.Hour)
	poll("se-02", 9)
	poll("se-02", 4)
	poll("se-02", 1) // 5 GiB on the second server

	// Back to the first. Its total continues from where it was rather than restarting.
	pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)
	poll("se-01", 7) // the straddling interval again: credited to neither
	poll("se-01", 2)

	stats := engine.state.snapshot().Stats
	for _, want := range []struct {
		hostname string
		giB      uint64
		visits   int
	}{
		{"se-01.protonvpn.net", 7, 2}, // 5 from the first stay, 2 from the second
		{"se-02.protonvpn.net", 5, 1},
	} {
		record := stats[want.hostname]
		if record.DownloadedBytes != want.giB<<30 {
			t.Errorf("%s = %s, want %s", want.hostname,
				formatBytes(record.DownloadedBytes), formatBytes(want.giB<<30))
		}
		if record.Visits != want.visits {
			t.Errorf("%s visits = %d, want %d", want.hostname, record.Visits, want.visits)
		}
	}

	// The invariant that matters most: the attributed bytes can fall short of what the
	// session moved, but must never exceed it. Anything more would mean an interval was
	// counted twice.
	var attributed uint64
	for _, record := range stats {
		attributed += record.DownloadedBytes
	}
	sessionMoved := session - 100<<30
	if attributed > sessionMoved {
		t.Errorf("attributed %s of a session that moved %s; an interval was double counted",
			formatBytes(attributed), formatBytes(sessionMoved))
	}
	// And the shortfall is exactly the two straddling intervals, not something unexplained.
	if shortfall := sessionMoved - attributed; shortfall != 16<<30 {
		t.Errorf("shortfall = %s, want exactly the two switch intervals (16 GiB)",
			formatBytes(shortfall))
	}
}

// A qBittorrent restart mid-stay is the other way the session counter lies. It must cost
// only the interval it happened in, not the server's accumulated total.
func TestAQBittorrentRestartDoesNotDisturbTheAccumulatedTotal(t *testing.T) {
	harness, _ := throughputHarness(t, 0)
	engine := harness.engine
	pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)

	engine.recordTransfer(transferAt(1<<20, 0, 50<<30, 0))
	engine.recordTransfer(transferAt(1<<20, 0, 56<<30, 0)) // +6 GiB

	// qBittorrent restarts: the session begins again from a low number.
	engine.recordTransfer(transferAt(1<<20, 0, 1<<30, 0))
	engine.recordTransfer(transferAt(1<<20, 0, 4<<30, 0)) // +3 GiB in the new session

	record := engine.state.snapshot().Stats["se-01.protonvpn.net"]
	if record.DownloadedBytes != 9<<30 {
		t.Errorf("total = %s, want 9 GiB: the restart should cost only its own interval",
			formatBytes(record.DownloadedBytes))
	}
}

// The figures have to survive a restart, which is the whole reason they are persisted.
//
// This shipped broken: the fast path updates them in memory to avoid rewriting the state
// file every fifteen seconds, and the only thing that wrote them out was the loads refresh
// - fifteen minutes apart, with nothing at all on shutdown. A restart inside that window
// discarded every byte counted since the last write.
func TestTransferredTotalsSurviveARestart(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	const hostname = "node-se-01.protonvpn.net"

	first := newStateStore(directory)
	if err := first.load(); err != nil {
		t.Fatal(err)
	}
	// Exactly what the fast path does: memory only, no write.
	first.mutate(func(state *persistedState) {
		state.Stats = map[string]ServerStats{hostname: {
			DownloadedBytes: 412 << 30, UploadedBytes: 38 << 30,
			MaxDownloadRate: 11 << 20, TransferReadings: 900, Visits: 3,
			LoadLast: 22, LoadLowest: 9, LoadHighest: 71,
		}}
	})

	// Nothing on disk yet, which is the state a kill -9 would catch.
	interim := newStateStore(directory)
	if err := interim.load(); err != nil {
		t.Fatal(err)
	}
	if len(interim.snapshot().Stats) != 0 {
		t.Fatal("mutate wrote the file; it is supposed to defer the write")
	}

	// The flush is what settles it, and it must report having done so.
	written, err := first.flush()
	if err != nil {
		t.Fatal(err)
	}
	if !written {
		t.Error("flush reported no write for pending changes")
	}

	second := newStateStore(directory)
	if err := second.load(); err != nil {
		t.Fatal(err)
	}
	record := second.snapshot().Stats[hostname]
	if record.DownloadedBytes != 412<<30 || record.UploadedBytes != 38<<30 {
		t.Errorf("totals did not survive: %+v", record)
	}
	if record.MaxDownloadRate != 11<<20 || record.Visits != 3 || record.LoadHighest != 71 {
		t.Errorf("part of the record was lost: %+v", record)
	}

	// A second flush with nothing pending must not rewrite the file: the whole point of
	// the dirty flag is that the timer is cheap when nothing has changed.
	if written, err := second.flush(); err != nil || written {
		t.Errorf("flush wrote with nothing pending (written=%v, err=%v)", written, err)
	}
}

// Shutdown has to settle pending state, and the engine's own loop is where that happens -
// a store-level test cannot prove the loop calls it.
func TestTheEngineFlushesStateOnShutdown(t *testing.T) {
	harness, _ := throughputHarness(t, 0)
	engine := harness.engine
	pinCurrent(t, engine, "se-01.protonvpn.net", time.Hour)

	// Settle everything the startup path queued, so the pending change below is the only
	// thing left unwritten.
	if err := engine.state.update(func(*persistedState) {}); err != nil {
		t.Fatal(err)
	}
	engine.recordTransfer(transferAt(5<<20, 0, 10<<30, 0))
	engine.recordTransfer(transferAt(5<<20, 0, 14<<30, 0)) // 4 GiB, in memory only

	onDisk := newStateStore(filepath.Dir(engine.state.path))
	if err := onDisk.load(); err != nil {
		t.Fatal(err)
	}
	if got := onDisk.snapshot().Stats["se-01.protonvpn.net"].DownloadedBytes; got != 0 {
		t.Fatalf("the poll wrote the file; expected it to defer (%d bytes on disk)", got)
	}

	engine.flushState("test")

	reloaded := newStateStore(filepath.Dir(engine.state.path))
	if err := reloaded.load(); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.snapshot().Stats["se-01.protonvpn.net"].DownloadedBytes; got != 4<<30 {
		t.Errorf("flushed total = %s, want 4 GiB", formatBytes(got))
	}

	// And the loop must actually do this on the way out, not just have the method.
	source, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatal(err)
	}
	shutdown := regexp.MustCompile(`(?s)case <-ctx\.Done\(\):.*?return nil`).Find(source)
	if shutdown == nil {
		t.Fatal("could not find the shutdown branch")
	}
	if !bytes.Contains(shutdown, []byte("e.flushState(")) {
		t.Error("the shutdown branch does not flush pending state")
	}
	if !bytes.Contains(source, []byte("flushTicker")) {
		t.Error("nothing flushes state on a timer, so an unclean kill loses everything since " +
			"the last loads refresh")
	}
}

// A switch must not go ahead during a transfer just because qBittorrent has not answered
// *yet*. Both containers restart together, qBittorrent is often not up when the first poll
// lands, and treating that as "nothing is transferring" interrupted a download on every
// restart - at the moment it is most likely to matter.
func TestSwitchingWaitsForQBittorrentsFirstAnswer(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 8<<20, 0)
	})
	// Failing from the start, as a qBittorrent that has not finished booting would.
	fake.fail(true)
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.LastError != "" })
	engine := harness.engine

	blocked, reason := engine.transferBlocksSwitch()
	if !blocked {
		t.Error("an automatic switch was allowed before qBittorrent had ever answered")
	}
	for _, want := range []string{"not answered yet", "waiting up to"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason = %q, should explain the wait (%q)", reason, want)
		}
	}

	// The safety valve: a wrong URL or key must not freeze selection for ever, so the wait
	// is bounded and then gives up.
	engine.startedAt = time.Now().Add(-firstReadingGrace - time.Minute)
	if blocked, _ := engine.transferBlocksSwitch(); blocked {
		t.Error("switching is still blocked after the grace period; a misconfiguration " +
			"would freeze selection")
	}
	if !engine.transferGraceExpired {
		t.Error("giving up was not recorded, so the warning would repeat on every evaluation")
	}

	// And once a reading does arrive, the rates decide - here, well over the threshold.
	engine.startedAt = time.Now()
	fake.fail(false)
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.HasReading })
	if blocked, reason := engine.transferBlocksSwitch(); !blocked {
		t.Errorf("a transfer at 8 MB/s should defer switching (reason: %q)", reason)
	}
}

// Waiting for qBittorrent's first answer must never delay the *initial* connection.
//
// The transfer gate sits before the "current server unknown" case on purpose - a transfer
// on a server outside the allowed set is still worth protecting - so a naive wait would
// have left a fresh start with no tunnel sitting idle for the whole grace period, which is
// worse than the interruption it was added to prevent.
func TestTheFirstReadingWaitDoesNotDelayTheInitialConnection(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 8<<20, 0)
	})
	fake.fail(true)
	harness.run(t, func() bool { return harness.engine.Snapshot().Transfer.LastError != "" })
	engine := harness.engine

	for _, testCase := range []struct {
		name        string
		hostname    string
		status      string
		wantBlocked bool
	}{
		// Nothing is running through a tunnel that is down, so there is nothing to protect.
		{"the tunnel is down", "se-01.protonvpn.net", "crashed", false},
		{"the tunnel is stopped", "se-01.protonvpn.net", "stopped", false},
		// A running tunnel may be carrying something whether or not this tool can name the
		// server it is on. Conflating those two shipped as a bug: on startup the server is
		// routinely unidentifiable for a moment while the tunnel is downloading at full
		// speed, and "unidentifiable" was taken as "nothing to protect", which switched
		// servers mid-transfer on every restart.
		{"running, server not yet identified", "", "running", true},
		{"running on a known server", "se-01.protonvpn.net", "running", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			engine.mutateSnapshot(func(snapshot *Snapshot) {
				snapshot.Gluetun.Status = testCase.status
				if testCase.hostname == "" {
					// Every route to a hostname has to be closed, not just the pin:
					// currentHostname also matches Gluetun's exit address against
					// Proton's, which the harness's fake answers.
					snapshot.Gluetun.Selection = nil
					snapshot.Gluetun.Exit.IP = ""
				} else {
					snapshot.Gluetun.Selection = map[string][]string{
						"hostnames": {testCase.hostname},
					}
				}
			})
			// The hostname must not be recoverable from the remembered pin either.
			if err := engine.state.update(func(state *persistedState) {
				state.PinnedHostname = testCase.hostname
			}); err != nil {
				t.Fatal(err)
			}
			engine.startedAt = time.Now()

			blocked, reason := engine.transferBlocksSwitch()
			if blocked != testCase.wantBlocked {
				t.Errorf("blocked = %v, want %v (reason: %q)", blocked, testCase.wantBlocked, reason)
			}
		})
	}
}

// Restarting Gluetun discards the hostname this tool selected: the selection is applied
// through the control server at runtime, not configured, so Gluetun comes back having
// chosen a server from its own filters.
//
// This shipped wrong. currentHostname's own comment said the remembered value was for when
// Gluetun could not be asked, but nothing checked that - so a readable Gluetun reporting no
// hostname selection still yielded the stale value. Everything downstream inherited it: the
// dashboard named the wrong server, transfer figures were credited to it, and selection saw
// nothing to fix because its own choice looked current.
func TestARestartedGluetunDoesNotLeaveAStaleCurrentServer(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	const selected = "se-01.protonvpn.net"
	if err := engine.state.update(func(state *persistedState) {
		state.PinnedHostname = selected
	}); err != nil {
		t.Fatal(err)
	}

	// While Gluetun agrees, the pin is the answer and nothing is disturbed.
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.SettingsReadable = true
		snapshot.Gluetun.Selection = map[string][]string{"hostnames": {selected}}
	})
	if hostname, source := engine.currentHostname(); hostname != selected {
		t.Errorf("hostname = %q (%s), want the pinned %q", hostname, source, selected)
	}
	engine.verifyGluetunPin()
	if got := engine.state.snapshot().PinnedHostname; got != selected {
		t.Errorf("the pin was forgotten while Gluetun still agreed: %q", got)
	}

	// Now Gluetun has restarted: readable settings, no hostname selection, and an exit
	// address that matches no Proton server so identification cannot fall back to it.
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.SettingsReadable = true
		snapshot.Gluetun.Selection = map[string][]string{"countries": {"Sweden"}}
		snapshot.Gluetun.Exit.IP = "203.0.113.7"
	})

	hostname, source := engine.currentHostname()
	if hostname == selected {
		t.Errorf("still reporting %q as current after Gluetun reported no selection", selected)
	}
	if hostname != "" || source != "unknown" {
		t.Errorf("hostname = %q (%s), want unknown so the next evaluation re-selects",
			hostname, source)
	}

	// And the stale value is forgotten rather than left to mislead the next reader.
	engine.verifyGluetunPin()
	if got := engine.state.snapshot().PinnedHostname; got != "" {
		t.Errorf("PinnedHostname = %q, want it cleared after Gluetun disproved it", got)
	}
}

// Unreadable settings prove nothing either way. Treating silence as disagreement would
// discard a good pin every time the control server hiccuped.
func TestAnUnreadableGluetunDoesNotDiscardThePin(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	const selected = "se-01.protonvpn.net"
	if err := engine.state.update(func(state *persistedState) {
		state.PinnedHostname = selected
	}); err != nil {
		t.Fatal(err)
	}
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.SettingsReadable = false
		snapshot.Gluetun.Selection = nil
		snapshot.Gluetun.Exit.IP = "203.0.113.7"
	})

	if hostname, source := engine.currentHostname(); hostname != selected || source != "remembered" {
		t.Errorf("hostname = %q (%s), want the remembered %q while Gluetun cannot be asked",
			hostname, source, selected)
	}
	engine.verifyGluetunPin()
	if got := engine.state.snapshot().PinnedHostname; got != selected {
		t.Errorf("the pin was discarded on unreadable settings: %q", got)
	}
}

// In the modes that never pin a hostname, Gluetun reporting no hostname is normal rather
// than evidence of anything, so the remembered value stays the best answer available.
func TestTheRememberedPinSurvivesInModesThatDoNotPin(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.Mode = config.ReconnectStatus
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	const selected = "se-01.protonvpn.net"
	if err := engine.state.update(func(state *persistedState) {
		state.PinnedHostname = selected
	}); err != nil {
		t.Fatal(err)
	}
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.SettingsReadable = true
		snapshot.Gluetun.Selection = map[string][]string{"countries": {"Sweden"}}
		snapshot.Gluetun.Exit.IP = "203.0.113.7"
	})

	if hostname, _ := engine.currentHostname(); hostname != selected {
		t.Errorf("hostname = %q, want the remembered %q in status mode", hostname, selected)
	}
	engine.verifyGluetunPin()
	if got := engine.state.snapshot().PinnedHostname; got != selected {
		t.Errorf("PinnedHostname = %q, want it kept in a mode that never pins", got)
	}
}

// Load and latency go through the immediate write path, not the deferred one, so they are
// on disk as soon as they are sampled. Asserted rather than assumed: the two paths look
// identical at the call site and the difference is one method name.
func TestLoadAndLatencyStatisticsAreOnDiskImmediately(t *testing.T) {
	var fake *fakeQBittorrent
	harness := newHarness(t, false, func(cfg *config.Config) {
		fake = withQBittorrent(t, cfg, 0, 0)
	})
	_ = fake
	engine := harness.engine
	engine.applyLogicals(mixedP2PLogicals(), false)

	hostname := engine.ranked[0].Candidate.Hostname
	engine.prober.Record(engine.ranked[0].Candidate.EntryIP, 37*time.Millisecond)
	engine.recordSamples()

	// A fresh store over the same directory, without any flush: whatever is there is what
	// a restart would find.
	reloaded := newStateStore(filepath.Dir(engine.state.path))
	if err := reloaded.load(); err != nil {
		t.Fatal(err)
	}
	record, found := reloaded.snapshot().Stats[hostname]
	if !found {
		t.Fatal("no statistics on disk after a sample")
	}
	if record.LoadLast == 0 || record.LoadLowest == 0 || record.LoadHighest == 0 {
		t.Errorf("load statistics did not reach the disk: %+v", record)
	}
	if record.RTTLastMS != 37 || record.RTTLowestMS != 37 || record.RTTHighestMS != 37 {
		t.Errorf("latency statistics did not reach the disk: %+v", record)
	}
	if record.Samples != 1 {
		t.Errorf("samples = %d, want 1", record.Samples)
	}

	// A second, worse reading widens the range rather than replacing it - the point of
	// keeping extremes at all.
	engine.prober.Record(engine.ranked[0].Candidate.EntryIP, 210*time.Millisecond)
	engine.recordSamples()

	reloaded = newStateStore(filepath.Dir(engine.state.path))
	if err := reloaded.load(); err != nil {
		t.Fatal(err)
	}
	record = reloaded.snapshot().Stats[hostname]
	if record.RTTLowestMS != 37 {
		t.Errorf("lowest = %d ms, want the earlier 37 kept", record.RTTLowestMS)
	}
	if record.RTTHighestMS < 100 {
		t.Errorf("highest = %d ms, want the slower reading recorded", record.RTTHighestMS)
	}
}

// The floor on how often the tunnel is torn down has to be absolute, or it is not a floor.
//
// It used to sit below the "current server unknown" case while claiming in its own comment
// that nothing bypassed it. That case did bypass it, which left a reconnect loop reachable:
// anything that keeps the current server unidentifiable would tear the tunnel down on every
// evaluation, for ever.
func TestTheMinimumIntervalAlsoBoundsAnUnidentifiedServer(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.MinInterval = time.Hour
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine
	engine.applyLogicals(mixedP2PLogicals(), false)

	// A switch happened moments ago, and the current server cannot be identified at all.
	if err := engine.state.update(func(state *persistedState) {
		state.LastSwitchAt = time.Now()
		state.PinnedHostname = ""
	}); err != nil {
		t.Fatal(err)
	}
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.SettingsReadable = true
		snapshot.Gluetun.Selection = nil
		snapshot.Gluetun.Exit.IP = ""
	})

	verdict := engine.decide(scoring.Scored{}, false, engine.ranked[0], false)
	if verdict.shouldSwitch {
		t.Errorf("switched with the floor armed: %+v", verdict)
	}
	if !strings.Contains(verdict.explanation, "minimum interval") {
		t.Errorf("explanation = %q, want it to name the floor", verdict.explanation)
	}

	// An explicit instruction is still the operator's to give.
	if forced := engine.decide(scoring.Scored{}, false, engine.ranked[0], true); !forced.shouldSwitch {
		t.Error("a forced switch should bypass the floor")
	}
}

// "Already on the best server" is the useful answer when it and the floor are both true, so
// it is checked first. Moving the floor up must not have swallowed it.
func TestAlreadyOnTheBestServerIsStillTheAnswerUnderTheFloor(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		cfg.Switch.MinInterval = time.Hour
	})
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine
	engine.applyLogicals(mixedP2PLogicals(), false)

	if err := engine.state.update(func(state *persistedState) {
		state.LastSwitchAt = time.Now()
	}); err != nil {
		t.Fatal(err)
	}

	best := engine.ranked[0]
	verdict := engine.decide(best, true, best, false)
	if verdict.explanation != "already on the best server" {
		t.Errorf("explanation = %q, want the friendlier truth", verdict.explanation)
	}
}

// A restarted Gluetun has re-read the servers file, so hostnames it rejected before are very
// likely valid now - that is what the restart fixes. Keeping the learned rejections would
// make this tool skip its best candidates for no reason.
func TestARestartedGluetunClearsLearnedRejections(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine

	// The set is learned from a rejection, which is how it is populated in practice.
	engine.gluetunKnownHosts = map[string]struct{}{"se-99.protonvpn.net": {}}
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Selection.NeedsGluetunRestart = true
	})
	if err := engine.state.update(func(state *persistedState) {
		state.PinnedHostname = "se-01.protonvpn.net"
	}); err != nil {
		t.Fatal(err)
	}
	if len(engine.gluetunKnownHosts) == 0 {
		t.Fatal("no rejections were learned, so this proves nothing")
	}

	// Gluetun comes back with no hostname selection: it has restarted.
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.SettingsReadable = true
		snapshot.Gluetun.Selection = map[string][]string{"countries": {"Sweden"}}
	})
	engine.verifyGluetunPin()

	if len(engine.gluetunKnownHosts) != 0 {
		t.Errorf("learned rejections survived a Gluetun restart: %v", engine.gluetunKnownHosts)
	}
	if engine.Snapshot().Selection.NeedsGluetunRestart {
		t.Error("the restart advice is still showing after Gluetun restarted")
	}
}

// Nothing may read the snapshot while holding the write lock on it.
//
// sync.RWMutex is not reentrant, so a read inside a mutateSnapshot closure deadlocks the
// engine loop permanently: no evaluations, no health checks, no dashboard updates, and no
// error either - the process simply stops doing anything. Several helpers guard against it
// by computing their values before taking the lock, and the comments say so, but a comment
// is not enforcement. This is.
func TestNothingReadsTheSnapshotWhileWritingIt(t *testing.T) {
	t.Parallel()

	// Reads of published state, directly or through a helper that performs one.
	readers := []string{
		"e.Snapshot()", "e.currentHostname(", "e.nextRuns(", "e.statsFor(",
		"e.transferView(", "e.onCurrentSince(", "e.transferBlocksSwitch(",
		"e.portForwardingVerdict(", "e.loadTrace(",
	}

	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, path := range sources {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)

		const opener = "mutateSnapshot(func(snapshot *Snapshot)"
		for offset := 0; ; {
			start := strings.Index(text[offset:], opener)
			if start < 0 {
				break
			}
			start += offset
			// Match braces to find the closure body exactly; a regex cannot, and being
			// approximate here would either miss cases or cry wolf.
			open := strings.Index(text[start:], "{") + start
			depth, end := 1, open+1
			for depth > 0 && end < len(text) {
				switch text[end] {
				case '{':
					depth++
				case '}':
					depth--
				}
				end++
			}
			body := text[open:end]
			line := 1 + strings.Count(text[:start], "\n")
			checked++

			for _, reader := range readers {
				if strings.Contains(body, reader) {
					t.Errorf("%s:%d takes the write lock and then calls %s, "+
						"which takes the read lock: the engine would deadlock. "+
						"Compute it before mutateSnapshot.", path, line, reader)
				}
			}
			offset = end
		}
	}
	if checked < 10 {
		t.Fatalf("only found %d snapshot writers; the scan is not working", checked)
	}
	t.Logf("checked %d mutateSnapshot closures", checked)
}

// A full list fetch is also a load refresh, because Proton embeds the utilisation figures in
// the logical servers it returns.
//
// Not treating it as one left a quarter of an hour of a run misreporting itself: the
// candidate list said "loads not fetched yet" while ranking on figures it had just received,
// and no server accumulated a load or latency reading until the first loads tick.
func TestAListFetchCountsAsALoadRefresh(t *testing.T) {
	harness := newHarness(t, false, nil)
	engine := harness.engine

	// Exactly the startup sequence: a list fetch, and no loads tick yet.
	engine.refreshServerList(context.Background(), "startup")

	proton := engine.Snapshot().Proton
	if proton.LastLoadRefresh.IsZero() {
		t.Error("the loads are reported as never fetched, though the list carried them")
	}
	if proton.LastLoadRefresh.Before(proton.LastFetch.Add(-time.Minute)) {
		t.Errorf("load refresh %v is older than the fetch %v that produced it",
			proton.LastLoadRefresh, proton.LastFetch)
	}

	// And the per-server statistics start accumulating immediately rather than in fifteen
	// minutes' time.
	stats := engine.state.snapshot().Stats
	if len(stats) == 0 {
		t.Fatal("no server statistics recorded from the list fetch")
	}
	var withLoad int
	for _, record := range stats {
		if record.Samples > 0 {
			withLoad++
		}
	}
	if withLoad == 0 {
		t.Error("statistics exist but none carries a load reading")
	}
}

// The startup sequence, reproduced from a real restart that switched servers during a
// 1.1 MB/s upload.
//
// What happened: Gluetun was checked first, found usable, and evaluated on the spot - all
// before qBittorrent had been asked whether anything was flowing. With no reading, switching
// fell open. Then the freshly applied pin was not recorded in the snapshot, so four seconds
// later the next evaluation saw readable settings naming no hostname, took that as proof the
// pin was stale, and switched again.
func TestARestartDuringATransferDoesNotSwitch(t *testing.T) {
	harness := newHarness(t, false, func(cfg *config.Config) {
		// Uploading hard, well over the threshold - the situation from the report.
		withQBittorrent(t, cfg, 0, 8<<20)
	})
	engine := harness.engine
	engine.applyLogicals(mixedP2PLogicals(), false)

	// The state a restart inherits: a remembered selection from the previous run, which
	// Gluetun has since forgotten because it restarted too.
	if err := engine.state.update(func(state *persistedState) {
		state.PinnedHostname = "node-se-p2p.protonvpn.net"
	}); err != nil {
		t.Fatal(err)
	}
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.Status = "running"
		snapshot.Gluetun.SettingsReadable = true
		snapshot.Gluetun.Selection = map[string][]string{"countries": {"Sweden"}}
	})

	// Startup order: the transfer reading must be in hand before anything evaluates.
	engine.identifyQBittorrent(context.Background())
	engine.refreshTransfer(context.Background(), "startup")

	if !engine.Snapshot().Transfer.HasReading {
		t.Fatal("no transfer reading after the startup poll; the order under test is wrong")
	}
	if !engine.Snapshot().Transfer.Busy {
		t.Fatalf("8 MB/s up should read as busy: %+v", engine.Snapshot().Transfer)
	}

	// The current server is genuinely unidentifiable at this point - that is the case that
	// went wrong - and switching must still be deferred.
	if hostname, _ := engine.currentHostname(); hostname != "" {
		t.Fatalf("hostname = %q, expected unidentifiable at this point", hostname)
	}
	blocked, reason := engine.transferBlocksSwitch()
	if !blocked {
		t.Error("switching was allowed during an active upload after a restart")
	}
	if !strings.Contains(reason, "transfer is in progress") {
		t.Errorf("reason = %q, want it to name the transfer", reason)
	}

	// And the whole decision agrees, rather than only the gate.
	verdict := engine.decide(scoring.Scored{}, false, engine.ranked[0], false)
	if verdict.shouldSwitch {
		t.Errorf("decided to switch mid-transfer: %+v", verdict)
	}
}

// A pin Gluetun accepted is where the tunnel is, and the snapshot has to say so at once.
//
// Otherwise the next evaluation sees readable settings naming no hostname, treats the
// remembered pin as disproven - which it is, in general - and switches again. That produced
// two switches four seconds apart on a restart.
func TestAnAcceptedPinIsImmediatelyTheCurrentServer(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine
	engine.applyLogicals(mixedP2PLogicals(), false)

	// Gluetun readable but naming no hostname: the post-restart state.
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.SettingsReadable = true
		snapshot.Gluetun.Selection = map[string][]string{"countries": {"Sweden"}}
	})

	target := engine.ranked[0]
	engine.performSwitch(context.Background(), "", scoring.Scored{}, false, "test")

	hostname, source := engine.currentHostname()
	if hostname != target.Candidate.Hostname {
		t.Errorf("current = %q (%s), want the server just pinned, %q",
			hostname, source, target.Candidate.Hostname)
	}
	if source != "pinned" {
		t.Errorf("source = %q, want it identified from Gluetun's own selection", source)
	}

	// So a second evaluation immediately afterwards has nothing to fix.
	verdict := engine.decide(target, true, target, false)
	if verdict.shouldSwitch {
		t.Errorf("switched again straight after a successful switch: %+v", verdict)
	}
}

// The startup order is load-bearing, and a reordering of six adjacent lines would break it
// silently, so it is asserted rather than left to a comment.
func TestTheStartupOrderReadsTheTransferStateBeforeAnythingEvaluates(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatal(err)
	}
	run := regexp.MustCompile(`(?s)func \(e \*Engine\) Run\(.*?\n\tfor \{`).Find(source)
	if run == nil {
		t.Fatal("could not find the startup sequence")
	}

	position := func(call string) int {
		at := bytes.Index(run, []byte(call))
		if at < 0 {
			t.Fatalf("the startup sequence does not call %s", call)
		}
		return at
	}

	transfer := position("e.refreshTransfer(ctx, \"startup\")")
	// checkGluetun evaluates on its own when Gluetun becomes usable, so it must not run
	// before the transfer state is known: with no reading, switching falls open and a
	// restart during a download moves the tunnel.
	if gluetun := position("e.checkGluetun(ctx)"); gluetun < transfer {
		t.Error("checkGluetun runs before the first transfer reading; it evaluates on its " +
			"own when Gluetun becomes usable, and an evaluation with no reading switches")
	}
	// And the explicit startup evaluation comes after everything it depends on.
	if evaluate := position("e.evaluate(ctx, \"startup\", false)"); evaluate < transfer {
		t.Error("the startup evaluation runs before the first transfer reading")
	}
	if identify := position("e.identifyQBittorrent(ctx)"); identify > transfer {
		t.Error("qBittorrent is identified after its rates are first read")
	}
}

// Identification from Gluetun's exit address, for when its selection cannot be read.
//
// The weaker of the two signals, and the only one available in the modes that never pin a
// hostname - so it keeps its own test now that a successful pin identifies itself exactly.
func TestTheCurrentServerCanBeIdentifiedFromTheExitAddress(t *testing.T) {
	harness := newHarness(t, false, nil)
	harness.run(t, func() bool { return harness.engine.Snapshot().Gluetun.Reachable })
	engine := harness.engine
	engine.applyLogicals(mixedP2PLogicals(), false)

	// Proton publishes an exit address per server; Gluetun reports the address the internet
	// sees. When they match, that is the server - no selection needed.
	target := engine.ranked[0].Candidate
	engine.mutateSnapshot(func(snapshot *Snapshot) {
		snapshot.Gluetun.SettingsReadable = true
		snapshot.Gluetun.Selection = map[string][]string{"countries": {"Sweden"}}
		snapshot.Gluetun.Exit.IP = target.ExitIP.String()
	})

	hostname, source := engine.currentHostname()
	if hostname != target.Hostname {
		t.Errorf("hostname = %q, want %q from the matching exit address", hostname, target.Hostname)
	}
	if source != "public-ip" {
		t.Errorf("source = %q, want public-ip", source)
	}

	// An address matching no Proton server means nothing rather than something wrong: Proton
	// publishes the server address, which is often not the one the internet sees.
	engine.mutateSnapshot(func(snapshot *Snapshot) { snapshot.Gluetun.Exit.IP = "203.0.113.7" })
	if hostname, source := engine.currentHostname(); hostname != "" || source != "unknown" {
		t.Errorf("hostname = %q (%s), want unknown for an unmatched address", hostname, source)
	}
}
