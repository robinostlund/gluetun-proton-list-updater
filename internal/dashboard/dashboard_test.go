package dashboard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/catalog"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/engine"
	"github.com/robinostlund/gluetun-proton-list-updater/internal/logbuf"
)

// stubController records what the dashboard asked for and lets tests inject
// failures.
type stubController struct {
	mu          sync.Mutex
	calls       []string
	failWith    error
	totpAccepts bool
	healthy     bool
	updates     chan struct{}
}

func newStub() *stubController {
	return &stubController{
		totpAccepts: true,
		healthy:     true,
		updates:     make(chan struct{}, 1),
	}
}

func (s *stubController) record(name string) error {
	s.mu.Lock()
	s.calls = append(s.calls, name)
	s.mu.Unlock()
	return s.failWith
}

func (s *stubController) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *stubController) Explain(query string) ([]catalog.Explanation, error) {
	_ = s.record("explain:" + query)
	if s.failWith != nil {
		return nil, s.failWith
	}
	return []catalog.Explanation{{ServerName: "SE#444", Country: "Sweden", Included: false,
		Reasons: []string{"load 95% is above MAX_LOAD=80"}}}, nil
}

func (s *stubController) Snapshot() engine.Snapshot {
	return engine.Snapshot{Version: "test", At: time.Now(), CandidatesTotal: 3}
}

func (s *stubController) Subscribe() (<-chan struct{}, func()) {
	return s.updates, func() {}
}

func (s *stubController) RefreshList(context.Context) error      { return s.record("refresh-list") }
func (s *stubController) RefreshLoads(context.Context) error     { return s.record("refresh-loads") }
func (s *stubController) ProbeLatency(context.Context) error     { return s.record("probe") }
func (s *stubController) Evaluate(context.Context) error         { return s.record("evaluate") }
func (s *stubController) SwitchToBest(context.Context) error     { return s.record("switch-best") }
func (s *stubController) WriteServersFile(context.Context) error { return s.record("write-servers") }

func (s *stubController) SwitchTo(_ context.Context, hostname string) error {
	return s.record("switch-to:" + hostname)
}

func (s *stubController) SetAutoSwitch(_ context.Context, enabled bool) error {
	if enabled {
		return s.record("auto-switch:on")
	}
	return s.record("auto-switch:off")
}

func (s *stubController) SubmitTOTP(code string) bool {
	_ = s.record("totp:" + code)
	return s.totpAccepts
}

func (s *stubController) Healthy() (bool, string) {
	if s.healthy {
		return true, "ok"
	}
	return false, "no candidate servers available"
}

func newTestServer(t *testing.T, controller Controller, opts Options) *httptest.Server {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	server := httptest.NewServer(New(controller, opts).routes())
	t.Cleanup(server.Close)
	return server
}

func TestServesTheEmbeddedPage(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, newStub(), Options{})
	response, err := server.Client().Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	body, _ := io.ReadAll(response.Body)
	// The page must be self-contained: a strict environment may have no
	// outbound access at all.
	if strings.Contains(string(body), "http://") || strings.Contains(string(body), "https://") {
		if !strings.Contains(string(body), "www.w3.org") { // the inline SVG namespace is fine
			t.Error("the page appears to reference an external resource")
		}
	}
	for _, want := range []string{"style.css", "app.js", "Current server"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

func TestServesAssets(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, newStub(), Options{})
	for _, asset := range []string{"/style.css", "/app.js"} {
		response, err := server.Client().Get(server.URL + asset)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d", asset, response.StatusCode)
		}
	}
}

func TestStateEndpoint(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, newStub(), Options{})
	response, err := server.Client().Get(server.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	var snapshot engine.Snapshot
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		t.Fatalf("decoding snapshot: %v", err)
	}
	if snapshot.Version != "test" || snapshot.CandidatesTotal != 3 {
		t.Errorf("unexpected snapshot: %+v", snapshot)
	}
}

func TestCommandEndpoints(t *testing.T) {
	t.Parallel()

	stub := newStub()
	server := newTestServer(t, stub, Options{})

	endpoints := map[string]string{
		"/api/refresh":       "refresh-list",
		"/api/loads":         "refresh-loads",
		"/api/probe":         "probe",
		"/api/evaluate":      "evaluate",
		"/api/reconnect":     "switch-best",
		"/api/servers/write": "write-servers",
	}

	for endpoint, wantCall := range endpoints {
		response, err := server.Client().Post(server.URL+endpoint, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: %v", endpoint, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusAccepted {
			t.Errorf("%s: status = %d, want 202", endpoint, response.StatusCode)
		}
		if !containsString(stub.recorded(), wantCall) {
			t.Errorf("%s did not invoke %q, calls: %v", endpoint, wantCall, stub.recorded())
		}
	}
}

func TestSwitchRequiresHostname(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, newStub(), Options{})
	response, err := server.Client().Post(server.URL+"/api/switch", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
}

func TestSwitchPassesHostname(t *testing.T) {
	t.Parallel()

	stub := newStub()
	server := newTestServer(t, stub, Options{})

	response, err := server.Client().Post(server.URL+"/api/switch", "application/json",
		strings.NewReader(`{"hostname":"se-02.protonvpn.net"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", response.StatusCode)
	}
	if !containsString(stub.recorded(), "switch-to:se-02.protonvpn.net") {
		t.Errorf("calls = %v", stub.recorded())
	}
}

// An unknown field is far more likely to be a client bug than an intention, so
// it should be rejected rather than silently ignored.
func TestRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, newStub(), Options{})
	response, err := server.Client().Post(server.URL+"/api/switch", "application/json",
		strings.NewReader(`{"host":"typo"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
}

func TestAutoSwitchToggle(t *testing.T) {
	t.Parallel()

	stub := newStub()
	server := newTestServer(t, stub, Options{})

	for body, wantCall := range map[string]string{
		`{"enabled":true}`:  "auto-switch:on",
		`{"enabled":false}`: "auto-switch:off",
	} {
		response, err := server.Client().Post(server.URL+"/api/auto-switch", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d", body, response.StatusCode)
		}
		if !containsString(stub.recorded(), wantCall) {
			t.Errorf("%s did not invoke %q", body, wantCall)
		}
	}
}

func TestTOTPSubmission(t *testing.T) {
	t.Parallel()

	stub := newStub()
	server := newTestServer(t, stub, Options{})

	response, err := server.Client().Post(server.URL+"/api/totp", "application/json",
		strings.NewReader(`{"code":"123456"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", response.StatusCode)
	}

	// When no login is waiting, the user needs to be told rather than left
	// thinking the code was used.
	stub.totpAccepts = false
	response, err = server.Client().Post(server.URL+"/api/totp", "application/json",
		strings.NewReader(`{"code":"123456"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", response.StatusCode)
	}
}

func TestCommandFailureIsReported(t *testing.T) {
	t.Parallel()

	stub := newStub()
	stub.failWith = context.DeadlineExceeded
	server := newTestServer(t, stub, Options{})

	response, err := server.Client().Post(server.URL+"/api/refresh", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", response.StatusCode)
	}
	var payload struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.OK || payload.Error == "" {
		t.Errorf("payload = %+v, want ok=false with an error", payload)
	}
}

func TestBasicAuth(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, newStub(), Options{Username: "admin", Password: "hunter2"})

	response, err := server.Client().Get(server.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status without credentials = %d, want 401", response.StatusCode)
	}

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/state", nil)
	request.SetBasicAuth("admin", "hunter2")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("status with credentials = %d, want 200", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/state", nil)
	request.SetBasicAuth("admin", "wrong")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("status with a wrong password = %d, want 401", response.StatusCode)
	}
}

// The health endpoint must stay open so Docker's health check works without
// credentials in the compose file.
func TestHealthEndpointNeedsNoAuth(t *testing.T) {
	t.Parallel()

	stub := newStub()
	server := newTestServer(t, stub, Options{Username: "admin", Password: "hunter2"})

	response, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", response.StatusCode)
	}

	stub.healthy = false
	response, err = server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("unhealthy status = %d, want 503", response.StatusCode)
	}
}

func TestLogsEndpoint(t *testing.T) {
	t.Parallel()

	logs := logbuf.NewBuffer(10)
	logs.Append(logbuf.Record{Time: time.Now(), Level: "INFO", Message: "hello"})

	server := newTestServer(t, newStub(), Options{Logs: logs})
	response, err := server.Client().Get(server.URL + "/api/logs?limit=5")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	var records []logbuf.Record
	if err := json.NewDecoder(response.Body).Decode(&records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Message != "hello" {
		t.Errorf("records = %+v", records)
	}
}

func TestEventStreamSendsAnInitialSnapshot(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, newStub(), Options{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/events", nil)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if got := response.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type = %q", got)
	}

	reader := bufio.NewReader(response.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the first event: %v", err)
	}
	if !strings.HasPrefix(line, "data: ") {
		t.Fatalf("first line = %q, want an SSE data frame", line)
	}

	var snapshot engine.Snapshot
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &snapshot); err != nil {
		t.Fatalf("decoding the streamed snapshot: %v", err)
	}
	if snapshot.Version != "test" {
		t.Errorf("streamed snapshot = %+v", snapshot)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

func TestExplainEndpoint(t *testing.T) {
	t.Parallel()

	stub := newStub()
	server := newTestServer(t, stub, Options{})

	response, err := server.Client().Get(server.URL + "/api/explain?q=SE%23444")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var payload struct {
		OK      bool                  `json:"ok"`
		Query   string                `json:"query"`
		Matches []catalog.Explanation `json:"matches"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if !payload.OK || payload.Query != "SE#444" || len(payload.Matches) != 1 {
		t.Fatalf("payload = %+v", payload)
	}
	if len(payload.Matches[0].Reasons) == 0 {
		t.Error("the explanation should carry a reason")
	}
	if !containsString(stub.recorded(), "explain:SE#444") {
		t.Errorf("calls = %v", stub.recorded())
	}
}

func TestExplainEndpointRequiresAQuery(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, newStub(), Options{})
	response, err := server.Client().Get(server.URL + "/api/explain")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", response.StatusCode)
	}
}

// Every element the front end writes to must exist in the page.
//
// This is a structural test rather than a behavioural one, and it exists because
// a careless edit to index.html once removed two whole cards: the front end then
// threw on the first missing element, and every render step after that point -
// including the switch history - silently stopped working. Nothing else in this
// suite noticed, because the server was serving a perfectly valid 200.
func TestEveryElementTheFrontEndUsesExists(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	// IDs present in the page.
	declared := map[string]bool{}
	for _, match := range regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`).FindAllSubmatch(page, -1) {
		declared[string(match[1])] = true
	}
	// IDs the page creates at runtime, inside rendered markup rather than the
	// static document.
	for _, match := range regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`).FindAllSubmatch(script, -1) {
		declared[string(match[1])] = true
	}

	// IDs the script looks up.
	used := map[string]bool{}
	for _, pattern := range []string{`el\('([a-zA-Z0-9_-]+)'\)`, `text\('([a-zA-Z0-9_-]+)'`} {
		for _, match := range regexp.MustCompile(pattern).FindAllSubmatch(script, -1) {
			used[string(match[1])] = true
		}
	}

	if len(used) < 20 {
		t.Fatalf("only found %d element lookups, the patterns are probably wrong", len(used))
	}

	var missing []string
	for id := range used {
		if !declared[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("app.js writes to elements that do not exist in index.html: %v\n"+
			"the front end throws on the first one, so every later render step stops working",
			missing)
	}
}

// The reverse direction: a card left in the page that nothing fills would show
// permanent placeholder dashes.
func TestEveryPageElementIsFilled(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	// Containers and inputs are addressed in other ways (listeners, querySelector,
	// tBodies), so only value placeholders are checked.
	ignored := map[string]bool{
		"alerts": true, "candidates": true, "history": true, "logs": true,
		"settings": true, "stats": true, "toast": true, "filter": true,
		"auto-switch": true, "explain-form": true, "explain-query": true,
		"explain-result": true, "totp-form": true, "totp-code": true,
		"activity": true, "gluetun-detail": true,
	}

	var unused []string
	for _, match := range regexp.MustCompile(`id="([a-zA-Z0-9_-]+)"`).FindAllSubmatch(page, -1) {
		id := string(match[1])
		if ignored[id] {
			continue
		}
		if !bytes.Contains(script, []byte("'"+id+"'")) {
			unused = append(unused, id)
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		t.Errorf("index.html declares elements nothing fills, so they show a permanent dash: %v", unused)
	}
}
