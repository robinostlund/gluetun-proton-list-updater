package dashboard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func (s *stubController) ClearHistory(_ context.Context) error {
	return s.record("clear-history")
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
	for _, want := range []string{"style.css", "app.js", "Server selection"} {
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
		// Addressed through data-collapse rather than by id, and it carries its own
		// label text in the markup, so it can never show a placeholder dash.
		"toggle-candidates": true,
		// A container for the table, not a value slot.
		"candidates-body": true,
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

// A blocked candidate is a row the operator can see but must not be able to use.
// The rendering is JavaScript, so this asserts statically on the asset: the fields
// the engine publishes have to be the ones the script reads, and the row has to be
// both styled and disabled. Getting either half wrong produces a row that looks
// selectable and fails on click.
func TestBlockedRowsAreRenderedAsUnusable(t *testing.T) {
	t.Parallel()

	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	for _, fragment := range []string{
		// The snapshot fields, spelled exactly as the JSON tags on CandidateView.
		"candidate.blocked",
		"candidate.blocked_by",
		// The Use button must be disabled for them, not merely styled.
		"candidate.is_current || candidate.blocked ? 'disabled' : ''",
		// And the row must be marked so it reads as unusable.
		"is-blocked",
		"tag-blocked",
	} {
		if !bytes.Contains(script, []byte(fragment)) {
			t.Errorf("app.js does not contain %q, so blocked servers are not handled", fragment)
		}
	}

	for _, selector := range []string{"tr.is-blocked", ".tag-blocked"} {
		if !bytes.Contains(styles, []byte(selector)) {
			t.Errorf("style.css has no %q rule, so a blocked row is indistinguishable", selector)
		}
	}
}

// The P2P restriction has two possible causes and the dashboard must be able to
// name the right one; "Gluetun requires one" is meaningless to an operator who only
// ever set VPN_PORT_FORWARDING.
func TestThePortForwardingReasonIsShown(t *testing.T) {
	t.Parallel()

	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	// The setting's name is interpolated from the snapshot rather than hard-coded, so
	// what matters is that the field is read and rendered as the restriction's cause.
	for _, fragment := range []string{
		"port_forward_requirement_from",
		"best-restriction",
	} {
		if !bytes.Contains(script, []byte(fragment)) {
			t.Errorf("app.js does not use %q, so the restriction cannot explain itself", fragment)
		}
	}
}

// Clearing the switch history goes through the engine, because the history is
// persisted: only the engine can write the state file.
func TestClearHistoryReachesTheController(t *testing.T) {
	t.Parallel()

	stub := newStub()
	server := newTestServer(t, stub, Options{})

	response, err := server.Client().Post(server.URL+"/api/history/clear",
		"application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", response.StatusCode)
	}
	if !containsString(stub.recorded(), "clear-history") {
		t.Errorf("calls = %v, want clear-history", stub.recorded())
	}
}

// Clearing the activity log empties the buffer the page reads, and deliberately
// does not involve the engine: there is no persisted state behind it.
func TestClearLogsEmptiesTheBuffer(t *testing.T) {
	t.Parallel()

	logs := logbuf.NewBuffer(50)
	logs.Append(logbuf.Record{Message: "something happened"})
	logs.Append(logbuf.Record{Message: "and again"})

	stub := newStub()
	server := newTestServer(t, stub, Options{Logs: logs})

	if got := len(logs.Records(0)); got != 2 {
		t.Fatalf("buffer should start with 2 records, got %d", got)
	}
	response, err := server.Client().Post(server.URL+"/api/logs/clear",
		"application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	// One record survives: the confirmation written by the handler itself, which is
	// what tells the operator the clear actually happened.
	remaining := logs.Records(0)
	for _, record := range remaining {
		if strings.Contains(record.Message, "something happened") {
			t.Error("the old records are still in the buffer")
		}
	}
	if len(stub.recorded()) != 0 {
		t.Errorf("the engine should not be involved, got %v", stub.recorded())
	}
}

// A clear on an unconfigured buffer must not panic - the buffer is optional.
func TestClearLogsWithoutABufferIsHarmless(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, newStub(), Options{})
	response, err := server.Client().Post(server.URL+"/api/logs/clear",
		"application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", response.StatusCode)
	}
}

// The candidate table's columns and the cells the script emits have to agree, or
// every row is shifted under the wrong headings - which looks like corrupt data
// rather than a layout bug.
func TestCandidateTableColumnsMatchTheRenderedCells(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	// Country and City are separate columns; a single merged "Location" is what this
	// replaced.
	head := regexp.MustCompile(`(?s)<table id="candidates">.*?</thead>`).Find(page)
	if head == nil {
		t.Fatal("could not find the candidates table head")
	}
	headings := regexp.MustCompile(`<th[^>]*>([^<]*)</th>`).FindAllSubmatch(head, -1)
	var got []string
	for _, match := range headings {
		got = append(got, strings.TrimSpace(string(match[1])))
	}
	want := []string{"#", "Server", "Country", "City", "Load", "Latency", "Score", "Features", "Action"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("headings = %v, want %v", got, want)
	}

	// The row template must emit exactly that many cells.
	row := regexp.MustCompile(`(?s)return \x60<tr class=.*?</tr>\x60;`).Find(script)
	if row == nil {
		t.Fatal("could not find the candidate row template in app.js")
	}
	if cells := bytes.Count(row, []byte("<td")); cells != len(want) {
		t.Errorf("the row template emits %d cells for %d columns", cells, len(want))
	}
}

// The switch history is rendered in a half-width panel, and it overflowed: two full
// hostnames, a reason and an error on one nowrap line are wider than the panel, so
// the table scrolled sideways. The reason now sits under the hostnames and the prose
// cells are allowed to wrap. This pins all three parts of that fix.
func TestSwitchHistoryFitsItsPanel(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	head := regexp.MustCompile(`(?s)<table id="history">.*?</thead>`).Find(page)
	if head == nil {
		t.Fatal("could not find the history table head")
	}
	if bytes.Contains(head, []byte("Reason")) {
		t.Error("the Reason column is back; it belongs under the hostnames")
	}
	var headings []string
	for _, match := range regexp.MustCompile(`<th[^>]*>([^<]*)</th>`).FindAllSubmatch(head, -1) {
		headings = append(headings, strings.TrimSpace(string(match[1])))
	}
	want := []string{"When", "From → to", "Score", "Result"}
	if strings.Join(headings, "|") != strings.Join(want, "|") {
		t.Errorf("headings = %v, want %v", headings, want)
	}

	row := regexp.MustCompile(`(?s)snapshot\.history \|\| \[\]\)\.map\(\(record\) => \x60<tr>.*?</tr>\x60\)`).Find(script)
	if row == nil {
		t.Fatal("could not find the history row template")
	}
	if cells := bytes.Count(row, []byte("<td")); cells != len(want) {
		t.Errorf("the row template emits %d cells for %d columns", cells, len(want))
	}
	// The reason has to still be shown, just in the hostname cell.
	if !bytes.Contains(row, []byte("record.reason")) {
		t.Error("the reason is no longer rendered at all")
	}
	// The empty-state row must span the new column count, or it renders short.
	if !bytes.Contains(script, []byte(`colspan="4" class="muted">No switches recorded yet.`)) {
		t.Error(`the empty-state row does not span 4 columns`)
	}

	// Without this the cells inherit the global nowrap and the panel scrolls again.
	if !bytes.Contains(styles, []byte("#history td { white-space: normal; }")) {
		t.Error("history cells are not allowed to wrap, so long rows will overflow the panel")
	}
	if !bytes.Contains(styles, []byte("#history td:first-child { white-space: nowrap; }")) {
		t.Error("the timestamp column should stay on one line")
	}
	// The shared domain suffix is dropped for width, so the full name has to remain
	// reachable somewhere or the panel loses information.
	if !bytes.Contains(script, []byte("shortHost(record.to)")) {
		t.Error("history hostnames are not shortened, so the row stays too wide")
	}
	if !bytes.Contains(script, []byte(`<td title="${escapeHTML(`+"`"+`${record.from || '—'} → ${record.to}`+"`"+`)}">`)) {
		t.Error("the full hostnames are not preserved in the cell title")
	}
}

// A static width budget, since the rendered page cannot be measured here. The
// widest realistic history row has to fit the narrowest panel the split grid
// produces, or the scrollbar comes back.
func TestSwitchHistoryRowFitsTheNarrowestPanel(t *testing.T) {
	t.Parallel()

	// .split uses minmax(340px, 1fr), so 340px is the narrowest a panel gets before
	// the grid drops to one column and each panel becomes full width.
	const panelWidth = 340
	const cellPadding = 12 * 2 // th, td { padding: 7px 12px }

	// Widths in pixels, measured conservatively: ~7px per character at 12px in a
	// monospace face, ~6.5px at 13px in the UI face.
	// Only the widest unbreakable token in each column has to fit: everything else
	// is allowed to wrap.
	widest := []struct {
		name  string
		token string
		px    float64
	}{
		// Pinned to one line, so the whole value must fit.
		{"When", "3h ago", 6 * 6.5},
		// Breaks at the arrow, and the shared domain is dropped, so one short
		// hostname plus the arrow is the widest unbreakable run.
		{"From → to", "node-se-20 →", 12 * 7},
		// Breaks at the arrow too, leaving one score.
		{"Score", "0.750", 5 * 7},
		// The error wraps; only "failed" is unbreakable.
		{"Result", "failed", 6 * 6.5},
	}

	total := 0.0
	for _, column := range widest {
		total += column.px + cellPadding
	}
	if total > panelWidth {
		var detail []string
		for _, column := range widest {
			detail = append(detail, fmt.Sprintf("%s(%q %.0fpx)", column.name, column.token, column.px))
		}
		t.Errorf("the widest history row needs %.0fpx but the narrowest panel is %dpx; "+
			"columns %v either need to wrap or the table needs fewer of them",
			total, panelWidth, detail)
	}
}

// The four additions are rendered by JavaScript, so this asserts statically on the
// assets: the snapshot fields the engine publishes must be exactly the ones the script
// reads, and each needs somewhere to render into.
func TestTheDashboardRendersTheNewDiagnostics(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	for _, addition := range []struct {
		name     string
		element  string
		fields   []string
		selector string
	}{
		{
			name:     "load freshness",
			element:  `id="candidates-freshness"`,
			fields:   []string{"snapshot.proton.last_load_refresh", "settings.load_refresh_interval"},
			selector: ".freshness",
		},
		{
			name:    "servers gluetun knows",
			element: "", // rendered into the existing gluetun-detail list
			fields:  []string{"gluetun.known_hostnames"},
		},
		{
			// The reasoning is now a labelled row rather than a paragraph, but it must
			// still be shown: it is the answer to "why is nothing happening".
			name:    "why nothing is happening",
			element: `id="best-decision"`,
			fields:  []string{"selection.explanation"},
		},
	} {
		t.Run(addition.name, func(t *testing.T) {
			if addition.element != "" && !bytes.Contains(page, []byte(addition.element)) {
				t.Errorf("index.html has no %s to render into", addition.element)
			}
			for _, field := range addition.fields {
				if !bytes.Contains(script, []byte(field)) {
					t.Errorf("app.js never reads %q", field)
				}
			}
			if addition.selector != "" && !bytes.Contains(styles, []byte(addition.selector)) {
				t.Errorf("style.css has no %q rule", addition.selector)
			}
		})
	}
}

// Gluetun's live selection is not the operator's configured filter: pinning a server
// replaces its countries and cities with that server's own, so an operator who set
// three countries sees one. Labelling those rows "Filter:" made correct behaviour look
// like lost configuration, which is what prompted the rename.
func TestGluetunsLiveSelectionIsNotLabelledAsAFilter(t *testing.T) {
	t.Parallel()

	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(script, []byte("`Filter: ${key}`")) {
		t.Error(`the rows are labelled "Filter: …" again; they are Gluetun's live selection, ` +
			"not the configured filters")
	}
	if !bytes.Contains(script, []byte("`Selected ${key}`")) {
		t.Error("the live-selection rows are not labelled")
	}
	// And the surprise has to be explained, not merely relabelled - now as a tooltip on
	// the rows themselves rather than a paragraph under the panel.
	for _, phrase := range []string{"SERVER_COUNTRIES", "restarts"} {
		if !bytes.Contains(script, []byte(phrase)) {
			t.Errorf("the explanation does not mention %q", phrase)
		}
	}
}

// The transfer card is rendered by JavaScript, so this asserts statically that the
// snapshot fields the engine publishes are the ones the script reads, and that each
// has somewhere to render into.
func TestTheTransferCardRendersWhatTheEnginePublishes(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	for _, element := range []string{
		"transfer-card", "transfer-down", "transfer-up",
		"transfer-down-limit", "transfer-up-limit", "transfer-total",
		"transfer-checked", "transfer-error",
		"transfer-connected", "transfer-portfwd", "transfer-outcome", "transfer-switching",
		"transfer-version", "transfer-listen", "transfer-random",
		"transfer-down-now", "transfer-up-now", "transfer-window",
	} {
		if !bytes.Contains(page, []byte(`id="`+element+`"`)) {
			t.Errorf("index.html has no %q element", element)
		}
	}

	// Field names must match the JSON tags on TransferStatus exactly.
	//
	// connection_status is deliberately absent: it feeds the port-forwarding verdict
	// in the engine, where the comparison against Gluetun's forwarded port lives, and
	// the page renders that verdict rather than re-deriving it.
	for _, field := range []string{
		"transfer.configured", "transfer.reachable", "transfer.download_speed",
		"transfer.upload_speed", "transfer.busy_download_threshold",
		"transfer.busy_upload_threshold", "transfer.busy", "transfer.deferred_for",
		"transfer.average_download", "transfer.average_upload", "transfer.busy_window",
		"transfer.max_defer", "transfer.version",
		"transfer.port_forwarding", "transfer.port_forwarding_detail",
		"transfer.listen_port", "transfer.random_port",
	} {
		if !bytes.Contains(script, []byte(field)) {
			t.Errorf("app.js never reads %q", field)
		}
	}
}

// An unconfigured feature must not render as an idle one. A card reading "0 B/s"
// claims the tunnel is quiet; hiding it admits nobody is measuring.
func TestTheTransferCardHidesItselfWhenNotConfigured(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	// Hidden in the markup, so it never flashes before the first snapshot arrives.
	if !regexp.MustCompile(`id="transfer-card"[^>]*hidden`).Match(page) {
		t.Error("the transfer card should start hidden")
	}
	if !bytes.Contains(script, []byte("card.hidden = !transfer.configured")) {
		t.Error("the card's visibility is not driven by transfer.configured")
	}
	if !bytes.Contains(script, []byte("if (!transfer.configured) return;")) {
		t.Error("rendering should stop early when the feature is off")
	}
}

// "Connected" must mean "this tool can reach qBittorrent's API", and nothing else.
//
// The card used to render connection_status under the words "qBittorrent is
// connected", which reads as exactly that but actually reports qBittorrent's *peer*
// connectivity. So a firewalled-but-perfectly-reachable instance looked unreachable,
// and the genuinely useful signal - can we talk to it at all - was not shown.
func TestConnectedMeansThisToolCanReachQBittorrent(t *testing.T) {
	t.Parallel()

	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(script, []byte("el('transfer-connected').innerHTML = transfer.reachable")) {
		t.Error(`the Connected row is not driven by transfer.reachable`)
	}
	// The old conflation must not come back.
	if bytes.Contains(script, []byte("qBittorrent is ${connection}")) {
		t.Error(`the card is labelling peer connectivity as "qBittorrent is connected" again`)
	}
	// The port verdict must be rendered, not re-derived in the browser.
	if !bytes.Contains(script, []byte("transfer.port_forwarding")) {
		t.Error("the port-forwarding verdict is not rendered")
	}
	if bytes.Contains(script, []byte("=== 'firewalled'")) {
		t.Error("the browser is re-deriving the verdict from connection_status; " +
			"that comparison needs Gluetun's forwarded port and belongs in the engine")
	}
}

// The cards were consolidated from eight to four, and every one of them now answers
// the same questions in the same shape. This pins that structure, because it is the
// kind of thing that erodes one ad-hoc addition at a time.
func TestTheCardsAreConsolidatedAndConsistent(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	cards := regexp.MustCompile(`(?s)<section class="cards">.*?</section>`).Find(page)
	if cards == nil {
		t.Fatal("could not find the cards section")
	}

	var titles []string
	for _, match := range regexp.MustCompile(`<h2>([^<]*)</h2>`).FindAllSubmatch(cards, -1) {
		titles = append(titles, string(match[1]))
	}
	want := []string{"Server selection", "Gluetun", "ProtonVPN", "qBittorrent"}
	if strings.Join(titles, "|") != strings.Join(want, "|") {
		t.Errorf("cards = %v, want %v", titles, want)
	}

	// Every integration answers "can we reach it" and "did the last exchange work" in
	// the same words, so the three cards can be read the same way.
	for _, id := range []string{
		"gluetun-reachable", "gluetun-outcome",
		"proton-login", "proton-outcome",
		"transfer-connected", "transfer-outcome",
	} {
		if !bytes.Contains(cards, []byte(`id="`+id+`"`)) {
			t.Errorf("the cards are missing %q, so the integrations are not consistent", id)
		}
	}
	for _, label := range []string{"<dt>Connected</dt>"} {
		if count := bytes.Count(cards, []byte(label)); count != 3 {
			t.Errorf("%q appears %d times, want once per integration (3)", label, count)
		}
	}

	// The prose paragraphs are gone. Only genuine error lines may remain, since those
	// report a failure rather than describing the UI.
	for _, gone := range []string{
		`class="card-note"></p>`, `class="reasoning"`, `class="panel-note"`,
	} {
		if bytes.Contains(page, []byte(gone)) {
			t.Errorf("a descriptive paragraph is back: %q", gone)
		}
	}
	if notes := bytes.Count(page, []byte(`class="card-note error"`)); notes == 0 {
		t.Error("the error lines were removed too; failures still need reporting")
	}
}

// Current and best are one card now, laid out as a comparison. If the two ever drift
// into separate row sets, reading across stops working - which was the point.
func TestCurrentAndBestAreOneComparison(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	compare := regexp.MustCompile(`(?s)<div class="compare">.*?</div>\s*</div>`).Find(page)
	if compare == nil {
		t.Fatal("the comparison grid is gone")
	}
	// Each labelled row must have exactly one current and one best cell.
	for _, pair := range [][2]string{
		{"current-load", "best-load"},
		{"current-rtt", "best-rtt"},
		{"current-score", "best-score"},
	} {
		for _, id := range pair {
			if !bytes.Contains(page, []byte(`id="`+id+`"`)) {
				t.Errorf("comparison row %q is missing", id)
			}
		}
	}
	if !bytes.Contains(styles, []byte(".compare {")) {
		t.Error("style.css has no .compare rule, so the columns will not line up")
	}
	if !bytes.Contains(styles, []byte(".cards { display: flex; flex-direction: column;")) {
		t.Error("the cards are not one per line, so the comparison has no room")
	}
}

// The improvement is the number that decides whether the best candidate is used, and a
// bare "0.021" next to a threshold two rows below left the reader to do the comparison.
// It now states the verdict, in colour.
func TestTheImprovementSaysWhetherItIsEnough(t *testing.T) {
	t.Parallel()

	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	for _, fragment := range []string{
		// Compared against the configured threshold, not a hard-coded number.
		"selection.improvement >= selection.min_improvement",
		// Said in words as well as colour, so it does not depend on colour alone.
		"too low",
		// And the good case is distinguishable, or "not red" would carry the meaning.
		`<span class="ok">${improvement}</span>`,
		// The explanation of what to do about it stays available on hover.
		"SWITCH_MIN_IMPROVEMENT requires",
	} {
		if !bytes.Contains(script, []byte(fragment)) {
			t.Errorf("app.js does not contain %q", fragment)
		}
	}

	// With no current server a switch is due regardless, so the verdict must be
	// withheld rather than claiming the gain is too small.
	if !bytes.Contains(script, []byte("const judged = Boolean(best && selection.current)")) {
		t.Error("the verdict is not withheld when there is no current server to improve on")
	}
}

// The strip answers "is everything working?" without reading four cards. It must be
// derived from the same snapshot the cards use - a second source of truth that could
// disagree with the card below it would be worse than no strip at all.
func TestTheStatusStripSummarisesEverySubsystem(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(page, []byte(`id="status-strip"`)) {
		t.Fatal("index.html has no status strip")
	}
	// Above the cards, or it is not a summary of them.
	if bytes.Index(page, []byte(`id="status-strip"`)) > bytes.Index(page, []byte(`class="cards"`)) {
		t.Error("the strip should come before the cards")
	}

	// Every subsystem a card covers has to be represented.
	for _, subject := range []string{"Tunnel", "ProtonVPN", "Server data", "qBittorrent",
		"Port forwarding", "Switching"} {
		if !bytes.Contains(script, []byte(`'`+subject+`'`)) {
			t.Errorf("the strip does not report %q", subject)
		}
	}
	// Read from the snapshot, not from the DOM the cards already rendered.
	for _, source := range []string{"snapshot.gluetun", "snapshot.proton",
		"snapshot.servers_file", "snapshot.transfer"} {
		if !bytes.Contains(script, []byte(source)) {
			t.Errorf("renderStatusStrip does not read %q", source)
		}
	}
	// Colour must not be the only carrier: each chip states its value in words.
	if !bytes.Contains(script, []byte("chip-label")) {
		t.Error("chips have no textual label")
	}
	for _, level := range []string{".chip-good", ".chip-warn", ".chip-bad"} {
		if !bytes.Contains(styles, []byte(level)) {
			t.Errorf("style.css has no %q rule", level)
		}
	}
}

// Reference panels fold away, and the tall candidate table can be hidden. The choice
// has to survive a reload, or re-hiding it every time is worse than no toggle.
func TestReferencePanelsFoldAndTheChoiceIsRemembered(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	// Native <details>: no JavaScript, and keyboard accessible for free.
	if folds := bytes.Count(page, []byte(`<details class="panel panel-fold">`)); folds != 3 {
		t.Errorf("found %d folding panels, want 3 (Gluetun's own view, settings, filtering)", folds)
	}
	// A form inside <summary> would toggle the panel shut instead of focusing the field.
	summaries := regexp.MustCompile(`(?s)<summary[^>]*>.*?</summary>`).FindAll(page, -1)
	for _, summary := range summaries {
		if bytes.Contains(summary, []byte("<form")) || bytes.Contains(summary, []byte("<input")) {
			t.Errorf("a summary contains a form or input, which cannot be used: %s", summary)
		}
	}

	if !bytes.Contains(page, []byte(`data-collapse="candidates-body"`)) {
		t.Error("the candidate table cannot be collapsed")
	}
	for _, fragment := range []string{"localStorage.getItem", "localStorage.setItem", "applyCollapse"} {
		if !bytes.Contains(script, []byte(fragment)) {
			t.Errorf("app.js does not use %q, so the choice is not remembered", fragment)
		}
	}
	// Storage can be unavailable; that must not break the toggle.
	if !bytes.Contains(script, []byte("} catch {")) {
		t.Error("localStorage access is not guarded")
	}
}

// The caps were fetched into the snapshot and rendered nowhere. They give the rates
// context, and must be clearly qBittorrent's rather than ours.
func TestQBittorrentsOwnCapsAreShown(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"transfer-down-cap", "transfer-up-cap"} {
		if !bytes.Contains(page, []byte(`id="`+id+`"`)) {
			t.Errorf("index.html has no %q row", id)
		}
	}
	for _, field := range []string{"transfer.download_limit", "transfer.upload_limit"} {
		if !bytes.Contains(script, []byte(field)) {
			t.Errorf("app.js never reads %q", field)
		}
	}
	// Zero means no cap, which is a different statement from "0 B/s".
	if !bytes.Contains(script, []byte("'unlimited'")) {
		t.Error("an absent cap should read as unlimited, not as a zero rate")
	}
	// And they must not be confused with this tool's thresholds.
	if !bytes.Contains(script, []byte("Independent of the thresholds above")) {
		t.Error("nothing distinguishes qBittorrent's caps from our busy thresholds")
	}
}

// Every function app.js calls must be defined in app.js.
//
// This is the bug class that keeps recurring and that the element-ID tests cannot see:
// rewriting one block deletes a helper that another still calls, and the page dies at
// the first call with "X is not defined" - taking every later render step with it. It
// happened to parseDuration when the best-candidate prose was replaced by rows.
//
// There is no JavaScript runtime here, so this is a static approximation: it collects
// bare `name(` call sites and checks each against the declarations in the same file.
func TestEveryFunctionAppJSCallsIsDefined(t *testing.T) {
	t.Parallel()

	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	// Strip string literals, then comments.
	//
	// The order matters: removing comments first destroys the "//" inside a URL in a
	// string, leaving the quote unterminated, after which the string pass eats the rest
	// of the file - including the declarations this is trying to find.
	//
	// Template literals may span lines; single- and double-quoted strings may not, so
	// newlines are excluded from those or one unbalanced quote swallows the file.
	source := regexp.MustCompile("(?s)`(?:\\\\.|[^`\\\\])*`").ReplaceAll(script, []byte("``"))
	source = regexp.MustCompile(`'(?:\\.|[^'\\\n])*'`).ReplaceAll(source, []byte(`''`))
	source = regexp.MustCompile(`"(?:\\.|[^"\\\n])*"`).ReplaceAll(source, []byte(`""`))
	source = regexp.MustCompile(`(?m)//.*$`).ReplaceAll(source, nil)
	source = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAll(source, nil)

	defined := map[string]bool{}
	for _, pattern := range []string{
		`(?:async\s+)?function\s+\*?\s*([A-Za-z_$][\w$]*)`,
		`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(`,
		`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?function`,
	} {
		for _, match := range regexp.MustCompile(pattern).FindAllSubmatch(source, -1) {
			defined[string(match[1])] = true
		}
	}
	if len(defined) < 15 {
		t.Fatalf("only found %d declarations; the patterns are wrong", len(defined))
	}

	// Language keywords and host/standard-library members reached as bare calls.
	ambient := map[string]bool{
		"if": true, "for": true, "while": true, "switch": true, "catch": true,
		"return": true, "function": true, "typeof": true, "await": true, "new": true,
		"parseFloat": true, "parseInt": true, "fetch": true, "confirm": true,
		"setTimeout": true, "setInterval": true, "isNaN": true, "alert": true,
		"encodeURIComponent": true, "decodeURIComponent": true, "require": true,
		"clearTimeout": true, "clearInterval": true,
		// "async (" is an arrow function, not a call.
		"async": true,
	}

	// Only bare calls: a method call has a "." before it and belongs to its receiver.
	callSites := regexp.MustCompile(`(^|[^.\w$])([a-z][A-Za-z0-9_$]*)\s*\(`).FindAllSubmatch(source, -1)
	var undefined []string
	seen := map[string]bool{}
	for _, match := range callSites {
		name := string(match[2])
		if defined[name] || ambient[name] || seen[name] {
			continue
		}
		seen[name] = true
		undefined = append(undefined, name)
	}
	sort.Strings(undefined)
	if len(undefined) > 0 {
		t.Errorf("app.js calls functions it does not define: %v\n"+
			"the page throws at the first one and every later render step stops", undefined)
	}
}

// The two merged cards are full width, and use that width to be *shorter* rather than
// to spread the same rows over more space. Without the side-by-side inner layouts,
// going full width just adds empty area to the right of a very tall card.
func TestTheMergedCardsUseTheirWidthToReduceHeight(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	// One card per line: every card has the whole row, so none is tall and narrow.
	if !bytes.Contains(styles, []byte(".cards { display: flex; flex-direction: column;")) {
		t.Error("the cards are not laid out one per line")
	}
	if bytes.Contains(page, []byte("card-wide")) {
		t.Error("card-wide is back; with one card per line there is nothing to widen")
	}
	// Server selection: comparison beside its details.
	if !bytes.Contains(page, []byte(`<div class="card-split">`)) {
		t.Error("the server selection card does not split comparison from details")
	}
	// Gluetun: three sections across, which is most of its height.
	if !bytes.Contains(page, []byte(`<div class="card-columns">`)) {
		t.Error("the Gluetun card does not lay its sections out in columns")
	}
	for _, rule := range []string{".card-split {", ".card-columns {", ".kv.one {"} {
		if !bytes.Contains(styles, []byte(rule)) {
			t.Errorf("style.css has no %q rule", rule)
		}
	}
	// Both must collapse to one column on a narrow screen.
	if !bytes.Contains(styles, []byte(".card-split, .card-columns { grid-template-columns: 1fr; }")) {
		t.Error("the split layouts do not collapse on narrow screens")
	}

	// Only <div> inside a card: an inner <section> makes "the cards section"
	// ambiguous for anything matching up to the first </section>.
	cards := regexp.MustCompile(`(?s)<section class="cards">.*?</section>`).Find(page)
	if cards == nil {
		t.Fatal("could not find the cards section")
	}
	// Skip the region's own opening tag before looking for a nested one.
	const opening = `<section class="cards">`
	if bytes.Contains(cards[len(opening):], []byte("<section")) {
		t.Error("a card contains a nested <section>; use <div> for layout groups")
	}
	// And the boundary must still enclose all four cards.
	if titles := bytes.Count(cards, []byte("<h2>")); titles != 4 {
		t.Errorf("the cards section encloses %d cards, want 4", titles)
	}
}

// The actions were a bare row of buttons with no heading. They are a subject like any
// other now, and the folding panels' titles sit on the left where a heading belongs.
func TestControlsAreAPanelAndFoldTitlesAreLeftAligned(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(page, []byte("<h2>Controls</h2>")) {
		t.Error("the actions have no heading of their own")
	}
	if bytes.Contains(page, []byte(`<section class="toolbar">`)) {
		t.Error("the toolbar is a bare section again rather than a panel")
	}
	// The automatic-switching toggle belongs with the controls.
	controls := regexp.MustCompile(`(?s)<h2>Controls</h2>.*?</section>`).Find(page)
	if controls == nil {
		t.Fatal("could not find the controls panel")
	}
	if !bytes.Contains(controls, []byte(`id="auto-switch"`)) {
		t.Error("the automatic-switching toggle is not in the controls panel")
	}

	// panel-head is space-between; a summary's disclosure marker is its first flex
	// item, which pushed the title to the far right until this override.
	if !bytes.Contains(styles, []byte("justify-content: flex-start;")) {
		t.Error("a folding panel's title will be pushed to the right by space-between")
	}
}

// Tags are for servers, and for the status strip at the top. Everywhere else a value
// belongs in a labelled row: a row of tags inside a card is a second, inconsistent way
// of presenting the same kind of information.
func TestTagsAreOnlyUsedForServersAndTheStatusStrip(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}

	// The only tag containers left in the markup are the two server ones, inside the
	// comparison, where a server's features genuinely are a set of flags.
	var containers []string
	for _, match := range regexp.MustCompile(`id="([a-z0-9-]+)" class="tags`).FindAllSubmatch(page, -1) {
		containers = append(containers, string(match[1]))
	}
	sort.Strings(containers)
	want := []string{"best-tags", "current-tags"}
	if strings.Join(containers, ",") != strings.Join(want, ",") {
		t.Errorf("tag containers = %v, want %v", containers, want)
	}

	// What the qBittorrent tags used to say now has rows of its own.
	for _, id := range []string{"transfer-version", "transfer-listen", "transfer-random"} {
		if !bytes.Contains(page, []byte(`id="`+id+`"`)) {
			t.Errorf("index.html has no %q row, so information was lost with the tags", id)
		}
	}

	// The status strip keeps its chips: there, a set of independent states is exactly
	// what is being shown, and each is one word.
	if !bytes.Contains(page, []byte(`id="status-strip"`)) {
		t.Error("the status strip is gone")
	}
}
