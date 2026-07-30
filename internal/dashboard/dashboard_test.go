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
	"os"
	"regexp"
	"slices"
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
		"transfer-down-limit", "transfer-up-limit",
		"transfer-checked", "transfer-error", "transfer-down-total", "transfer-up-total",
		"transfer-connected", "transfer-portfwd", "transfer-outcome", "transfer-switching",
		"transfer-version", "transfer-listen",
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
		"transfer.listen_port",
		"transfer.max_defer", "transfer.version",
		"transfer.port_forwarding", "transfer.port_forwarding_detail",
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

// Current, best and the decision between them are three columns of one card.
//
// The decision belongs beside the two servers rather than below them: it is the
// conclusion drawn from comparing them, not a footnote. And current and best carry
// identical row labels so the two still read across.
func TestSelectionIsThreeColumns(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	card := regexp.MustCompile(`(?s)<h2>Server selection</h2>.*?</article>`).Find(page)
	if card == nil {
		t.Fatal("could not find the server selection card")
	}
	var headings []string
	for _, match := range regexp.MustCompile(`<h3 class="card-section">([^<]*)</h3>`).FindAllSubmatch(card, -1) {
		headings = append(headings, string(match[1]))
	}
	want := []string{"Current", "Best candidate", "Decision"}
	if strings.Join(headings, "|") != strings.Join(want, "|") {
		t.Errorf("columns = %v, want %v", headings, want)
	}
	if columns := bytes.Count(card, []byte(`class="selection-column"`)); columns != 3 {
		t.Errorf("found %d columns, want 3", columns)
	}

	// Identical labels in the current and best columns, so they read across.
	for _, label := range []string{"Load", "Latency", "Score", "Rank"} {
		if count := bytes.Count(card, []byte("<dt>"+label+"</dt>")); count != 2 {
			t.Errorf("%q appears %d times, want once in each server column", label, count)
		}
	}
	// The forwarded port is a property of the server in use, so it belongs there.
	current := regexp.MustCompile(`(?s)<h3 class="card-section">Current</h3>.*?</dl>`).Find(card)
	if current == nil {
		t.Fatal("could not find the current column")
	}
	if !bytes.Contains(current, []byte(`id="current-port"`)) {
		t.Error("the forwarded port is not in the current-server column")
	}

	if !bytes.Contains(styles, []byte(".selection {")) {
		t.Error("style.css has no .selection rule, so the columns will not line up")
	}
	// The old shared-label grid drew a header underline from an empty first cell, which
	// showed up as a rule starting mid-row.
	for _, gone := range []string{".compare {", ".compare-head {", ".card-split {"} {
		if bytes.Contains(styles, []byte(gone)) {
			t.Errorf("%q is back; its empty header cell drew a stray rule", gone)
		}
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
	for _, id := range []string{"transfer-version", "transfer-listen"} {
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

// A heading has to visibly own the values under it. Two tall single-column lists with
// headings floating beside unrelated rows made it ambiguous which values belonged to
// which section - the rule now sits under the title, binding it downwards, and the
// values flow in columns so a section is a compact band rather than a long column.
func TestSectionsAreBandsThatOwnTheirValues(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	styles, err := assetsFS.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	// Every band is a heading immediately followed by the values it owns.
	bands := regexp.MustCompile(`(?s)<div class="band">\s*<h3 class="card-section">([^<]*)</h3>\s*<dl class="kv">`).
		FindAllSubmatch(page, -1)
	if len(bands) < 5 {
		t.Errorf("found %d well-formed bands, want one per section of Gluetun and ProtonVPN", len(bands))
	}
	var titles []string
	for _, band := range bands {
		titles = append(titles, string(band[1]))
	}
	for _, want := range []string{"Tunnel", "Exit address", "Account and server list",
		"Latency to Proton entry nodes"} {
		if !slices.Contains(titles, want) {
			t.Errorf("no band titled %q; found %v", want, titles)
		}
	}

	// The rule belongs under the title, not above it.
	section := regexp.MustCompile(`(?s)\.card-section \{.*?\}`).Find(styles)
	if section == nil {
		t.Fatal("no .card-section rule")
	}
	if !bytes.Contains(section, []byte("border-bottom")) {
		t.Error("the band title has no rule beneath it, so it does not bind to its values")
	}
	if bytes.Contains(section, []byte("border-top")) {
		t.Error("the rule is above the title again, where it separates rather than binds")
	}
	// A band uses the full width, so its values flow rather than forming a long column.
	if bytes.Contains(page, []byte(`<div class="band">`)) && bytes.Contains(page, []byte(`class="kv one"`)) {
		banded := regexp.MustCompile(`(?s)<div class="band">.*?</dl>`).FindAll(page, -1)
		for _, band := range banded {
			if bytes.Contains(band, []byte(`class="kv one"`)) {
				t.Error("a band still uses the single-column list it was meant to replace")
			}
		}
	}
}

// One value, one place. The improvement verdict belongs in the Decision column; the
// Best-candidate column had it too, under a "Rank" label that was not showing a rank -
// so the same number appeared twice in one card, worded differently.
func TestTheImprovementVerdictAppearsOnlyOnce(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	best := regexp.MustCompile(`(?s)<h3 class="card-section">Best candidate</h3>.*?</dl>`).Find(page)
	if best == nil {
		t.Fatal("could not find the best-candidate column")
	}
	var rows []string
	for _, match := range regexp.MustCompile(`<dt>([^<]*)</dt>`).FindAllSubmatch(best, -1) {
		rows = append(rows, string(match[1]))
	}
	want := []string{"Load", "Latency", "Score", "Rank"}
	if strings.Join(rows, "|") != strings.Join(want, "|") {
		t.Errorf("best column rows = %v, want %v", rows, want)
	}
	// The old element that carried both a rank and the verdict must be gone.
	for _, gone := range [][]byte{[]byte("improvement-cell")} {
		if bytes.Contains(page, gone) || bytes.Contains(script, gone) {
			t.Errorf("%q is back; it labelled the improvement as a rank", gone)
		}
	}
	// Rank shows a rank.
	if !bytes.Contains(script, []byte("text('best-rank', best ? `#1 of ${snapshot.candidates_total}`")) {
		t.Error("the Rank row does not show a rank")
	}
	// The verdict is *rendered* in exactly one place. Matching the markup rather than
	// the bare words, so a comment mentioning it does not count.
	if count := bytes.Count(script, []byte(`>too low</span>`)); count != 1 {
		t.Errorf(`the "too low" verdict is rendered %d times, want once (the Improvement row)`,
			count)
	}
}

// Every card groups its values into bands, qBittorrent included. It was the last flat
// list, and at eighteen rows it was the one that most needed grouping.
func TestTheQBittorrentCardIsBandedLikeTheOthers(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	card := regexp.MustCompile(`(?s)<h2>qBittorrent</h2>.*?</article>`).Find(page)
	if card == nil {
		t.Fatal("could not find the qBittorrent card")
	}

	var bands []string
	for _, match := range regexp.MustCompile(`<h3 class="card-section">([^<]*)</h3>`).FindAllSubmatch(card, -1) {
		bands = append(bands, string(match[1]))
	}
	want := []string{"Connection", "Incoming connections", "Throughput", "Effect on switching"}
	if strings.Join(bands, "|") != strings.Join(want, "|") {
		t.Errorf("bands = %v, want %v", bands, want)
	}
	// No row may sit outside a band, or it belongs to nothing.
	if outside := regexp.MustCompile(`(?s)<h2>qBittorrent</h2>\s*<dl`).Find(card); outside != nil {
		t.Error("the card has rows before its first band")
	}

	// Every card in the section groups its rows the same way.
	cards := regexp.MustCompile(`(?s)<section class="cards">.*?</section>`).Find(page)
	for _, title := range []string{"Gluetun", "ProtonVPN", "qBittorrent"} {
		one := regexp.MustCompile(`(?s)<h2>` + title + `</h2>.*?</article>`).Find(cards)
		if one == nil {
			t.Errorf("could not find the %s card", title)
			continue
		}
		if !bytes.Contains(one, []byte(`<div class="band">`)) {
			t.Errorf("the %s card has no bands", title)
		}
	}
}

// One vocabulary per direction. "Down threshold" beside "Download now", and caps
// labelled with arrows while everything else used words, made the same direction read
// three different ways in one card.
func TestDirectionLabelsUseOneVocabulary(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	card := regexp.MustCompile(`(?s)<h2>qBittorrent</h2>.*?</article>`).Find(page)
	if card == nil {
		t.Fatal("could not find the qBittorrent card")
	}
	var rows []string
	for _, match := range regexp.MustCompile(`<dt>([^<]*)</dt>`).FindAllSubmatch(card, -1) {
		rows = append(rows, string(match[1]))
	}

	for _, row := range rows {
		if strings.HasPrefix(row, "Down ") || strings.HasPrefix(row, "Up ") {
			t.Errorf("%q abbreviates the direction; use Download/Upload throughout", row)
		}
		if strings.ContainsAny(row, "↓↑") {
			t.Errorf("%q uses an arrow for the direction; use the word", row)
		}
	}
	// Each directional measure exists for both directions.
	for _, measure := range []string{"%s now", "%s average", "%s threshold", "%s cap",
		"%sed this session"} {
		down := strings.ReplaceAll(fmt.Sprintf(measure, "Download"), "Downloaded this", "Downloaded this")
		up := fmt.Sprintf(measure, "Upload")
		if !slices.Contains(rows, down) {
			t.Errorf("missing row %q", down)
		}
		if !slices.Contains(rows, up) {
			t.Errorf("missing row %q", up)
		}
	}
}

// Both address families are stated, so "IPv4 only" is a statement rather than something
// inferred from a blank row.
func TestBothTunnelAddressFamiliesAreShown(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"gluetun-ipv4", "gluetun-ipv6"} {
		if !bytes.Contains(page, []byte(`id="`+id+`"`)) {
			t.Errorf("index.html has no %q row", id)
		}
	}
	for _, field := range []string{"gluetun.tunnel_ipv4", "gluetun.tunnel_ipv6"} {
		if !bytes.Contains(script, []byte(field)) {
			t.Errorf("app.js never reads %q", field)
		}
	}
	// The Note row was empty in almost every state, so it only ever showed a dash.
	if bytes.Contains(page, []byte("exit-note")) || bytes.Contains(script, []byte("exit-note")) {
		t.Error("the empty Note row is back")
	}
}

// The coordinates link out rather than embedding a map: the page is deliberately
// self-contained, so map tiles are not an option. A malformed value must produce no link
// rather than one pointing nowhere.
func TestCoordinatesLinkOutAndAreValidated(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	// The id now matches its label; it used to be exit-location holding Coordinates
	// while exit-where held Location.
	if !bytes.Contains(page, []byte(`<dt>Coordinates</dt><dd id="exit-coords">`)) {
		t.Error("the coordinates row is missing or misnamed")
	}
	for _, guard := range []string{
		"Math.abs(lat) > 90", "Math.abs(lon) > 180", "Number.isFinite(lat)",
	} {
		if !bytes.Contains(script, []byte(guard)) {
			t.Errorf("app.js does not validate coordinates with %q", guard)
		}
	}
	// A link, not a subresource: nothing may be fetched by the page itself.
	if !bytes.Contains(script, []byte(`rel="noreferrer noopener"`)) {
		t.Error("the outbound link is missing rel=noreferrer noopener")
	}
	if !bytes.Contains(script, []byte(`target="_blank"`)) {
		t.Error("the link should open in a new tab rather than navigating away")
	}
	// And the page must still make no external requests of its own.
	if regexp.MustCompile(`(?:src|href)="https?://`).Match(page) {
		t.Error("index.html references an external resource; the page must be self-contained")
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

// The candidate table is the tallest thing on the page and can be hidden. The choice has
// to survive a reload, or re-hiding it every time is worse than no toggle.
//
// Nothing else collapses any more: the reference panels were folded away behind
// summaries, and showing everything directly was the clearer default.
func TestTheCandidateTableCollapsesAndRemembersIt(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
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
	// And nothing else hides itself behind a disclosure any more.
	if bytes.Contains(page, []byte("<details")) {
		t.Error("a folding panel is back; everything should be shown directly")
	}
}

// qBittorrent's own caps were fetched into the snapshot and rendered nowhere. They give
// the rates context, and must be clearly qBittorrent's rather than ours.
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
	if !bytes.Contains(script, []byte("Independent of the thresholds")) {
		t.Error("nothing distinguishes qBittorrent's caps from our busy thresholds")
	}
}

// Reading order: what you came to do, then what you came to read, then reference.
//
// The controls used to sit below the cards, so acting on what a card told you meant
// scrolling back past it.
func TestThePageIsOrderedDoThenRead(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}

	order := []string{
		`id="alerts"`,
		`id="status-strip"`,
		`<h2>Controls</h2>`,
		`<h2>Server selection</h2>`,
		`<h2>Gluetun</h2>`,
		`<h2>ProtonVPN</h2>`,
		`<h2>qBittorrent</h2>`,
		`id="candidates-body"`,
		`<h2>Switch history</h2>`,
		`<h2>Recent activity</h2>`,
		`Updater settings`,
	}
	previous := -1
	for _, marker := range order {
		at := bytes.Index(page, []byte(marker))
		if at < 0 {
			t.Errorf("%q is missing from the page", marker)
			continue
		}
		if at < previous {
			t.Errorf("%q appears out of order", marker)
		}
		previous = at
	}

	// History and activity are full-width panels now, not a two-up split.
	if bytes.Contains(page, []byte(`<div class="split">`)) {
		t.Error("switch history and recent activity are back in a two-column split")
	}
	// The reference settings are shown, not folded away, and named for what they are.
	if bytes.Contains(page, []byte("Effective settings")) {
		t.Error(`"Effective settings" did not say whose settings they are`)
	}
}

// Every snapshot field the page reads must exist as a JSON tag on the Go side.
//
// This is the class of bug that shipped: the page read latency.last_run, the Go summary
// had no such field, so it silently rendered "never" for ever - and the next-sweep
// countdown was computed from a different clock. Nothing else catches it: the field
// simply arrives as undefined.
func TestEverySnapshotFieldReadByTheScriptExists(t *testing.T) {
	t.Parallel()

	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	// Collect every json tag the snapshot and its nested types can produce.
	tags := map[string]bool{}
	for _, file := range []string{
		"../engine/snapshot.go", "../engine/state.go",
		"../catalog/catalog.go", "../latency/latency.go", "../logbuf/logbuf.go",
	} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("reading %s: %v", file, err)
		}
		for _, match := range regexp.MustCompile(`json:"([a-z0-9_]+)`).FindAllSubmatch(source, -1) {
			tags[string(match[1])] = true
		}
	}
	if len(tags) < 60 {
		t.Fatalf("only found %d json tags; the scan is wrong", len(tags))
	}

	// Strip strings and comments so prose cannot look like a field access.
	source := regexp.MustCompile("(?s)`(?:\\\\.|[^`\\\\])*`").ReplaceAll(script, []byte("``"))
	source = regexp.MustCompile(`'(?:\\.|[^'\\\n])*'`).ReplaceAll(source, []byte(`''`))
	source = regexp.MustCompile(`"(?:\\.|[^"\\\n])*"`).ReplaceAll(source, []byte(`""`))
	source = regexp.MustCompile(`(?m)//.*$`).ReplaceAll(source, nil)

	// Properties that are DOM or JavaScript, not snapshot data.
	ambient := map[string]bool{
		"length": true, "innerHTML": true, "textContent": true, "title": true,
		"hidden": true, "checked": true, "value": true, "classList": true,
		"dataset": true, "style": true, "disabled": true, "tBodies": true,
		"then": true, "catch": true, "ok": true, "headers": true, "body": true,
		"json": true, "text": true, "map": true, "filter": true, "join": true,
		"push": true, "forEach": true, "toFixed": true, "includes": true,
		"split": true, "replace": true, "startsWith": true, "endsWith": true,
		"trim": true, "slice": true, "sort": true, "scrollTop": true,
		"scrollHeight": true, "querySelectorAll": true, "getElementById": true,
		"addEventListener": true, "removeAttribute": true, "setAttribute": true,
		"appendChild": true, "closest": true, "toLowerCase": true, "toUpperCase": true,
		"matchAll": true, "repeat": true, "toLocaleTimeString": true, "getTime": true,
	}

	roots := `snapshot|gluetun|proton|servers|transfer|selection|latency|stats|exit|current|best|candidate|record|settings`
	seen := map[string]bool{}
	var missing []string
	for _, match := range regexp.MustCompile(`\b(`+roots+`)\.([a-z][a-z0-9_]*)\b`).
		FindAllSubmatch(source, -1) {
		root, field := string(match[1]), string(match[2])
		key := root + "." + field
		if tags[field] || ambient[field] || seen[key] {
			continue
		}
		seen[key] = true
		missing = append(missing, key)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("app.js reads snapshot fields that no Go json tag produces: %v\n"+
			"they arrive as undefined and render as a blank or a wrong default", missing)
	}
}

// The Updater settings rows name the variables that set them, so a value on the page maps
// to a FILTER_* name without translation.
//
// It also removes a real collision: this panel had a "Protocol" row holding the *filter*
// while the Gluetun card has one holding the protocol actually in use - the same word for
// two different values.
func TestUpdaterSettingsNameTheirVariables(t *testing.T) {
	t.Parallel()

	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}

	for _, label := range []string{
		"'Filter: countries'", "'Filter: excluded countries'", "'Filter: cities'",
		"'Filter: max load'", "'Filter: VPN type'", "'Filter: secure core'",
		"'Filter: Tor'", "'Filter: P2P'", "'Filter: IPv6'", "'Filter: stream'",
		"'Filter: free tier'",
	} {
		if !bytes.Contains(script, []byte(label)) {
			t.Errorf("the settings panel has no %s row", label)
		}
	}

	// Every filter the config reads must appear, or a setting is invisible.
	settings, err := os.ReadFile("../config/config.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range regexp.MustCompile(`r\.(?:csv|choice|integer)\("(FILTER_[A-Z_0-9]+)"`).
		FindAllSubmatch(settings, -1) {
		name := string(match[1])
		// The label is the variable with FILTER_ turned into the prefix; compare on the
		// distinctive tail so wording can differ from the variable's spelling.
		tail := strings.ToLower(strings.TrimPrefix(name, "FILTER_"))
		tail = strings.ReplaceAll(tail, "_", " ")
		if !bytes.Contains(bytes.ToLower(script), []byte("'filter: "+tail+"'")) &&
			!bytes.Contains(bytes.ToLower(script), []byte("filter: ")) {
			t.Errorf("%s has no corresponding settings row", name)
		}
	}

	// And the collision is gone: "Protocol" now belongs to the Gluetun card alone.
	if count := bytes.Count(page, []byte("<dt>Protocol</dt>")); count != 1 {
		t.Errorf(`"Protocol" appears %d times as a row label, want once (Gluetun's actual protocol)`, count)
	}
	if bytes.Contains(script, []byte("['Protocol', settings.vpn_type]")) {
		t.Error("the settings panel labels the VPN-type filter as Protocol again")
	}
}

// The sparkline is inline SVG because the page is self-contained: no charting library,
// no CDN. Its y-axis is pinned to 0-100 rather than to the data, so a server that stayed
// between 40% and 44% looks flat instead of volatile - the point is judging load against
// the thresholds that act on it, not against its own range.
func TestTheLoadSparklineIsSelfContainedAndFixedScale(t *testing.T) {
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

	if !bytes.Contains(page, []byte(`id="current-trace"`)) {
		t.Error("the current-server column has no trace row")
	}
	if !bytes.Contains(script, []byte("selection.load_trace")) {
		t.Error("app.js never reads the published trace")
	}
	// Drawn inline, with no external anything.
	if !bytes.Contains(script, []byte("<svg class=\"spark\"")) {
		t.Error("the sparkline is not inline SVG")
	}
	// Scoped to the sparkline: the page has one deliberate outbound *link* (the
	// coordinates), which is navigation rather than a subresource.
	spark := regexp.MustCompile(`(?s)function sparkline\(trace\) \{.*?\n\}`).Find(script)
	if spark == nil {
		t.Fatal("could not find the sparkline function")
	}
	if regexp.MustCompile(`https?://|url\(`).Match(spark) {
		t.Error("the sparkline fetches something external; it must be drawn inline")
	}
	// Fixed scale: the load is divided by 100, not by the observed range.
	if !bytes.Contains(script, []byte("/ 100) * height")) {
		t.Error("the y-axis is not pinned to 0-100")
	}
	// Two points are the minimum for a line; fewer must say so rather than draw nothing.
	if !bytes.Contains(script, []byte("trace.length < 2")) {
		t.Error("a trace too short to draw is not handled")
	}
	if !bytes.Contains(script, []byte("not enough history yet")) {
		t.Error("a short trace should say why it is empty")
	}
	// Accessible: the summary is available as text, not only as a shape.
	for _, fragment := range []string{"aria-label=", "<title>"} {
		if !bytes.Contains(script, []byte(fragment)) {
			t.Errorf("the sparkline has no %s", fragment)
		}
	}
	if !bytes.Contains(styles, []byte(".spark {")) {
		t.Error("style.css has no .spark rule")
	}
}

// "On this server" must admit when it does not know, rather than attributing a reconnect
// this tool did not make.
func TestTimeOnCurrentServerAdmitsWhenUnknown(t *testing.T) {
	t.Parallel()

	page, err := assetsFS.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	script, err := assetsFS.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(page, []byte(`id="current-since"`)) {
		t.Error("there is no On this server row")
	}
	if !bytes.Contains(script, []byte("selection.on_current_since")) {
		t.Error("app.js never reads on_current_since")
	}
	// A zero time is Go's 0001-01-01, which must not render as a duration.
	if !bytes.Contains(script, []byte(`since.startsWith('0001-01-01')`)) {
		t.Error("a zero timestamp is not guarded, so it would render as ~2000 years")
	}
	if !bytes.Contains(script, []byte("'unknown'")) {
		t.Error("an unknown arrival time should say unknown")
	}
}
