package gluetunapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return New(Options{BaseURL: server.URL, HTTPClient: server.Client()})
}

func TestStatus(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vpn/status" || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"status":"running"}`)
	})

	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status != StatusRunning {
		t.Errorf("status = %q, want running", status)
	}
}

// Pinning a hostname is the mechanism that makes Gluetun reconnect to a
// specific server, so the request body shape matters.
func TestPinHostnameSendsMinimalPatch(t *testing.T) {
	t.Parallel()

	var body map[string]any
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/vpn/settings" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding body: %v", err)
		}
		_, _ = io.WriteString(w, "VPN settings updated")
	})

	outcome, err := client.PinServer(context.Background(), PinTarget{
		Hostname: "se-01.protonvpn.net", Country: "Sweden", City: "Stockholm",
	})
	if err != nil {
		t.Fatalf("PinHostname: %v", err)
	}
	if outcome != "VPN settings updated" {
		t.Errorf("outcome = %q", outcome)
	}

	// Only the hostname may be present: anything else would overwrite settings
	// the operator configured on the Gluetun container.
	provider, ok := body["provider"].(map[string]any)
	if !ok {
		t.Fatalf("provider missing from body: %v", body)
	}
	selection, ok := provider["server_selection"].(map[string]any)
	if !ok {
		t.Fatalf("server_selection missing from body: %v", body)
	}
	hostnames, ok := selection["hostnames"].([]any)
	if !ok || len(hostnames) != 1 || hostnames[0] != "se-01.protonvpn.net" {
		t.Errorf("hostnames = %v", selection["hostnames"])
	}
	// Country and city must travel with the hostname: Gluetun ANDs its selection
	// filters, so a hostname alone would still be intersected with whatever
	// SERVER_COUNTRIES the container was started with.
	countries, _ := selection["countries"].([]any)
	if len(countries) != 1 || countries[0] != "Sweden" {
		t.Errorf("countries = %v, want [Sweden]", selection["countries"])
	}
	cities, _ := selection["cities"].([]any)
	if len(cities) != 1 || cities[0] != "Stockholm" {
		t.Errorf("cities = %v, want [Stockholm]", selection["cities"])
	}
	// The "only" filters must be cleared explicitly. Gluetun ANDs them with the
	// pinned hostname, and its built-in view of a server's features can disagree
	// with Proton's current data - one disagreement leaves nothing matching and
	// crashes Gluetun's VPN loop. Clearing them is safe because pinning a single
	// hostname is already the most specific selection possible.
	for _, flag := range []string{
		"port_forward_only", "secure_core_only", "tor_only", "stream_only",
		"free_only", "premium_only", "multi_hop_only", "owned_only",
	} {
		value, present := selection[flag]
		if !present {
			t.Errorf("%s must be sent so the filter is cleared, not left in force", flag)
			continue
		}
		if value != false {
			t.Errorf("%s = %v, want false", flag, value)
		}
	}

	// Still nothing beyond the server selection: the patch must not disturb any
	// other Gluetun setting.
	const wantSelectionFields = 3 + 8 // hostname, country, city + the cleared flags
	if len(body) != 1 || len(provider) != 1 || len(selection) != wantSelectionFields {
		t.Errorf("patch carries unexpected fields: %v", body)
	}
}

// Reading back what Gluetun enforces is what lets the tool choose a server that
// satisfies it, rather than pinning one Gluetun will refuse.
func TestRequirementsFromSettings(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{
			"provider":{"name":"protonvpn","server_selection":{
				"port_forward_only":true,"secure_core_only":false,"tor_only":false,
				"stream_only":true,"free_only":false,"premium_only":false,
				"multi_hop_only":true,"owned_only":false}}}`)
	})

	settings, err := client.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	requirements := settings.Requirements()
	switch {
	case !requirements.PortForward:
		t.Error("port_forward_only should be reported")
	case !requirements.Stream:
		t.Error("stream_only should be reported")
	case !requirements.MultiHop:
		t.Error("multi_hop_only should be reported")
	case requirements.SecureCore || requirements.Tor || requirements.Free || requirements.Premium || requirements.Owned:
		t.Errorf("unset filters must not be reported: %+v", requirements)
	}

	// A zero Settings must not claim anything is required.
	var empty Settings
	if (empty.Requirements() != Requirements{}) {
		t.Error("empty settings must report no requirements")
	}
}

// Gluetun answers 400 for a hostname it does not know, which the engine must be
// able to distinguish from an outage so it can try the next candidate.
func TestPinHostnameUnknownIsRejected(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no server found for hostname", http.StatusBadRequest)
	})

	_, err := client.PinServer(context.Background(), PinTarget{
		Hostname: "unknown.protonvpn.net", Country: "Sweden",
	})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Error("a rejection must not be reported as unavailability")
	}
}

func TestUnreachableServerIsUnavailable(t *testing.T) {
	t.Parallel()

	// Port 0 on a closed loopback address never accepts a connection.
	client := New(Options{BaseURL: "http://127.0.0.1:1"})
	_, err := client.Status(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestServerErrorIsUnavailable(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})

	_, err := client.Status(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable for a 5xx", err)
	}
}

func TestAuthenticationHeaders(t *testing.T) {
	t.Parallel()

	t.Run("api key", func(t *testing.T) {
		var key string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key = r.Header.Get("X-API-Key")
			_, _ = io.WriteString(w, `{"status":"running"}`)
		}))
		defer server.Close()

		client := New(Options{BaseURL: server.URL, APIKey: "secret", HTTPClient: server.Client()})
		if _, err := client.Status(context.Background()); err != nil {
			t.Fatal(err)
		}
		if key != "secret" {
			t.Errorf("X-API-Key = %q", key)
		}
	})

	t.Run("basic auth", func(t *testing.T) {
		var username, password string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, _ = r.BasicAuth()
			_, _ = io.WriteString(w, `{"status":"running"}`)
		}))
		defer server.Close()

		client := New(Options{
			BaseURL: server.URL, Username: "user", Password: "pass",
			HTTPClient: server.Client(),
		})
		if _, err := client.Status(context.Background()); err != nil {
			t.Fatal(err)
		}
		if username != "user" || password != "pass" {
			t.Errorf("basic auth = %q/%q", username, password)
		}
	})
}

func TestUnauthorizedMentionsCredentials(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := client.Status(context.Background())
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	if got := err.Error(); !contains(got, "GLUETUN_API_KEY") {
		t.Errorf("error should hint at the credentials settings, got %q", got)
	}
}

func TestReconnectStopsThenStarts(t *testing.T) {
	t.Parallel()

	var statuses []string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		statuses = append(statuses, body.Status)
		_, _ = io.WriteString(w, `{"outcome":"ok"}`)
	})

	if _, err := client.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if len(statuses) != 2 || statuses[0] != StatusStopped || statuses[1] != StatusRunning {
		t.Errorf("statuses = %v, want [stopped running]", statuses)
	}
}

func TestGetForwardedPortHandlesBothShapes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body string
		want uint16
	}{
		"single port": {body: `{"port":5914}`, want: 5914},
		"port list":   {body: `{"ports":[5914,5915]}`, want: 5914},
		"no port":     {body: `{"port":0}`, want: 0},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, test.body)
			})
			port, err := client.GetForwardedPort(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if port != test.want {
				t.Errorf("port = %d, want %d", port, test.want)
			}
		})
	}
}

func TestSettingsAccessors(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{
			"type":"wireguard",
			"provider":{"name":"Protonvpn","server_selection":{"vpn":"wireguard","hostnames":["se-01.protonvpn.net"]}}
		}`)
	})

	settings, err := client.GetSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if settings.VPNType() != "wireguard" {
		t.Errorf("VPNType = %q", settings.VPNType())
	}
	if settings.ProviderName() != "protonvpn" {
		t.Errorf("ProviderName = %q, want it lowercased", settings.ProviderName())
	}
	if hostnames := settings.PinnedHostnames(); len(hostnames) != 1 {
		t.Errorf("PinnedHostnames = %v", hostnames)
	}
}

func TestSettingsAccessorsOnEmptySettings(t *testing.T) {
	t.Parallel()

	var settings Settings
	if settings.VPNType() != "" || settings.ProviderName() != "" || settings.PinnedHostnames() != nil {
		t.Error("accessors must tolerate a zero Settings value")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestGetForwardedPortsHandlesBothShapes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body string
		want []uint16
	}{
		"port list":   {body: `{"ports":[5914,5915]}`, want: []uint16{5914, 5915}},
		"single port": {body: `{"port":5914}`, want: []uint16{5914}},
		"no port":     {body: `{"port":0,"ports":null}`, want: nil},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, test.body)
			})
			ports, err := client.GetForwardedPorts(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(ports) != len(test.want) {
				t.Fatalf("ports = %v, want %v", ports, test.want)
			}
			for i := range ports {
				if ports[i] != test.want[i] {
					t.Errorf("ports = %v, want %v", ports, test.want)
				}
			}
		})
	}
}

func TestDNSStatus(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/dns/status" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"status":"running"}`)
	})

	status, err := client.DNSStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Errorf("status = %q", status)
	}
}

func TestVersionReturnsBuildInfo(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"version":"v3.41.1","commit":"abc1234","created":"2026-02-11T14:22:29Z"}`)
	})

	build, err := client.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if build.Version != "v3.41.1" || build.Commit != "abc1234" || build.Created == "" {
		t.Errorf("build = %+v", build)
	}
}

// The dashboard shows the filters Gluetun is enforcing, because they are usually
// the reason a particular server was refused.
func TestSelectionSummaryAndPortForwarding(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{
			"type":"wireguard",
			"provider":{
				"name":"protonvpn",
				"server_selection":{"vpn":"wireguard","countries":["Sweden"],"cities":["Stockholm"],
					"hostnames":["se-01.protonvpn.net"],"names":null},
				"port_forwarding":{"enabled":true}
			}
		}`)
	})

	settings, err := client.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	summary := settings.SelectionSummary()
	for _, key := range []string{"countries", "cities", "hostnames"} {
		if len(summary[key]) == 0 {
			t.Errorf("summary is missing %q: %v", key, summary)
		}
	}
	// Empty filters must be omitted rather than shown as empty rows.
	if _, present := summary["names"]; present {
		t.Errorf("empty filters should be omitted: %v", summary)
	}

	enabled, known := settings.PortForwardingEnabled()
	if !known || !enabled {
		t.Errorf("PortForwardingEnabled = (%v, %v), want (true, true)", enabled, known)
	}

	// An absent section must be reported as unknown, not as false: "not requested"
	// and "no answer yet" are different things on the dashboard.
	var empty Settings
	if _, known := empty.PortForwardingEnabled(); known {
		t.Error("a missing port_forwarding section must report unknown")
	}
	if summary := empty.SelectionSummary(); summary != nil {
		t.Errorf("SelectionSummary on empty settings = %v, want nil", summary)
	}
}

// A state change that does not answer in time has an unknown outcome: Gluetun may
// well have applied it. That must be distinguishable from "Gluetun is down", or
// the caller would retry and cause a second reconnect.
func TestMutationTimeoutIsDistinctFromUnavailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			time.Sleep(300 * time.Millisecond) // outlast the mutation timeout
		}
		_, _ = io.WriteString(w, `{"status":"running"}`)
	}))
	defer server.Close()

	client := New(Options{
		BaseURL:         server.URL,
		Timeout:         5 * time.Second,
		MutationTimeout: 50 * time.Millisecond,
	})

	_, err := client.SetStatus(context.Background(), StatusRunning)
	if !errors.Is(err, ErrTimedOut) {
		t.Fatalf("err = %v, want ErrTimedOut for a slow state change", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Error("a timed-out mutation must not be classified as unavailability")
	}
}

// A read that times out carries no such ambiguity: Gluetun simply is not
// answering, and calling that "outcome unknown" would be misleading.
func TestReadTimeoutIsUnavailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, `{"status":"running"}`)
	}))
	defer server.Close()

	client := New(Options{BaseURL: server.URL, Timeout: 50 * time.Millisecond})

	_, err := client.Status(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable for a slow read", err)
	}
	if errors.Is(err, ErrTimedOut) {
		t.Error("a slow read must not be reported as an unknown outcome")
	}
}

// VPN_PORT_FORWARDING and PORT_FORWARD_ONLY are different settings with different
// meanings, and conflating them is exactly the bug this guards: Gluetun will
// connect to a non-P2P server while asking Proton for a port it can never give.
func TestPortForwardingRequestIsReportedSeparatelyFromTheOnlyFilter(t *testing.T) {
	enabled, disabled := true, false

	for _, testCase := range []struct {
		name            string
		portForwarding  *bool
		portForwardOnly *bool
		wantRequested   bool
		wantOnly        bool
	}{
		{"neither", &disabled, &disabled, false, false},
		{"port forwarding requested but not enforced", &enabled, &disabled, true, false},
		{"enforced as well", &enabled, &enabled, true, true},
		{"enforced without a request", &disabled, &enabled, false, true},
		{"unset", nil, nil, false, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			settings := Settings{Provider: &Provider{
				PortForwarding:  &PortForwarding{Enabled: testCase.portForwarding},
				ServerSelection: &ServerSelection{PortForwardOnly: testCase.portForwardOnly},
			}}
			got := settings.Requirements()
			if got.PortForwardingRequested != testCase.wantRequested {
				t.Errorf("PortForwardingRequested = %v, want %v",
					got.PortForwardingRequested, testCase.wantRequested)
			}
			if got.PortForward != testCase.wantOnly {
				t.Errorf("PortForward = %v, want %v", got.PortForward, testCase.wantOnly)
			}
		})
	}
}

// A settings body with port forwarding but no server selection at all must still
// report the request, or the requirement is silently lost.
func TestPortForwardingRequestSurvivesAnAbsentServerSelection(t *testing.T) {
	enabled := true
	settings := Settings{Provider: &Provider{PortForwarding: &PortForwarding{Enabled: &enabled}}}
	if !settings.Requirements().PortForwardingRequested {
		t.Error("a port-forwarding request should be reported without a server_selection block")
	}
}

// Rejecting a hostname makes Gluetun list every hostname it would have accepted -
// about 30 kB, ~570 names. That was quoted verbatim into the log, the dashboard and
// the switch history, burying the one useful fact. This is the real message from a
// deployment, shortened here only in the middle of the choices list.
func TestTheChoicesWallIsSummarizedNotQuoted(t *testing.T) {
	raw := "provider settings: server selection: for VPN service provider protonvpn: " +
		"the hostname specified is not valid: value is not one of the possible choices: " +
		"none of node-se-10.protonvpn.net is one of the choices available " +
		"af-03.protonvpn.net, al-02.protonvpn.net, al-03.protonvpn.net, mz-01.protonvpn.net, " +
		"node-se-07.protonvpn.net, node-se-20.protonvpn.net"

	got := summarizeError([]byte(raw))

	if len(got) > maxErrorLength {
		t.Errorf("summary is %d characters, want at most %d:\n%s", len(got), maxErrorLength, got)
	}
	// The rejected hostname is the whole point of the message.
	if !strings.Contains(got, "node-se-10.protonvpn.net") {
		t.Errorf("the rejected hostname is missing from %q", got)
	}
	// The count is diagnostic: a few hundred means Gluetun is on its built-in list.
	if !strings.Contains(got, "6 choices") {
		t.Errorf("the number of choices is missing from %q", got)
	}
	// And it must not have pasted the list back in.
	if strings.Contains(got, "al-02.protonvpn.net") {
		t.Errorf("the choices list was quoted verbatim: %q", got)
	}
	// The actionable part: Gluetun is not using the list written here.
	if !strings.Contains(got, "restart the gluetun container") {
		t.Errorf("the summary does not say what to do about it: %q", got)
	}
	// The context Gluetun gave still has to survive.
	if !strings.Contains(got, "protonvpn") || !strings.Contains(got, "hostname specified is not valid") {
		t.Errorf("the original context was lost: %q", got)
	}
}

// Any other long body is truncated rather than dumped whole.
func TestLongErrorBodiesAreTruncated(t *testing.T) {
	raw := strings.Repeat("x", maxErrorLength*3)
	got := summarizeError([]byte(raw))
	if len(got) > maxErrorLength+len("… (truncated)") {
		t.Errorf("length = %d, want it bounded", len(got))
	}
	if !strings.HasSuffix(got, "… (truncated)") {
		t.Error("a truncated message should say so")
	}
}

// Short messages must pass through untouched, or every ordinary error gets noisier.
func TestShortErrorsArePassedThrough(t *testing.T) {
	const raw = "  provider settings: bad request  "
	if got := summarizeError([]byte(raw)); got != "provider settings: bad request" {
		t.Errorf("summarizeError = %q, want the trimmed original", got)
	}
}

// The end-to-end path: a real rejection reaching the caller must be both classified
// as ErrRejected and short enough to log.
func TestRejectionErrorsReachTheCallerSummarized(t *testing.T) {
	choices := make([]string, 0, 400)
	for i := range 400 {
		choices = append(choices, fmt.Sprintf("node-xx-%03d.protonvpn.net", i))
	}
	body := "provider settings: server selection: the hostname specified is not valid: " +
		"value is not one of the possible choices: none of node-se-10.protonvpn.net is " +
		"one of the choices available " + strings.Join(choices, ", ")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, body, http.StatusBadRequest)
	}))
	defer server.Close()

	client := New(Options{BaseURL: server.URL, HTTPClient: server.Client()})
	_, err := client.PinServer(context.Background(), PinTarget{Hostname: "node-se-10.protonvpn.net"})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("error = %v, want ErrRejected", err)
	}
	if len(err.Error()) > maxErrorLength+200 {
		t.Errorf("the error is %d characters; the choices wall was not summarized:\n%s",
			len(err.Error()), err)
	}
	if !strings.Contains(err.Error(), "400 choices") {
		t.Errorf("the choice count is missing from %q", err)
	}
}

// A rejection is the only time Gluetun discloses the server list it is actually
// using, so the hostnames have to survive on the error rather than be summarised
// away. That list is what lets a caller pick a server that works instead of failing.
func TestRejectionCarriesTheHostnamesGluetunWouldAccept(t *testing.T) {
	body := "provider settings: server selection: the hostname specified is not valid: " +
		"value is not one of the possible choices: none of mz-03.protonvpn.net is one of " +
		"the choices available af-03.protonvpn.net, mz-01.protonvpn.net, node-se-20.protonvpn.net"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, body, http.StatusBadRequest)
	}))
	defer server.Close()

	client := New(Options{BaseURL: server.URL, HTTPClient: server.Client()})
	_, err := client.PinServer(context.Background(), PinTarget{Hostname: "mz-03.protonvpn.net"})

	// The richer type must not break the sentinel every caller already checks.
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("errors.Is(err, ErrRejected) = false for %v", err)
	}

	known, found := KnownHostnames(err)
	if !found {
		t.Fatal("the hostnames Gluetun listed were not kept on the error")
	}
	want := []string{"af-03.protonvpn.net", "mz-01.protonvpn.net", "node-se-20.protonvpn.net"}
	if strings.Join(known, ",") != strings.Join(want, ",") {
		t.Errorf("KnownHostnames = %v, want %v", known, want)
	}
}

// A rejection about something other than a hostname must not be mined for hostnames,
// or a country list would be mistaken for a server list and narrow selection to
// nothing.
func TestNonHostnameRejectionsCarryNoHostnames(t *testing.T) {
	for _, body := range []string{
		"provider settings: server selection: value is not one of the possible choices: Sweden, Norway, Denmark",
		"provider settings: something else entirely went wrong",
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, body, http.StatusBadRequest)
		}))
		client := New(Options{BaseURL: server.URL, HTTPClient: server.Client()})
		_, err := client.PinServer(context.Background(), PinTarget{Hostname: "x.protonvpn.net"})
		server.Close()

		if known, found := KnownHostnames(err); found {
			t.Errorf("body %q yielded hostnames %v; only hostname lists should be parsed", body, known)
		}
	}
}
