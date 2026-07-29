package gluetunapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
