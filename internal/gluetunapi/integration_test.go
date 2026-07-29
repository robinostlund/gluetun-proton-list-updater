//go:build integration

// This file verifies the client against a real Gluetun container rather than a
// hand-written fake. Fakes can only ever confirm that the code matches the
// author's understanding of the API; this confirms the understanding itself.
//
// Run it with:
//
//	make integration
//
// or manually:
//
//	docker run -d --name gluetun-itest --cap-add=NET_ADMIN --device=/dev/net/tun \
//	  -p 18000:8000 \
//	  -e VPN_SERVICE_PROVIDER=protonvpn -e VPN_TYPE=wireguard \
//	  -e WIREGUARD_PRIVATE_KEY="$(head -c 32 /dev/urandom | base64)" \
//	  -e SERVER_COUNTRIES=Sweden \
//	  -e HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE='{"name":"updater","auth":"apikey","apikey":"itest-secret"}' \
//	  qmcgaw/gluetun:v3.41.1
//	GLUETUN_ITEST_URL=http://127.0.0.1:18000 GLUETUN_ITEST_API_KEY=itest-secret \
//	  go test -tags integration ./internal/gluetunapi/ -v
//
// The WireGuard key is deliberately random: the tunnel never comes up, which is
// irrelevant here. What is being tested is the control-server contract.
package gluetunapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func integrationClient(t *testing.T) *Client {
	t.Helper()

	baseURL := os.Getenv("GLUETUN_ITEST_URL")
	if baseURL == "" {
		t.Skip("GLUETUN_ITEST_URL is not set; skipping the real-Gluetun integration test")
	}
	return New(Options{
		BaseURL: baseURL,
		APIKey:  os.Getenv("GLUETUN_ITEST_API_KEY"),
		Timeout: 30 * time.Second,
	})
}

func TestIntegrationStatusAndVersion(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()

	build, err := client.Version(ctx)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	// A release reports v3.x; a master build reports "latest". Both are valid.
	if build.Version == "" {
		t.Error("version is empty")
	}
	if build.Commit == "" {
		t.Error("commit is empty")
	}
	t.Logf("gluetun version: %s (commit %s, built %s)", build.Version, build.Commit, build.Created)

	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	switch status {
	case StatusRunning, StatusStopped, StatusStarting, StatusStopping, StatusCrashed:
	default:
		t.Errorf("unexpected status %q", status)
	}
	t.Logf("tunnel status: %s", status)
}

// This is the capability the whole tool depends on. If real Gluetun ever stops
// accepting this patch shape, or stops applying it, this test is how we find out.
func TestIntegrationPinHostnameIsAcceptedAndApplied(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()

	hostname, country := firstKnownServer(t, client)
	t.Logf("pinning %s in %s", hostname, country)

	outcome, err := client.PinServer(ctx, PinTarget{Hostname: hostname, Country: country})
	if err != nil {
		if errors.Is(err, ErrRejected) && strings.Contains(err.Error(), "401") {
			t.Fatalf("Gluetun refused the request for lack of permission. The control server must allow "+
				"GET and PUT /v1/vpn/settings, which its default 'public' role does not: %v", err)
		}
		t.Fatalf("PinHostname: %v", err)
	}
	t.Logf("outcome: %s", outcome)

	// Gluetun applies the patch synchronously, so the selection must be visible
	// on the very next read.
	settings, err := client.GetSettings(ctx)
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	pinned := settings.PinnedHostnames()
	if len(pinned) != 1 || pinned[0] != hostname {
		t.Fatalf("pinned hostnames = %v, want exactly [%s]", pinned, hostname)
	}

	// The patch must not have disturbed anything else: it carries only the
	// hostname, so the provider and protocol have to be untouched.
	if settings.ProviderName() != "protonvpn" {
		t.Errorf("provider = %q, want protonvpn: the patch changed more than intended",
			settings.ProviderName())
	}
	if settings.VPNType() == "" {
		t.Error("VPN type was lost by the patch")
	}
}

// Regression test for the most damaging failure this tool can cause.
//
// Gluetun ANDs every server-selection filter. Pinning a hostname without also
// sending its country leaves the container's own SERVER_COUNTRIES in force, and
// if the two disagree nothing matches: Gluetun logs "no server found", its VPN
// loop crashes, and the tunnel stays down. Sending the server's own country
// makes the selection self-consistent, which this test proves against the real
// filter logic.
func TestIntegrationCrossCountryPinDoesNotCrashTheTunnel(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()

	hostname, country := serverOutsideCountry(t, os.Getenv("GLUETUN_ITEST_COUNTRY"))
	t.Logf("pinning %s in %s while Gluetun is configured for %s",
		hostname, country, os.Getenv("GLUETUN_ITEST_COUNTRY"))

	if _, err := client.PinServer(ctx, PinTarget{Hostname: hostname, Country: country}); err != nil {
		t.Fatalf("PinServer: %v", err)
	}

	// Give Gluetun a moment to act on the new selection, then confirm it did not
	// end up with an empty candidate set.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err := client.Status(ctx)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if status == StatusCrashed {
			t.Fatalf("the tunnel crashed after a cross-country pin: Gluetun found no server " +
				"matching both the pinned hostname and its configured countries")
		}
		if status == StatusRunning {
			break
		}
		time.Sleep(2 * time.Second)
	}

	settings, err := client.GetSettings(ctx)
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	// The country filter must have been replaced, not merely added to.
	countries := settings.Provider.ServerSelection.Countries
	if len(countries) != 1 || countries[0] != country {
		t.Errorf("countries = %v, want exactly [%s]", countries, country)
	}
}

// A hostname Gluetun does not know must be a distinguishable rejection, not an
// outage: that difference is what lets the engine try the next candidate rather
// than give up.
func TestIntegrationUnknownHostnameIsRejected(t *testing.T) {
	client := integrationClient(t)

	_, err := client.PinServer(context.Background(), PinTarget{
		Hostname: "definitely-not-a-server.protonvpn.net", Country: "Sweden",
	})
	if err == nil {
		t.Fatal("expected Gluetun to refuse an unknown hostname")
	}
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Error("a rejection must not be classified as unavailability")
	}
}

// The stop/start fallback for setups that cannot allow PUT /v1/vpn/settings.
func TestIntegrationReconnectViaStatus(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()

	if _, err := client.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}

	// Gluetun returns from the start request once the loop is running again.
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status == StatusStopped {
		t.Errorf("tunnel is still stopped after a reconnect")
	}
	t.Logf("status after reconnect: %s", status)
}

// Triggering Gluetun's own updater is the only way to make it aware of servers
// added since it started, so the endpoint's availability matters.
func TestIntegrationTriggerUpdater(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()

	before, err := client.UpdaterStatus(ctx)
	if err != nil {
		t.Fatalf("UpdaterStatus: %v", err)
	}
	t.Logf("updater status before: %s", before)

	outcome, err := client.TriggerUpdater(ctx)
	if err != nil {
		t.Fatalf("TriggerUpdater: %v", err)
	}
	t.Logf("updater outcome: %s", outcome)

	// Without UPDATER_PROTONVPN_EMAIL/PASSWORD on the container, Gluetun logs
	// "credentials missing" and finishes immediately. Either way it must stop
	// running within the timeout.
	if err := client.WaitForUpdater(ctx, 60*time.Second); err != nil {
		t.Errorf("WaitForUpdater: %v", err)
	}
}

func TestIntegrationPortForwardAndPublicIP(t *testing.T) {
	client := integrationClient(t)
	ctx := context.Background()

	// Neither of these can be asserted on a tunnel that will never come up with
	// a random key; what matters is that both decode without error.
	if _, err := client.GetForwardedPort(ctx); err != nil {
		t.Errorf("GetForwardedPort: %v", err)
	}
	if _, err := client.GetPublicIP(ctx); err != nil {
		t.Logf("GetPublicIP returned %v (expected while the tunnel is down)", err)
	}
}

// firstKnownServer reads a server out of the list Gluetun itself wrote, which is
// by definition one it will accept.
func firstKnownServer(t *testing.T, client *Client) (hostname, country string) {
	t.Helper()

	if hostname := os.Getenv("GLUETUN_ITEST_HOSTNAME"); hostname != "" {
		return hostname, os.Getenv("GLUETUN_ITEST_COUNTRY")
	}

	path := os.Getenv("GLUETUN_ITEST_SERVERS_FILE")
	if path == "" {
		t.Skip("set GLUETUN_ITEST_HOSTNAME or GLUETUN_ITEST_SERVERS_FILE to a hostname Gluetun knows")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	servers, err := decodeServers(data)
	if err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	file := struct {
		Protonvpn struct{ Servers []serverEntry }
	}{}
	file.Protonvpn.Servers = servers

	settings, err := client.GetSettings(context.Background())
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	wantVPN := settings.VPNType()

	// Prefer a server in a country Gluetun was started with, so the pin exercises
	// the normal path rather than the cross-country one.
	wantCountry := os.Getenv("GLUETUN_ITEST_COUNTRY")
	for _, server := range file.Protonvpn.Servers {
		if server.VPN != wantVPN || server.Hostname == "" {
			continue
		}
		if wantCountry == "" || server.Country == wantCountry {
			return server.Hostname, server.Country
		}
	}
	t.Fatalf("no %s server found in %s", wantVPN, path)
	return "", ""
}

// serverOutsideCountry finds a server in some country other than the one given.
func serverOutsideCountry(t *testing.T, excluded string) (hostname, country string) {
	t.Helper()

	path := os.Getenv("GLUETUN_ITEST_SERVERS_FILE")
	if path == "" {
		t.Skip("GLUETUN_ITEST_SERVERS_FILE is not set")
	}
	if excluded == "" {
		t.Skip("GLUETUN_ITEST_COUNTRY is not set, so there is no configured country to differ from")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	servers, err := decodeServers(data)
	if err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}

	for _, server := range servers {
		if server.Country != excluded && server.Hostname != "" && server.Country != "" {
			return server.Hostname, server.Country
		}
	}
	t.Fatalf("no server outside %s found in %s", excluded, path)
	return "", ""
}

// serverEntry is the part of a Gluetun server entry these tests need.
type serverEntry struct {
	VPN      string `json:"vpn"`
	Country  string `json:"country"`
	Hostname string `json:"hostname"`
}

// decodeServers reads a server list from either Gluetun storage layout: a
// per-provider file ({"version":..,"servers":[..]}) or the legacy fat file
// ({"protonvpn":{"servers":[..]}}).
func decodeServers(data []byte) (servers []serverEntry, err error) {
	var providerFile struct {
		Servers []serverEntry `json:"servers"`
	}
	if err := json.Unmarshal(data, &providerFile); err == nil && len(providerFile.Servers) > 0 {
		return providerFile.Servers, nil
	}

	var legacy struct {
		Protonvpn struct {
			Servers []serverEntry `json:"servers"`
		} `json:"protonvpn"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, err
	}
	return legacy.Protonvpn.Servers, nil
}
