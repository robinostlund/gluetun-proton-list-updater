// Package gluetunapi is a client for Gluetun's HTTP control server.
//
// The interesting capability is PUT /v1/vpn/settings: patching the server
// selection makes Gluetun stop the tunnel, apply the new selection and start
// again. That is what lets this tool move the tunnel onto a specific server
// without restarting the Gluetun container.
package gluetunapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Tunnel status values used by the control server.
const (
	StatusRunning  = "running"
	StatusStopped  = "stopped"
	StatusStarting = "starting"
	StatusStopping = "stopping"
	StatusCrashed  = "crashed"
)

// ErrUnavailable reports that Gluetun could not be reached at all, as opposed
// to answering with an error. The engine treats this as "degraded, keep going"
// rather than a fatal condition.
var ErrUnavailable = errors.New("gluetun control server unavailable")

// ErrRejected reports that Gluetun understood the request and refused it,
// typically because a hostname is not in the server list it loaded at startup.
var ErrRejected = errors.New("gluetun rejected the request")

// ErrTimedOut reports that a state-changing request did not answer in time.
//
// It is deliberately distinct from ErrUnavailable: Gluetun applies these changes
// synchronously, so a timeout means the outcome is unknown, not failed. The
// caller must verify the resulting state rather than retrying, or it risks
// reconnecting a tunnel that already moved.
var ErrTimedOut = errors.New("gluetun did not answer in time; outcome unknown")

// Options configures a Client.
type Options struct {
	BaseURL  string
	APIKey   string
	Username string
	Password string
	// Timeout bounds read-only requests.
	Timeout time.Duration
	// MutationTimeout bounds requests that change the tunnel state.
	//
	// It needs to be far more generous than Timeout: Gluetun does not answer a
	// status or settings change until its VPN loop has actually stopped and
	// started, which takes seconds normally and can block for much longer while
	// a tunnel is unhealthy and cycling.
	MutationTimeout time.Duration
	// HTTPClient overrides the default client for reads. Used by tests.
	HTTPClient *http.Client
}

// Client talks to one Gluetun control server. It is safe for concurrent use.
type Client struct {
	baseURL        string
	apiKey         string
	username       string
	password       string
	httpClient     *http.Client
	mutationClient *http.Client
}

// New builds a Client.
func New(opts Options) *Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	mutationTimeout := opts.MutationTimeout
	if mutationTimeout <= 0 {
		mutationTimeout = 2 * time.Minute
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	// Tests that inject an HTTPClient get it for both, so their fake server
	// still sees every request.
	mutationClient := httpClient
	if opts.HTTPClient == nil {
		mutationClient = &http.Client{Timeout: mutationTimeout}
	}

	return &Client{
		baseURL:        strings.TrimSuffix(opts.BaseURL, "/"),
		apiKey:         opts.APIKey,
		username:       opts.Username,
		password:       opts.Password,
		httpClient:     httpClient,
		mutationClient: mutationClient,
	}
}

// Status returns the current tunnel status.
func (c *Client) Status(ctx context.Context) (status string, err error) {
	var response struct {
		Status string `json:"status"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/vpn/status", nil, &response); err != nil {
		return "", err
	}
	return response.Status, nil
}

// SetStatus stops or starts the tunnel and returns Gluetun's outcome string.
func (c *Client) SetStatus(ctx context.Context, status string) (outcome string, err error) {
	var response struct {
		Outcome string `json:"outcome"`
	}
	body := map[string]string{"status": status}
	if err := c.mutate(ctx, http.MethodPut, "/v1/vpn/status", body, &response); err != nil {
		return "", err
	}
	return response.Outcome, nil
}

// Reconnect stops and then starts the tunnel, leaving server choice to
// Gluetun's own filters. Used as a fallback when pinning a hostname is not
// possible.
func (c *Client) Reconnect(ctx context.Context) (outcome string, err error) {
	if _, err := c.SetStatus(ctx, StatusStopped); err != nil {
		return "", fmt.Errorf("stopping tunnel: %w", err)
	}
	outcome, err = c.SetStatus(ctx, StatusRunning)
	if err != nil {
		return "", fmt.Errorf("starting tunnel: %w", err)
	}
	return outcome, nil
}

// Updater status values.
const (
	UpdaterRunning   = "running"
	UpdaterStopped   = "stopped"
	UpdaterCompleted = "completed"
)

// UpdaterStatus reports whether Gluetun's own server-list updater is running.
func (c *Client) UpdaterStatus(ctx context.Context) (status string, err error) {
	var response struct {
		Status string `json:"status"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/updater/status", nil, &response); err != nil {
		return "", err
	}
	return response.Status, nil
}

// TriggerUpdater asks Gluetun to run its own server-list updater.
//
// This exists to solve a specific problem: Gluetun reads servers.json only at
// startup, and validates a pinned hostname against that in-memory list. A server
// Proton added after Gluetun started is therefore unusable, however current our
// servers.json is, and there is no control-server route that re-reads the file.
//
// Running Gluetun's own updater makes it fetch from Proton and replace its
// in-memory list, which does make new hostnames selectable without restarting
// the container. It requires UPDATER_PROTONVPN_EMAIL and
// UPDATER_PROTONVPN_PASSWORD to be set on the Gluetun container; without them
// Gluetun logs "credentials missing" and skips the update, which is why callers
// must treat a successful call as "asked", not "done".
func (c *Client) TriggerUpdater(ctx context.Context) (outcome string, err error) {
	var response struct {
		Outcome string `json:"outcome"`
	}
	body := map[string]string{"status": UpdaterRunning}
	if err := c.mutate(ctx, http.MethodPut, "/v1/updater/status", body, &response); err != nil {
		return "", err
	}
	return response.Outcome, nil
}

// WaitForUpdater polls until Gluetun's updater is no longer running.
func (c *Client) WaitForUpdater(ctx context.Context, timeout time.Duration) (err error) {
	deadline := time.Now().Add(timeout)
	const pollInterval = 2 * time.Second

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}

		status, statusErr := c.UpdaterStatus(ctx)
		if statusErr != nil {
			return statusErr
		}
		if status != UpdaterRunning {
			return nil
		}
	}
	return fmt.Errorf("gluetun updater still running after %s", timeout)
}

// Settings is the subset of Gluetun's VPN settings this tool reads or writes.
// Every field is a pointer or slice so that a patch omits what it does not
// change: Gluetun merges a partial body over its current settings.
type Settings struct {
	Type      string     `json:"type,omitempty"`
	Provider  *Provider  `json:"provider,omitempty"`
	Wireguard *Wireguard `json:"wireguard,omitempty"`
}

// Provider identifies the VPN provider and its server selection.
type Provider struct {
	Name            string           `json:"name,omitempty"`
	ServerSelection *ServerSelection `json:"server_selection,omitempty"`
}

// ServerSelection is Gluetun's server filter set.
type ServerSelection struct {
	VPN       string   `json:"vpn,omitempty"`
	Countries []string `json:"countries,omitempty"`
	Cities    []string `json:"cities,omitempty"`
	Names     []string `json:"names,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
}

// Wireguard carries WireGuard specifics; only present so decoding a full
// settings response does not lose the protocol in use.
type Wireguard struct {
	Implementation string `json:"implementation,omitempty"`
}

// GetSettings reads Gluetun's current VPN settings.
func (c *Client) GetSettings(ctx context.Context) (settings Settings, err error) {
	if err := c.request(ctx, http.MethodGet, "/v1/vpn/settings", nil, &settings); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

// PinTarget identifies the server to pin.
//
// Country and City are not decoration. Gluetun combines every selection filter
// with AND, so pinning only a hostname leaves whatever SERVER_COUNTRIES the
// container was started with in force. Pin a Norwegian hostname on a container
// configured for Sweden and the filters intersect to nothing: Gluetun logs
// "no server found", the VPN loop crashes, and the tunnel stays down. Sending
// the chosen server's own location makes the selection self-consistent whatever
// Gluetun was started with.
type PinTarget struct {
	Hostname string
	Country  string
	City     string
}

// PinServer patches the server selection to exactly one server, which makes
// Gluetun reconnect to it.
//
// Gluetun validates the hostname against the server list it loaded at startup.
// A hostname it has never seen is refused with HTTP 400, surfaced here as
// ErrRejected so the caller can try the next candidate.
func (c *Client) PinServer(ctx context.Context, target PinTarget) (outcome string, err error) {
	if target.Hostname == "" {
		return "", errors.New("gluetunapi: empty hostname")
	}

	selection := &ServerSelection{Hostnames: []string{target.Hostname}}
	if target.Country != "" {
		selection.Countries = []string{target.Country}
	}
	// A city is only sent when known. Gluetun cannot be told to clear a filter
	// (an empty list means "leave unchanged"), so a container started with
	// SERVER_CITIES and a server with no city would still conflict - which is
	// why the documentation asks for city filtering to live here, not there.
	if target.City != "" {
		selection.Cities = []string{target.City}
	}

	patch := Settings{Provider: &Provider{ServerSelection: selection}}

	// This endpoint answers with a bare outcome string, not JSON.
	raw, err := c.mutateRaw(ctx, http.MethodPut, "/v1/vpn/settings", patch)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// PublicIP is Gluetun's view of the current exit address.
type PublicIP struct {
	IP       string `json:"public_ip"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	City     string `json:"city"`
	Location string `json:"location"`
	Org      string `json:"organization"`
}

// GetPublicIP returns the current public IP as seen through the tunnel.
func (c *Client) GetPublicIP(ctx context.Context) (publicIP PublicIP, err error) {
	if err := c.request(ctx, http.MethodGet, "/v1/publicip/ip", nil, &publicIP); err != nil {
		return PublicIP{}, err
	}
	return publicIP, nil
}

// GetForwardedPort returns the port Proton forwarded, or 0 when there is none.
func (c *Client) GetForwardedPort(ctx context.Context) (port uint16, err error) {
	var response struct {
		Port  uint16   `json:"port"`
		Ports []uint16 `json:"ports"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/portforward", nil, &response); err != nil {
		return 0, err
	}
	if response.Port != 0 {
		return response.Port, nil
	}
	if len(response.Ports) > 0 {
		return response.Ports[0], nil
	}
	return 0, nil
}

// Version reports Gluetun's build information, which the dashboard shows and
// which helps diagnose servers.json schema mismatches.
func (c *Client) Version(ctx context.Context) (version string, err error) {
	var response struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
		Created string `json:"created"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/version", nil, &response); err != nil {
		return "", err
	}
	return response.Version, nil
}

// mutate performs a state-changing request using the longer timeout.
func (c *Client) mutate(ctx context.Context, method, path string, body, out any) (err error) {
	raw, err := c.mutateRaw(ctx, method, path, body)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding %s %s response: %w", method, path, err)
	}
	return nil
}

func (c *Client) mutateRaw(ctx context.Context, method, path string, body any) (raw []byte, err error) {
	return c.do(ctx, c.mutationClient, method, path, body)
}

func (c *Client) request(ctx context.Context, method, path string, body, out any) (err error) {
	raw, err := c.requestRaw(ctx, method, path, body)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding %s %s response: %w", method, path, err)
	}
	return nil
}

func (c *Client) requestRaw(ctx context.Context, method, path string, body any) (raw []byte, err error) {
	return c.do(ctx, c.httpClient, method, path, body)
}

func (c *Client) do(ctx context.Context, httpClient *http.Client,
	method, path string, body any,
) (raw []byte, err error) {
	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding %s %s body: %w", method, path, err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	switch {
	case c.apiKey != "":
		request.Header.Set("X-API-Key", c.apiKey)
	case c.username != "":
		request.SetBasicAuth(c.username, c.password)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		// A timeout on a state-changing request is not the same as "down":
		// Gluetun may well have applied the change and simply not answered yet.
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			return nil, fmt.Errorf("%w: %s %s: %w", ErrTimedOut, method, path, err)
		}
		// Any other transport error means Gluetun is down or unreachable.
		return nil, fmt.Errorf("%w: %s %s: %w", ErrUnavailable, method, path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}()

	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil {
		return nil, fmt.Errorf("%w: reading %s %s response: %w", ErrUnavailable, method, path, readErr)
	}

	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return raw, nil
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%w: %s %s: HTTP %d - check GLUETUN_API_KEY or GLUETUN_USERNAME/GLUETUN_PASSWORD "+
			"and that the control server role allows this route",
			ErrRejected, method, path, response.StatusCode)
	case response.StatusCode >= 400 && response.StatusCode < 500:
		return nil, fmt.Errorf("%w: %s %s: HTTP %d: %s",
			ErrRejected, method, path, response.StatusCode, strings.TrimSpace(string(raw)))
	default:
		return nil, fmt.Errorf("%w: %s %s: HTTP %d: %s",
			ErrUnavailable, method, path, response.StatusCode, strings.TrimSpace(string(raw)))
	}
}

// VPNType reports the protocol Gluetun is configured for, normalised to
// "wireguard" or "openvpn".
func (s Settings) VPNType() string {
	if s.Provider != nil && s.Provider.ServerSelection != nil && s.Provider.ServerSelection.VPN != "" {
		return strings.ToLower(s.Provider.ServerSelection.VPN)
	}
	return strings.ToLower(s.Type)
}

// ProviderName reports the configured VPN provider, lowercased.
func (s Settings) ProviderName() string {
	if s.Provider == nil {
		return ""
	}
	return strings.ToLower(s.Provider.Name)
}

// PinnedHostnames reports the hostnames Gluetun is currently restricted to.
func (s Settings) PinnedHostnames() []string {
	if s.Provider == nil || s.Provider.ServerSelection == nil {
		return nil
	}
	return s.Provider.ServerSelection.Hostnames
}
