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
	"regexp"
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

// SetDNSStatus starts or stops Gluetun's DNS-over-TLS resolver.
//
// PUT /v1/dns/status takes the same shape as the VPN one, and like it applies the change
// synchronously - so the mutation timeout applies rather than the read timeout.
func (c *Client) SetDNSStatus(ctx context.Context, status string) (outcome string, err error) {
	var response struct {
		Outcome string `json:"outcome"`
	}
	body := map[string]string{"status": status}
	if err := c.mutate(ctx, http.MethodPut, "/v1/dns/status", body, &response); err != nil {
		return "", err
	}
	return response.Outcome, nil
}

// Updater status values.
//
// Only "running" is compared against - the poll below waits for the status to stop being it,
// which is what "no longer running" means whichever of the others Gluetun reports. The other
// two are named so a reader of a Gluetun log or an API response can find them here.
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
	PortForwarding  *PortForwarding  `json:"port_forwarding,omitempty"`
}

// PortForwarding reports whether Gluetun asks the provider to forward a port.
// Without it, "no forwarded port" means "not requested" rather than "failed".
type PortForwarding struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// ServerSelection is Gluetun's server filter set.
//
// The boolean filters are pointers for a reason: Gluetun's patch semantics
// override a pointer field whenever it is non-nil, so a pointer to false is the
// only way to *clear* one. An empty slice, by contrast, means "leave unchanged" -
// which is why a list filter can never be cleared through this API.
type ServerSelection struct {
	VPN       string   `json:"vpn,omitempty"`
	Countries []string `json:"countries,omitempty"`
	Cities    []string `json:"cities,omitempty"`
	Names     []string `json:"names,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`

	PortForwardOnly *bool `json:"port_forward_only,omitempty"`
	SecureCoreOnly  *bool `json:"secure_core_only,omitempty"`
	TorOnly         *bool `json:"tor_only,omitempty"`
	StreamOnly      *bool `json:"stream_only,omitempty"`
	FreeOnly        *bool `json:"free_only,omitempty"`
	PremiumOnly     *bool `json:"premium_only,omitempty"`
	MultiHopOnly    *bool `json:"multi_hop_only,omitempty"`
	OwnedOnly       *bool `json:"owned_only,omitempty"`
}

// Requirements are the "only" filters Gluetun is enforcing.
//
// They matter because Gluetun ANDs them with a pinned hostname: pin a server that
// does not satisfy one and nothing matches, so Gluetun's VPN loop crashes and the
// tunnel stays down. Reading them lets a caller choose a server that satisfies
// them in the first place.
type Requirements struct {
	PortForward bool
	SecureCore  bool
	Tor         bool
	Stream      bool
	Free        bool
	Premium     bool
	// MultiHop and Owned are reported for completeness; ProtonVPN exposes no
	// equivalent, so they cannot be satisfied deliberately.
	MultiHop bool
	Owned    bool
	// PortForwardingRequested is VPN_PORT_FORWARDING, which is a *different*
	// setting from PORT_FORWARD_ONLY and easy to confuse with it.
	//
	// PORT_FORWARD_ONLY makes Gluetun refuse a server that cannot forward a port.
	// VPN_PORT_FORWARDING merely asks for a port once connected - Gluetun will
	// happily connect to a server that has no port to give. With ProtonVPN only P2P
	// servers forward ports, so turning port forwarding on without the "only"
	// filter is a configuration that connects fine and never gets a port. Reporting
	// the two separately lets a caller treat the request as a reason to prefer P2P
	// while still knowing Gluetun is not itself enforcing it.
	PortForwardingRequested bool
}

// OnlyFiltersCleared reports whether no "only" filter is in force.
//
// PortForwardingRequested is deliberately excluded. Pinning a server clears the
// filters - they are redundant next to an exact hostname and can crash Gluetun's VPN
// loop - but it must never cancel the request for a forwarded port, which is a
// feature the operator asked for rather than a selection constraint.
func (r Requirements) OnlyFiltersCleared() bool {
	r.PortForwardingRequested = false
	return r == Requirements{}
}

// Requirements reports the "only" filters currently in force, plus whether a
// forwarded port is being requested at all.
func (s Settings) Requirements() (requirements Requirements) {
	if s.Provider == nil {
		return requirements
	}
	enabled, _ := s.PortForwardingEnabled()
	if s.Provider.ServerSelection == nil {
		return Requirements{PortForwardingRequested: enabled}
	}
	selection := s.Provider.ServerSelection
	isSet := func(flag *bool) bool { return flag != nil && *flag }
	return Requirements{
		PortForwardingRequested: enabled,
		PortForward:             isSet(selection.PortForwardOnly),
		SecureCore:              isSet(selection.SecureCoreOnly),
		Tor:                     isSet(selection.TorOnly),
		Stream:                  isSet(selection.StreamOnly),
		Free:                    isSet(selection.FreeOnly),
		Premium:                 isSet(selection.PremiumOnly),
		MultiHop:                isSet(selection.MultiHopOnly),
		Owned:                   isSet(selection.OwnedOnly),
	}
}

// Wireguard carries WireGuard specifics; only present so decoding a full
// settings response does not lose the protocol in use.
type Wireguard struct {
	Implementation string `json:"implementation,omitempty"`
	// Addresses are the tunnel interface's own addresses. They are read to answer
	// whether the tunnel has IPv6 at all.
	//
	// This is the only IPv6 fact Gluetun exposes. Its /v1/publicip/ip returns a single
	// public_ip field, so there is no separate public IPv6 exit address to report - it
	// is whichever family the resolver happened to see.
	Addresses []string `json:"addresses,omitempty"`
}

// TunnelAddresses returns the tunnel interface's addresses, split by family.
func (s Settings) TunnelAddresses() (ipv4, ipv6 []string) {
	if s.Wireguard == nil {
		return nil, nil
	}
	for _, address := range s.Wireguard.Addresses {
		// The values are prefixes ("10.2.0.2/32", "fd00::1/128"); a colon is the only
		// thing needed to tell the families apart.
		if strings.Contains(address, ":") {
			ipv6 = append(ipv6, address)
		} else {
			ipv4 = append(ipv4, address)
		}
	}
	return ipv4, ipv6
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

	// Clearing the "only" filters is what keeps the selection satisfiable.
	//
	// Pinning one hostname is already the most specific selection possible, so
	// every other filter is redundant - but not harmless: Gluetun ANDs them, and
	// its built-in view of a server's features can disagree with Proton's current
	// data. A single disagreement (a server Proton marks P2P that Gluetun does
	// not) leaves nothing matching, and Gluetun's VPN loop crashes rather than
	// connecting. The operator's intent is honoured on our side instead, by only
	// ever choosing servers that satisfy what Gluetun asked for.
	no := false
	selection := &ServerSelection{
		Hostnames:       []string{target.Hostname},
		PortForwardOnly: &no,
		SecureCoreOnly:  &no,
		TorOnly:         &no,
		StreamOnly:      &no,
		FreeOnly:        &no,
		PremiumOnly:     &no,
		MultiHopOnly:    &no,
		OwnedOnly:       &no,
	}
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

// PublicIP is Gluetun's view of the current exit address. Every field Gluetun
// publishes is captured, because they are exactly what an operator wants to see
// to confirm where traffic is actually coming out.
type PublicIP struct {
	IP           string `json:"public_ip"`
	Region       string `json:"region,omitempty"`
	Country      string `json:"country,omitempty"`
	City         string `json:"city,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	Location     string `json:"location,omitempty"`
	Organization string `json:"organization,omitempty"`
	PostalCode   string `json:"postal_code,omitempty"`
	Timezone     string `json:"timezone,omitempty"`
}

// GetPublicIP returns the current public IP as seen through the tunnel.
func (c *Client) GetPublicIP(ctx context.Context) (publicIP PublicIP, err error) {
	if err := c.request(ctx, http.MethodGet, "/v1/publicip/ip", nil, &publicIP); err != nil {
		return PublicIP{}, err
	}
	return publicIP, nil
}

// GetForwardedPorts returns every port Proton has forwarded.
//
// Gluetun has answered with a single "port" historically and a "ports" list more
// recently, so both shapes are accepted.
func (c *Client) GetForwardedPorts(ctx context.Context) (ports []uint16, err error) {
	var response struct {
		Port  uint16   `json:"port"`
		Ports []uint16 `json:"ports"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/portforward", nil, &response); err != nil {
		return nil, err
	}
	if len(response.Ports) > 0 {
		return response.Ports, nil
	}
	if response.Port != 0 {
		return []uint16{response.Port}, nil
	}
	return nil, nil
}

// GetForwardedPort returns the first forwarded port, or 0 when there is none.
func (c *Client) GetForwardedPort(ctx context.Context) (port uint16, err error) {
	ports, err := c.GetForwardedPorts(ctx)
	if err != nil || len(ports) == 0 {
		return 0, err
	}
	return ports[0], nil
}

// DNSStatus reports whether Gluetun's built-in DNS-over-TLS resolver is running.
func (c *Client) DNSStatus(ctx context.Context) (status string, err error) {
	var response struct {
		Status string `json:"status"`
	}
	if err := c.request(ctx, http.MethodGet, "/v1/dns/status", nil, &response); err != nil {
		return "", err
	}
	return response.Status, nil
}

// BuildInfo is Gluetun's build information.
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Created string `json:"created"`
}

// Version reports Gluetun's build information. It matters beyond display: the
// version determines the storage layout and the servers schema version.
func (c *Client) Version(ctx context.Context) (info BuildInfo, err error) {
	if err := c.request(ctx, http.MethodGet, "/v1/version", nil, &info); err != nil {
		return BuildInfo{}, err
	}
	return info, nil
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
	// Only a state-changing request has an outcome worth being uncertain about. A
	// read that times out just means Gluetun is not answering.
	isMutation := httpClient == c.mutationClient && method != http.MethodGet
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
		if isMutation && (errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err)) {
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
		// The rejection carries the full set of hostnames Gluetun would have
		// accepted. That is far too useful to summarise away: keeping it on the
		// error lets the caller choose a server Gluetun can actually reach instead
		// of failing outright, without a second request.
		return nil, &RejectionError{
			message: fmt.Sprintf("%s: %s %s: HTTP %d: %s",
				ErrRejected.Error(), method, path, response.StatusCode, summarizeError(raw)),
			KnownHostnames: parseChoices(raw),
		}
	default:
		return nil, fmt.Errorf("%w: %s %s: HTTP %d: %s",
			ErrUnavailable, method, path, response.StatusCode, summarizeError(raw))
	}
}

// RejectionError is a refusal from Gluetun that carries what it would have
// accepted.
//
// It exists so a caller can recover rather than merely report. Gluetun validates a
// pinned hostname against the list it loaded at startup, and when it refuses one it
// enumerates every hostname in that list. Those names are the authoritative answer
// to "what can this Gluetun actually be switched to right now?" - better than any
// inference from files on disk, because it is Gluetun's own in-memory state.
type RejectionError struct {
	message string
	// KnownHostnames is every hostname Gluetun listed as acceptable, nil when the
	// refusal was about something else.
	KnownHostnames []string
}

func (e *RejectionError) Error() string { return e.message }

// Unwrap keeps errors.Is(err, ErrRejected) working, so existing callers are
// unaffected by the richer type.
func (e *RejectionError) Unwrap() error { return ErrRejected }

// KnownHostnames extracts the hostnames Gluetun said it would accept, if the error
// was that kind of rejection.
func KnownHostnames(err error) (hostnames []string, found bool) {
	var rejection *RejectionError
	if !errors.As(err, &rejection) || len(rejection.KnownHostnames) == 0 {
		return nil, false
	}
	return rejection.KnownHostnames, true
}

// parseChoices pulls the hostname list out of a rejection body.
func parseChoices(raw []byte) (hostnames []string) {
	match := choicesPattern.FindStringSubmatch(string(raw))
	if match == nil {
		return nil
	}
	for _, choice := range strings.Split(match[2], ",") {
		choice = strings.TrimSpace(choice)
		// Gluetun lists values for other fields the same way, so only accept
		// something that looks like a hostname rather than, say, a country name.
		if choice != "" && strings.Contains(choice, ".") && !strings.Contains(choice, " ") {
			hostnames = append(hostnames, choice)
		}
	}
	return hostnames
}

// choicesPattern matches the tail Gluetun appends when it rejects a value: the
// complete list of what it would have accepted.
var choicesPattern = regexp.MustCompile(
	`(?s)value is not one of the possible choices: (?:none of (\S+) is one of the choices available )?(.*)`)

// maxErrorLength bounds an error message that is quoted into logs and the
// dashboard.
const maxErrorLength = 400

// summarizeError makes a Gluetun error fit in a log line.
//
// Rejecting a hostname makes Gluetun list every hostname it *would* have accepted -
// around 30 kB of it, roughly 570 names. Quoting that verbatim buried the one useful
// fact (which hostname was refused) under a wall of text, in the log, in the
// dashboard, and in the switch history. The count is kept because it is genuinely
// diagnostic: a few hundred choices means Gluetun is running on its small built-in
// list rather than the one written here.
func summarizeError(raw []byte) string {
	message := strings.TrimSpace(string(raw))

	if match := choicesPattern.FindStringSubmatch(message); match != nil {
		prefix := strings.TrimSpace(message[:strings.Index(message, "value is not one of the possible choices:")])
		choices := strings.Count(match[2], ",") + 1
		rejected := match[1]
		if rejected == "" {
			return fmt.Sprintf("%s value is not one of the %d choices gluetun knows",
				prefix, choices)
		}
		return fmt.Sprintf("%s %s is not one of the %d choices gluetun knows "+
			"(it is using its own server list, not the one written here - restart the gluetun "+
			"container to load it)", prefix, rejected, choices)
	}

	if len(message) > maxErrorLength {
		return message[:maxErrorLength] + "… (truncated)"
	}
	return message
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

// PortForwardingEnabled reports whether Gluetun requests a forwarded port.
func (s Settings) PortForwardingEnabled() (enabled, known bool) {
	if s.Provider == nil || s.Provider.PortForwarding == nil || s.Provider.PortForwarding.Enabled == nil {
		return false, false
	}
	return *s.Provider.PortForwarding.Enabled, true
}

// SelectionSummary renders Gluetun's active server filters for display, so the
// dashboard can show what Gluetun itself is restricted to - which is often the
// reason a switch was refused.
func (s Settings) SelectionSummary() map[string][]string {
	if s.Provider == nil || s.Provider.ServerSelection == nil {
		return nil
	}
	selection := s.Provider.ServerSelection
	summary := map[string][]string{}
	for key, values := range map[string][]string{
		"countries": selection.Countries,
		"cities":    selection.Cities,
		"names":     selection.Names,
		"hostnames": selection.Hostnames,
	} {
		if len(values) > 0 {
			summary[key] = values
		}
	}
	if len(summary) == 0 {
		return nil
	}
	return summary
}

// PinnedHostnames reports the hostnames Gluetun is currently restricted to.
func (s Settings) PinnedHostnames() []string {
	if s.Provider == nil || s.Provider.ServerSelection == nil {
		return nil
	}
	return s.Provider.ServerSelection.Hostnames
}
