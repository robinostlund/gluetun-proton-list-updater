// Package qbittorrent reads current transfer rates from a qBittorrent Web API.
//
// It exists to answer one question: is anything being transferred right now? A
// server switch tears the tunnel down and with it every connection through it, so a
// switch during an active download is a self-inflicted interruption. Knowing the
// rate lets the engine wait instead.
//
// Only reads are performed. Nothing here can start, stop or alter a torrent.
package qbittorrent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// apiKeyPrefix and apiKeyLength are qBittorrent's own format for a Web API key,
// from Utils::APIKey in its source: a "qbt_" prefix and 28 generated characters.
//
// The format is checked so an obviously wrong value - a password, a session cookie,
// a truncated paste - is reported as a configuration mistake rather than surfacing
// later as an unexplained 401.
const (
	apiKeyPrefix = "qbt_"
	apiKeyLength = len(apiKeyPrefix) + 28
)

// ErrUnavailable reports that qBittorrent could not be reached or did not answer
// usefully. The engine treats it as "no information", never as "idle": assuming a
// tunnel is idle because the check failed is how a transfer gets interrupted.
var ErrUnavailable = errors.New("qbittorrent is unavailable")

// ErrUnauthorized reports that qBittorrent refused the API key.
var ErrUnauthorized = errors.New("qbittorrent rejected the API key")

// Options configures a Client.
type Options struct {
	// BaseURL is the Web UI address, e.g. http://qbittorrent:8080.
	BaseURL string
	// APIKey is a Web API key generated in qBittorrent's own settings
	// (Preferences → Web UI → API keys). It is sent as a bearer token.
	APIKey string
	// Timeout bounds each request. It should stay well below the poll interval.
	Timeout time.Duration
	// HTTPClient overrides the default client. Used by tests.
	HTTPClient *http.Client
}

// Client reads transfer statistics from one qBittorrent instance. It is safe for
// concurrent use.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// New builds a Client. An empty BaseURL means the feature is switched off, which is
// the caller's business rather than an error here.
func New(opts Options) *Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	return &Client{
		baseURL:    strings.TrimSuffix(opts.BaseURL, "/"),
		apiKey:     opts.APIKey,
		httpClient: httpClient,
	}
}

// APIKeyLooksValid reports whether a key matches qBittorrent's own format.
//
// It is advisory. qBittorrent is the authority on whether a key works, and a future
// version could change the format, so a mismatch is worth warning about but never
// worth refusing to try.
func APIKeyLooksValid(key string) bool {
	return strings.HasPrefix(key, apiKeyPrefix) && len(key) == apiKeyLength
}

// Transfer is qBittorrent's global transfer state, from GET /api/v2/transfer/info.
type Transfer struct {
	// DownloadSpeed and UploadSpeed are the current rates in bytes per second.
	DownloadSpeed uint64 `json:"dl_info_speed"`
	UploadSpeed   uint64 `json:"up_info_speed"`
	// DownloadTotal and UploadTotal are bytes moved this session.
	DownloadTotal uint64 `json:"dl_info_data"`
	UploadTotal   uint64 `json:"up_info_data"`
	// DownloadLimit and UploadLimit are the configured rate caps, 0 for unlimited.
	// They give the rates context: 900 kB/s means something different against a
	// 1 MB/s cap than against no cap at all.
	DownloadLimit uint64 `json:"dl_rate_limit"`
	UploadLimit   uint64 `json:"up_rate_limit"`
	// ConnectionStatus is qBittorrent's own view of its connectivity:
	// "connected", "firewalled" or "disconnected". Worth surfacing, because
	// "firewalled" on a port-forwarding setup usually means the forwarded port is
	// not reaching qBittorrent.
	ConnectionStatus string `json:"connection_status"`
}

// Transfer fetches the current global transfer state.
func (c *Client) Transfer(ctx context.Context) (transfer Transfer, err error) {
	raw, err := c.get(ctx, "/api/v2/transfer/info")
	if err != nil {
		return Transfer{}, err
	}
	if err := json.Unmarshal(raw, &transfer); err != nil {
		return Transfer{}, fmt.Errorf("%w: decoding transfer info: %w", ErrUnavailable, err)
	}
	return transfer, nil
}

// Version reports qBittorrent's application version, used once at startup to prove
// the credentials work and to record what is being talked to.
func (c *Client) Version(ctx context.Context) (version string, err error) {
	raw, err := c.get(ctx, "/api/v2/app/version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (c *Client) get(ctx context.Context, path string) (raw []byte, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("building %s request: %w", path, err)
	}
	// A bearer API key is qBittorrent's own scheme for programmatic access. It also
	// bypasses its CSRF protection, so no Referer or Origin juggling is needed - and
	// unlike a login session it does not expire, so there is no re-authentication
	// path to get wrong and no risk of tripping the brute-force lockout.
	if c.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	request.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrUnavailable, path, err)
	}
	defer response.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrUnavailable, path, readErr)
	}

	switch {
	case response.StatusCode == http.StatusOK:
		return raw, nil
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		// Worth being specific: qBittorrent answers 401 for a bad key *and* for a
		// request its host-header validation rejects, which is a completely
		// different fix.
		return nil, fmt.Errorf("%w (HTTP %d on %s): check QBITTORRENT_API_KEY, and that "+
			"qBittorrent's Web UI accepts requests for this address - its host-header "+
			"validation refuses unknown ones with the same status",
			ErrUnauthorized, response.StatusCode, path)
	default:
		return nil, fmt.Errorf("%w: %s: HTTP %d: %s",
			ErrUnavailable, path, response.StatusCode, truncate(strings.TrimSpace(string(raw))))
	}
}

// truncate bounds a quoted response body, so an HTML error page cannot fill the log.
func truncate(message string) string {
	const limit = 200
	if len(message) > limit {
		return message[:limit] + "… (truncated)"
	}
	return message
}
