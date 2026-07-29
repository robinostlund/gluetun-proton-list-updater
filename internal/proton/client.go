// Package proton is a small, dependency-light client for the parts of the
// Proton API this tool needs: SRP login (with TOTP two-factor), the logical
// server list and the cheap server-load endpoint.
//
// Proton's server list has required authentication since 2025 - an
// unauthenticated /vpn/v1/logicals request answers 401 - so the SRP flow is
// mandatory rather than an optional extra.
package proton

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// Endpoints. SecureCoreFilter=all is essential: without it Proton silently
// omits every Secure Core logical server, which is the usual reason a
// hand-rolled fetcher ends up with an incomplete list. WithState=true is what
// Proton's own clients send. WithIpV6=1 adds EntryIPv6 to physical servers.
const (
	pathAuthInfo     = "/auth/info"
	pathAuth         = "/auth"
	pathAuth2FA      = "/auth/2fa"
	pathAuthRefresh  = "/auth/refresh"
	pathLogicals     = "/vpn/v1/logicals?SecureCoreFilter=all&WithState=true&WithIpV6=1"
	pathAccount      = "/vpn/v2"
	pathLoads        = "/vpn/v1/loads"
	protonSuccessAPI = 1000
)

// Errors callers are expected to branch on.
var (
	// ErrTOTPRequired means the account has two-factor authentication enabled
	// and no code was available. Supply PROTON_TOTP_SECRET or submit a code
	// from the dashboard.
	ErrTOTPRequired = errors.New("proton: two-factor code required")
	// ErrInvalidCredentials means the username or password was rejected.
	// Retrying will not help.
	ErrInvalidCredentials = errors.New("proton: invalid credentials")
	// ErrNotModified is returned by Logicals when the server list has not
	// changed since the supplied timestamp.
	ErrNotModified = errors.New("proton: server list not modified")
)

// CodeProvider supplies a TOTP code on demand. Implementations either compute
// it from a shared secret or wait for a human to type it into the dashboard.
type CodeProvider interface {
	// Code returns a six-digit TOTP code, blocking until one is available or
	// ctx is done. It must return ErrTOTPRequired when it cannot provide one.
	Code(ctx context.Context) (code string, err error)
}

// Options configures a Client.
type Options struct {
	BaseURL      string
	AppVersion   string
	UserAgent    string
	Timeout      time.Duration
	Username     string
	Password     string
	CodeProvider CodeProvider
	// SessionStore persists tokens between restarts so the tool does not
	// re-authenticate (and risk Proton's rate limits) on every container
	// restart. Optional.
	SessionStore SessionStore
	Logger       *slog.Logger
	// HTTPClient overrides the default client. Used by tests.
	HTTPClient *http.Client
}

// Client talks to the Proton API. It is safe for concurrent use.
type Client struct {
	baseURL    string
	appVersion string
	userAgent  string
	username   string
	password   string
	codes      CodeProvider
	store      SessionStore
	logger     *slog.Logger
	httpClient *http.Client

	session *sessionHolder
}

// New builds a Client and restores any persisted session.
func New(opts Options) (client *Client, err error) {
	if opts.Username == "" || opts.Password == "" {
		return nil, errors.New("proton: username and password are required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		httpClient = &http.Client{
			Timeout: timeout,
			// Proton's auth flow is token based, never cookie based here, so
			// redirects carrying credentials are not a concern; the default
			// redirect policy is fine.
		}
	}

	client = &Client{
		baseURL:    opts.BaseURL,
		appVersion: opts.AppVersion,
		userAgent:  opts.UserAgent,
		username:   opts.Username,
		password:   opts.Password,
		codes:      opts.CodeProvider,
		store:      opts.SessionStore,
		logger:     logger,
		httpClient: httpClient,
		session:    &sessionHolder{},
	}

	if client.store != nil {
		restored, err := client.store.Load()
		switch {
		case err != nil:
			logger.Warn("could not restore proton session, will log in again", "error", err)
		case restored.valid():
			client.session.set(restored)
			logger.Info("restored proton session from disk", "uid", redactUID(restored.UID))
		}
	}
	return client, nil
}

// Logicals fetches the full logical server list.
//
// ifModifiedSince, when non-zero, is sent as an If-Modified-Since header;
// Proton then answers 304 and Logicals returns ErrNotModified, which lets a
// periodic refresh cost almost nothing when nothing changed.
func (c *Client) Logicals(ctx context.Context, ifModifiedSince time.Time) (
	servers []LogicalServer, lastModified time.Time, err error,
) {
	headers := http.Header{}
	if !ifModifiedSince.IsZero() {
		headers.Set("If-Modified-Since", ifModifiedSince.UTC().Format(http.TimeFormat))
	}

	var response logicalsResponse
	responseHeader, err := c.authenticatedRequest(ctx, http.MethodGet, pathLogicals, nil, headers, &response)
	if err != nil {
		return nil, time.Time{}, err
	}
	if response.Code != protonSuccessAPI {
		return nil, time.Time{}, fmt.Errorf("proton: logicals response code %d is not %d",
			response.Code, protonSuccessAPI)
	}
	if len(response.LogicalServers) == 0 {
		// Never let an empty-but-successful response wipe a good list.
		return nil, time.Time{}, errors.New("proton: logicals response contains no servers")
	}

	lastModified = parseLastModified(responseHeader)
	return response.LogicalServers, lastModified, nil
}

// Loads fetches only the utilisation figures for every logical server. The
// response is a few kilobytes instead of several megabytes, so it can be
// polled far more often than Logicals.
func (c *Client) Loads(ctx context.Context) (loads []ServerLoad, err error) {
	var response loadsResponse
	_, err = c.authenticatedRequest(ctx, http.MethodGet, pathLoads, nil, nil, &response)
	if err != nil {
		return nil, err
	}
	if response.Code != protonSuccessAPI {
		return nil, fmt.Errorf("proton: loads response code %d is not %d",
			response.Code, protonSuccessAPI)
	}
	if len(response.LogicalServers) == 0 {
		return nil, errors.New("proton: loads response contains no servers")
	}
	return response.LogicalServers, nil
}

// Account reports what Proton says about the signed-in account, most importantly
// the highest server tier it may connect to.
func (c *Client) Account(ctx context.Context) (info AccountInfo, err error) {
	var response accountResponse
	if _, err := c.authenticatedRequest(ctx, http.MethodGet, pathAccount, nil, nil, &response); err != nil {
		return AccountInfo{}, err
	}
	if response.Code != protonSuccessAPI {
		return AccountInfo{}, fmt.Errorf("proton: account response code %d is not %d",
			response.Code, protonSuccessAPI)
	}
	return AccountInfo{
		Tier:           response.VPN.MaxTier,
		PlanName:       response.VPN.PlanName,
		PlanTitle:      response.VPN.PlanTitle,
		MaxConnections: response.VPN.MaxConnect,
		Status:         response.VPN.Status,
		Delinquent:     response.Delinquent,
	}, nil
}

// SessionUID returns the current session identifier, redacted for logging. It
// is empty when not logged in.
func (c *Client) SessionUID() string { return redactUID(c.session.get().UID) }

// LoggedIn reports whether a usable session is held.
func (c *Client) LoggedIn() bool { return c.session.get().valid() }

// maxTransientAttempts bounds retries of Proton failures that could clear up on
// their own (rate limits, gateway hiccups).
const maxTransientAttempts = 3

// authenticatedRequest performs a request with the current session, logging in
// or refreshing tokens as needed.
//
// It handles the three ways a Proton request goes wrong without the caller
// caring: an expired access token (refresh and retry), a rate limit or gateway
// error (wait and retry), and a dead session (log in again).
func (c *Client) authenticatedRequest(ctx context.Context, method, path string,
	body any, headers http.Header, out any,
) (responseHeader http.Header, err error) {
	for attempt := 1; ; attempt++ {
		responseHeader, err = c.attempt(ctx, method, path, body, headers, out)
		if err == nil || errors.Is(err, ErrNotModified) {
			return responseHeader, err
		}

		var apiErr *APIError
		if attempt >= maxTransientAttempts || !errors.As(err, &apiErr) || !apiErr.Retryable() {
			return responseHeader, err
		}

		// Honour Retry-After when Proton sends it; otherwise back off
		// exponentially so a struggling API is not hammered.
		wait := apiErr.RetryAfter
		if wait < 0 {
			wait = time.Duration(attempt) * 2 * time.Second
		}
		c.logger.Warn("proton request failed, retrying",
			"path", redactPath(path), "attempt", attempt, "wait", wait, "error", err)

		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return responseHeader, ctx.Err()
		}
	}
}

// attempt performs one request, transparently refreshing or re-establishing the
// session when the access token is rejected.
func (c *Client) attempt(ctx context.Context, method, path string,
	body any, headers http.Header, out any,
) (responseHeader http.Header, err error) {
	if err := c.ensureSession(ctx); err != nil {
		return nil, err
	}

	responseHeader, status, err := c.do(ctx, method, path, body, headers, c.session.get(), out)
	if err == nil {
		return responseHeader, nil
	}

	switch {
	case status == http.StatusNotModified:
		return responseHeader, ErrNotModified
	case status == http.StatusUnauthorized:
		// Access token expired: refresh and retry exactly once. If the refresh
		// token is dead too, fall back to a full login.
		c.logger.Debug("proton access token rejected, refreshing session")
		if refreshErr := c.refresh(ctx); refreshErr != nil {
			c.logger.Debug("proton refresh failed, logging in again", "error", refreshErr)
			c.session.clear()
			if loginErr := c.login(ctx); loginErr != nil {
				return nil, loginErr
			}
		}
		responseHeader, status, err = c.do(ctx, method, path, body, headers, c.session.get(), out)
		if status == http.StatusNotModified {
			return responseHeader, ErrNotModified
		}
		return responseHeader, err
	default:
		return responseHeader, err
	}
}

// do performs a single HTTP request, decoding the body into out on success.
// It returns the HTTP status code so callers can branch on it even when err is
// non-nil.
func (c *Client) do(ctx context.Context, method, path string, body any,
	headers http.Header, session Session, out any,
) (responseHeader http.Header, status int, err error) {
	var bodyReader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("encoding request body: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("creating request: %w", err)
	}

	request.Header.Set("x-pm-appversion", c.appVersion)
	request.Header.Set("User-Agent", c.userAgent)
	request.Header.Set("Accept", "application/vnd.protonmail.v1+json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if session.UID != "" {
		request.Header.Set("x-pm-uid", session.UID)
	}
	if session.AccessToken != "" {
		request.Header.Set("Authorization", "Bearer "+session.AccessToken)
	}
	for key, values := range headers {
		for _, value := range values {
			request.Header.Set(key, value)
		}
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("%s %s: %w", method, redactPath(path), err)
	}
	defer func() {
		// Draining lets the connection be reused; the body is small except for
		// logicals, which we decode in full anyway.
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}()

	status = response.StatusCode
	responseHeader = response.Header

	if status == http.StatusNotModified {
		return responseHeader, status, errNotModifiedSentinel
	}
	if status < 200 || status >= 300 {
		return responseHeader, status, c.apiError(response)
	}
	if out != nil {
		if err := json.NewDecoder(response.Body).Decode(out); err != nil {
			return responseHeader, status, fmt.Errorf("decoding %s response: %w", redactPath(path), err)
		}
	}
	return responseHeader, status, nil
}

// errNotModifiedSentinel keeps do's contract simple: any non-2xx is an error.
// authenticatedRequest translates it into ErrNotModified.
var errNotModifiedSentinel = errors.New("not modified")

// apiError turns a Proton error body into a Go error, preserving Proton's
// numeric code because it carries the real reason (8002 = bad password, and so
// on).
func (c *Client) apiError(response *http.Response) error {
	var payload struct {
		Code    int               `json:"Code"`
		Error   string            `json:"Error"`
		Details map[string]any    `json:"Details"`
		Errors  map[string]string `json:"Errors"`
	}
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	_ = json.Unmarshal(raw, &payload)

	if payload.Error == "" {
		return &APIError{
			HTTPStatus: response.StatusCode,
			Message:    string(raw),
			RetryAfter: retryAfter(response.Header),
		}
	}
	return &APIError{
		HTTPStatus: response.StatusCode,
		Code:       payload.Code,
		Message:    payload.Error,
		RetryAfter: retryAfter(response.Header),
	}
}

// APIError is a structured Proton API failure.
type APIError struct {
	HTTPStatus int
	Code       int
	Message    string
	// RetryAfter is how long Proton asked us to wait. It is negative when
	// Proton sent no Retry-After header, which lets a caller distinguish
	// "wait zero seconds" from "no guidance given".
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("proton API: HTTP %d: %s (code %d)", e.HTTPStatus, e.Message, e.Code)
	}
	return fmt.Sprintf("proton API: HTTP %d: %s", e.HTTPStatus, e.Message)
}

// Retryable reports whether waiting and trying again could succeed.
func (e *APIError) Retryable() bool {
	switch e.HTTPStatus {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// retryAfterAbsent is returned when Proton gave no Retry-After guidance.
const retryAfterAbsent = -1

func retryAfter(header http.Header) time.Duration {
	value := header.Get("Retry-After")
	if value == "" {
		return retryAfterAbsent
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if until := time.Until(when); until > 0 {
			return until
		}
		return 0
	}
	return retryAfterAbsent
}

func parseLastModified(header http.Header) time.Time {
	if header == nil {
		return time.Time{}
	}
	if when, err := http.ParseTime(header.Get("Last-Modified")); err == nil {
		return when
	}
	return time.Time{}
}

// redactPath keeps query strings out of logs; they are harmless today but this
// removes the whole class of accidental leak.
func redactPath(path string) string {
	for i := range path {
		if path[i] == '?' {
			return path[:i]
		}
	}
	return path
}

func redactUID(uid string) string {
	const keep = 6
	if len(uid) <= keep {
		return "…"
	}
	return uid[:keep] + "…"
}
