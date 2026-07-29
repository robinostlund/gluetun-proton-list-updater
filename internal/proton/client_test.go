package proton

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// memoryStore is a SessionStore that lets tests start from an authenticated
// state, so the SRP handshake does not have to be simulated.
type memoryStore struct {
	session Session
	saved   Session
}

func (s *memoryStore) Load() (Session, error)     { return s.session, nil }
func (s *memoryStore) Save(session Session) error { s.saved = session; return nil }
func (s *memoryStore) Clear() error               { s.session = Session{}; return nil }

func validSession() Session {
	return Session{
		UID:          "uid-1234567890",
		AccessToken:  "access",
		RefreshToken: "refresh",
		Scopes:       []string{"self", "vpn"},
		CreatedAt:    time.Now(),
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestClient(t *testing.T, store SessionStore, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := New(Options{
		BaseURL:      server.URL,
		AppVersion:   "linux-vpn-cli@4.15.2",
		UserAgent:    "test",
		Username:     "user@example.com",
		Password:     "secret",
		SessionStore: store,
		Logger:       quietLogger(),
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, server
}

func TestLogicalsSendsProtonHeadersAndCompletenessParameters(t *testing.T) {
	t.Parallel()

	var path, appVersion, uid, authorization string
	client, _ := newTestClient(t, &memoryStore{session: validSession()},
		func(w http.ResponseWriter, r *http.Request) {
			path = r.URL.RequestURI()
			appVersion = r.Header.Get("x-pm-appversion")
			uid = r.Header.Get("x-pm-uid")
			authorization = r.Header.Get("Authorization")
			_, _ = io.WriteString(w, `{"Code":1000,"LogicalServers":[
				{"ID":"a","Name":"SE#1","ExitCountry":"SE","Load":11,"Status":1,"Tier":2,
				 "Servers":[{"EntryIP":"1.2.3.4","ExitIP":"5.6.7.8","Domain":"se-01.protonvpn.net","Status":1}]}
			]}`)
		})

	servers, _, err := client.Logicals(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("Logicals: %v", err)
	}
	if len(servers) != 1 || servers[0].Load != 11 {
		t.Fatalf("unexpected servers: %+v", servers)
	}

	// SecureCoreFilter=all is what makes Proton return the complete list;
	// without it Secure Core logicals are silently omitted.
	for _, want := range []string{"/vpn/v1/logicals", "SecureCoreFilter=all", "WithState=true", "WithIpV6=1"} {
		if !contains(path, want) {
			t.Errorf("request %q is missing %q", path, want)
		}
	}
	if appVersion == "" {
		t.Error("x-pm-appversion must be sent or Proton answers 400")
	}
	if uid == "" || authorization != "Bearer access" {
		t.Errorf("session headers missing: uid=%q authorization=%q", uid, authorization)
	}
}

func TestLogicalsIfModifiedSince(t *testing.T) {
	t.Parallel()

	var sent string
	client, _ := newTestClient(t, &memoryStore{session: validSession()},
		func(w http.ResponseWriter, r *http.Request) {
			sent = r.Header.Get("If-Modified-Since")
			w.WriteHeader(http.StatusNotModified)
		})

	since := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	_, _, err := client.Logicals(context.Background(), since)
	if !errors.Is(err, ErrNotModified) {
		t.Fatalf("err = %v, want ErrNotModified", err)
	}
	if sent == "" {
		t.Error("If-Modified-Since should have been sent")
	}
}

// An empty-but-successful response must never be allowed to replace a good
// server list.
func TestLogicalsRejectsEmptyList(t *testing.T) {
	t.Parallel()

	client, _ := newTestClient(t, &memoryStore{session: validSession()},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"Code":1000,"LogicalServers":[]}`)
		})

	if _, _, err := client.Logicals(context.Background(), time.Time{}); err == nil {
		t.Fatal("expected an error for an empty server list")
	}
}

func TestLoadsParsesResponse(t *testing.T) {
	t.Parallel()

	client, _ := newTestClient(t, &memoryStore{session: validSession()},
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/vpn/v1/loads" {
				t.Errorf("unexpected path %q", r.URL.Path)
			}
			_, _ = io.WriteString(w, `{"Code":1000,"LogicalServers":[{"ID":"a","Load":42,"Score":1.25,"Status":1}]}`)
		})

	loads, err := client.Loads(context.Background())
	if err != nil {
		t.Fatalf("Loads: %v", err)
	}
	if len(loads) != 1 || loads[0].Load != 42 || loads[0].Score != 1.25 {
		t.Errorf("unexpected loads: %+v", loads)
	}
}

// A 401 means the access token expired; the client must refresh and retry
// without the caller noticing.
func TestExpiredTokenIsRefreshedTransparently(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	store := &memoryStore{session: validSession()}
	client, _ := newTestClient(t, store, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/refresh":
			_, _ = io.WriteString(w, `{"Code":1000,"AccessToken":"new-access","RefreshToken":"new-refresh","Scopes":["vpn"]}`)
		case requests.Add(1) == 1:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"Code":401,"Error":"Invalid access token"}`)
		default:
			if got := r.Header.Get("Authorization"); got != "Bearer new-access" {
				t.Errorf("retry used %q, want the refreshed token", got)
			}
			_, _ = io.WriteString(w, `{"Code":1000,"LogicalServers":[{"ID":"a","Load":1,"Status":1}]}`)
		}
	})

	if _, err := client.Loads(context.Background()); err != nil {
		t.Fatalf("Loads: %v", err)
	}
	if store.saved.AccessToken != "new-access" {
		t.Errorf("refreshed session was not persisted: %+v", store.saved)
	}
}

// Rate limits must be retried, honouring Retry-After, rather than surfaced as a
// hard failure.
func TestRateLimitIsRetried(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	client, _ := newTestClient(t, &memoryStore{session: validSession()},
		func(w http.ResponseWriter, r *http.Request) {
			if attempts.Add(1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"Code":429,"Error":"Too many requests"}`)
				return
			}
			_, _ = io.WriteString(w, `{"Code":1000,"LogicalServers":[{"ID":"a","Load":1,"Status":1}]}`)
		})

	if _, err := client.Loads(context.Background()); err != nil {
		t.Fatalf("Loads: %v", err)
	}
	if attempts.Load() != 2 {
		t.Errorf("attempts = %d, want 2", attempts.Load())
	}
}

func TestRetryGivesUpAndReportsTheError(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	client, _ := newTestClient(t, &memoryStore{session: validSession()},
		func(w http.ResponseWriter, r *http.Request) {
			attempts.Add(1)
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"Code":503,"Error":"Unavailable"}`)
		})

	_, err := client.Loads(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if attempts.Load() != maxTransientAttempts {
		t.Errorf("attempts = %d, want %d", attempts.Load(), maxTransientAttempts)
	}
}

// A wrong password must be reported distinctly so the caller stops retrying.
func TestInvalidCredentialsAreDistinct(t *testing.T) {
	t.Parallel()

	client, _ := newTestClient(t, &memoryStore{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/info":
			// Enough for the client to reach the /auth call; SRP itself is
			// exercised against Proton's real modulus, not here.
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"Code":8002,"Error":"Incorrect login credentials"}`)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	})

	_, err := client.Loads(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 8002 {
		t.Errorf("err = %v, want a Proton API error with code 8002", err)
	}
}

func TestAPIErrorRetryable(t *testing.T) {
	t.Parallel()

	retryable := []int{408, 429, 502, 503, 504}
	for _, status := range retryable {
		if !(&APIError{HTTPStatus: status}).Retryable() {
			t.Errorf("HTTP %d should be retryable", status)
		}
	}
	for _, status := range []int{400, 401, 403, 404, 422} {
		if (&APIError{HTTPStatus: status}).Retryable() {
			t.Errorf("HTTP %d should not be retryable", status)
		}
	}
}

func TestRetryAfterParsing(t *testing.T) {
	t.Parallel()

	header := http.Header{}
	header.Set("Retry-After", "12")
	if got := retryAfter(header); got != 12*time.Second {
		t.Errorf("retryAfter = %s, want 12s", got)
	}

	header.Set("Retry-After", "not a number")
	if got := retryAfter(header); got != retryAfterAbsent {
		t.Errorf("retryAfter = %s, want absent for an unparseable value", got)
	}

	// A missing header must be distinguishable from "wait zero seconds", so an
	// explicit Retry-After: 0 means retry immediately rather than back off.
	if got := retryAfter(http.Header{}); got != retryAfterAbsent {
		t.Errorf("retryAfter with no header = %s, want absent", got)
	}
}

func TestSessionRestoredFromStore(t *testing.T) {
	t.Parallel()

	client, _ := newTestClient(t, &memoryStore{session: validSession()},
		func(w http.ResponseWriter, r *http.Request) {})

	if !client.LoggedIn() {
		t.Error("a stored session should be restored on construction")
	}
	// The UID must never be logged in full.
	if uid := client.SessionUID(); uid == "uid-1234567890" {
		t.Errorf("SessionUID should be redacted, got %q", uid)
	}
}

func TestNewRequiresCredentials(t *testing.T) {
	t.Parallel()

	if _, err := New(Options{Username: "user"}); err == nil {
		t.Error("expected an error without a password")
	}
	if _, err := New(Options{Password: "pass"}); err == nil {
		t.Error("expected an error without a username")
	}
}

func TestSessionHasVPNScope(t *testing.T) {
	t.Parallel()

	if !(Session{Scopes: []string{"self", "vpn"}}).HasVPNScope() {
		t.Error("vpn scope should be detected")
	}
	// A session stuck at the two-factor step has no vpn scope, which is how the
	// client knows to finish the login.
	if (Session{Scopes: []string{"self"}}).HasVPNScope() {
		t.Error("a session without the vpn scope must not claim it has one")
	}
}

func TestRedactPath(t *testing.T) {
	t.Parallel()
	if got := redactPath("/vpn/v1/logicals?SecureCoreFilter=all"); got != "/vpn/v1/logicals" {
		t.Errorf("redactPath = %q", got)
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

// The account's tier decides which servers are usable at all, so reading it
// correctly matters more than it looks.
func TestAccountInfo(t *testing.T) {
	t.Parallel()

	client, _ := newTestClient(t, &memoryStore{session: validSession()},
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/vpn/v2" {
				t.Errorf("unexpected path %q", r.URL.Path)
			}
			_, _ = io.WriteString(w, `{"Code":1000,"VPN":{"Status":1,"PlanName":"vpn2022",
				"PlanTitle":"VPN Plus","MaxTier":2,"MaxConnect":10,"GroupID":"g"},
				"Delinquent":0,"Subscribed":1}`)
		})

	info, err := client.Account(context.Background())
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	switch {
	case info.Tier != 2:
		t.Errorf("Tier = %d, want 2", info.Tier)
	case info.PlanTitle != "VPN Plus":
		t.Errorf("PlanTitle = %q", info.PlanTitle)
	case info.MaxConnections != 10:
		t.Errorf("MaxConnections = %d, want 10", info.MaxConnections)
	case info.Free():
		t.Error("tier 2 is not free")
	}
}

func TestAccountInfoFreeTier(t *testing.T) {
	t.Parallel()

	client, _ := newTestClient(t, &memoryStore{session: validSession()},
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"Code":1000,"VPN":{"Status":1,"PlanName":"free",
				"PlanTitle":"VPN Free","MaxTier":0,"MaxConnect":1},"Delinquent":1}`)
		})

	info, err := client.Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Free() {
		t.Error("tier 0 is the free tier")
	}
	// Delinquency is surfaced because it causes refusals that look like server
	// faults.
	if info.Delinquent == 0 {
		t.Error("Delinquent should be reported")
	}
}
