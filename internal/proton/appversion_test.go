package proton

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

const unsupportedBody = `{"Code":5003,"Error":"This version of the app is no longer supported, please update to continue using the app","Details":{}}`

// newVersionTestClient builds a client whose server accepts only accepted as
// x-pm-appversion and answers 5003 to anything else.
func newVersionTestClient(t *testing.T, accepted string, resolver AppVersionResolver) (*Client, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("x-pm-appversion") != accepted {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(unsupportedBody))
			return
		}
		_, _ = w.Write([]byte(`{"Code":1000,"LogicalServers":[{"ID":"a","Load":10}]}`))
	}))
	t.Cleanup(server.Close)

	client, err := New(Options{
		BaseURL:           server.URL,
		AppVersion:        "linux-vpn-cli@4.15.2",
		UserAgent:         "ProtonVPN/4.15.2 (Linux)",
		Username:          "user@example.com",
		Password:          "secret",
		SessionStore:      &memoryStore{session: validSession()},
		Logger:            quietLogger(),
		HTTPClient:        server.Client(),
		ResolveAppVersion: resolver,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, &requests
}

func TestUnsupportedAppVersionIsUpgradedAndRetried(t *testing.T) {
	t.Parallel()
	var lookups atomic.Int32
	resolver := func(context.Context) (string, error) {
		lookups.Add(1)
		return "4.19.0", nil
	}
	client, requests := newVersionTestClient(t, "linux-vpn-gui@4.19.0", resolver)

	if _, err := client.Loads(context.Background()); err != nil {
		t.Fatalf("Loads: %v", err)
	}
	if got := client.AppVersion(); got != "linux-vpn-gui@4.19.0" {
		t.Errorf("AppVersion = %q, want linux-vpn-gui@4.19.0", got)
	}
	if requests.Load() != 2 || lookups.Load() != 1 {
		t.Errorf("requests=%d lookups=%d, want 2 and 1", requests.Load(), lookups.Load())
	}

	// The upgraded version sticks: no further lookups or rejected requests.
	if _, err := client.Loads(context.Background()); err != nil {
		t.Fatalf("second Loads: %v", err)
	}
	if requests.Load() != 3 || lookups.Load() != 1 {
		t.Errorf("after second call requests=%d lookups=%d, want 3 and 1", requests.Load(), lookups.Load())
	}
}

func TestUnsupportedAppVersionWithoutResolverFails(t *testing.T) {
	t.Parallel()
	client, requests := newVersionTestClient(t, "linux-vpn-gui@4.19.0", nil)

	_, err := client.Loads(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != codeAppVersionUnsupported {
		t.Fatalf("err = %v, want a 5003 APIError", err)
	}
	if requests.Load() != 1 {
		t.Errorf("requests = %d, want 1 (5003 is not transient)", requests.Load())
	}
}

func TestUnsupportedAppVersionLookupIsRateLimited(t *testing.T) {
	t.Parallel()
	var lookups atomic.Int32
	resolver := func(context.Context) (string, error) {
		lookups.Add(1)
		return "", errors.New("github unavailable")
	}
	client, _ := newVersionTestClient(t, "linux-vpn-gui@4.19.0", resolver)

	for range 3 {
		if _, err := client.Loads(context.Background()); err == nil {
			t.Fatal("Loads succeeded with a rejected version")
		}
	}
	if lookups.Load() != 1 {
		t.Errorf("lookups = %d, want 1 within the cooldown", lookups.Load())
	}
}

func TestNewestStableTag(t *testing.T) {
	t.Parallel()
	tags := []string{"v4.9.7", "v4.19.0", "v4.18.8", "v5.0.0-beta1", "debian/4.20.0", "v4.10.2"}
	version, ok := newestStableTag(tags)
	if !ok || version != "4.19.0" {
		t.Errorf("newestStableTag = %q, %v; want 4.19.0, true", version, ok)
	}
	if _, ok := newestStableTag([]string{"nightly"}); ok {
		t.Error("newestStableTag found a version among non-release tags")
	}
}
