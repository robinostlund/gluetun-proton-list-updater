package qbittorrent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return New(Options{BaseURL: server.URL, APIKey: "qbt_" + strings.Repeat("x", 28),
		HTTPClient: server.Client()})
}

// The bearer header is the whole contract with qBittorrent: it is what authenticates
// the request and what makes it exempt from CSRF protection, so no Referer or Origin
// handling is needed. Getting the scheme or the header name wrong fails as a bare 401.
func TestTheAPIKeyIsSentAsABearerToken(t *testing.T) {
	t.Parallel()

	var authorization, accept, path string
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		accept = r.Header.Get("Accept")
		path = r.URL.Path
		_, _ = w.Write([]byte(`{"dl_info_speed":0,"up_info_speed":0}`))
	})

	if _, err := client.Transfer(context.Background()); err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if want := "Bearer qbt_" + strings.Repeat("x", 28); authorization != want {
		t.Errorf("Authorization = %q, want %q", authorization, want)
	}
	if accept != "application/json" {
		t.Errorf("Accept = %q, want application/json", accept)
	}
	if path != "/api/v2/transfer/info" {
		t.Errorf("path = %q, want /api/v2/transfer/info", path)
	}
}

// The field names come from qBittorrent's own response, so they are pinned against a
// verbatim body captured from a real v5.2.2.
func TestTransferDecodesARealResponse(t *testing.T) {
	t.Parallel()

	const body = `{"connection_status":"connected","dht_nodes":321,` +
		`"dl_info_data":12884901888,"dl_info_speed":13107200,"dl_rate_limit":0,` +
		`"last_external_address_v4":"","last_external_address_v6":"",` +
		`"up_info_data":2147483648,"up_info_speed":1153433,"up_rate_limit":5242880}`

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})

	transfer, err := client.Transfer(context.Background())
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	for _, field := range []struct {
		name string
		got  uint64
		want uint64
	}{
		{"DownloadSpeed", transfer.DownloadSpeed, 13107200},
		{"UploadSpeed", transfer.UploadSpeed, 1153433},
		{"DownloadTotal", transfer.DownloadTotal, 12884901888},
		{"UploadTotal", transfer.UploadTotal, 2147483648},
		{"DownloadLimit", transfer.DownloadLimit, 0},
		{"UploadLimit", transfer.UploadLimit, 5242880},
	} {
		if field.got != field.want {
			t.Errorf("%s = %d, want %d", field.name, field.got, field.want)
		}
	}
	if transfer.ConnectionStatus != "connected" {
		t.Errorf("ConnectionStatus = %q, want connected", transfer.ConnectionStatus)
	}
}

// A refused key and a refused host both answer 401, and they need completely
// different fixes, so the error has to point at both possibilities.
func TestARefusedKeyIsDistinguishableAndActionable(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Unauthorized", status)
		})
		_, err := client.Transfer(context.Background())
		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("HTTP %d gave %v, want ErrUnauthorized", status, err)
			continue
		}
		for _, want := range []string{"QBITTORRENT_API_KEY", "host-header"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("HTTP %d error %q should mention %q", status, err, want)
			}
		}
	}
}

// Anything else is "no information", never "idle": the engine must be able to tell
// the two apart, because assuming idle is what breaks a transfer.
func TestOtherFailuresAreUnavailableNotUnauthorized(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	_, err := client.Transfer(context.Background())
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable", err)
	}
	if errors.Is(err, ErrUnauthorized) {
		t.Error("a 500 must not be reported as an authentication problem")
	}
}

// A reverse proxy in front of qBittorrent can answer with an HTML page. Quoting it
// whole would fill the log and the dashboard.
func TestLongErrorBodiesAreTruncated(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, strings.Repeat("<html>padding</html>", 500), http.StatusBadGateway)
	})
	_, err := client.Transfer(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) > 400 {
		t.Errorf("error is %d characters; the body was not truncated", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Error("a truncated body should say so")
	}
}

// Malformed JSON is a failure, not an empty reading: silently treating it as zero
// rates would let a switch through during a transfer.
func TestMalformedJSONIsAnError(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	})
	if _, err := client.Transfer(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable", err)
	}
}

// The format check is advisory but useful: it turns a pasted password or a truncated
// key into a warning at startup rather than a puzzling 401 later.
func TestAPIKeyFormatCheck(t *testing.T) {
	t.Parallel()

	valid := "qbt_" + strings.Repeat("a", 28)
	for _, testCase := range []struct {
		key  string
		want bool
	}{
		{valid, true},
		{"", false},
		{"qbt_tooshort", false},
		{strings.Repeat("a", 32), false},          // right length, no prefix
		{"qbt_" + strings.Repeat("a", 29), false}, // one too long
		{"my-qbittorrent-password", false},
	} {
		if got := APIKeyLooksValid(testCase.key); got != testCase.want {
			t.Errorf("APIKeyLooksValid(%q) = %v, want %v", testCase.key, got, testCase.want)
		}
	}
}

func TestVersionReadsThePlainTextBody(t *testing.T) {
	t.Parallel()

	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/app/version" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte("v5.2.2\n"))
	})
	version, err := client.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if version != "v5.2.2" {
		t.Errorf("version = %q, want v5.2.2", version)
	}
}

// A trailing slash on the configured URL must not produce a double slash in the path,
// which some reverse proxies reject.
func TestATrailingSlashInTheURLIsHarmless(t *testing.T) {
	t.Parallel()

	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := New(Options{BaseURL: server.URL + "/", HTTPClient: server.Client()})
	if _, err := client.Transfer(context.Background()); err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if path != "/api/v2/transfer/info" {
		t.Errorf("path = %q, want no doubled slash", path)
	}
}
