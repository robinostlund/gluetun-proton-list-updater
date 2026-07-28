package serversfile

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleServers() []Server {
	return []Server{
		{
			VPN: "wireguard", Country: "Sweden", City: "Stockholm",
			ServerName: "SE#2", Hostname: "se-02.protonvpn.net",
			WgPubKey: "key2", PortForward: true,
			IPs: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			VPN: "openvpn", Country: "Netherlands", City: "Amsterdam",
			ServerName: "NL#1", Hostname: "nl-01.protonvpn.net",
			TCP: true, UDP: true,
			IPs: []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		},
	}
}

func TestWriteProducesGluetunSchema(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "servers.json")
	now := time.Unix(1_700_000_000, 0)

	result, err := Write(sampleServers(), Options{Path: path, SchemaVersion: 4, Now: now})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if result.ServerCount != 2 {
		t.Errorf("ServerCount = %d, want 2", result.ServerCount)
	}

	var file struct {
		Version   uint16 `json:"version"`
		Protonvpn struct {
			Version   uint16   `json:"version"`
			Timestamp int64    `json:"timestamp"`
			Servers   []Server `json:"servers"`
		} `json:"protonvpn"`
	}
	readJSON(t, path, &file)

	if file.Version != topLevelSchemaVersion {
		t.Errorf("top-level version = %d, want %d", file.Version, topLevelSchemaVersion)
	}
	if file.Protonvpn.Version != 4 {
		t.Errorf("provider version = %d, want 4", file.Protonvpn.Version)
	}
	if file.Protonvpn.Timestamp != now.Unix() {
		t.Errorf("timestamp = %d, want %d", file.Protonvpn.Timestamp, now.Unix())
	}
	// Sorted by country: Netherlands must come before Sweden.
	if got := file.Protonvpn.Servers[0].Country; got != "Netherlands" {
		t.Errorf("first server country = %q, want Netherlands", got)
	}
}

// Gluetun reads the whole file, so an update must not destroy another
// provider's section.
func TestWritePreservesOtherProviders(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "servers.json")

	existing := `{
	  "version": 1,
	  "mullvad": {"version": 9, "timestamp": 42, "servers": [{"vpn": "wireguard"}]},
	  "protonvpn": {"version": 4, "timestamp": 1, "servers": []}
	}`
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Write(sampleServers(), Options{
		Path: path, SchemaVersion: 4, PreserveOtherProviders: true,
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(result.PreservedKeys) != 1 || result.PreservedKeys[0] != "mullvad" {
		t.Errorf("PreservedKeys = %v, want [mullvad]", result.PreservedKeys)
	}

	var file map[string]json.RawMessage
	readJSON(t, path, &file)
	if _, ok := file["mullvad"]; !ok {
		t.Error("mullvad section was lost")
	}
}

func TestWriteReplaceModeDropsOtherProviders(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "servers.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"mullvad":{"version":9,"timestamp":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Write(sampleServers(), Options{Path: path, SchemaVersion: 4}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var file map[string]json.RawMessage
	readJSON(t, path, &file)
	if _, ok := file["mullvad"]; ok {
		t.Error("mullvad section should have been replaced")
	}
}

// An empty list would leave Gluetun with nothing to connect to, which is worse
// than keeping a stale file.
func TestWriteRefusesEmptyList(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "servers.json")

	if _, err := Write(nil, Options{Path: path, SchemaVersion: 4}); err == nil {
		t.Fatal("expected an error for an empty server list")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("no file should have been created")
	}
}

func TestWriteRefusesZeroSchemaVersion(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "servers.json")
	if _, err := Write(sampleServers(), Options{Path: path}); err == nil {
		t.Fatal("expected an error for a zero schema version")
	}
}

// The schema version must be read back from whatever Gluetun wrote, since it
// changes between Gluetun releases.
func TestDetectSchemaVersion(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()

	tests := map[string]struct {
		content     string
		wantVersion uint16
		wantFound   bool
		wantErr     bool
	}{
		"present":         {content: `{"version":1,"protonvpn":{"version":7,"timestamp":1}}`, wantVersion: 7, wantFound: true},
		"provider absent": {content: `{"version":1,"mullvad":{"version":9}}`},
		"empty file":      {content: ``},
		"zero version":    {content: `{"version":1,"protonvpn":{"timestamp":1}}`},
		"invalid json":    {content: `{`, wantErr: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".json")
			if err := os.WriteFile(path, []byte(test.content), 0o644); err != nil {
				t.Fatal(err)
			}

			version, found, err := DetectSchemaVersion(path)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("DetectSchemaVersion: %v", err)
			}
			if found != test.wantFound || version != test.wantVersion {
				t.Errorf("got (%d, %v), want (%d, %v)", version, found, test.wantVersion, test.wantFound)
			}
		})
	}
}

func TestDetectSchemaVersionMissingFile(t *testing.T) {
	t.Parallel()
	_, found, err := DetectSchemaVersion(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("DetectSchemaVersion: %v", err)
	}
	if found {
		t.Error("found should be false for a missing file")
	}
}

// Gluetun only accepts the exact field names of its own model, so a change to
// the struct tags must break a test rather than production.
func TestServerJSONFieldNames(t *testing.T) {
	t.Parallel()
	server := Server{
		VPN: "wireguard", Country: "Sweden", Region: "Europe", City: "Stockholm",
		ServerName: "SE#1", Hostname: "se-01.protonvpn.net", WgPubKey: "k",
		Free: true, Stream: true, SecureCore: true, Tor: true, PortForward: true,
		IPs: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
	}
	encoded, err := json.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}

	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{
		"vpn", "country", "region", "city", "server_name", "hostname",
		"wgpubkey", "free", "stream", "secure_core", "tor", "port_forward", "ips",
	} {
		if _, ok := fields[expected]; !ok {
			t.Errorf("field %q missing from encoded server: %s", expected, encoded)
		}
	}

	// False booleans must be omitted, exactly as Gluetun's own writer does.
	openvpn := Server{VPN: "openvpn", TCP: true, IPs: server.IPs}
	encoded, err = json.Marshal(openvpn)
	if err != nil {
		t.Fatal(err)
	}
	fields = map[string]any{}
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["udp"]; ok {
		t.Errorf("udp should be omitted when false: %s", encoded)
	}
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
}
