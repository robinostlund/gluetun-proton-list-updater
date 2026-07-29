package serversfile

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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

func legacyPaths(t *testing.T) (paths Paths, legacy string) {
	t.Helper()
	dir := t.TempDir()
	legacy = filepath.Join(dir, "servers.json")
	return Paths{Directory: filepath.Join(dir, "servers"), LegacyFile: legacy}, legacy
}

func TestWriteProducesGluetunSchema(t *testing.T) {
	t.Parallel()
	paths, path := legacyPaths(t)
	now := time.Unix(1_700_000_000, 0)

	result, err := Write(sampleServers(), Options{
		Paths: paths, Layout: LayoutLegacy, SchemaVersion: 4, Now: now,
	})
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
	paths, path := legacyPaths(t)

	existing := `{
	  "version": 1,
	  "mullvad": {"version": 9, "timestamp": 42, "servers": [{"vpn": "wireguard"}]},
	  "protonvpn": {"version": 4, "timestamp": 1, "servers": []}
	}`
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Write(sampleServers(), Options{
		Paths: paths, Layout: LayoutLegacy, SchemaVersion: 4, PreserveOtherProviders: true,
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
	paths, path := legacyPaths(t)
	if err := os.WriteFile(path, []byte(`{"version":1,"mullvad":{"version":9,"timestamp":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := Write(sampleServers(), Options{Paths: paths, Layout: LayoutLegacy, SchemaVersion: 4}); err != nil {
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
	paths, path := legacyPaths(t)

	if _, err := Write(nil, Options{Paths: paths, SchemaVersion: 4}); err == nil {
		t.Fatal("expected an error for an empty server list")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("no file should have been created")
	}
}

func TestWriteRefusesZeroSchemaVersion(t *testing.T) {
	t.Parallel()
	paths, _ := legacyPaths(t)
	if _, err := Write(sampleServers(), Options{Paths: paths}); err == nil {
		t.Fatal("expected an error for a zero schema version")
	}
}

// The schema version must be read back from whatever Gluetun wrote, because it
// changes between Gluetun releases.
func TestDetectSchemaVersion(t *testing.T) {
	t.Parallel()

	t.Run("from the per-provider file", func(t *testing.T) {
		dir := t.TempDir()
		serversDir := filepath.Join(dir, "servers")
		if err := os.MkdirAll(serversDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(serversDir, "protonvpn.json"),
			[]byte(`{"version":7,"timestamp":1,"servers":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}

		version, source, err := DetectSchemaVersion(Paths{
			Directory: serversDir, LegacyFile: filepath.Join(dir, "servers.json"),
		})
		if err != nil {
			t.Fatalf("DetectSchemaVersion: %v", err)
		}
		if version != 7 {
			t.Errorf("version = %d, want 7", version)
		}
		if source == "" {
			t.Error("source should name the file it came from")
		}
	})

	t.Run("from the legacy file", func(t *testing.T) {
		dir := t.TempDir()
		legacy := filepath.Join(dir, "servers.json")
		if err := os.WriteFile(legacy,
			[]byte(`{"version":1,"protonvpn":{"version":5,"timestamp":1}}`), 0o644); err != nil {
			t.Fatal(err)
		}

		version, _, err := DetectSchemaVersion(Paths{
			Directory: filepath.Join(dir, "servers"), LegacyFile: legacy,
		})
		if err != nil {
			t.Fatalf("DetectSchemaVersion: %v", err)
		}
		if version != 5 {
			t.Errorf("version = %d, want 5", version)
		}
	})

	// The per-provider file wins: on a migrated Gluetun the legacy file may still
	// exist but be stale.
	t.Run("per-provider file takes precedence", func(t *testing.T) {
		dir := t.TempDir()
		serversDir := filepath.Join(dir, "servers")
		if err := os.MkdirAll(serversDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(serversDir, "protonvpn.json"),
			[]byte(`{"version":9,"timestamp":1,"servers":[]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		legacy := filepath.Join(dir, "servers.json")
		if err := os.WriteFile(legacy,
			[]byte(`{"version":1,"protonvpn":{"version":3,"timestamp":1}}`), 0o644); err != nil {
			t.Fatal(err)
		}

		version, _, err := DetectSchemaVersion(Paths{Directory: serversDir, LegacyFile: legacy})
		if err != nil {
			t.Fatalf("DetectSchemaVersion: %v", err)
		}
		if version != 9 {
			t.Errorf("version = %d, want 9 from the per-provider file", version)
		}
	})

	t.Run("nothing written yet", func(t *testing.T) {
		dir := t.TempDir()
		version, _, err := DetectSchemaVersion(Paths{
			Directory: filepath.Join(dir, "servers"), LegacyFile: filepath.Join(dir, "servers.json"),
		})
		if err != nil {
			t.Fatalf("DetectSchemaVersion: %v", err)
		}
		if version != 0 {
			t.Errorf("version = %d, want 0 when Gluetun has written nothing", version)
		}
	})
}

// Which layout Gluetun uses decides where the data must go. Getting this wrong
// means writing a file a current Gluetun never reads.
func TestDetectLayout(t *testing.T) {
	t.Parallel()

	t.Run("directory when a manifest exists", func(t *testing.T) {
		dir := t.TempDir()
		serversDir := filepath.Join(dir, "servers")
		if err := os.MkdirAll(serversDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(serversDir, "manifest.json"), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		// A legacy file left over from before a migration must not win.
		legacy := filepath.Join(dir, "servers.json")
		if err := os.WriteFile(legacy, []byte(`{"version":1}`), 0o644); err != nil {
			t.Fatal(err)
		}

		if got := DetectLayout(Paths{Directory: serversDir, LegacyFile: legacy}); got != LayoutDirectory {
			t.Errorf("layout = %q, want directory", got)
		}
	})

	t.Run("legacy when only the fat file exists", func(t *testing.T) {
		dir := t.TempDir()
		legacy := filepath.Join(dir, "servers.json")
		if err := os.WriteFile(legacy, []byte(`{"version":1}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := DetectLayout(Paths{Directory: filepath.Join(dir, "servers"), LegacyFile: legacy}); got != LayoutLegacy {
			t.Errorf("layout = %q, want legacy", got)
		}
	})

	t.Run("both when Gluetun has not run yet", func(t *testing.T) {
		dir := t.TempDir()
		got := DetectLayout(Paths{
			Directory: filepath.Join(dir, "servers"), LegacyFile: filepath.Join(dir, "servers.json"),
		})
		if got != LayoutBoth {
			t.Errorf("layout = %q, want both", got)
		}
	})
}

// Current Gluetun reads /gluetun/servers/protonvpn.json and ignores the legacy
// file entirely, so this is the path that matters most.
func TestWriteDirectoryLayout(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	paths := Paths{
		Directory:  filepath.Join(dir, "servers"),
		LegacyFile: filepath.Join(dir, "servers.json"),
	}

	result, err := Write(sampleServers(), Options{
		Paths: paths, Layout: LayoutDirectory, SchemaVersion: 4, Preferred: true,
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if result.Layout != LayoutDirectory {
		t.Errorf("layout = %q", result.Layout)
	}
	if len(result.Written) != 1 || result.Written[0] != paths.ProviderPath() {
		t.Errorf("written = %v, want just the per-provider file", result.Written)
	}
	// The legacy file must not be created: doing so on a migrated Gluetun would
	// resurrect a file it deliberately removed.
	if _, err := os.Stat(paths.LegacyFile); !os.IsNotExist(err) {
		t.Error("the legacy file should not be written in directory layout")
	}

	var section struct {
		Version   uint16   `json:"version"`
		Timestamp int64    `json:"timestamp"`
		Preferred bool     `json:"preferred"`
		Servers   []Server `json:"servers"`
	}
	readJSON(t, paths.ProviderPath(), &section)

	if section.Version != 4 {
		t.Errorf("version = %d, want 4", section.Version)
	}
	// preferred makes Gluetun use our list regardless of timestamps.
	if !section.Preferred {
		t.Error("preferred should be set")
	}
	if len(section.Servers) != 2 {
		t.Errorf("servers = %d, want 2", len(section.Servers))
	}
	// There is no top-level "version" key in a per-provider file.
	var raw map[string]json.RawMessage
	readJSON(t, paths.ProviderPath(), &raw)
	if _, present := raw["protonvpn"]; present {
		t.Error("a per-provider file must not be wrapped in a provider key")
	}
}

// On a fresh volume neither layout exists yet, so both are written and whichever
// Gluetun starts finds data it understands.
func TestWriteBothLayouts(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	paths := Paths{
		Directory:  filepath.Join(dir, "servers"),
		LegacyFile: filepath.Join(dir, "servers.json"),
	}

	result, err := Write(sampleServers(), Options{Paths: paths, SchemaVersion: 4, Preferred: true})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if result.Layout != LayoutBoth {
		t.Errorf("layout = %q, want both", result.Layout)
	}
	for _, path := range []string{paths.ProviderPath(), paths.LegacyFile} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was not written: %v", path, err)
		}
	}
}

func TestWritePreferredFlagIsOmittedWhenFalse(t *testing.T) {
	t.Parallel()

	paths, _ := legacyPaths(t)
	if _, err := Write(sampleServers(), Options{
		Paths: paths, Layout: LayoutLegacy, SchemaVersion: 4, Preferred: false,
	}); err != nil {
		t.Fatal(err)
	}

	// The top-level "version" is a number, so the file is decoded loosely and only
	// the provider section is inspected.
	var file map[string]json.RawMessage
	readJSON(t, paths.LegacyFile, &file)

	var section map[string]any
	if err := json.Unmarshal(file["protonvpn"], &section); err != nil {
		t.Fatal(err)
	}
	if _, present := section["preferred"]; present {
		t.Error("preferred should be omitted when false, matching Gluetun's own encoding")
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

// Regression test: a second run must not mistake its own output for Gluetun's.
//
// File existence alone cannot distinguish them, because this tool writes into the
// same locations. Getting this wrong meant a restart concluded that Gluetun kept
// server data on disk when it did not.
func TestHasGluetunDataIgnoresOurOwnWrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	paths := Paths{
		Directory:  filepath.Join(dir, "servers"),
		LegacyFile: filepath.Join(dir, "servers.json"),
	}

	if HasGluetunData(paths) {
		t.Error("nothing written yet, so there is no Gluetun data")
	}

	// Write exactly what this tool writes, to both layouts.
	if _, err := Write(sampleServers(), Options{
		Paths: paths, Layout: LayoutBoth, SchemaVersion: 4, Preferred: true,
	}); err != nil {
		t.Fatal(err)
	}
	if HasGluetunData(paths) {
		t.Error("our own files must not count as Gluetun's server data")
	}

	// A manifest is written only by Gluetun, so it is conclusive.
	if err := os.WriteFile(paths.ManifestPath(), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if !HasGluetunData(paths) {
		t.Error("a manifest means Gluetun keeps server data on disk")
	}
}

// The other signal: Gluetun writes every provider it knows, this tool writes only
// protonvpn.
func TestHasGluetunDataDetectsOtherProviders(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	paths := Paths{
		Directory:  filepath.Join(dir, "servers"),
		LegacyFile: filepath.Join(dir, "servers.json"),
	}

	if err := os.WriteFile(paths.LegacyFile,
		[]byte(`{"version":1,"protonvpn":{"version":4,"timestamp":1},"mullvad":{"version":9,"timestamp":1}}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	if !HasGluetunData(paths) {
		t.Error("a provider other than protonvpn can only have come from Gluetun")
	}
}

// A relative path writes into the working directory rather than Gluetun's volume,
// where it does nothing and is easy not to notice - a stray protonvpn.json once
// appeared in the source tree exactly this way.
func TestWriteRejectsRelativePaths(t *testing.T) {
	t.Parallel()

	_, err := Write(sampleServers(), Options{
		Paths:         Paths{Directory: "servers", LegacyFile: "servers.json"},
		SchemaVersion: 4,
	})
	if err == nil {
		t.Fatal("expected a relative path to be refused")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("error should explain the requirement, got %v", err)
	}

	if _, err := Write(sampleServers(), Options{SchemaVersion: 4}); err == nil {
		t.Error("expected an error when no path is configured at all")
	}
}
