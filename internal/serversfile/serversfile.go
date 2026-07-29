// Package serversfile produces the server data Gluetun reads.
//
// Gluetun has two storage layouts, and which one is in use decides where the
// data has to go:
//
//   - Legacy (up to and including v3.41.1): one "fat" file, /gluetun/servers.json,
//     holding a schema version and one section per provider.
//   - Directory (current master, published as :latest): /gluetun/servers/ with a
//     manifest.json pointing at one file per provider, e.g.
//     /gluetun/servers/protonvpn.json.
//
// The distinction is not cosmetic. A Gluetun using the directory layout reads
// the legacy file *only* when manifest.json is absent, so writing just
// servers.json to a current Gluetun means the data is silently ignored - the
// tool looks like it is working while having no effect whatsoever.
//
// Three details decide whether the data is actually used:
//
//  1. The provider "version" must equal the version compiled into the running
//     Gluetun, or it logs "discarded because they have version X" and falls back
//     to its built-in list.
//  2. "preferred": true makes Gluetun use our servers regardless of timestamps.
//     Older versions ignore the unknown field harmlessly.
//  3. Failing that, the "timestamp" must beat Gluetun's built-in one, because
//     Gluetun otherwise merges by recency.
package serversfile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/atomicfile"
)

// Provider is the key Gluetun uses for ProtonVPN.
const Provider = "protonvpn"

// manifestFilename is the file whose presence identifies the directory layout.
const manifestFilename = "manifest.json"

// topLevelSchemaVersion is the legacy file's own "version" field. It has been 1
// for every release that supports a custom servers file.
const topLevelSchemaVersion = 1

// Layout identifies which storage layout a Gluetun instance uses.
type Layout string

const (
	// LayoutDirectory is /gluetun/servers/ with a manifest and per-provider files.
	LayoutDirectory Layout = "directory"
	// LayoutLegacy is the single /gluetun/servers.json file.
	LayoutLegacy Layout = "legacy"
	// LayoutBoth is used when neither exists yet, typically because Gluetun has
	// not started against a fresh volume. Writing both costs nothing and means
	// whichever Gluetun starts finds data it understands.
	LayoutBoth Layout = "both"
)

// Server mirrors Gluetun's models.Server. Field names, JSON tags and omitempty
// behaviour are deliberately identical to Gluetun's, so the file we write is
// comparable with one Gluetun produces itself.
type Server struct {
	VPN         string       `json:"vpn,omitempty"`
	Country     string       `json:"country,omitempty"`
	Region      string       `json:"region,omitempty"`
	City        string       `json:"city,omitempty"`
	ServerName  string       `json:"server_name,omitempty"`
	Hostname    string       `json:"hostname,omitempty"`
	TCP         bool         `json:"tcp,omitempty"`
	UDP         bool         `json:"udp,omitempty"`
	WgPubKey    string       `json:"wgpubkey,omitempty"`
	Free        bool         `json:"free,omitempty"`
	Stream      bool         `json:"stream,omitempty"`
	SecureCore  bool         `json:"secure_core,omitempty"`
	Tor         bool         `json:"tor,omitempty"`
	PortForward bool         `json:"port_forward,omitempty"`
	IPs         []netip.Addr `json:"ips,omitempty"`
}

// providerServers is the per-provider object, used as a section of the legacy
// file and as the whole of a per-provider file.
type providerServers struct {
	Version   uint16   `json:"version"`
	Timestamp int64    `json:"timestamp"`
	Preferred bool     `json:"preferred,omitempty"`
	Servers   []Server `json:"servers"`
}

// Paths locates both layouts.
type Paths struct {
	// Directory is Gluetun's servers directory, /gluetun/servers/ by default.
	Directory string
	// LegacyFile is Gluetun's legacy fat file, /gluetun/servers.json by default.
	LegacyFile string
}

// ManifestPath is the file whose presence means the directory layout is in use.
func (p Paths) ManifestPath() string { return filepath.Join(p.Directory, manifestFilename) }

// ProviderPath is where the per-provider file belongs in the directory layout.
func (p Paths) ProviderPath() string { return filepath.Join(p.Directory, Provider+".json") }

// DetectLayout works out which layout the running Gluetun uses, by looking for
// the artefacts it creates on startup.
func DetectLayout(paths Paths) (layout Layout) {
	if paths.Directory != "" && fileExists(paths.ManifestPath()) {
		return LayoutDirectory
	}
	if paths.LegacyFile != "" && fileExists(paths.LegacyFile) {
		return LayoutLegacy
	}
	return LayoutBoth
}

// HasGluetunData reports whether Gluetun itself has written server data.
//
// File existence alone cannot answer this, because our own writes create files in
// the very same places - which previously made a second run mistake its own
// output for Gluetun's. Two signals are used that our writes cannot forge:
//
//   - manifest.json, which only Gluetun ever writes.
//   - a provider section other than protonvpn in the legacy file, since Gluetun
//     writes every provider it knows and this tool only ever writes protonvpn
//     (plus any sections it preserved, which were Gluetun's to begin with).
//
// A running Gluetun with no data of its own is one that will ignore everything
// written here: it has STORAGE_SERVERS_ENABLED=no, or the /gluetun volume is not
// shared with this container.
func HasGluetunData(paths Paths) bool {
	if paths.Directory != "" && fileExists(paths.ManifestPath()) {
		return true
	}
	if paths.LegacyFile == "" {
		return false
	}

	existing, err := readRawFile(paths.LegacyFile)
	if err != nil {
		return false
	}
	for key := range existing {
		if key != "version" && key != Provider {
			return true
		}
	}
	return false
}

// DetectSchemaVersion reads the provider schema version from whatever Gluetun
// has already written. Gluetun writes its built-in version there on startup,
// which makes those files the most reliable source for the version we must
// match - a version hardcoded here would rot with every Gluetun release.
func DetectSchemaVersion(paths Paths) (version uint16, source string, err error) {
	// The per-provider file is checked first: on a Gluetun that has migrated, the
	// legacy file may still exist but be stale.
	if paths.Directory != "" {
		version, found, err := providerFileVersion(paths.ProviderPath())
		if err != nil {
			return 0, "", err
		}
		if found {
			return version, paths.ProviderPath(), nil
		}
	}
	if paths.LegacyFile != "" {
		version, found, err := legacyFileVersion(paths.LegacyFile)
		if err != nil {
			return 0, "", err
		}
		if found {
			return version, paths.LegacyFile, nil
		}
	}
	return 0, "", nil
}

func providerFileVersion(path string) (version uint16, found bool, err error) {
	data, err := readFileIfPresent(path)
	if err != nil || data == nil {
		return 0, false, err
	}

	var metadata struct {
		Version uint16 `json:"version"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return 0, false, fmt.Errorf("decoding %s: %w", path, err)
	}
	if metadata.Version == 0 {
		return 0, false, nil
	}
	return metadata.Version, true, nil
}

func legacyFileVersion(path string) (version uint16, found bool, err error) {
	data, err := readFileIfPresent(path)
	if err != nil || data == nil {
		return 0, false, err
	}

	var file map[string]json.RawMessage
	if err := json.Unmarshal(data, &file); err != nil {
		return 0, false, fmt.Errorf("decoding %s: %w", path, err)
	}
	raw, ok := file[Provider]
	if !ok {
		return 0, false, nil
	}

	var metadata struct {
		Version uint16 `json:"version"`
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return 0, false, fmt.Errorf("decoding %s section of %s: %w", Provider, path, err)
	}
	if metadata.Version == 0 {
		return 0, false, nil
	}
	return metadata.Version, true, nil
}

// WriteResult describes what Write did, for logging and the dashboard.
type WriteResult struct {
	// Written lists every file replaced.
	Written []string
	Layout  Layout
	// ServerCount is the number of server entries written.
	ServerCount   int
	SchemaVersion uint16
	Preferred     bool
	Timestamp     time.Time
	// PreservedKeys are the other providers kept in the legacy file.
	PreservedKeys []string
}

// Options configures Write.
type Options struct {
	Paths Paths
	// Layout selects where to write. Zero value detects it.
	Layout Layout
	// SchemaVersion must match the running Gluetun's protonvpn version.
	SchemaVersion uint16
	// Preferred sets Gluetun's "preferred" flag, which makes it use our servers
	// regardless of timestamps. Older Gluetun versions ignore the field.
	Preferred bool
	// PreserveOtherProviders keeps every other key of an existing legacy file.
	// It has no meaning for the directory layout, where each provider has its
	// own file and cannot be disturbed.
	PreserveOtherProviders bool
	// Now allows tests to pin the timestamp.
	Now time.Time
}

// Write renders servers into Gluetun's format and replaces the relevant files
// atomically.
//
// Writing an empty list is refused: it would leave Gluetun with no servers to
// choose from after a restart, which is strictly worse than a stale list.
func Write(servers []Server, opts Options) (result WriteResult, err error) {
	switch {
	case len(servers) == 0:
		return result, fmt.Errorf("refusing to write an empty server list")
	case opts.SchemaVersion == 0:
		return result, fmt.Errorf("refusing to write without a schema version")
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	layout := opts.Layout
	if layout == "" {
		layout = DetectLayout(opts.Paths)
	}

	sortServers(servers)
	section := providerServers{
		Version:   opts.SchemaVersion,
		Timestamp: now.Unix(),
		Preferred: opts.Preferred,
		Servers:   servers,
	}

	result = WriteResult{
		Layout:        layout,
		ServerCount:   len(servers),
		SchemaVersion: opts.SchemaVersion,
		Preferred:     opts.Preferred,
		Timestamp:     now,
	}

	if layout == LayoutDirectory || layout == LayoutBoth {
		path := opts.Paths.ProviderPath()
		if err := atomicfile.WriteJSON(path, section, 0o644); err != nil {
			return result, err
		}
		result.Written = append(result.Written, path)
	}

	if layout == LayoutLegacy || layout == LayoutBoth {
		preserved, err := writeLegacy(opts.Paths.LegacyFile, section, opts.PreserveOtherProviders)
		if err != nil {
			return result, err
		}
		result.Written = append(result.Written, opts.Paths.LegacyFile)
		result.PreservedKeys = preserved
	}

	return result, nil
}

// writeLegacy replaces the protonvpn section of the fat file, optionally keeping
// every other provider already in it.
func writeLegacy(path string, section providerServers, preserveOthers bool) (preserved []string, err error) {
	file := make(map[string]json.RawMessage)

	if preserveOthers {
		existing, err := readRawFile(path)
		if err != nil {
			// A corrupt existing file must not stop us writing a good one; we
			// simply cannot preserve its contents.
			return nil, fmt.Errorf("reading existing %s: %w", path, err)
		}
		for key, value := range existing {
			if key == Provider || key == "version" {
				continue
			}
			file[key] = value
			preserved = append(preserved, key)
		}
		sort.Strings(preserved)
	}

	encodedSection, err := json.Marshal(section)
	if err != nil {
		return nil, fmt.Errorf("encoding %s servers: %w", Provider, err)
	}
	file[Provider] = encodedSection

	encodedVersion, err := json.Marshal(topLevelSchemaVersion)
	if err != nil {
		return nil, fmt.Errorf("encoding schema version: %w", err)
	}
	file["version"] = encodedVersion

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding %s: %w", path, err)
	}
	data = append(data, '\n')

	if err := atomicfile.Write(path, data, 0o644); err != nil {
		return nil, err
	}
	return preserved, nil
}

func readRawFile(path string) (file map[string]json.RawMessage, err error) {
	data, err := readFileIfPresent(path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return map[string]json.RawMessage{}, nil
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return file, nil
}

// readFileIfPresent returns nil data (and no error) for a missing or empty file,
// which is the normal state before Gluetun has ever run.
func readFileIfPresent(path string) (data []byte, err error) {
	data, err = os.ReadFile(path) //nolint:gosec // operator-provided path by design
	switch {
	case os.IsNotExist(err):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("reading %s: %w", path, err)
	case len(data) == 0:
		return nil, nil
	}
	return data, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// sortServers orders servers the way Gluetun's own updater does, so a diff
// against a Gluetun-generated file stays readable: country, then city, then
// server name, then protocol.
func sortServers(servers []Server) {
	sort.SliceStable(servers, func(i, j int) bool {
		a, b := servers[i], servers[j]
		switch {
		case a.Country != b.Country:
			return a.Country < b.Country
		case a.City != b.City:
			return a.City < b.City
		case a.ServerName != b.ServerName:
			return a.ServerName < b.ServerName
		case a.Hostname != b.Hostname:
			return a.Hostname < b.Hostname
		default:
			return a.VPN < b.VPN
		}
	})
}
