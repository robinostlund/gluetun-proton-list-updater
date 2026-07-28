// Package serversfile produces the servers.json file Gluetun reads.
//
// The format is Gluetun's own: a top-level object with a schema "version" and
// one key per provider. Two details decide whether Gluetun actually uses our
// data, and both are easy to get wrong:
//
//  1. The provider "version" must equal the version compiled into the running
//     Gluetun. A mismatch makes Gluetun log "discarded because they have
//     version X" and silently fall back to its built-in list.
//  2. The provider "timestamp" must be newer than Gluetun's built-in one.
//     Gluetun merges by recency, so an older timestamp means our servers lose.
//
// Because requirement 1 changes between Gluetun releases, the version is
// detected from the file Gluetun itself wrote rather than hardcoded.
package serversfile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/atomicfile"
)

// Provider is the key Gluetun uses for ProtonVPN inside servers.json.
const Provider = "protonvpn"

// topLevelSchemaVersion is Gluetun's own top-level "version" field. It has been
// 1 for every release that supports a custom servers file.
const topLevelSchemaVersion = 1

// Server mirrors Gluetun's models.Server. Field names, JSON tags and omitempty
// behaviour are deliberately identical to Gluetun's so the file we write is
// byte-comparable with one Gluetun produces itself.
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

// providerServers is the per-provider object inside servers.json.
type providerServers struct {
	Version   uint16   `json:"version"`
	Timestamp int64    `json:"timestamp"`
	Servers   []Server `json:"servers"`
}

// DetectSchemaVersion reads the provider schema version from an existing
// servers.json. Gluetun writes its built-in version there on startup, which
// makes the file itself the most reliable source for the version we must match.
func DetectSchemaVersion(path string) (version uint16, found bool, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path by design
	switch {
	case os.IsNotExist(err):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("reading %s: %w", path, err)
	case len(data) == 0:
		return 0, false, nil
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
	Path             string
	ServerCount      int
	SchemaVersion    uint16
	Timestamp        time.Time
	PreservedKeys    []string
	PreviousModified time.Time
}

// Options configures Write.
type Options struct {
	Path string
	// SchemaVersion must match the running Gluetun's protonvpn version.
	SchemaVersion uint16
	// PreserveOtherProviders keeps every other key of an existing file, so a
	// setup that also stores another provider's servers is not damaged. This
	// corresponds to SERVERS_WRITE_MODE=update.
	PreserveOtherProviders bool
	// Now allows tests to pin the timestamp.
	Now time.Time
}

// Write renders servers to Gluetun's format and replaces the file atomically.
//
// Writing an empty list is refused: an empty protonvpn section would leave
// Gluetun with no servers to choose from after a restart, which is strictly
// worse than a stale list.
func Write(servers []Server, opts Options) (result WriteResult, err error) {
	if len(servers) == 0 {
		return result, fmt.Errorf("refusing to write %s with an empty server list", opts.Path)
	}
	if opts.SchemaVersion == 0 {
		return result, fmt.Errorf("refusing to write %s without a schema version", opts.Path)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	file := make(map[string]json.RawMessage)
	var preserved []string
	if opts.PreserveOtherProviders {
		existing, err := readRawFile(opts.Path)
		if err != nil {
			// A corrupt or unreadable existing file must not stop us from
			// writing a good one; we just cannot preserve its contents.
			return result, fmt.Errorf("reading existing %s: %w", opts.Path, err)
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

	sortServers(servers)

	section, err := json.Marshal(providerServers{
		Version:   opts.SchemaVersion,
		Timestamp: now.Unix(),
		Servers:   servers,
	})
	if err != nil {
		return result, fmt.Errorf("encoding %s servers: %w", Provider, err)
	}
	file[Provider] = section

	topLevel, err := json.Marshal(topLevelSchemaVersion)
	if err != nil {
		return result, fmt.Errorf("encoding schema version: %w", err)
	}
	file["version"] = topLevel

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return result, fmt.Errorf("encoding %s: %w", opts.Path, err)
	}
	data = append(data, '\n')

	var previousModified time.Time
	if info, statErr := os.Stat(opts.Path); statErr == nil {
		previousModified = info.ModTime()
	}

	if err := atomicfile.Write(opts.Path, data, 0o644); err != nil {
		return result, err
	}

	return WriteResult{
		Path:             opts.Path,
		ServerCount:      len(servers),
		SchemaVersion:    opts.SchemaVersion,
		Timestamp:        now,
		PreservedKeys:    preserved,
		PreviousModified: previousModified,
	}, nil
}

func readRawFile(path string) (file map[string]json.RawMessage, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path by design
	switch {
	case os.IsNotExist(err):
		return map[string]json.RawMessage{}, nil
	case err != nil:
		return nil, err
	case len(data) == 0:
		return map[string]json.RawMessage{}, nil
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	return file, nil
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
