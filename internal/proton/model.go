package proton

import (
	"net/netip"
)

// Feature bits of a logical server, as published by Proton. They are exported
// because callers (and tests) legitimately need to construct and inspect them.
// See ProtonVPN's ServerFeatureEnum.
const (
	FeatureSecureCore = 1 << 0
	FeatureTor        = 1 << 1
	FeatureP2P        = 1 << 2
	FeatureStreaming  = 1 << 3
	FeatureIPv6       = 1 << 4
)

// Status values used by both logical and physical servers.
const (
	statusDisabled = 0
)

// LogicalServer is one entry of Proton's /vpn/v1/logicals response. A logical
// server is a virtual location ("SE#12") backed by one or more physical
// servers.
type LogicalServer struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	// EntryCountry is where traffic enters Proton's network; for Secure Core
	// servers it differs from ExitCountry.
	EntryCountry string  `json:"EntryCountry"`
	ExitCountry  string  `json:"ExitCountry"`
	Region       *string `json:"Region"`
	City         *string `json:"City"`
	// Load is the utilisation percentage Proton reports, 0-100. This is the
	// value the whole tool is built around.
	Load uint8 `json:"Load"`
	// Score is Proton's own routing preference; lower is better. It bakes in
	// capacity and geography, so it is a useful secondary signal.
	Score float64 `json:"Score"`
	// Status is 0 when the logical server is administratively disabled.
	Status uint8 `json:"Status"`
	// Tier 0 is the free tier, 2 is Plus.
	Tier     *uint8           `json:"Tier"`
	Features uint16           `json:"Features"`
	Servers  []PhysicalServer `json:"Servers"`
}

// PhysicalServer is one machine backing a logical server.
type PhysicalServer struct {
	ID              string     `json:"ID"`
	EntryIP         netip.Addr `json:"EntryIP"`
	ExitIP          netip.Addr `json:"ExitIP"`
	EntryIPv6       string     `json:"EntryIPv6"`
	Domain          string     `json:"Domain"`
	Status          uint8      `json:"Status"`
	X25519PublicKey string     `json:"X25519PublicKey"`
	Label           string     `json:"Label"`
}

// SecureCore reports whether the logical server routes through a Secure Core
// entry node.
func (l LogicalServer) SecureCore() bool { return l.Features&FeatureSecureCore != 0 }

// Tor reports whether the logical server exits through the Tor network.
func (l LogicalServer) Tor() bool { return l.Features&FeatureTor != 0 }

// P2P reports whether the logical server allows peer-to-peer traffic. Gluetun
// maps this onto its port_forward field, because Proton only forwards ports on
// P2P servers.
func (l LogicalServer) P2P() bool { return l.Features&FeatureP2P != 0 }

// Streaming reports whether the logical server is optimised for streaming
// services.
func (l LogicalServer) Streaming() bool { return l.Features&FeatureStreaming != 0 }

// IPv6 reports whether Proton flags the logical server as IPv6 capable.
func (l LogicalServer) IPv6() bool { return l.Features&FeatureIPv6 != 0 }

// Free reports whether the logical server is available on the free tier.
// A missing Tier is treated as paid, matching Gluetun's behaviour.
func (l LogicalServer) Free() bool { return l.Tier != nil && *l.Tier == 0 }

// Enabled reports whether Proton currently considers the logical server usable.
func (l LogicalServer) Enabled() bool { return l.Status != statusDisabled }

// Enabled reports whether the physical machine is currently usable.
func (p PhysicalServer) Enabled() bool { return p.Status != statusDisabled }

// ServerLoad is one entry of the cheap /vpn/v1/loads response, used to refresh
// utilisation without re-downloading the multi-megabyte logicals list.
type ServerLoad struct {
	ID     string  `json:"ID"`
	Load   uint8   `json:"Load"`
	Score  float64 `json:"Score"`
	Status uint8   `json:"Status"`
}

// logicalsResponse is the envelope Proton wraps both responses in.
type logicalsResponse struct {
	Code           int             `json:"Code"`
	LogicalServers []LogicalServer `json:"LogicalServers"`
}

type loadsResponse struct {
	Code           int          `json:"Code"`
	LogicalServers []ServerLoad `json:"LogicalServers"`
}
