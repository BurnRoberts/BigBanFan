package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// allowAll is the default allow-ranges value: permit all IPv4 and IPv6.
var allowAll = []string{"0.0.0.0/0", "::/0"}

// Config holds all BigBanFan configuration.
type Config struct {
	// NodeID is a stable, unique identifier for this node (e.g. "cdn12").
	// It is sent on every wire message so peers can route correctly and
	// avoid echoing messages back to their origin node.
	NodeID string `yaml:"node_id"`

	// Peers is the static list of peer node addresses (host:port) to connect to.
	Peers []string `yaml:"peers"`

	// MaxPeers caps simultaneous outbound peer connections.
	MaxPeers int `yaml:"max_peers"`

	// ListenPort is the TCP port for inter-node (node-to-node) connections.
	ListenPort int `yaml:"listen_port"`

	// ClientPort is the TCP port for external client injection (Python/PHP scripts).
	// Set to 0 or omit to disable this port entirely.
	ClientPort int `yaml:"client_port"`

	// MgmtPort is the TCP port for the persistent management connection (GUI / monitoring).
	// Uses the same AES-256-GCM frame protocol as client_port.
	// Set to 0 or omit to disable this port entirely.
	MgmtPort int `yaml:"mgmt_port"`

	// UnixSocket is the path to the Unix domain socket for local IP injection.
	UnixSocket string `yaml:"unix_socket"`

	// NodeKey is a 32-byte hex AES-256 key for node-to-node frame encryption/signing.
	NodeKey string `yaml:"node_key"`

	// ClientKey is a 32-byte hex AES-256 key for external client frame encryption/signing.
	ClientKey string `yaml:"client_key"`

	// TLSCert is the path to the PEM TLS certificate for inter-node connections.
	TLSCert string `yaml:"tls_cert"`

	// TLSKey is the path to the PEM TLS private key for inter-node connections.
	TLSKey string `yaml:"tls_key"`

	// DBPath is the path to the SQLite database file.
	DBPath string `yaml:"db_path"`

	// LogFile is the path to the log file.
	LogFile string `yaml:"log_file"`

	// LogLevel controls minimum log level: "info", "warn", "error".
	LogLevel string `yaml:"log_level"`

	// BanDurationHours is how many hours an IP is banned before automatic expiry.
	BanDurationHours float64 `yaml:"ban_duration_hours"`

	// ScanDetect controls automatic banning of port scanners and probers.
	ScanDetectEnabled    bool `yaml:"scan_detect_enabled"`
	ScanDetectThreshold  int  `yaml:"scan_detect_threshold"`
	ScanDetectWindowSecs int  `yaml:"scan_detect_window_secs"`

	// IgnoreRanges is a list of CIDR ranges that will NEVER be banned.
	IgnoreRanges []string `yaml:"ignore_ranges"`

	// ParsedIgnoreRanges is populated from IgnoreRanges during Validate().
	ParsedIgnoreRanges []*net.IPNet `yaml:"-"`

	// PeerAllowRanges restricts which source IPs may connect to the inter-node
	// listen_port. Default: ["0.0.0.0/0", "::/0"] (all addresses allowed).
	PeerAllowRanges []string `yaml:"peer_allow_ranges"`

	// ClientAllowRanges restricts which source IPs may connect to client_port.
	// Default: ["0.0.0.0/0", "::/0"] (all addresses allowed).
	ClientAllowRanges []string `yaml:"client_allow_ranges"`

	// MgmtAllowRanges restricts which source IPs may connect to mgmt_port.
	// Default: ["0.0.0.0/0", "::/0"] (all addresses allowed).
	MgmtAllowRanges []string `yaml:"mgmt_allow_ranges"`

	// Parsed allow-range nets (populated by Validate).
	ParsedPeerAllowRanges   []*net.IPNet `yaml:"-"`
	ParsedClientAllowRanges []*net.IPNet `yaml:"-"`
	ParsedMgmtAllowRanges   []*net.IPNet `yaml:"-"`
}

// DefaultConfig returns a Config filled with sensible defaults.
// ClientPort and MgmtPort default to 0 (disabled) — set them explicitly to enable.
func DefaultConfig() *Config {
	return &Config{
		NodeID:               "node01",
		MaxPeers:             8,
		ListenPort:           7777,
		ClientPort:           0, // disabled unless configured
		MgmtPort:             0, // disabled unless configured
		UnixSocket:           "/run/bigbanfan.sock",
		DBPath:               "/var/lib/bigbanfan/bans.db",
		LogFile:              "/var/log/bigbanfan.log",
		LogLevel:             "info",
		BanDurationHours:     24,
		ScanDetectEnabled:    true,
		ScanDetectThreshold:  5,
		ScanDetectWindowSecs: 60,
		PeerAllowRanges:      append([]string{}, allowAll...),
		ClientAllowRanges:    append([]string{}, allowAll...),
		MgmtAllowRanges:      append([]string{}, allowAll...),
	}
}

// Load reads a YAML config file and returns the populated Config.
// Missing fields fall back to DefaultConfig values.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w\n\nHint: check YAML indentation and quoting", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate returns an error if required fields are missing or invalid.
// It also parses IgnoreRanges and *AllowRanges into their Parsed* counterparts.
func (c *Config) Validate() error {
	if c.NodeID == "" {
		return fmt.Errorf("config: node_id is required")
	}
	if c.NodeKey == "" {
		return fmt.Errorf("config: node_key is required (32-byte hex)")
	}
	if c.TLSCert == "" {
		return fmt.Errorf("config: tls_cert is required")
	}
	if c.TLSKey == "" {
		return fmt.Errorf("config: tls_key is required")
	}
	if c.BanDurationHours <= 0 {
		return fmt.Errorf("config: ban_duration_hours must be > 0")
	}

	// client_key is only required when client_port or mgmt_port is enabled.
	if (c.ClientPort > 0 || c.MgmtPort > 0) && c.ClientKey == "" {
		return fmt.Errorf("config: client_key is required when client_port or mgmt_port is enabled")
	}

	// Parse and validate ignore_ranges CIDRs.
	// [:0:0] resets both length and capacity so repeated Validate() calls
	// don't share the backing array with a previous parse.
	c.ParsedIgnoreRanges = c.ParsedIgnoreRanges[:0:0]
	for _, cidr := range c.IgnoreRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("config: ignore_ranges: invalid CIDR %q: %w", cidr, err)
		}
		c.ParsedIgnoreRanges = append(c.ParsedIgnoreRanges, network)
	}

	// Parse allow_ranges for each port. Empty slice → fall back to allowAll.
	var err error
	if c.ParsedPeerAllowRanges, err = parseAllowRanges("peer_allow_ranges", c.PeerAllowRanges); err != nil {
		return err
	}
	if c.ParsedClientAllowRanges, err = parseAllowRanges("client_allow_ranges", c.ClientAllowRanges); err != nil {
		return err
	}
	if c.ParsedMgmtAllowRanges, err = parseAllowRanges("mgmt_allow_ranges", c.MgmtAllowRanges); err != nil {
		return err
	}

	return nil
}

// parseAllowRanges parses a list of CIDR strings into *net.IPNet values.
// An empty list is treated as "allow all" (0.0.0.0/0 + ::/0).
func parseAllowRanges(field string, ranges []string) ([]*net.IPNet, error) {
	if len(ranges) == 0 {
		ranges = allowAll
	}
	var nets []*net.IPNet
	for _, cidr := range ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("config: %s: invalid CIDR %q: %w", field, cidr, err)
		}
		nets = append(nets, network)
	}
	return nets, nil
}

// IsIgnored returns true if ip falls within any of the configured ignore_ranges.
func (c *Config) IsIgnored(ipStr string) bool {
	return c.inRanges(ipStr, c.ParsedIgnoreRanges)
}

// IsPeerAllowed returns true if the source IP is permitted to connect to listen_port.
func (c *Config) IsPeerAllowed(ipStr string) bool {
	return c.inRanges(ipStr, c.ParsedPeerAllowRanges)
}

// IsClientAllowed returns true if the source IP is permitted to connect to client_port.
func (c *Config) IsClientAllowed(ipStr string) bool {
	return c.inRanges(ipStr, c.ParsedClientAllowRanges)
}

// IsMgmtAllowed returns true if the source IP is permitted to connect to mgmt_port.
func (c *Config) IsMgmtAllowed(ipStr string) bool {
	return c.inRanges(ipStr, c.ParsedMgmtAllowRanges)
}

// inRanges is the shared implementation for all range checks.
func (c *Config) inRanges(ipStr string, ranges []*net.IPNet) bool {
	// Strip any CIDR suffix or port suffix for lookup.
	host := ipStr
	for i, ch := range ipStr {
		if ch == '/' || ch == ':' {
			// For IPv4:port (host:port), strip the port.
			// Don't strip colons in bare IPv6 addresses.
			if ch == ':' {
				// Only strip if it looks like host:port (host has no other colons).
				if net.ParseIP(ipStr) != nil {
					break // bare IPv6, keep as-is
				}
			}
			host = ipStr[:i]
			break
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Try host:port split as fallback.
		if h, _, err := net.SplitHostPort(ipStr); err == nil {
			ip = net.ParseIP(h)
		}
	}
	if ip == nil {
		return false
	}
	for _, network := range ranges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
