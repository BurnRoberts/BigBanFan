package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

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
	ClientPort int `yaml:"client_port"`

	// MgmtPort is the TCP port for the persistent management connection (GUI / monitoring).
	// Uses the same AES-256-GCM frame protocol as client_port but keeps connections
	// alive and supports bidirectional request/response + push events.
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
	// Any inbound connection that fails before completing a valid handshake
	// (TLS error, bad cipher, EOF) increments a per-IP failure counter.
	// When the counter hits Threshold within WindowSecs seconds, the IP is
	// automatically submitted for banning across the cluster.
	ScanDetectEnabled    bool `yaml:"scan_detect_enabled"`
	ScanDetectThreshold  int  `yaml:"scan_detect_threshold"`
	ScanDetectWindowSecs int  `yaml:"scan_detect_window_secs"`

	// IgnoreRanges is a list of CIDR ranges that will NEVER be banned.
	// Any IP (or range) submitted via socket, TCP client, or peer broadcast
	// that falls within one of these ranges is silently dropped.
	// Example: your own node IPs, Kubernetes pod/service subnets, management IPs.
	IgnoreRanges []string `yaml:"ignore_ranges"`

	// ParsedIgnoreRanges is populated from IgnoreRanges during Validate().
	// Use this for runtime checks — not the raw string slice.
	ParsedIgnoreRanges []*net.IPNet `yaml:"-"`
}

// DefaultConfig returns a Config filled with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		NodeID:               "node01",
		MaxPeers:             8,
		ListenPort:           7777,
		ClientPort:           7778,
		MgmtPort:             7779,
		UnixSocket:           "/run/bigbanfan.sock",
		DBPath:               "/var/lib/bigbanfan/bans.db",
		LogFile:              "/var/log/bigbanfan.log",
		LogLevel:             "info",
		BanDurationHours:     24,
		ScanDetectEnabled:    true,
		ScanDetectThreshold:  5,
		ScanDetectWindowSecs: 60,
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
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate returns an error if required fields are missing or invalid.
// It also parses IgnoreRanges into ParsedIgnoreRanges.
func (c *Config) Validate() error {
	if c.NodeID == "" {
		return fmt.Errorf("config: node_id is required")
	}
	if c.NodeKey == "" {
		return fmt.Errorf("config: node_key is required (32-byte hex)")
	}
	if c.ClientKey == "" {
		return fmt.Errorf("config: client_key is required (32-byte hex)")
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

	// Parse and validate ignore_ranges CIDRs.
	c.ParsedIgnoreRanges = c.ParsedIgnoreRanges[:0] // reset in case Validate called again
	for _, cidr := range c.IgnoreRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("config: ignore_ranges: invalid CIDR %q: %w", cidr, err)
		}
		c.ParsedIgnoreRanges = append(c.ParsedIgnoreRanges, network)
	}

	return nil
}

// IsIgnored returns true if ip falls within any of the configured ignore_ranges.
func (c *Config) IsIgnored(ipStr string) bool {
	// Strip any CIDR suffix for lookup.
	host := ipStr
	for i, ch := range ipStr {
		if ch == '/' {
			host = ipStr[:i]
			break
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range c.ParsedIgnoreRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
