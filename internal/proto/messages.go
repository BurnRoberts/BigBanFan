package proto

import "encoding/json"

// MsgType identifies the kind of BigBanFan protocol message.
type MsgType string

const (
	// ── Core cluster messages ─────────────────────────────────────────────────

	// MsgBan notifies peers of a new IP/CIDR to ban.
	MsgBan MsgType = "BAN"

	// MsgUnban notifies peers to lift an existing ban on an IP/CIDR.
	MsgUnban MsgType = "UNBAN"

	// MsgDedupeCheck asks a peer whether they have already seen a dedupe ID.
	MsgDedupeCheck MsgType = "DEDUPE_CHECK"

	// MsgDedupeAck is the reply to MsgDedupeCheck.
	MsgDedupeAck MsgType = "DEDUPE_ACK"

	// MsgHeartbeat is a keep-alive probe.
	MsgHeartbeat MsgType = "HEARTBEAT"

	// ── Management port — requests (GUI → node) ───────────────────────────────

	// MsgListBans requests a paginated, searchable ban list from the node.
	MsgListBans MsgType = "LIST_BANS"

	// MsgStatus requests node identity and health summary.
	MsgStatus MsgType = "STATUS"

	// MsgListPeers requests the peer list with connection state.
	MsgListPeers MsgType = "LIST_PEERS"

	// MsgStats requests session-only counters (bans, unbans, scan-detects).
	MsgStats MsgType = "STATS"

	// MsgLogSubscribe starts streaming filtered log lines to the management client.
	MsgLogSubscribe MsgType = "LOG_SUBSCRIBE"

	// MsgLogUnsubscribe stops the log stream.
	MsgLogUnsubscribe MsgType = "LOG_UNSUBSCRIBE"

	// ── Management port — responses / push (node → GUI) ───────────────────────

	// MsgBansList is the response to MsgListBans.
	MsgBansList MsgType = "BANS_LIST"

	// MsgStatusReply is the response to MsgStatus.
	MsgStatusReply MsgType = "STATUS_REPLY"

	// MsgPeersList is the response to MsgListPeers.
	MsgPeersList MsgType = "PEERS_LIST"

	// MsgStatsReply is the response to MsgStats.
	MsgStatsReply MsgType = "STATS_REPLY"

	// MsgBanEvent is pushed to all management clients when a new ban is applied.
	MsgBanEvent MsgType = "BAN_EVENT"

	// MsgUnbanEvent is pushed when a ban is lifted.
	MsgUnbanEvent MsgType = "UNBAN_EVENT"

	// MsgPeerUp is pushed when a peer connection is established.
	MsgPeerUp MsgType = "PEER_UP"

	// MsgPeerDown is pushed when a peer connection drops.
	MsgPeerDown MsgType = "PEER_DOWN"

	// MsgLogLine is pushed when log_subscribe is active.
	MsgLogLine MsgType = "LOG_LINE"

	// MsgError is returned when the node cannot fulfil a management request.
	MsgError MsgType = "ERROR"
)

// Message is the canonical wire message exchanged between all BigBanFan nodes,
// between clients and nodes (client-port variant), and between the management
// GUI and nodes (management-port variant).
//
// Not all fields are populated for every message type — see per-type docs.
type Message struct {
	// Type is the message kind.
	Type MsgType `json:"type"`

	// NodeID is the stable identifier (from config.node_id) of the node that
	// *originated* this event. Used for loop prevention.
	NodeID string `json:"node_id,omitempty"`

	// IP is the IPv4/IPv6 address or CIDR range (BAN / UNBAN / *_EVENT messages).
	IP string `json:"ip,omitempty"`

	// DedupeID is the globally-unique identifier for this ban event (UUIDv4).
	DedupeID string `json:"dedupe_id,omitempty"`

	// Known is set in DEDUPE_ACK replies: true means the recipient already
	// has this event in its seen-set.
	Known bool `json:"known,omitempty"`

	// Ts is the Unix epoch (seconds) when the originating node created the event.
	Ts int64 `json:"ts"`

	// ── Management request fields ─────────────────────────────────────────────

	// Page is the requested page number (1-indexed, LIST_BANS).
	Page int `json:"page,omitempty"`

	// PageSize is the number of records per page (LIST_BANS).
	PageSize int `json:"page_size,omitempty"`

	// Search is an IP substring to filter by (LIST_BANS, min 3 chars enforced by GUI).
	Search string `json:"search,omitempty"`

	// FilterSource limits results to bans originating from a specific node_id (LIST_BANS).
	FilterSource string `json:"filter_source,omitempty"`

	// FilterActiveOnly: when true, only return bans that have not yet expired (LIST_BANS).
	FilterActiveOnly bool `json:"filter_active_only,omitempty"`

	// LogLevel is the minimum log level to stream: "info", "warn", or "error" (LOG_SUBSCRIBE).
	LogLevel string `json:"log_level,omitempty"`

	// ── Management response fields ────────────────────────────────────────────

	// Total is the total number of matching records (BANS_LIST — drives pagination).
	Total int `json:"total,omitempty"`

	// Bans is the list of ban records returned by BANS_LIST.
	Bans []BanRecord `json:"bans,omitempty"`

	// Peers is the list of peer records returned by PEERS_LIST.
	Peers []PeerRecord `json:"peers,omitempty"`

	// Status is the node health summary returned by STATUS_REPLY.
	Status *StatusInfo `json:"status,omitempty"`

	// Stats is the session counter payload returned by STATS_REPLY.
	Stats *StatsInfo `json:"stats,omitempty"`

	// Line is a single log line (LOG_LINE push).
	Line string `json:"line,omitempty"`

	// ErrorMsg is a human-readable error description (ERROR messages).
	ErrorMsg string `json:"error,omitempty"`
}

// BanRecord is a single ban entry returned in BANS_LIST responses.
type BanRecord struct {
	ID        int64  `json:"id"`
	IP        string `json:"ip"`
	DedupeID  string `json:"dedupe_id"`
	BannedAt  int64  `json:"banned_at"`
	ExpiresAt int64  `json:"expires_at"`
	Source    string `json:"source"`
}

// PeerRecord describes a single peer node and its current connection state.
type PeerRecord struct {
	// NodeID is the remote node's stable identifier (empty if not yet handshaked).
	NodeID string `json:"node_id"`

	// Addr is the remote address (host:port).
	Addr string `json:"addr"`

	// Connected is true if the TCP connection is currently active.
	Connected bool `json:"connected"`

	// LastSeen is the Unix epoch of the last received message from this peer.
	LastSeen int64 `json:"last_seen"`

	// Direction is "inbound" or "outbound".
	Direction string `json:"direction"`
}

// StatusInfo is the node health payload in STATUS_REPLY messages.
type StatusInfo struct {
	NodeID    string `json:"node_id"`
	Version   string `json:"version"`
	UptimeSec int64  `json:"uptime_sec"`
	PeerCount int    `json:"peer_count"`
	BanCount  int    `json:"ban_count"`
}

// StatsInfo holds session-only counters (zeroed on restart).
type StatsInfo struct {
	BansThisSession        int64 `json:"bans_this_session"`
	UnbansThisSession      int64 `json:"unbans_this_session"`
	ScanDetectsThisSession int64 `json:"scan_detects_this_session"`
	ConnectionsAccepted    int64 `json:"connections_accepted"`
}

// Encode serialises a Message to JSON bytes.
func (m *Message) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// Decode deserialises JSON bytes into a Message.
func Decode(data []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
