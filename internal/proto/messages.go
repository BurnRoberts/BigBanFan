package proto

import "encoding/json"

// MsgType identifies the kind of BigBanFan protocol message.
type MsgType string

const (
	// MsgBan notifies peers of a new IP to ban.
	MsgBan MsgType = "BAN"

	// MsgUnban notifies peers to lift an existing ban on an IP.
	MsgUnban MsgType = "UNBAN"

	// MsgDedupeCheck asks a peer whether they have already seen a dedupe ID.
	MsgDedupeCheck MsgType = "DEDUPE_CHECK"

	// MsgDedupeAck is the reply to MsgDedupeCheck.
	MsgDedupeAck MsgType = "DEDUPE_ACK"

	// MsgHeartbeat is a keep-alive probe.
	MsgHeartbeat MsgType = "HEARTBEAT"
)

// Message is the canonical wire message exchanged between all BigBanFan nodes
// and between clients and nodes (client-port variant).
//
// NodeID identifies the *originating* node of the event — not the forwarding
// relay.  All hops MUST preserve the original NodeID so that every recipient
// can avoid echoing the message back toward its source.
type Message struct {
	// Type is the message kind.
	Type MsgType `json:"type"`

	// NodeID is the stable identifier (from config.node_id) of the node
	// that *originated* this event.  Used for loop prevention: a node that
	// receives a BAN message from node X must not forward the message back
	// to node X even via another path.
	NodeID string `json:"node_id"`

	// IP is the bad-actor IPv4 or IPv6 address (BAN messages only).
	IP string `json:"ip,omitempty"`

	// DedupeID is the globally-unique identifier for this ban event (UUIDv4).
	// All nodes that have already processed this event will have it in their
	// seen-set and will drop the duplicate.
	DedupeID string `json:"dedupe_id,omitempty"`

	// Known is set in DEDUPE_ACK replies: true means the recipient already
	// has this event in its seen-set.
	Known bool `json:"known,omitempty"`

	// Ts is the Unix epoch (seconds) when the originating node created the event.
	Ts int64 `json:"ts"`
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
