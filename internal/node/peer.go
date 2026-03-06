package node

import (
	"bigbanfan/internal/crypto"
	"bigbanfan/internal/logger"
	"bigbanfan/internal/proto"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	reconnectFastInterval = 30 * time.Second
	reconnectFastTimeout  = 5 * time.Minute
	reconnectSlowInterval = 30 * time.Minute
	reconnectSlowTimeout  = 5 * time.Hour
)

// Peer represents one persistent inter-node connection.
type Peer struct {
	remoteAddr   string
	remoteNodeID string
	key          []byte
	manager      *Manager
	conn         net.Conn
	mu           sync.Mutex
	// outbound-only fields
	tlsCert   string
	tlsKey    string
	isInbound bool
}

func newInboundPeer(conn net.Conn, remoteAddr string, key []byte, mgr *Manager) *Peer {
	return &Peer{
		remoteAddr: remoteAddr,
		key:        key,
		manager:    mgr,
		conn:       conn,
		isInbound:  true,
	}
}

func newOutboundPeer(remoteAddr string, key []byte, tlsCert, tlsKey string, mgr *Manager) *Peer {
	return &Peer{
		remoteAddr: remoteAddr,
		key:        key,
		manager:    mgr,
		tlsCert:    tlsCert,
		tlsKey:     tlsKey,
		isInbound:  false,
	}
}

// RemoteNodeID returns the peer's self-reported node_id (set on first HEARTBEAT).
func (p *Peer) RemoteNodeID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.remoteNodeID
}

func (p *Peer) setRemoteNodeID(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.remoteNodeID = id
}

// Send encrypts and writes a framed message to the peer connection.
func (p *Peer) Send(plaintext []byte) error {
	p.mu.Lock()
	conn := p.conn
	p.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("peer %s: not connected", p.remoteAddr)
	}
	encFn := func(b []byte) ([]byte, error) { return crypto.Encrypt(p.key, b) }
	signFn := func(b []byte) []byte { return crypto.Sign(p.key, b) }
	return proto.WriteFrame(conn, plaintext, encFn, signFn)
}

// readLoop continuously reads frames from the peer and dispatches them.
// Returns true if the loop exited due to an error (TLS failure, timeout, bad frame, etc.)
// vs false for a clean peer disconnect. The caller uses this to detect scanners.
func (p *Peer) readLoop() (wasError bool) {
	decFn := func(b []byte) ([]byte, error) { return crypto.Decrypt(p.key, b) }
	verFn := func(data, sig []byte) bool { return crypto.Verify(p.key, data, sig) }

	handshakeDone := false
	for {
		raw, err := proto.ReadFrame(p.conn, decFn, verFn)
		if err != nil {
			if isEOF(err) {
				logger.Info("peer %s disconnected", p.remoteAddr)
				return false // clean disconnect
			}
			logger.Warn("peer %s read error: %v", p.remoteAddr, err)
			return true // protocol / TLS error / timeout → potential scanner
		}
		// First valid frame received — clear the handshake deadline so the
		// connection can run indefinitely as a normal long-lived peer.
		if !handshakeDone {
			p.conn.SetDeadline(time.Time{})
			handshakeDone = true
		}
		msg, err := proto.Decode(raw)
		if err != nil {
			logger.Warn("peer %s bad message: %v", p.remoteAddr, err)
			continue
		}
		p.handleMessage(msg)
	}
}

func (p *Peer) handleMessage(msg *proto.Message) {
	// Always update our knowledge of the peer's node_id.
	if msg.NodeID != "" && p.RemoteNodeID() != msg.NodeID {
		p.setRemoteNodeID(msg.NodeID)
		logger.Info("peer %s identified as node=%s", p.remoteAddr, msg.NodeID)
	}

	switch msg.Type {
	case proto.MsgHeartbeat:
		// If we are the inbound (server) side, reply with our own HEARTBEAT so
		// the outbound peer learns our node_id. Without this, outbound peers
		// see (node=) forever and the broadcast dedup map can't tell both
		// connections belong to the same logical peer.
		if p.isInbound {
			p.sendHeartbeat()
		}

	case proto.MsgBan:
		if msg.IP == "" || msg.DedupeID == "" {
			logger.Warn("peer %s sent incomplete BAN", p.remoteAddr)
			return
		}
		logger.Info("BAN received from %s: %s (dedupe=%s)", msg.NodeID, msg.IP, msg.DedupeID)
		p.manager.HandleIncoming(msg)

	default:
		logger.Warn("peer %s unknown msg type: %s", p.remoteAddr, msg.Type)
	}
}

// reconnectLoop is the outbound connection state machine.
//
//	Phase 1 (fast): retry every 30s for 5 min.
//	Phase 2 (slow): retry every 30 min for 5 hr.
//	Phase 3 (dead): log ERROR and stop.
func (p *Peer) reconnectLoop() {
	fastDeadline := time.Now().Add(reconnectFastTimeout)
	slowDeadline := time.Now().Add(reconnectFastTimeout + reconnectSlowTimeout)

	dial := func() bool {
		conn, err := p.dial()
		if err != nil {
			return false
		}
		p.mu.Lock()
		p.conn = conn
		p.mu.Unlock()

		// Register before entering read-loop.
		p.manager.RegisterPeer(p)

		// Send initial heartbeat so peer learns our node_id.
		p.sendHeartbeat()

		logger.Info("peer connected: %s", p.remoteAddr)
		p.readLoop()

		p.manager.UnregisterPeer(p)
		p.mu.Lock()
		p.conn = nil
		p.mu.Unlock()
		return true
	}

	for {
		now := time.Now()
		if dial() {
			// Successfully connected and then disconnected — reset timers.
			fastDeadline = time.Now().Add(reconnectFastTimeout)
			slowDeadline = time.Now().Add(reconnectFastTimeout + reconnectSlowTimeout)
		}

		now = time.Now()
		if now.Before(fastDeadline) {
			logger.Warn("peer %s unreachable, retrying in %s (fast phase)", p.remoteAddr, reconnectFastInterval)
			time.Sleep(reconnectFastInterval)
		} else if now.Before(slowDeadline) {
			logger.Warn("peer %s unreachable, retrying in %s (slow phase)", p.remoteAddr, reconnectSlowInterval)
			time.Sleep(reconnectSlowInterval)
		} else {
			logger.Error("peer %s has FAILED — node unreachable after 5 hours of retries", p.remoteAddr)
			return
		}
	}
}

func (p *Peer) dial() (net.Conn, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // frame-level HMAC provides integrity; node_id tracks identity
		MinVersion:         tls.VersionTLS13,
	}
	conn, err := tls.Dial("tcp", p.remoteAddr, tlsCfg)
	if err != nil {
		logger.Warn("dial %s: %v", p.remoteAddr, err)
		return nil, err
	}
	return conn, nil
}

func (p *Peer) sendHeartbeat() {
	msg := &proto.Message{
		Type:   proto.MsgHeartbeat,
		NodeID: p.manager.cfg.NodeID,
		Ts:     time.Now().Unix(),
	}
	data, _ := json.Marshal(msg)
	if err := p.Send(data); err != nil {
		logger.Warn("heartbeat to %s: %v", p.remoteAddr, err)
	}
}

func isEOF(err error) bool {
	return err == io.EOF || err == io.ErrUnexpectedEOF
}
