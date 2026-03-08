package node

import (
	"bigbanfan/internal/config"
	"bigbanfan/internal/db"
	"bigbanfan/internal/dedupe"
	"bigbanfan/internal/ipt"
	"bigbanfan/internal/logger"
	"bigbanfan/internal/proto"
	"bigbanfan/internal/scandetect"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// MgmtSession is implemented by mgmt.Session. The manager calls Push on all
// registered sessions when ban/unban/peer events occur.
type MgmtSession interface {
	Push(msg *proto.Message)
}

// Manager owns the peer pool, the node server, and the ban pipeline.
// It is the central coordinator for all inter-node communication.
type Manager struct {
	cfg       *config.Config
	nodeKey   []byte
	db        *db.DB
	dedupeSet *dedupe.Set
	detector  *scandetect.Detector // nil if scan detection is disabled
	startTime time.Time
	version   string

	mu    sync.RWMutex
	peers map[string]*Peer // keyed by peer.remoteAddr (host:port)

	// Management sessions registry — push events to all connected GUI clients.
	mgmtMu   sync.RWMutex
	mgmtSess map[MgmtSession]struct{}

	banCh   chan banEvent   // internal: trigger a ban pipeline
	unbanCh chan unbanEvent // internal: trigger an unban pipeline

	// Session stats (atomic, zeroed on restart — not persisted).
	statBans        atomic.Int64
	statUnbans      atomic.Int64
	statScanDetects atomic.Int64
	statConnsIn     atomic.Int64
}

type banEvent struct {
	ip         string
	dedupeID   string
	originNode string // node_id of the original source (never re-send to this node)
}

type unbanEvent struct {
	ip         string
	originNode string
}

// NewManager creates a Manager.
func NewManager(cfg *config.Config, nodeKey []byte, database *db.DB, ds *dedupe.Set, version string) *Manager {
	return &Manager{
		cfg:       cfg,
		nodeKey:   nodeKey,
		db:        database,
		dedupeSet: ds,
		version:   version,
		startTime: time.Now(),
		peers:     make(map[string]*Peer),
		mgmtSess:  make(map[MgmtSession]struct{}),
		banCh:     make(chan banEvent, 256),
		unbanCh:   make(chan unbanEvent, 256),
	}
}

// SetDetector attaches a scan-detect detector to the manager.
// Call this before Start() if scan detection is enabled in config.
func (m *Manager) SetDetector(d *scandetect.Detector) {
	m.detector = d
}

// Start starts the manager's background goroutines.
func (m *Manager) Start() {
	go m.banPipeline()
	go m.unbanPipeline()
}

// BanCh returns the channel for submitting local or client-injected ban events.
func (m *Manager) BanCh() chan<- banEvent {
	return m.banCh
}

// SubmitBan queues a new ban from a local source (Unix socket, TCP client).
// A fresh dedupe ID is generated here.
func (m *Manager) SubmitBan(ip string) {
	dedupeID := uuid.New().String()
	m.banCh <- banEvent{ip: ip, dedupeID: dedupeID, originNode: m.cfg.NodeID}
}

// RegisterMgmtSession registers a management GUI session to receive push events.
func (m *Manager) RegisterMgmtSession(s MgmtSession) {
	m.mgmtMu.Lock()
	m.mgmtSess[s] = struct{}{}
	m.mgmtMu.Unlock()
}

// UnregisterMgmtSession removes a management session (called on disconnect).
func (m *Manager) UnregisterMgmtSession(s MgmtSession) {
	m.mgmtMu.Lock()
	delete(m.mgmtSess, s)
	m.mgmtMu.Unlock()
}

// pushToMgmt broadcasts a message to all connected management sessions.
func (m *Manager) pushToMgmt(msg *proto.Message) {
	m.mgmtMu.RLock()
	defer m.mgmtMu.RUnlock()
	for s := range m.mgmtSess {
		s.Push(msg)
	}
}

// GetPeers returns a snapshot of all known peers and their connection state.
func (m *Manager) GetPeers() []proto.PeerRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var records []proto.PeerRecord
	for _, p := range m.peers {
		records = append(records, proto.PeerRecord{
			NodeID:    p.RemoteNodeID(),
			Addr:      p.remoteAddr,
			Connected: p.IsConnected(),
			LastSeen:  p.LastSeen().Unix(),
			Direction: p.Direction(),
		})
	}
	return records
}

// GetStats returns a snapshot of session-only counters.
func (m *Manager) GetStats() proto.StatsInfo {
	return proto.StatsInfo{
		BansThisSession:        m.statBans.Load(),
		UnbansThisSession:      m.statUnbans.Load(),
		ScanDetectsThisSession: m.statScanDetects.Load(),
		ConnectionsAccepted:    m.statConnsIn.Load(),
	}
}

// GetStatus returns a status summary for this node.
func (m *Manager) GetStatus() (*proto.StatusInfo, error) {
	m.mu.RLock()
	peerCount := len(m.peers)
	m.mu.RUnlock()

	banCount := 0
	if n, err := m.db.CountBans("", "", true); err == nil {
		banCount = n
	}

	return &proto.StatusInfo{
		NodeID:    m.cfg.NodeID,
		Version:   m.version,
		UptimeSec: int64(time.Since(m.startTime).Seconds()),
		PeerCount: peerCount,
		BanCount:  banCount,
	}, nil
}

// IncrScanDetect is called by the scanner detector to increment the session counter.
func (m *Manager) IncrScanDetect() { m.statScanDetects.Add(1) }

// banPipeline processes ban events: applies locally if new, then notifies peers.
func (m *Manager) banPipeline() {
	for ev := range m.banCh {
		// ── Ignore-list check ─────────────────────────────────────────────────
		// Drop the event immediately if the IP falls within a configured
		// ignore_range (e.g. your own node IPs, Kubernetes subnets).
		// This gate applies to ALL sources: socket, TCP client, and peer broadcasts.
		if m.cfg.IsIgnored(ev.ip) {
			logger.Info("ignore-list: skipping %s (matches ignore_ranges)", ev.ip)
			continue
		}

		// ── IP-level dedup ────────────────────────────────────────────────────
		// Skip if this IP already has an active ban in the DB.
		if active, err := m.db.IsActiveBan(ev.ip); err != nil {
			logger.Warn("isActiveBan query %s: %v", ev.ip, err)
		} else if active {
			logger.Info("already banned: %s — skipping duplicate submission", ev.ip)
			continue
		}

		// UUID-level dedup: prevents the same broadcast event from being
		// processed more than once (loop prevention across nodes).
		if m.dedupeSet.HasSeen(ev.dedupeID) {
			logger.Info("dedupe skip %s (id=%s)", ev.ip, ev.dedupeID)
			continue
		}
		m.dedupeSet.MarkSeen(ev.dedupeID)

		// Persist.
		dur := time.Duration(float64(time.Hour) * m.cfg.BanDurationHours)
		now := time.Now()
		if err := m.db.Insert(ev.ip, ev.dedupeID, ev.originNode, now, now.Add(dur)); err != nil {
			logger.Warn("db insert %s: %v", ev.ip, err)
		}

		// Apply iptables rule.
		if err := ipt.AddBan(ev.ip); err != nil {
			logger.Warn("iptables add %s: %v", ev.ip, err)
		} else {
			logger.Info("BANNED %s (dedupe=%s origin=%s ttl=%.0fh)", ev.ip, ev.dedupeID, ev.originNode, m.cfg.BanDurationHours)
		}
		m.statBans.Add(1)

		// Broadcast BAN to all peers EXCEPT the origin node.
		msg := &proto.Message{
			Type:     proto.MsgBan,
			NodeID:   m.cfg.NodeID,
			IP:       ev.ip,
			DedupeID: ev.dedupeID,
			Ts:       now.Unix(),
		}
		m.broadcast(msg, ev.originNode)

		// Push BAN_EVENT to all management sessions.
		m.pushToMgmt(&proto.Message{
			Type:     proto.MsgBanEvent,
			NodeID:   m.cfg.NodeID,
			IP:       ev.ip,
			DedupeID: ev.dedupeID,
			Ts:       now.Unix(),
		})
	}
}

// SubmitUnban queues an unban for a locally-requested IP removal.
func (m *Manager) SubmitUnban(ip string) {
	m.unbanCh <- unbanEvent{ip: ip, originNode: m.cfg.NodeID}
}

// unbanPipeline processes unban events: removes from DB, removes iptables rule, broadcasts.
func (m *Manager) unbanPipeline() {
	for ev := range m.unbanCh {
		logger.Info("UNBAN %s (origin=%s)", ev.ip, ev.originNode)

		if err := m.db.RemoveBan(ev.ip); err != nil {
			logger.Warn("db remove ban %s: %v", ev.ip, err)
		}
		if err := ipt.RemoveBan(ev.ip); err != nil {
			// Not fatal — rule may not exist if ban already expired.
			logger.Warn("iptables remove %s: %v", ev.ip, err)
		}
		m.statUnbans.Add(1)

		msg := &proto.Message{
			Type:   proto.MsgUnban,
			NodeID: m.cfg.NodeID,
			IP:     ev.ip,
			Ts:     time.Now().Unix(),
		}
		m.broadcast(msg, ev.originNode)

		// Push UNBAN_EVENT to all management sessions.
		m.pushToMgmt(&proto.Message{
			Type:   proto.MsgUnbanEvent,
			NodeID: m.cfg.NodeID,
			IP:     ev.ip,
			Ts:     time.Now().Unix(),
		})
	}
}

// HandleIncoming processes a BAN or UNBAN message received from a peer.
func (m *Manager) HandleIncoming(msg *proto.Message) {
	switch msg.Type {
	case proto.MsgBan:
		// Enqueue through the same pipeline (dedupe check inside).
		m.banCh <- banEvent{
			ip:         msg.IP,
			dedupeID:   msg.DedupeID,
			originNode: msg.NodeID,
		}
	case proto.MsgUnban:
		m.unbanCh <- unbanEvent{ip: msg.IP, originNode: msg.NodeID}
	}
}

// broadcast sends msg to all connected peers, skipping the origin node.
// In a fully-meshed topology each pair of nodes may have BOTH an inbound
// and an outbound connection simultaneously. We deduplicate by remoteNodeID
// so each logical peer receives the message exactly once regardless of how
// many sockets exist between them.
func (m *Manager) broadcast(msg *proto.Message, excludeNodeID string) {
	data, err := json.Marshal(msg)
	if err != nil {
		logger.Error("broadcast marshal: %v", err)
		return
	}

	sentTo := make(map[string]bool) // nodeID → already sent
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, p := range m.peers {
		rid := p.RemoteNodeID()

		// Skip the node that originated this event.
		if rid == excludeNodeID {
			continue
		}

		// Skip if we've already sent to this nodeID via another connection.
		// Peers whose nodeID is not yet known (empty string, pre-heartbeat)
		// are always included — we can't dedup them yet.
		if rid != "" && sentTo[rid] {
			logger.Info("broadcast dedup: skipping extra connection to %s (%s)", rid, p.remoteAddr)
			continue
		}

		if err := p.Send(data); err != nil {
			logger.Warn("broadcast to %s: %v", p.remoteAddr, err)
		}
		if rid != "" {
			sentTo[rid] = true
		}
	}
}

// RegisterPeer adds a peer to the pool and pushes PEER_UP to management sessions.
func (m *Manager) RegisterPeer(p *Peer) {
	m.mu.Lock()
	m.peers[p.remoteAddr] = p
	m.mu.Unlock()
	logger.Info("peer registered: %s (node=%s)", p.remoteAddr, p.RemoteNodeID())
	m.pushToMgmt(&proto.Message{
		Type:   proto.MsgPeerUp,
		NodeID: p.RemoteNodeID(),
		IP:     p.remoteAddr,
		Ts:     time.Now().Unix(),
	})
}

// UnregisterPeer removes a peer and pushes PEER_DOWN to management sessions.
func (m *Manager) UnregisterPeer(p *Peer) {
	m.mu.Lock()
	delete(m.peers, p.remoteAddr)
	m.mu.Unlock()
	m.pushToMgmt(&proto.Message{
		Type:   proto.MsgPeerDown,
		NodeID: p.RemoteNodeID(),
		IP:     p.remoteAddr,
		Ts:     time.Now().Unix(),
	})
}

// StartServer begins accepting inbound TLS connections from peer nodes.
func (m *Manager) StartServer(tlsCert, tlsKey string) error {
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("node server: load tls keypair: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.NoClientCert, // frame-level HMAC provides auth
	}
	// Listen on [::] to accept both IPv4 and IPv6 inbound peer connections.
	// On Linux with net.ipv6only=0 (the default), this is a true dual-stack listener.
	addr := fmt.Sprintf("[::]:%d", m.cfg.ListenPort)
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("node server: listen %s: %w", addr, err)
	}
	logger.Info("node server listening on %s (TLS, dual-stack IPv4+IPv6)", addr)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				logger.Error("node server accept: %v", err)
				continue
			}
			m.statConnsIn.Add(1)
			go m.serveInbound(conn)
		}
	}()
	return nil
}

func (m *Manager) serveInbound(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	logger.Info("inbound peer connect: %s", remote)

	p := newInboundPeer(conn, remote, m.nodeKey, m)
	m.RegisterPeer(p)
	defer m.UnregisterPeer(p)

	// Set a handshake deadline: if no valid frame arrives within this window
	// the connection is closed. This kills scanners that connect and hold the
	// socket open without sending anything.
	// The deadline is cleared by readLoop after the first successful frame read.
	handshakeTimeout := 30 * time.Second
	if m.cfg.ScanDetectWindowSecs > 0 {
		// Use half the scan-detect window so a slow scanner still gets counted.
		handshakeTimeout = time.Duration(m.cfg.ScanDetectWindowSecs/2) * time.Second
		if handshakeTimeout < 10*time.Second {
			handshakeTimeout = 10 * time.Second
		}
	}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	wasError := p.readLoop()

	// Scanner detection: count this connection as a failure if:
	//   1. The read loop exited due to an error (TLS/protocol failure, timeout)
	//   2. The peer never identified itself (remoteNodeID still empty)
	//      — a legitimate node always sends a HEARTBEAT with its node_id
	//   3. The source IP is NOT in the configured ignore_ranges
	if wasError && p.RemoteNodeID() == "" && m.detector != nil && !m.cfg.IsIgnored(remote) {
		m.detector.RecordFailure(remote)
	}
}

// ConnectToPeer dials a peer address and starts the outbound reconnect loop.
func (m *Manager) ConnectToPeer(addr string, tlsCert, tlsKey string) {
	p := newOutboundPeer(addr, m.nodeKey, tlsCert, tlsKey, m)
	go p.reconnectLoop()
}

// FlushExpired removes expired bans from iptables (called by the expiry ticker).
func (m *Manager) FlushExpired() {
	expired, err := m.db.GetExpired()
	if err != nil {
		logger.Error("expiry query: %v", err)
		return
	}
	for _, ban := range expired {
		if err := ipt.RemoveBan(ban.IP); err != nil {
			logger.Warn("expiry remove %s: %v", ban.IP, err)
		} else {
			logger.Info("UNBANNED %s (dedupe=%s expired)", ban.IP, ban.DedupeID)
		}
		if err := m.db.DeleteByDedupeID(ban.DedupeID); err != nil {
			logger.Warn("expiry db delete %s: %v", ban.DedupeID, err)
		}
	}
}
