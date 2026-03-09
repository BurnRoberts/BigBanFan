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
	"unicode/utf8"

	"github.com/google/uuid"
)

// MgmtSession is implemented by mgmt.Session. The manager calls Push on all
// registered sessions when ban/unban/peer events occur.
type MgmtSession interface {
	Push(msg *proto.Message)
	PushLogLine(level, line string)
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

	// stopCh is closed by Shutdown() to signal all reconnect goroutines to exit.
	stopCh chan struct{}

	// Session stats (atomic, zeroed on restart — not persisted).
	statBans        atomic.Int64
	statUnbans      atomic.Int64
	statScanDetects atomic.Int64
	statConnsIn     atomic.Int64

	// Startup ban-sync state.
	// initialSyncDone is set to true (CAS) the moment a SYNC_REQUEST is sent.
	// isolatedAt records the unix epoch when the last peer disconnected;
	// 0 means at least one peer is currently connected.
	initialSyncDone atomic.Bool
	isolatedAt      atomic.Int64
}

type banEvent struct {
	ip         string
	dedupeID   string
	originNode string // node_id of the original source (never re-send to this node)
	reason     string // optional human-readable ban reason
}

type unbanEvent struct {
	ip         string
	dedupeID   string
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
		stopCh:    make(chan struct{}),
	}
}

// Shutdown signals all outbound reconnect goroutines to stop and exit cleanly.
// Call this from the signal handler before os.Exit so sleeping goroutines
// don't linger for up to 30 minutes waiting for their slow-phase interval.
func (m *Manager) Shutdown() {
	close(m.stopCh)
}

// SetDetector attaches a scan-detect detector to the manager.
// Call this before Start() if scan detection is enabled in config.
func (m *Manager) SetDetector(d *scandetect.Detector) {
	m.detector = d
}

// Detector returns the attached scan-detect detector (nil if disabled).
func (m *Manager) Detector() *scandetect.Detector {
	return m.detector
}

// Start starts the manager's background goroutines.
func (m *Manager) Start() {
	go m.banPipeline()
	go m.unbanPipeline()
}

// SubmitBan queues a new ban from a local source (Unix socket, TCP client).
// A fresh dedupe ID is generated here. Reason is empty for auto-bans.
func (m *Manager) SubmitBan(ip string) {
	m.SubmitBanWithReason(ip, "")
}

// SubmitBanWithReason queues a new ban with an optional reason string.
// Max 1024 runes enforced here — longer values are silently truncated.
// Rune-aware truncation ensures we never split a multi-byte UTF-8 character.
// The send is non-blocking: if the pipeline is congested (channel full) the ban is
// dropped with a warning rather than deadlocking the caller's goroutine.
func (m *Manager) SubmitBanWithReason(ip, reason string) {
	if utf8.RuneCountInString(reason) > 1024 {
		runes := []rune(reason)
		reason = string(runes[:1024])
	}
	ev := banEvent{ip: ip, dedupeID: uuid.New().String(), originNode: m.cfg.NodeID, reason: reason}
	select {
	case m.banCh <- ev:
	default:
		logger.Warn("banCh full — dropping ban for %s (pipeline congested)", ip)
	}
}

// RegisterMgmtSession registers a management GUI session to receive push events.
func (m *Manager) RegisterMgmtSession(s MgmtSession) {
	m.mgmtMu.Lock()
	m.mgmtSess[s] = struct{}{}
	m.mgmtMu.Unlock()
	// rewireLogSubscriber acquires subMu (via logger.SetSubscriber); calling it
	// outside mgmtMu prevents a lock-order inversion with PushLogLine which
	// enters subMu first then (inside the callback) takes mgmtMu.RLock.
	m.rewireLogSubscriber()
}

// UnregisterMgmtSession removes a management session (called on disconnect).
func (m *Manager) UnregisterMgmtSession(s MgmtSession) {
	m.mgmtMu.Lock()
	delete(m.mgmtSess, s)
	m.mgmtMu.Unlock()
	// Same lock-order concern as RegisterMgmtSession — call after releasing lock.
	m.rewireLogSubscriber()
}

// rewireLogSubscriber installs or clears the logger subscriber based on
// whether any management sessions are currently registered.
// Must NOT be called with mgmtMu held (logger.SetSubscriber acquires subMu).
func (m *Manager) rewireLogSubscriber() {
	m.mgmtMu.RLock()
	hasClients := len(m.mgmtSess) > 0
	m.mgmtMu.RUnlock()
	if !hasClients {
		logger.ClearSubscriber()
		return
	}
	logger.SetSubscriber(func(level, line string) {
		m.mgmtMu.RLock()
		defer m.mgmtMu.RUnlock()
		for s := range m.mgmtSess {
			s.PushLogLine(level, line)
		}
	})
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
		if err := m.db.Insert(ev.ip, ev.dedupeID, ev.originNode, ev.reason, now, now.Add(dur)); err != nil {
			logger.Warn("db insert %s: %v", ev.ip, err)
		}

		// Apply iptables rule.
		if err := ipt.AddBan(ev.ip); err != nil {
			logger.Warn("iptables add %s: %v", ev.ip, err)
		} else {
			logger.Info("BANNED %s (dedupe=%s origin=%s ttl=%.0fh)", ev.ip, ev.dedupeID, ev.originNode, m.cfg.BanDurationHours)
			m.statBans.Add(1)
		}

		// Broadcast BAN to all peers EXCEPT the origin node.
		msg := &proto.Message{
			Type:     proto.MsgBan,
			NodeID:   m.cfg.NodeID,
			IP:       ev.ip,
			DedupeID: ev.dedupeID,
			Reason:   ev.reason,
			Ts:       now.Unix(),
		}
		m.broadcast(msg, ev.originNode)

		// Push BAN_EVENT to all management sessions.
		m.pushToMgmt(&proto.Message{
			Type:     proto.MsgBanEvent,
			NodeID:   m.cfg.NodeID,
			IP:       ev.ip,
			DedupeID: ev.dedupeID,
			Reason:   ev.reason,
			Ts:       now.Unix(),
		})
	}
}

// SubmitUnban queues an unban. Non-blocking — drops with warning if pipeline full.
func (m *Manager) SubmitUnban(ip string) {
	ev := unbanEvent{ip: ip, dedupeID: uuid.New().String(), originNode: m.cfg.NodeID}
	select {
	case m.unbanCh <- ev:
	default:
		logger.Warn("unbanCh full — dropping unban for %s (pipeline congested)", ip)
	}
}

// unbanPipeline processes unban events: removes from DB, removes iptables rule, broadcasts.
func (m *Manager) unbanPipeline() {
	for ev := range m.unbanCh {
		// UUID-level dedupe: prevents the same UNBAN broadcast from looping
		// back through the mesh indefinitely.
		if m.dedupeSet.HasSeen(ev.dedupeID) {
			logger.Info("unban dedupe skip %s (id=%s)", ev.ip, ev.dedupeID)
			continue
		}
		m.dedupeSet.MarkSeen(ev.dedupeID)

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
			Type:     proto.MsgUnban,
			NodeID:   m.cfg.NodeID,
			IP:       ev.ip,
			DedupeID: ev.dedupeID,
			Ts:       time.Now().Unix(),
		}
		m.broadcast(msg, ev.originNode)

		// Push UNBAN_EVENT to all management sessions.
		m.pushToMgmt(&proto.Message{
			Type:     proto.MsgUnbanEvent,
			NodeID:   m.cfg.NodeID,
			IP:       ev.ip,
			DedupeID: ev.dedupeID,
			Ts:       time.Now().Unix(),
		})
	}
}

// HandleIncoming processes a BAN or UNBAN message received from a peer.
// Uses non-blocking channel sends: if the pipeline is full (burst from a peer)
// the message is dropped with a warning rather than freezing the readLoop goroutine.
func (m *Manager) HandleIncoming(msg *proto.Message) {
	switch msg.Type {
	case proto.MsgBan:
		ev := banEvent{
			ip:         msg.IP,
			dedupeID:   msg.DedupeID,
			originNode: msg.NodeID,
			reason:     msg.Reason,
		}
		select {
		case m.banCh <- ev:
		default:
			logger.Warn("banCh full — dropping peer BAN for %s from %s (pipeline congested)", msg.IP, msg.NodeID)
		}
	case proto.MsgUnban:
		ev := unbanEvent{ip: msg.IP, dedupeID: msg.DedupeID, originNode: msg.NodeID}
		select {
		case m.unbanCh <- ev:
		default:
			logger.Warn("unbanCh full — dropping peer UNBAN for %s from %s (pipeline congested)", msg.IP, msg.NodeID)
		}
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
// If the node was fully isolated for more than 30 seconds, the sync flag is
// reset so the next outbound peer connection will trigger a fresh ban-list sync.
func (m *Manager) RegisterPeer(p *Peer) {
	m.mu.Lock()
	m.peers[p.remoteAddr] = p
	m.mu.Unlock()

	// Isolation check: if we were peer-less for >30s, reset sync so we catch
	// up any bans we may have missed during the outage.
	if iso := m.isolatedAt.Load(); iso != 0 {
		if time.Since(time.Unix(iso, 0)) > 30*time.Second {
			logger.Info("sync: was isolated for >30s — resetting ban-sync flag for re-sync")
			m.initialSyncDone.Store(false)
		}
		m.isolatedAt.Store(0) // back in the cluster
	}

	logger.Info("peer registered: %s (node=%s)", p.remoteAddr, p.RemoteNodeID())
	m.pushToMgmt(&proto.Message{
		Type:   proto.MsgPeerUp,
		NodeID: p.RemoteNodeID(),
		IP:     p.remoteAddr,
		Ts:     time.Now().Unix(),
	})
}

// UnregisterPeer removes a peer and pushes PEER_DOWN to management sessions.
// When the last peer drops, isolatedAt is recorded so RegisterPeer can detect
// a prolonged outage and trigger a re-sync.
func (m *Manager) UnregisterPeer(p *Peer) {
	m.mu.Lock()
	delete(m.peers, p.remoteAddr)
	remaining := len(m.peers)
	m.mu.Unlock()

	if remaining == 0 {
		logger.Info("sync: all peers disconnected — starting isolation timer")
		m.isolatedAt.Store(time.Now().Unix())
	}

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
				// Log and backoff — don't hot-spin on transient errors (e.g. EMFILE).
				logger.Warn("node server accept: %v — retrying", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// Allow-range check: reject before peer handshake if IP is not whitelisted.
			if !m.cfg.IsPeerAllowed(conn.RemoteAddr().String()) {
				logger.Warn("node server: rejected %s (not in peer_allow_ranges)", conn.RemoteAddr())
				conn.Close()
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

// TryClaimSync atomically marks the initial sync as in-progress/done.
// Returns true only for the first caller — all subsequent callers get false.
// This prevents two outbound peers from both sending SYNC_REQUEST simultaneously.
func (m *Manager) TryClaimSync() bool {
	return m.initialSyncDone.CompareAndSwap(false, true)
}

// GetActiveBans returns all unexpired bans for use in a SYNC_REPLY response.
func (m *Manager) GetActiveBans() ([]proto.BanRecord, error) {
	bans, err := m.db.GetActive()
	if err != nil {
		return nil, err
	}
	records := make([]proto.BanRecord, len(bans))
	for i, b := range bans {
		records[i] = proto.BanRecord{
			IP:        b.IP,
			DedupeID:  b.DedupeID,
			BannedAt:  b.BannedAt.Unix(),
			ExpiresAt: b.ExpiresAt.Unix(),
			Source:    b.Source,
			Reason:    b.Reason,
		}
	}
	return records, nil
}

// ApplySyncedBans applies a ban list received from a peer during initial sync.
//
// IMPORTANT: this method writes DIRECTLY to the database, iptables, and the
// dedupe set. It does NOT write to banCh and therefore does NOT broadcast
// any of these bans to other peers. The dedupe IDs are seeded so that if a
// peer later broadcasts one of these same bans via the normal mesh, it will
// be recognised as already-seen and silently dropped.
func (m *Manager) ApplySyncedBans(bans []proto.BanRecord) {
	applied := 0
	skipped := 0
	for _, b := range bans {
		// Skip IPs in the ignore list (our own node IPs, k8s subnets, etc.)
		if m.cfg.IsIgnored(b.IP) {
			skipped++
			continue
		}

		// Skip if already active in our DB (no duplicate rules).
		if active, err := m.db.IsActiveBan(b.IP); err != nil {
			logger.Warn("sync: isActiveBan %s: %v", b.IP, err)
			continue
		} else if active {
			// Still seed the dedupe ID so we don't echo it back.
			if b.DedupeID != "" {
				m.dedupeSet.MarkSeen(b.DedupeID)
			}
			skipped++
			continue
		}

		// Preserve exact timestamps from the originating node.
		bannedAt := time.Unix(b.BannedAt, 0)
		expiresAt := time.Unix(b.ExpiresAt, 0)

		// Skip if the ban has already expired on the originating node.
		if time.Now().After(expiresAt) {
			skipped++
			continue
		}

		if err := m.db.Insert(b.IP, b.DedupeID, b.Source, b.Reason, bannedAt, expiresAt); err != nil {
			logger.Warn("sync: db insert %s: %v", b.IP, err)
			continue
		}
		if err := ipt.AddBan(b.IP); err != nil {
			logger.Warn("sync: iptables add %s: %v", b.IP, err)
		}
		// Seed dedupe set so this ban is never re-broadcast.
		if b.DedupeID != "" {
			m.dedupeSet.MarkSeen(b.DedupeID)
		}
		applied++
	}
	logger.Info("sync: applied %d bans from peer (%d skipped)", applied, skipped)
}

// FlushExpired removes expired bans from iptables and DB (called by the expiry ticker).
// If the iptables removal fails, the DB row is preserved so the next tick can retry.
func (m *Manager) FlushExpired() {
	expired, err := m.db.GetExpired()
	if err != nil {
		logger.Error("expiry query: %v", err)
		return
	}
	for _, ban := range expired {
		if err := ipt.RemoveBan(ban.IP); err != nil {
			// Leave the DB row intact so the next tick retries the iptables removal.
			logger.Warn("expiry: iptables remove %s failed (%v) — will retry next tick", ban.IP, err)
			continue
		}
		logger.Info("UNBANNED %s (dedupe=%s expired)", ban.IP, ban.DedupeID)
		if err := m.db.DeleteByDedupeID(ban.DedupeID); err != nil {
			logger.Warn("expiry: db delete %s: %v", ban.DedupeID, err)
		}
	}
}
