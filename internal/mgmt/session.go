package mgmt

import (
	"bigbanfan/internal/crypto"
	"bigbanfan/internal/db"
	"bigbanfan/internal/logger"
	"bigbanfan/internal/proto"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// Session is one connected management client.
// It implements node.MgmtSession so the manager can call Push() on it.
type Session struct {
	conn      net.Conn
	key       []byte
	mgr       MgrIface
	db        *db.DB
	onFailure FailureFunc
	logSub    bool
	logLevel  string
	pushCh    chan *proto.Message
	closeOnce sync.Once
	done      chan struct{}
}

func newSession(conn net.Conn, key []byte, mgr MgrIface, database *db.DB, onFailure FailureFunc) *Session {
	return &Session{
		conn:      conn,
		key:       key,
		mgr:       mgr,
		db:        database,
		onFailure: onFailure,
		pushCh:    make(chan *proto.Message, 256),
		done:      make(chan struct{}),
	}
}

// Push implements node.MgmtSession. Called by the manager on ban/unban/peer events.
// Non-blocking: drops the event if the push channel is full.
func (s *Session) Push(msg *proto.Message) {
	select {
	case s.pushCh <- msg:
	default:
		// Drop if the channel is full (slow client).
	}
}

// run is the main session goroutine.
func (s *Session) run() {
	go s.pushWriter()
	defer s.close()

	// Clear the 30s connect deadline — session is now live.
	s.conn.SetDeadline(time.Time{})

	decFn := func(b []byte) ([]byte, error) { return crypto.Decrypt(s.key, b) }
	verFn := func(data, sig []byte) bool { return crypto.Verify(s.key, data, sig) }

	handshakeDone := false
	for {
		raw, err := proto.ReadFrame(s.conn, decFn, verFn)
		if err != nil {
			if !handshakeDone && s.onFailure != nil {
				// Auth failure on first frame — count as a scan-detect hit.
				s.onFailure(s.conn.RemoteAddr().String())
			}
			return
		}
		handshakeDone = true
		msg, err := proto.Decode(raw)
		if err != nil {
			logger.Warn("mgmt: bad message from %s: %v", s.conn.RemoteAddr(), err)
			continue
		}
		s.handleRequest(msg)
	}
}

// close shuts down the session's push writer.
func (s *Session) close() {
	s.closeOnce.Do(func() { close(s.done) })
}

// pushWriter drains pushCh and writes out-of-band push events to the client.
func (s *Session) pushWriter() {
	encFn := func(b []byte) ([]byte, error) { return crypto.Encrypt(s.key, b) }
	signFn := func(b []byte) []byte { return crypto.Sign(s.key, b) }

	for {
		select {
		case <-s.done:
			return
		case msg := <-s.pushCh:
			data, err := msg.Encode()
			if err != nil {
				continue
			}
			if err := proto.WriteFrame(s.conn, data, encFn, signFn); err != nil {
				return // connection gone
			}
		}
	}
}

// send writes a response frame to the client synchronously.
func (s *Session) send(msg *proto.Message) {
	encFn := func(b []byte) ([]byte, error) { return crypto.Encrypt(s.key, b) }
	signFn := func(b []byte) []byte { return crypto.Sign(s.key, b) }

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	if err := proto.WriteFrame(s.conn, data, encFn, signFn); err != nil {
		logger.Warn("mgmt: send to %s: %v", s.conn.RemoteAddr(), err)
	}
}

// sendError sends a structured error reply back to the client.
func (s *Session) sendError(errMsg string) {
	s.send(&proto.Message{
		Type:     proto.MsgError,
		ErrorMsg: errMsg,
		Ts:       time.Now().Unix(),
	})
}

// handleRequest dispatches a decoded request message from the GUI client.
func (s *Session) handleRequest(msg *proto.Message) {
	switch msg.Type {

	// ── Ban / Unban ──────────────────────────────────────────────────────────

	case proto.MsgBan:
		if msg.IP == "" {
			s.sendError("ip field is required")
			return
		}
		logger.Info("mgmt: BAN %s (client=%s)", msg.IP, s.conn.RemoteAddr())
		s.mgr.SubmitBanWithReason(msg.IP, msg.Reason)

	case proto.MsgUnban:
		if msg.IP == "" {
			s.sendError("ip field is required")
			return
		}
		logger.Info("mgmt: UNBAN %s (client=%s)", msg.IP, s.conn.RemoteAddr())
		s.mgr.SubmitUnban(msg.IP)

	// ── Queries ──────────────────────────────────────────────────────────────

	case proto.MsgListBans:
		pageSize := msg.PageSize
		if pageSize <= 0 || pageSize > 200 {
			pageSize = 25
		}
		page := msg.Page
		if page < 1 {
			page = 1
		}

		bans, err := s.db.SearchBans(msg.Search, msg.FilterSource, msg.FilterActiveOnly, page, pageSize)
		if err != nil {
			s.sendError(fmt.Sprintf("list_bans query: %v", err))
			return
		}
		total, err := s.db.CountBans(msg.Search, msg.FilterSource, msg.FilterActiveOnly)
		if err != nil {
			total = -1
		}

		// Convert db.Ban → proto.BanRecord
		records := make([]proto.BanRecord, len(bans))
		for i, b := range bans {
			records[i] = proto.BanRecord{
				ID:        b.ID,
				IP:        b.IP,
				DedupeID:  b.DedupeID,
				BannedAt:  b.BannedAt.Unix(),
				ExpiresAt: b.ExpiresAt.Unix(),
				Source:    b.Source,
				Reason:    b.Reason,
			}
		}

		s.send(&proto.Message{
			Type:  proto.MsgBansList,
			Total: total,
			Page:  page,
			Bans:  records,
			Ts:    time.Now().Unix(),
		})

	case proto.MsgListPeers:
		peers := s.mgr.GetPeers()
		s.send(&proto.Message{
			Type:  proto.MsgPeersList,
			Peers: peers,
			Ts:    time.Now().Unix(),
		})

	case proto.MsgStats:
		stats := s.mgr.GetStats()
		s.send(&proto.Message{
			Type:  proto.MsgStatsReply,
			Stats: &stats,
			Ts:    time.Now().Unix(),
		})

	case proto.MsgStatus:
		status, err := s.mgr.GetStatus()
		if err != nil {
			s.sendError(fmt.Sprintf("status query: %v", err))
			return
		}
		s.send(&proto.Message{
			Type:   proto.MsgStatusReply,
			Status: status,
			Ts:     time.Now().Unix(),
		})

	// ── Log subscription ─────────────────────────────────────────────────────

	case proto.MsgLogSubscribe:
		s.logSub = true
		s.logLevel = msg.LogLevel
		if s.logLevel == "" {
			s.logLevel = "info"
		}
		logger.Info("mgmt: %s subscribed to log stream (level=%s)", s.conn.RemoteAddr(), s.logLevel)

	case proto.MsgLogUnsubscribe:
		s.logSub = false
		logger.Info("mgmt: %s unsubscribed from log stream", s.conn.RemoteAddr())

	case proto.MsgGetLogs:
		// Return the last 100 buffered log lines in chronological order.
		lines := logger.GetRecentLines()
		s.send(&proto.Message{
			Type:     proto.MsgLogsReply,
			LogLines: lines,
			Ts:       time.Now().Unix(),
		})

	default:
		logger.Warn("mgmt: unknown request type %q from %s", msg.Type, s.conn.RemoteAddr())
		s.sendError(fmt.Sprintf("unknown request type: %s", msg.Type))
	}
}

// PushLogLine delivers a log line to this session if it has subscribed.
// Called by the logger bridge (future): level is "info", "warn", or "error".
func (s *Session) PushLogLine(level, line string) {
	if !s.logSub {
		return
	}
	// Honour level filter.
	if !s.levelAllowed(level) {
		return
	}
	s.Push(&proto.Message{
		Type: proto.MsgLogLine,
		Line: line,
		Ts:   time.Now().Unix(),
	})
}

func (s *Session) levelAllowed(level string) bool {
	switch s.logLevel {
	case "error":
		return level == "error"
	case "warn":
		return level == "warn" || level == "error"
	default: // "info" and anything else
		return true
	}
}
