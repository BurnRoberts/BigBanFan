// Package mgmt implements the BigBanFan management port server.
//
// The management port uses the same AES-256-GCM + HMAC-SHA256 frame protocol
// as the client port (internal/client), but keeps connections alive for
// bidirectional request/response and real-time push events.
//
// Authentication: same client_key as the client port.
// Default port: 7779 (cfg.MgmtPort).
package mgmt

import (
	"bigbanfan/internal/db"
	"bigbanfan/internal/logger"
	"bigbanfan/internal/node"
	"bigbanfan/internal/proto"
	"fmt"
	"net"
	"time"
)

// MgrIface is the subset of node.Manager that the mgmt server needs.
// Defined as an interface to keep the mgmt package decoupled.
type MgrIface interface {
	RegisterMgmtSession(s node.MgmtSession)
	UnregisterMgmtSession(s node.MgmtSession)
	SubmitBan(ip string)
	SubmitUnban(ip string)
	GetPeers() []proto.PeerRecord
	GetStats() proto.StatsInfo
	GetStatus() (*proto.StatusInfo, error)
}

// Server is the management port listener.
type Server struct {
	mgr       MgrIface
	db        *db.DB
	clientKey []byte
}

// New creates a management Server.
func New(mgr MgrIface, database *db.DB, clientKey []byte) *Server {
	return &Server{
		mgr:       mgr,
		db:        database,
		clientKey: clientKey,
	}
}

// Serve starts listening on the given port (dual-stack IPv4+IPv6).
func (s *Server) Serve(port int) error {
	addr := fmt.Sprintf("[::]:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("mgmt: listen %s: %w", addr, err)
	}
	logger.Info("mgmt port listening on %s (dual-stack)", addr)
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				logger.Error("mgmt: accept: %v", err)
				continue
			}
			go s.serveConn(conn)
		}
	}()
	return nil
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	sess := newSession(conn, s.clientKey, s.mgr, s.db)
	s.mgr.RegisterMgmtSession(sess)
	defer s.mgr.UnregisterMgmtSession(sess)

	logger.Info("mgmt: client connected: %s", conn.RemoteAddr())
	sess.run()
	logger.Info("mgmt: client disconnected: %s", conn.RemoteAddr())
}
