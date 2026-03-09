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
	cryptotls "crypto/tls"
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
	SubmitBanWithReason(ip, reason string)
	SubmitUnban(ip string)
	GetPeers() []proto.PeerRecord
	GetStats() proto.StatsInfo
	GetStatus() (*proto.StatusInfo, error)
}

// FailureFunc is called when a management connection fails authentication.
// Wire in the scan-detect detector to auto-ban attackers.
type FailureFunc func(remoteAddr string)

// Server is the management port listener.
type Server struct {
	mgr       MgrIface
	db        *db.DB
	clientKey []byte
	tlsCert   string
	tlsKey    string
	onFailure FailureFunc
	allowFn   func(string) bool // nil = allow all
}

// New creates a management Server.
func New(mgr MgrIface, database *db.DB, clientKey []byte, tlsCert, tlsKey string, onFailure FailureFunc, allowFn func(string) bool) *Server {
	return &Server{
		mgr:       mgr,
		db:        database,
		clientKey: clientKey,
		tlsCert:   tlsCert,
		tlsKey:    tlsKey,
		onFailure: onFailure,
		allowFn:   allowFn,
	}
}

// Serve starts listening on the management port.
func (s *Server) Serve(port int) error {
	cert, err := cryptotls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
	if err != nil {
		return fmt.Errorf("mgmt: load tls keypair: %w", err)
	}
	tlsCfg := &cryptotls.Config{
		Certificates: []cryptotls.Certificate{cert},
		MinVersion:   cryptotls.VersionTLS13,
		ClientAuth:   cryptotls.NoClientCert,
	}
	addr := fmt.Sprintf("[::]:%d", port)
	ln, err := cryptotls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("mgmt listen %s: %w", addr, err)
	}
	logger.Info("mgmt listening on %s (TLS 1.3 + AES-256-GCM, dual-stack)", addr)
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Log and backoff — don't hot-spin on transient errors (e.g. EMFILE).
				logger.Warn("mgmt accept: %v — retrying", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// Allow-range check: reject before TLS handshake if IP is not whitelisted.
			if s.allowFn != nil && !s.allowFn(conn.RemoteAddr().String()) {
				logger.Warn("mgmt: rejected %s (not in mgmt_allow_ranges)", conn.RemoteAddr())
				conn.Close()
				continue
			}
			go s.serveConn(conn)
		}
	}()
	return nil
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	sess := newSession(conn, s.clientKey, s.mgr, s.db, s.onFailure)
	s.mgr.RegisterMgmtSession(sess)
	defer s.mgr.UnregisterMgmtSession(sess)

	logger.Info("mgmt: client connected: %s", remote)
	sess.run()
	logger.Info("mgmt: client disconnected: %s", remote)
}
