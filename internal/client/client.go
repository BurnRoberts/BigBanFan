package client

import (
	"bigbanfan/internal/crypto"
	"bigbanfan/internal/logger"
	"bigbanfan/internal/proto"
	"bufio"
	cryptotls "crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// BanFunc is called when a valid BAN request is received.
// reason is optional and may be empty.
type BanFunc func(ip, reason string)

// UnbanFunc is called when a valid UNBAN request is received.
type UnbanFunc func(ip string)

// FailureFunc is called when a connection fails authentication (bad HMAC,
// decrypt error, or timeout). Used to feed the scan-detect detector.
// May be nil — in that case failures are only logged.
type FailureFunc func(remoteAddr string)

// ServeUnixSocket listens on a Unix domain socket for plaintext IP injection.
//
// Protocol:
//
//	"1.2.3.4"                → ban the IP
//	"1.2.3.4|reason text"   → ban the IP with an optional reason (pipe-delimited)
//	"!1.2.3.4"               → unban the IP (prefix with '!')
//	"# comment"              → ignored
//
// This socket is root-local-only; no encryption is applied (OS permissions protect it).
func ServeUnixSocket(path string, onBan BanFunc, onUnban UnbanFunc) error {
	// Remove stale socket file.
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("unix socket %s: listen: %w", path, err)
	}
	// Restrict to root-only access.
	if err := os.Chmod(path, 0600); err != nil {
		logger.Warn("unix socket chmod: %v", err)
	}

	logger.Info("unix socket listening: %s", path)
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				logger.Warn("unix socket accept: %v — retrying", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go handleUnixConn(conn, onBan, onUnban)
		}
	}()
	return nil
}

func handleUnixConn(conn net.Conn, onBan BanFunc, onUnban UnbanFunc) {
	defer conn.Close()

	// Set a 2-second read deadline so that after the sender stops writing
	// (e.g. echo "ip" | nc -U ...) the server-side closes the connection
	// automatically. This makes nc exit cleanly without needing Ctrl+C.
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Increase the scanner buffer to handle unusually long lines (e.g. long
	// ban reasons). Default is 64 KB which is fine for normal use, but we
	// set an explicit 256 KB limit to be safe and visible.
	const scanBufSize = 256 * 1024
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, scanBufSize), scanBufSize)
	for sc.Scan() {
		// Refresh the deadline on each received line.
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// "!ip" prefix = unban request.
		if strings.HasPrefix(line, "!") {
			ip := strings.TrimSpace(line[1:])
			if !isValidIPOrCIDR(ip) {
				logger.Warn("unix socket: invalid IP for unban %q — ignored", ip)
				fmt.Fprintf(conn, "ERR: invalid IP %q\n", ip)
				continue
			}
			logger.Info("unix socket: unban request %s", ip)
			if onUnban != nil {
				onUnban(ip)
			}
			fmt.Fprintf(conn, "OK: %s queued for unban\n", ip)
			continue
		}

		// Plain IP = ban request. Optionally includes a reason after a pipe:
		// "1.2.3.4|port scan detected"
		ip := line
		reason := ""
		if idx := strings.IndexByte(line, '|'); idx >= 0 {
			ip = strings.TrimSpace(line[:idx])
			reason = strings.TrimSpace(line[idx+1:])
		}
		if !isValidIPOrCIDR(ip) {
			logger.Warn("unix socket: invalid IP %q — ignored", ip)
			fmt.Fprintf(conn, "ERR: invalid IP %q\n", ip)
			continue
		}
		logger.Info("unix socket: ban request %s", ip)
		if onBan != nil {
			onBan(ip, reason)
		}
		fmt.Fprintf(conn, "OK: %s queued for ban\n", ip)
	}
	if err := sc.Err(); err != nil {
		logger.Warn("unix socket: scanner error from %s: %v", conn.RemoteAddr(), err)
	}
}

// ServeClientTCP listens on the client TCP port for external clients (Python/PHP).
// Each connection is wrapped in TLS 1.3 and then authenticated via AES-256-GCM
// frame-level HMAC using clientKey — same double-layer encryption as the node port.
// allowFn (optional) is called with the remote IP string; return false to reject immediately.
// onFailure (optional) is called with the remote address when auth fails.
func ServeClientTCP(port int, clientKey []byte, tlsCert, tlsKey string, allowFn func(string) bool, onBan BanFunc, onUnban UnbanFunc, onFailure FailureFunc) error {
	cert, err := cryptotls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("client tcp: load tls keypair: %w", err)
	}
	tlsCfg := &cryptotls.Config{
		Certificates: []cryptotls.Certificate{cert},
		MinVersion:   cryptotls.VersionTLS13,
		ClientAuth:   cryptotls.NoClientCert, // frame-level HMAC provides mutual auth
	}
	addr := fmt.Sprintf("[::]:%d", port)
	ln, err := cryptotls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("client tcp %s: listen: %w", addr, err)
	}
	logger.Info("client TCP listening on %s (TLS 1.3 + AES-256-GCM, dual-stack)", addr)
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				logger.Warn("client tcp accept: %v — retrying", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// Allow-range check: reject immediately if the source IP is not whitelisted.
			if allowFn != nil && !allowFn(conn.RemoteAddr().String()) {
				logger.Warn("client tcp: rejected %s (not in client_allow_ranges)", conn.RemoteAddr())
				conn.Close()
				continue
			}
			go handleClientConn(conn, clientKey, onBan, onUnban, onFailure)
		}
	}()
	return nil
}

func handleClientConn(conn net.Conn, key []byte, onBan BanFunc, onUnban UnbanFunc, onFailure FailureFunc) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fail := func(format string, args ...any) {
		logger.Info(format, args...)
		if onFailure != nil {
			onFailure(remote)
		}
	}

	decFn := func(b []byte) ([]byte, error) { return crypto.Decrypt(key, b) }
	verFn := func(data, sig []byte) bool { return crypto.Verify(key, data, sig) }

	raw, err := proto.ReadFrame(conn, decFn, verFn)
	if err != nil {
		fail("client %s failed auth: %v", remote, err)
		return
	}
	// Successful frame — clear deadline for subsequent operations.
	conn.SetDeadline(time.Time{})

	msg, err := proto.Decode(raw)
	if err != nil {
		fail("client %s bad message: %v", remote, err)
		return
	}

	switch msg.Type {
	case proto.MsgBan:
		if !isValidIPOrCIDR(msg.IP) {
			logger.Warn("client %s: invalid IP %q", remote, msg.IP)
			return
		}
		logger.Info("client %s BAN %s", remote, msg.IP)
		if onBan != nil {
			onBan(msg.IP, msg.Reason)
		}
	case proto.MsgUnban:
		if !isValidIPOrCIDR(msg.IP) {
			logger.Warn("client %s: invalid IP for unban %q", remote, msg.IP)
			return
		}
		logger.Info("client %s UNBAN %s", remote, msg.IP)
		if onUnban != nil {
			onUnban(msg.IP)
		}
	default:
		logger.Warn("client %s: unknown message type %q", remote, msg.Type)
	}
}

// isValidIPOrCIDR returns true if s is a valid IPv4/IPv6 address OR a valid
// CIDR range (e.g. "1.2.3.0/24" or "2001:db8::/32").
func isValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
