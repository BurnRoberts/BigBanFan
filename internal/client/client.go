package client

import (
	"bigbanfan/internal/crypto"
	"bigbanfan/internal/logger"
	"bigbanfan/internal/proto"
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// BanFunc is the callback invoked when a client submits an IP to ban.
type BanFunc func(ip string)

// UnbanFunc is the callback invoked when a client requests an IP to be unbanned.
type UnbanFunc func(ip string)

// ServeUnixSocket listens on a Unix domain socket for plaintext IP injection.
//
// Protocol:
//
//	"1.2.3.4"        → ban the IP
//	"!1.2.3.4"       → unban the IP (prefix with '!')
//	"# comment"      → ignored
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
				logger.Error("unix socket accept: %v", err)
				return
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

	sc := bufio.NewScanner(conn)
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

		// Plain IP = ban request.
		ip := line
		if !isValidIPOrCIDR(ip) {
			logger.Warn("unix socket: invalid IP %q — ignored", ip)
			fmt.Fprintf(conn, "ERR: invalid IP %q\n", ip)
			continue
		}
		logger.Info("unix socket: ban request %s", ip)
		onBan(ip)
		fmt.Fprintf(conn, "OK: %s queued for ban\n", ip)
	}
}

// ServeClientTCP listens on the client TCP port for external clients (Python/PHP).
// Each connection is authenticated via frame-level AES-256-GCM + HMAC using clientKey.
func ServeClientTCP(port int, clientKey []byte, onBan BanFunc, onUnban UnbanFunc) error {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("client tcp %s: listen: %w", addr, err)
	}
	logger.Info("client TCP listening on %s", addr)
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				logger.Error("client tcp accept: %v", err)
				return
			}
			go handleClientConn(conn, clientKey, onBan, onUnban)
		}
	}()
	return nil
}

func handleClientConn(conn net.Conn, key []byte, onBan BanFunc, onUnban UnbanFunc) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	decFn := func(b []byte) ([]byte, error) { return crypto.Decrypt(key, b) }
	verFn := func(data, sig []byte) bool { return crypto.Verify(key, data, sig) }

	raw, err := proto.ReadFrame(conn, decFn, verFn)
	if err != nil {
		logger.Info("client %s disconnected: %v", conn.RemoteAddr(), err)
		return
	}

	msg, err := proto.Decode(raw)
	if err != nil {
		logger.Warn("client %s bad message: %v", conn.RemoteAddr(), err)
		return
	}

	switch msg.Type {
	case proto.MsgBan:
		if !isValidIPOrCIDR(msg.IP) {
			logger.Warn("client %s: invalid IP %q", conn.RemoteAddr(), msg.IP)
			return
		}
		logger.Info("client %s BAN %s", conn.RemoteAddr(), msg.IP)
		onBan(msg.IP)
	case proto.MsgUnban:
		if !isValidIPOrCIDR(msg.IP) {
			logger.Warn("client %s: invalid IP for unban %q", conn.RemoteAddr(), msg.IP)
			return
		}
		logger.Info("client %s UNBAN %s", conn.RemoteAddr(), msg.IP)
		if onUnban != nil {
			onUnban(msg.IP)
		}
	default:
		logger.Warn("client %s: unknown message type %q", conn.RemoteAddr(), msg.Type)
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
