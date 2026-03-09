package main

import (
	"bigbanfan/internal/client"
	"bigbanfan/internal/config"
	"bigbanfan/internal/crypto"
	"bigbanfan/internal/db"
	"bigbanfan/internal/dedupe"
	"bigbanfan/internal/ipt"
	"bigbanfan/internal/logger"
	"bigbanfan/internal/mgmt"
	"bigbanfan/internal/node"
	"bigbanfan/internal/scandetect"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// version is set at build time by the Makefile via:
//
//	go build -ldflags "-X main.version=1.2.3"
//
// Falls back to "dev" when built without ldflags (local dev builds).
var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/bigbanfan/config.yaml", "path to config file")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("BigBanFan %s\n", version)
		os.Exit(0)
	}

	// ── Load Config ──────────────────────────────────────────────────────────
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bigbanfan: config: %v\n", err)
		os.Exit(1)
	}

	// ── Init Logger ───────────────────────────────────────────────────────────
	if err := logger.Init(cfg.LogFile, cfg.LogLevel); err != nil {
		fmt.Fprintf(os.Stderr, "bigbanfan: logger: %v\n", err)
		os.Exit(1)
	}
	logger.Info("BigBanFan v%s starting — node_id=%s", version, cfg.NodeID)
	if len(cfg.IgnoreRanges) > 0 {
		logger.Info("ignore_ranges (%d): %s", len(cfg.IgnoreRanges), strings.Join(cfg.IgnoreRanges, ", "))
	} else {
		logger.Info("ignore_ranges: none configured")
	}

	// ── Parse Keys ────────────────────────────────────────────────────────────
	nodeKey, err := crypto.ParseKey(cfg.NodeKey)
	if err != nil {
		logger.Error("parse node_key: %v", err)
		os.Exit(1)
	}
	// client_key is only required when client_port or mgmt_port is enabled.
	// config.Validate() enforces this; we guard here so an empty client_key
	// string (disabled ports) doesn't cause crypto.ParseKey to error out.
	var clientKey []byte
	if cfg.ClientPort > 0 || cfg.MgmtPort > 0 {
		clientKey, err = crypto.ParseKey(cfg.ClientKey)
		if err != nil {
			logger.Error("parse client_key: %v", err)
			os.Exit(1)
		}
	}

	// ── Open Database ─────────────────────────────────────────────────────────
	database, err := db.Open(cfg.DBPath)
	if err != nil {
		logger.Error("open database: %v", err)
		os.Exit(1)
	}
	defer database.Close()
	logger.Info("database opened: %s", cfg.DBPath)

	// ── Init Deduplication Set ────────────────────────────────────────────────
	banTTL := time.Duration(float64(time.Hour) * cfg.BanDurationHours)
	ds := dedupe.New(banTTL, 10*time.Minute)
	defer ds.Stop()

	// Seed dedupe set from DB — prevents the daemon from re-broadcasting bans
	// it already processed before the last restart (mesh loop prevention).
	// Note: seeded IDs get seenAt=now, so they expire from the in-memory set
	// after banTTL. That is fine: the banPipeline's IsActiveBan DB check is
	// the primary duplicate guard; dedupe is only the fast-path loop-breaker.
	ids, err := database.AllDedupeIDs()
	if err != nil {
		logger.Warn("seed dedupe: %v", err)
	} else {
		ds.Seed(ids)
		logger.Info("dedupe set seeded with %d existing IDs", len(ids))
	}

	// ── Setup IPTables ────────────────────────────────────────────────────────
	if err := ipt.Setup(); err != nil {
		logger.Error("iptables setup: %v", err)
		os.Exit(1)
	}
	logger.Info("iptables BANNED chain ready")

	// Flush the BANNED chain so we start clean, then re-add all active bans
	// from the DB. This guarantees exactly one rule per IP on every start or
	// restart — no stale duplicates regardless of prior state.
	if err := ipt.FlushChain(); err != nil {
		logger.Warn("flush BANNED chain: %v", err)
	}
	activeBans, err := database.GetActive()
	if err != nil {
		logger.Warn("restore active bans: %v", err)
	} else {
		for _, ban := range activeBans {
			if err := ipt.AddBan(ban.IP); err != nil {
				logger.Warn("restore ban %s: %v", ban.IP, err)
			} else {
				logger.Info("restored ban: %s (dedupe=%s expires=%s)", ban.IP, ban.DedupeID, ban.ExpiresAt.Format(time.RFC3339))
			}
		}
		logger.Info("restored %d active bans from database", len(activeBans))
	}

	// ── Node Manager ──────────────────────────────────────────────────────────
	mgr := node.NewManager(cfg, nodeKey, database, ds, version)

	// ── Scan Detection ────────────────────────────────────────────────────────
	var detStop func() // called on shutdown to stop the scan-detect cleanup goroutine
	if cfg.ScanDetectEnabled {
		window := time.Duration(cfg.ScanDetectWindowSecs) * time.Second
		detector := scandetect.New(cfg.ScanDetectThreshold, window, func(ip string) {
			logger.Warn("scan-detect: auto-banning %s", ip)
			mgr.SubmitBanWithReason(ip, "Port scan detected: banned for getting a bit too handsy with my ports.")
		})
		mgr.SetDetector(detector)
		detStop = detector.Stop
		logger.Info("scan-detect: enabled (threshold=%d failures / %ds window)",
			cfg.ScanDetectThreshold, cfg.ScanDetectWindowSecs)
	} else {
		detStop = func() {}
		logger.Info("scan-detect: disabled")
	}

	mgr.Start()

	// Start inter-node TLS server.
	if err := mgr.StartServer(cfg.TLSCert, cfg.TLSKey); err != nil {
		logger.Error("node server: %v", err)
		os.Exit(1)
	}

	// Connect to configured peers.
	for _, peer := range cfg.Peers {
		mgr.ConnectToPeer(peer, cfg.TLSCert, cfg.TLSKey)
	}

	// ── Client Layer ──────────────────────────────────────────────────────────
	banFn := func(ip, reason string) { mgr.SubmitBanWithReason(ip, reason) }
	unbanFn := func(ip string) { mgr.SubmitUnban(ip) }

	// failFn feeds failed connections into scan-detect (auto-ban on threshold).
	// Nil when scan-detect is disabled so both ports stay nil-safe.
	var failFn client.FailureFunc
	if cfg.ScanDetectEnabled && mgr.Detector() != nil {
		det := mgr.Detector()
		failFn = func(remoteAddr string) {
			if !cfg.IsIgnored(remoteAddr) {
				det.RecordFailure(remoteAddr)
			}
		}
	}

	if cfg.UnixSocket != "" {
		if err := client.ServeUnixSocket(cfg.UnixSocket, banFn, unbanFn); err != nil {
			logger.Error("unix socket: %v", err)
			os.Exit(1)
		}
	} else {
		logger.Info("unix socket disabled (unix_socket not set)")
	}

	// ── Client TCP Port (optional — disabled when client_port = 0) ────────────
	if cfg.ClientPort > 0 {
		if err := client.ServeClientTCP(
			cfg.ClientPort, clientKey, cfg.TLSCert, cfg.TLSKey,
			cfg.IsClientAllowed,
			banFn, unbanFn, failFn,
		); err != nil {
			logger.Error("client tcp: %v", err)
			os.Exit(1)
		}
	} else {
		logger.Info("client port disabled (client_port = 0)")
	}

	// ── Management Port (optional — disabled when mgmt_port = 0) ────────────
	if cfg.MgmtPort > 0 {
		mgmtServer := mgmt.New(mgr, database, clientKey, cfg.TLSCert, cfg.TLSKey,
			mgmt.FailureFunc(failFn), cfg.IsMgmtAllowed)
		if err := mgmtServer.Serve(cfg.MgmtPort); err != nil {
			logger.Error("mgmt port: %v", err)
			os.Exit(1)
		}
		logger.Info("mgmt port: listening on :%d (client_key auth, persistent connections)", cfg.MgmtPort)
	} else {
		logger.Info("mgmt port disabled (mgmt_port = 0)")
	}

	// ── Expiry Ticker ─────────────────────────────────────────────────────────
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			mgr.FlushExpired()
		}
	}()
	clientInfo := "disabled"
	if cfg.ClientPort > 0 {
		clientInfo = fmt.Sprintf(":%d", cfg.ClientPort)
	}
	mgmtInfo := "disabled"
	if cfg.MgmtPort > 0 {
		mgmtInfo = fmt.Sprintf(":%d", cfg.MgmtPort)
	}
	logger.Info("BigBanFan v%s running — node_id=%s listen=:%d client=%s mgmt=%s socket=%s peers=%d",
		version, cfg.NodeID, cfg.ListenPort, clientInfo, mgmtInfo, cfg.UnixSocket, len(cfg.Peers))

	// ── Signal Handling ───────────────────────────────────────────────────────
	// SIGTERM/SIGINT → graceful shutdown.
	// SIGHUP         → reopen log file (logrotate support — no daemon restart needed).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			logger.Info("received SIGHUP — reopening log file")
			if err := logger.Reopen(); err != nil {
				logger.Warn("log reopen failed: %v", err)
			} else {
				logger.Info("log file reopened successfully")
			}
		default:
			logger.Info("received signal %s — shutting down", sig)
			mgr.Shutdown() // unblocks reconnect goroutines sleeping in select
			detStop()
			logger.Info("BigBanFan stopped")
			return
		}
	}
}
