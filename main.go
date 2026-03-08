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
	clientKey, err := crypto.ParseKey(cfg.ClientKey)
	if err != nil {
		logger.Error("parse client_key: %v", err)
		os.Exit(1)
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

	// Seed dedupe set from DB (survive reboot).
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
	if cfg.ScanDetectEnabled {
		window := time.Duration(cfg.ScanDetectWindowSecs) * time.Second
		detector := scandetect.New(cfg.ScanDetectThreshold, window, func(ip string) {
			logger.Warn("scan-detect: auto-banning %s", ip)
			mgr.SubmitBan(ip)
		})
		mgr.SetDetector(detector)
		logger.Info("scan-detect: enabled (threshold=%d failures / %ds window)",
			cfg.ScanDetectThreshold, cfg.ScanDetectWindowSecs)
	} else {
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
	banFn := func(ip string) { mgr.SubmitBan(ip) }
	unbanFn := func(ip string) { mgr.SubmitUnban(ip) }

	if err := client.ServeUnixSocket(cfg.UnixSocket, banFn, unbanFn); err != nil {
		logger.Error("unix socket: %v", err)
		os.Exit(1)
	}

	if err := client.ServeClientTCP(cfg.ClientPort, clientKey, banFn, unbanFn); err != nil {
		logger.Error("client tcp: %v", err)
		os.Exit(1)
	}

	// ── Management Port ───────────────────────────────────────────────────────
	mgmtServer := mgmt.New(mgr, database, clientKey)
	if err := mgmtServer.Serve(cfg.MgmtPort); err != nil {
		logger.Error("mgmt port: %v", err)
		os.Exit(1)
	}
	logger.Info("mgmt port: listening on :%d (client_key auth, persistent connections)", cfg.MgmtPort)

	// ── Expiry Ticker ─────────────────────────────────────────────────────────
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			mgr.FlushExpired()
		}
	}()
	logger.Info("BigBanFan v%s running — node_id=%s listen=:%d client=:%d socket=%s peers=%d",
		version, cfg.NodeID, cfg.ListenPort, cfg.ClientPort, cfg.UnixSocket, len(cfg.Peers))

	// ── Signal Handling ───────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("received signal %s — shutting down", sig)
	logger.Info("BigBanFan stopped")
}
