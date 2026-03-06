<div align="center">

# BigBanFan 🔥

**Ban once. Protected everywhere.**

*Distributed real-time IP threat response for Linux server clusters*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://kernel.org)

</div>

---

## The Problem

You're running multiple Linux servers — VPS, CDN nodes, bare metal. Attackers don't knock on one door. They hit all of them at once.

You ban a scanner on `cdn12`. It keeps hammering `cdn13`. You ban it there. It moves to `cdn14`.

You're playing whac-a-mole with `iptables` across a dozen servers while your logs fill with garbage and your team wastes time on it.

**There has to be a better way.**

---

## The Solution

BigBanFan is a lightweight Go daemon that runs on every node. The moment any node bans an IP — from a script, a honeypot log, a socket command, or auto-detected scanner behavior — **every other node applies the same rule within seconds**, automatically, with no manual intervention.

```
Node 1 detects scanner → bans it → broadcasts to cluster
                                         ↓
                              Node 2 applies rule  ✓
                              Node 3 applies rule  ✓
                              Node N applies rule  ✓
```

One ban, everywhere, instantly.

---

## Who It's For

BigBanFan is built for **DevOps and SRE teams** who:

- Run **2 or more Linux servers** (VPS, bare metal, CDN nodes, Kubernetes host nodes)
- Are already using `iptables` / `ip6tables` but managing them per-node
- Are seeing **brute force attacks, port scanners, and bot floods** across their infrastructure
- Are tired of `fail2ban` only protecting the single machine it's installed on
- Want **automation** — ban it once, forget it

**Perfect for:** Self-hosted infrastructure, CDN clusters, game servers, SaaS backends, hosting providers, security-conscious homelab operators

---

## Features

| Feature | What it means for you |
|---|---|
| **Instant cluster propagation** | One ban command → every node protected in seconds |
| **Scanner auto-ban** | IPs that probe your ports get caught and banned automatically |
| **Full IPv6 support** | `ip6tables` rules handled alongside `iptables`, native dual-stack |
| **Cluster-wide unban** | Lift a ban from every node with one command |
| **Ignore ranges** | Your own IPs are never accidentally banned |
| **Honeypot log watchers** | Python daemons feed web/DNS/SSH honeypet logs straight into the ban pipeline |
| **Persistent bans** | SQLite-backed; survives restarts and restores automatically |
| **Multiple injection methods** | Unix socket, TCP client port, Python and PHP scripts |
| **Encrypted peer mesh** | AES-256-GCM + HMAC-SHA256 between all nodes. TLS transport |

---

## How Fast Is It?

> *"In less than 10 seconds after starting the log watcher, it grabbed an IP and banned it — and it propagated through the network perfectly."*

Typical ban propagation across a 3-node cluster: **< 1 second**.

---

## Compared to Alternatives

| | BigBanFan | fail2ban | Manual iptables | Commercial WAF |
|---|---|---|---|---|
| Cluster-wide propagation | ✅ | ❌ (single node) | ❌ (manual per node) | ✅ |
| Scanner auto-detection | ✅ | ✅ | ❌ | ✅ |
| IPv6 | ✅ | ✅ | Manual | ✅ |
| Open source | ✅ | ✅ | N/A | ❌ |
| Honeypot log integration | ✅ | Partial | ❌ | ❌ |
| Cost | **Free** | Free | Free | $$$$/month |
| Operational complexity | Low | Medium | High | High |

---

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │           Encrypted TLS peer mesh           │
                    │                                             │
  [Unix socket] ──▶ │  Node A ◀──AES-256-GCM──▶ Node B            │
  [Python/PHP]  ──▶ │    │                          │             │
  [BotCatcher]  ──▶ │  iptables               iptables            │
  [Auto-detect] ──▶ │  ip6tables              ip6tables           │
                    │    │                          │             │
                    │    └──────────── Node C ──────┘             │
                    └─────────────────────────────────────────────┘
```

Each node runs a single `bigbanfan` binary. Nodes discover each other via the static peer list in config. Every ban event is deduplicated (UUID-based), so an IP is always processed exactly once per node regardless of mesh topology.

---

## Quick Start

### Requirements

- Linux (Debian, Ubuntu, RHEL, CentOS, Alpine)
- `iptables` + `ip6tables`
- Go 1.21+ (build only — binary has no runtime deps)
- Root privileges

### 1 — Build

```bash
git clone https://github.com/yourorg/bigbanfan
cd bigbanfan
make build
```

### 2 — Generate keys and certs

```bash
make gen-keys    # node_key (shared across cluster) + client_key (for scripts)
make gen-certs   # self-signed TLS cert+key for peer connections
```

### 3 — Configure each node

```bash
cp config.example.yaml /etc/bigbanfan/config.yaml
# Set: node_id (unique per node), peers, node_key, client_key, tls_cert, tls_key
```

### 4 — Install and start

```bash
cp bin/bigbanfan /usr/local/bin/bigbanfan
cp bigbanfan.service /etc/systemd/system/
systemctl enable --now bigbanfan
```

### 5 — Ban something

```bash
# On the node (instant, no auth required)
echo "1.2.3.4" | nc -U /run/bigbanfan.sock

# From your workstation
bigban 1.2.3.4

# Unban
bigban -u 1.2.3.4
```

**Done.** Every node in your cluster now has that rule.

---

## Banning & Unbanning

### From the host (Unix socket)
```bash
echo "1.2.3.4" | nc -U /run/bigbanfan.sock        # ban
echo "!1.2.3.4" | nc -U /run/bigbanfan.sock       # unban
```

### From your workstation (bigban script)

Copy `bigban`, set `HOST`, `PORT`, `KEY` at the top:
```bash
bigban 203.0.113.45           # ban — also handles ::ffff: prefixes
bigban -u 203.0.113.45        # unban
bigban 2001:db8::1            # native IPv6
```

### Python client (from any machine)
```bash
python3 scripts/bigbanfan_client.py cdn12.example.com 7778 <client_key> 1.2.3.4
python3 scripts/bigbanfan_client.py cdn12.example.com 7778 <client_key> -u 1.2.3.4
```

### PHP client
```bash
php scripts/bigbanfan_client.php cdn12.example.com 7778 <client_key> 1.2.3.4
```

---

## Scanner Auto-Ban

BigBanFan watches for IPs that hammer the node port with bad TLS, unsupported ciphers, or empty connections — classic scanner behavior. After a configurable number of failures in a time window, the IP is automatically banned and propagated to the whole cluster.

```yaml
scan_detect_enabled: true
scan_detect_threshold: 5      # failures in the window
scan_detect_window_secs: 60   # sliding window
```

Connections that open and idle (slowloris-style) are force-closed after a deadline, counted as failures, and cleaned up without leaking goroutines.

**Example log output when a scanner hits the threshold:**
```
[INFO ] scan-detect: 71.6.242.137 failure count=5/5 (window=60s)
[WARN ] scan-detect: THRESHOLD REACHED for 71.6.242.137 — auto-banning
[WARN ] scan-detect: auto-banning 71.6.242.137
[INFO ] BANNED 71.6.242.137
```

---

## Ignore Ranges

CIDR ranges in `ignore_ranges` are **never** banned — regardless of source. This protects your own node IPs, Kubernetes subnets, and management networks from being accidentally blocked.

```yaml
ignore_ranges:
  - "127.0.0.0/8"          # loopback
  - "::1/128"              # IPv6 loopback
  - "10.0.0.0/8"           # private
  - "192.168.0.0/16"       # private
  - "203.0.113.0/29"       # your CDN node subnet
```

This check runs in the Go daemon **and** in the Python scripts — double protection.

---

## BotCatcher9000

Feed your existing honeypot logs directly into BigBanFan with zero extra infrastructure.

### `ipwatch.py` — raw IP file watcher

For log files that output one IP per line (with optional `::ffff:` prefix from IPv4-mapped IPv6):

```bash
# Set LOG_FILE at the top, then:
python3 BotCatcher9000/ipwatch.py
```

Handles all formats automatically:
```
::ffff:207.244.239.45     → 207.244.239.45
::ffff:1.2.3.4:56789      → 1.2.3.4  (port stripped)
2604:4300:a:27a::188      → 2604:4300:a:27a::188
```

### `frontend.py` — multi-source monitor

Tails web honeypot logs, DNS abuse logs, and SSH honeypot logs simultaneously — and submits offending IPs in real time. Supports three Apache/nginx log patterns out of the box plus custom parser functions.

---

## Configuration Reference

| Field | Default | Description |
|---|---|---|
| `node_id` | *(required)* | Unique stable name for this node (`"cdn12"`) |
| `peers` | `[]` | Peer addresses: `["cdn13.example.com:7777"]` |
| `listen_port` | `7777` | Inter-node TLS port |
| `client_port` | `7778` | External Python/PHP client port |
| `unix_socket` | `/run/bigbanfan.sock` | Local root-only Unix socket |
| `node_key` | *(required)* | 64 hex chars — shared cluster encryption key |
| `client_key` | *(required)* | 64 hex chars — external script key |
| `tls_cert` / `tls_key` | — | TLS cert/key paths (`make gen-certs`) |
| `db_path` | `/var/lib/bigbanfan/bans.db` | SQLite ban database |
| `ban_duration_hours` | `24` | Auto-expire bans after N hours |
| `ignore_ranges` | `[]` | CIDRs that are never banned |
| `scan_detect_enabled` | `true` | Enable scanner auto-ban |
| `scan_detect_threshold` | `5` | Failures before auto-ban |
| `scan_detect_window_secs` | `60` | Detection window (seconds) |

See [`config.example.yaml`](config.example.yaml) for fully annotated examples.

---

## Security

- **Shared `node_key`** is required across all nodes — generates with `make gen-keys`
- **Separate `client_key`** for scripts — compromise doesn't expose node comms
- All inter-node frames: **AES-256-GCM encrypted + HMAC-SHA256 signed**
- **TLS transport** between all peers — no plaintext on the wire
- Unix socket is **chmod 0600 root-only** — no auth needed at that layer
- **Never commit `config.yaml`** — it contains your keys (it's in `.gitignore`)

---

## Makefile

```bash
make build       # build ./bin/bigbanfan
make gen-keys    # generate random node_key and client_key
make gen-certs   # generate self-signed TLS cert + key
make clean       # remove build artifacts
```

---

## Project Structure

```
bigbanfan/
├── main.go                        # Entry point
├── Makefile
├── config.example.yaml            # Annotated reference config
├── bigbanfan.service              # systemd unit file
├── bigban                         # Workstation ban/unban helper script
├── reload.sh                      # Node-side build + restart script
├── internal/
│   ├── config/     config.go      # Config + CIDR range validation
│   ├── proto/      messages.go    # BAN/UNBAN/HEARTBEAT wire protocol
│   │               frame.go       # AES-256-GCM + HMAC-SHA256 framing
│   ├── node/       manager.go     # Peer pool, ban/unban pipelines, broadcast
│   │               peer.go        # Per-connection read loop + handshake timeout
│   ├── ipt/        iptables.go    # iptables + ip6tables rule management
│   ├── db/         db.go          # SQLite ban persistence
│   ├── client/     client.go      # Unix socket + TCP client listener
│   ├── crypto/     crypto.go      # AES-256-GCM + HMAC helpers
│   ├── dedupe/     dedupe.go      # Event deduplication (UUID-based)
│   ├── scandetect/ detector.go    # Scanner auto-ban engine
│   └── logger/     logger.go      # Structured logging
├── scripts/
│   ├── bigbanfan_client.py        # Python client (ban + unban)
│   └── bigbanfan_client.php       # PHP client
└── BotCatcher9000/
    ├── ipwatch.py                 # Single-file raw IP log watcher
    └── frontend.py                # Multi-source honeypot log monitor
```

---

## Contributing

PRs welcome. Open an issue first for major changes.

---

## License

MIT — use it, modify it, ship it.
