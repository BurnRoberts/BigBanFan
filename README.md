<div align="center">

<img src="assets/banner.png" alt="BigBanFan" width="420" />


*Distributed real-time IP threat response for Linux server clusters*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://kernel.org)

</div>

---

## The Problem

You're running multiple Linux servers: VPS, CDN nodes, bare metal. Attackers don't knock on one door. They hit all of them at once.

You ban a scanner on `cdn12`. It keeps hammering `cdn13`. You ban it there. It moves to `cdn14`.

You're playing whac-a-mole with `iptables` across a dozen servers while your logs fill with garbage and your team wastes time on it.

**There has to be a better way.**

---

## The Solution

BigBanFan is a lightweight Go daemon that runs on every node. The moment any node bans an IP (from a script, a honeypot log, a socket command, or auto-detected scanner behavior), **every other node applies the same rule within seconds**, automatically, with no manual intervention.

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
- Want **automation**: ban it once, forget it

**Perfect for:** Self-hosted infrastructure, CDN clusters, game servers, SaaS backends, hosting providers, security-conscious homelab operators

---

## Features

| Feature | What it means for you |
|---|---|
| **Instant cluster propagation** | One ban command → every node protected in seconds |
| **Scanner auto-ban** | IPs that probe your ports get caught and banned automatically |
| **Full IPv6 support** | `ip6tables` rules handled alongside `iptables`, native dual-stack |
| **Cluster-wide unban** | Lift a ban from every node with one command |
| **Ban reasons** | Attach a reason to any ban. Stored, propagated, and queryable |
| **Remote GUI management** | Full cluster control from a desktop GUI, no SSH required |
| **Ignore ranges** | Your own IPs are never accidentally banned |
| **Honeypot log watchers** | Python daemons feed web/DNS/SSH honeypot logs straight into the ban pipeline |
| **Persistent bans** | SQLite-backed; survives restarts and restores automatically |
| **Multiple input methods** | Unix socket, TCP client port, Python and PHP scripts |
| **Per-port access control** | Allowlist which IPs can connect to each port independently |
| **Encrypted peer mesh** | AES-256-GCM + HMAC-SHA256 between all nodes. TLS 1.3 transport |

---

## How Fast Is It?

> *"In less than 10 seconds after starting the log watcher, it grabbed an IP and banned it. It propagated through the network perfectly."*

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
| Remote GUI | ✅ | ❌ | ❌ | ✅ |
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
  [GUI / mgmt]  ──▶ │    │                          │             │
                    │    └──────────── Node C ──────┘             │
                    └─────────────────────────────────────────────┘
```

Each node runs a single `bigbanfan` binary. Nodes discover each other via the static peer list in config. Every ban event is deduplicated (UUID-based), so an IP is always processed exactly once per node regardless of mesh topology.

---

## Quick Start

### Requirements

- Linux (Debian, Ubuntu, RHEL, CentOS, Alpine)
- `iptables` + `ip6tables`
- Go 1.21+ (build only, the binary has no runtime dependencies)
- Root privileges

### 1. Build

```bash
git clone https://github.com/BurnRoberts/BigBanFan
cd bigbanfan
make build
```

### 2. Generate keys and certs

```bash
make gen-keys    # node_key (shared across cluster) + client_key (for scripts/GUI)
make gen-certs   # self-signed TLS cert+key for peer connections
```

### 3. Configure each node

```bash
cp config.example.yaml /etc/bigbanfan/config.yaml
# Set: node_id (unique per node), peers, node_key, client_key, tls_cert, tls_key
```

### 4. Install and start

```bash
cp bin/bigbanfan /usr/local/bin/bigbanfan
cp bigbanfan.service /etc/systemd/system/
systemctl enable --now bigbanfan
```

### 5. Ban something

```bash
# On the node (instant, no auth required)
echo "1.2.3.4" | nc -U /run/bigbanfan.sock

# With a reason
echo "1.2.3.4|ssh brute force" | nc -U /run/bigbanfan.sock

# From your workstation
bigban 1.2.3.4
bigban 1.2.3.4 "repeat offender"

# Unban
bigban -u 1.2.3.4
```

**Done.** Every node in your cluster now has that rule.

---

## Banning & Unbanning

### From the host (Unix socket)
```bash
echo "1.2.3.4" | nc -U /run/bigbanfan.sock           # ban
echo "1.2.3.4|reason text" | nc -U /run/bigbanfan.sock # ban with reason
echo "!1.2.3.4" | nc -U /run/bigbanfan.sock           # unban
```

### From your workstation (bigban script)

Copy `bigban`, set `HOST`, `PORT`, `KEY` at the top:
```bash
bigban 203.0.113.45                     # ban
bigban 203.0.113.45 "reason text"       # ban with reason
bigban -u 203.0.113.45                  # unban
bigban 2001:db8::1                      # native IPv6
```

### Python client (from any machine)
```bash
python3 scripts/bigbanfan_client.py cdn12.example.com 7778 <client_key> 1.2.3.4
python3 scripts/bigbanfan_client.py cdn12.example.com 7778 <client_key> 1.2.3.4 --reason "port scan"
python3 scripts/bigbanfan_client.py cdn12.example.com 7778 <client_key> -u 1.2.3.4
```

### PHP client
```bash
php scripts/bigbanfan_client.php cdn12.example.com 7778 <client_key> 1.2.3.4
```

---

## Remote GUI Management

A desktop GUI client ([bigbanfan-gui](https://github.com/BurnRoberts/BigBanFan-Gui)) connects to the management port (`mgmt_port`, default `:7779`) and provides full cluster control without SSH access.

Enable the management port in your config:
```yaml
mgmt_port: 7779
client_key: "your-64-hex-char-client-key"
```

GUI capabilities:
- Live ban and unban feed, updates the moment any node in the cluster acts
- Search, filter, and paginate the full ban history by IP, source node, or active-only
- View cluster topology, peer connection state, and last-seen times
- Real-time log stream, filterable by severity level (info / warn / error)
- Fetch the last 100 buffered log lines immediately on connect
- Issue cluster-wide ban and unban commands with an optional reason
- Query node health, version, uptime, and session statistics

The management port uses the same TLS 1.3 + AES-256-GCM + HMAC-SHA256 frame protocol as the client port. It is **disabled by default**. Set `mgmt_port` in your config to enable it.

---

## Scanner Auto-Ban

BigBanFan watches for IPs that hammer the node port with bad TLS, unsupported ciphers, or empty connections. This is classic scanner behavior. After a configurable number of failures in a time window, the IP is automatically banned and propagated to the whole cluster.

```yaml
scan_detect_enabled: true
scan_detect_threshold: 5      # failures in the window
scan_detect_window_secs: 60   # sliding window
```

Connections that open and idle (slowloris-style) are force-closed after a deadline, counted as failures, and cleaned up without leaking goroutines.

**Example log output when a scanner hits the threshold:**
```
[INFO ] scan-detect: 71.6.242.137 failure count=5/5 (window=60s)
[WARN ] scan-detect: THRESHOLD REACHED for 71.6.242.137, auto-banning
[INFO ] BANNED 71.6.242.137
```

---

## Ignore Ranges

CIDR ranges in `ignore_ranges` are **never** banned, regardless of source. This protects your own node IPs, Kubernetes subnets, and management networks from being accidentally blocked.

```yaml
ignore_ranges:
  - "127.0.0.0/8"          # loopback
  - "::1/128"              # IPv6 loopback
  - "10.0.0.0/8"           # private
  - "192.168.0.0/16"       # private
```

This check runs before any ban is applied, whether it arrives via socket, TCP client, or peer propagation.

---

## Per-Port Access Control

Each port has its own IP allowlist. Connections from IPs not in the allowlist are dropped before any TLS handshake or authentication attempt.

```yaml
# Only your node IPs can reach the peer mesh port
peer_allow_ranges:
  - "192.0.2.0/24"
  - "198.51.100.0/24"

# Only your workstation can reach the management GUI port
mgmt_allow_ranges:
  - "192.168.1.0/24"

# client_allow_ranges controls the client submission port
# client_allow_ranges:
#   - "10.0.0.0/8"
```

All three default to `["0.0.0.0/0", "::/0"]` (allow all) if not specified, so existing deployments need no config changes.

---

## BotCatcher9000

Feed your existing honeypot logs directly into BigBanFan with zero extra infrastructure.

### `ipwatch.py` - raw IP file watcher

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

### `frontend.py` - multi-source monitor

Tails web honeypot logs, DNS abuse logs, and SSH honeypot logs simultaneously and submits offending IPs in real time. Supports three Apache/nginx log patterns out of the box plus custom parser functions.

---

## Configuration Reference

| Field | Default | Description |
|---|---|---|
| `node_id` | *(required)* | Unique stable name for this node (`"cdn12"`) |
| `peers` | `[]` | Peer addresses: `["cdn13.example.com:7777"]` |
| `max_peers` | `8` | Maximum simultaneous outbound peer connections |
| `listen_port` | `7777` | Inter-node TLS port |
| `client_port` | `0` (disabled) | External Python/PHP client port. Set a port number to enable |
| `mgmt_port` | `0` (disabled) | Management GUI port. Set a port number to enable |
| `unix_socket` | `/run/bigbanfan.sock` | Local root-only Unix socket. Set to `""` to disable |
| `node_key` | *(required)* | 64 hex chars, shared cluster encryption key |
| `client_key` | *(required if client_port or mgmt_port > 0)* | 64 hex chars, client/GUI auth key |
| `tls_cert` / `tls_key` | *(required)* | TLS cert/key paths (`make gen-certs`) |
| `db_path` | `/var/lib/bigbanfan/bans.db` | SQLite ban database |
| `log_file` | `/var/log/bigbanfan.log` | Log file path |
| `log_level` | `info` | Minimum log level: `info`, `warn`, `error` |
| `ban_duration_hours` | `24` | Auto-expire bans after N hours |
| `ignore_ranges` | `[]` | CIDRs that are never banned |
| `peer_allow_ranges` | allow-all | CIDRs allowed to connect to `listen_port` |
| `client_allow_ranges` | allow-all | CIDRs allowed to connect to `client_port` |
| `mgmt_allow_ranges` | allow-all | CIDRs allowed to connect to `mgmt_port` |
| `scan_detect_enabled` | `true` | Enable scanner auto-ban |
| `scan_detect_threshold` | `5` | Failures before auto-ban |
| `scan_detect_window_secs` | `60` | Detection window (seconds) |

See [`config.example.yaml`](config.example.yaml) for fully annotated examples.

---

## Security

- **Shared `node_key`** is required across all nodes. Generate with `make gen-keys`
- **Separate `client_key`** for scripts and GUI. A compromised client key does not expose inter-node comms
- All inter-node frames: **AES-256-GCM encrypted + HMAC-SHA256 signed**
- **TLS 1.3** transport between all peers. No plaintext on the wire
- Unix socket is **chmod 0600 root-only**. No auth needed at that layer
- Per-port allowlists drop connections before any handshake
- Failed auth attempts on client and management ports count toward scan detection
- **Never commit `config.yaml`**. It contains your keys (it's in `.gitignore`)

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
├── MGMT_API.md                    # Management port protocol reference
├── internal/
│   ├── config/     config.go      # Config + CIDR range validation
│   ├── proto/      messages.go    # Wire protocol message types
│   │               frame.go       # AES-256-GCM + HMAC-SHA256 framing
│   ├── node/       manager.go     # Peer pool, ban/unban pipelines, broadcast
│   │               peer.go        # Per-connection read loop + handshake timeout
│   ├── ipt/        iptables.go    # iptables + ip6tables rule management
│   ├── db/         db.go          # SQLite ban persistence
│   ├── client/     client.go      # Unix socket + TCP client listener
│   ├── mgmt/       server.go      # Management port server
│   │               session.go     # Per-client management session handler
│   ├── crypto/     crypto.go      # AES-256-GCM + HMAC helpers
│   ├── dedupe/     dedupe.go      # Event deduplication (UUID-based)
│   ├── scandetect/ detector.go    # Scanner auto-ban engine
│   └── logger/     logger.go      # Structured logging + ring buffer
├── scripts/
│   ├── bigbanfan_client.py        # Python client (ban + unban + reason)
│   └── bigbanfan_client.php       # PHP client (ban + unban + reason)
└── BotCatcher9000/
    ├── ipwatch.py                 # Single-file raw IP log watcher
    └── frontend.py                # Multi-source honeypot log monitor
```

---

## Contributing

PRs welcome. Open an issue first for major changes.

---

## License

MIT. Use it, modify it, ship it.
