#!/usr/bin/env python3
"""
BotCatcher9000 — Honeypot Log Monitor for BigBanFan
====================================================
Tails multiple log files, extracts offending IPs, and submits them
to the local BigBanFan Unix socket for banning across the cluster.

Log pattern modes (pass as log_pattern= to monitor_web_trap):
  1  — Apache/nginx with IPv4-mapped IPv6 prefix:
         ::ffff:78.96.72.141 - - [05/Mar/2026:22:47:01 +0000] "POST /xmlrpc.php HTTP/1.1" 444 0
       The ::ffff: prefix is stripped; the underlying IPv4 is submitted.
  2  — Standard Apache/nginx, bare IPv4 as first field:
         66.29.141.128 - - [08/Jun/2025:20:29:02 +0000] "GET /wp-login.php HTTP/1.1" 200 -
  3  — Reverse-proxy / HAProxy where first field is the CDN IP and
       second field is the real client IP:
         69.197.188.186 - 40.113.19.56 - - [24/Oct/2025:14:06:36 +0000] "GET /wsr2.php HTTP/1.1"
  callable — Pass any function(line: str) -> str|None for custom parsing.
             Return the IP string, or None to skip the line.
"""

import ipaddress
import os
import subprocess
import threading
import time

# ── Configuration ──────────────────────────────────────────────────────────────

BIGBANFAN_SOCK  = "/run/bigbanfan.sock"
SEEN_TTL_HOURS  = 12          # IPs are re-eligible for submission after this
SEEN_CLEANUP_INTERVAL = 3600  # seconds between SEEN cache eviction runs

LOG_FILE     = "/mnt/logs/bunnycalls-web/trap_ips.log"
DNS_LOG_FILE = "/var/log/syslog"

# CIDRs that should never be banned (keep in sync with bigbanfan config.yaml
# ignore_ranges).  BigBanFan also enforces this server-side, but checking here
# avoids unnecessary socket chatter.
IGNORE_RANGES = [
    "127.0.0.0/8",           # loopback
    "::1/128",               # IPv6 loopback
    "69.30.224.154/30",      # k8bunny-control
    "107.150.36.26/29",      # cdn12
    "69.197.188.186/29",     # cdn13
    "192.168.0.0/16",        # Kubernetes pod subnet
    "10.96.0.0/16",          # Kubernetes service subnet
]
_IGNORE_NETWORKS = [ipaddress.ip_network(r, strict=False) for r in IGNORE_RANGES]

# ── Seen Cache ─────────────────────────────────────────────────────────────────

class SeenCache:
    """Thread-safe IP cache with TTL expiry.

    An IP is considered 'seen' until SEEN_TTL_HOURS have elapsed since it
    was first submitted.  After expiry it becomes eligible again so that
    persistent attackers are re-evaluated and re-banned if they return after
    a ban expires.
    """

    def __init__(self, ttl_hours: float = SEEN_TTL_HOURS):
        self._ttl = ttl_hours * 3600
        self._cache: dict[str, float] = {}  # ip -> expiry timestamp
        self._lock = threading.Lock()

    def has(self, ip: str) -> bool:
        with self._lock:
            exp = self._cache.get(ip)
            if exp is None:
                return False
            if time.time() > exp:
                del self._cache[ip]
                return False
            return True

    def add(self, ip: str) -> None:
        with self._lock:
            self._cache[ip] = time.time() + self._ttl

    def cleanup(self) -> int:
        """Remove expired entries. Returns number of entries removed."""
        now = time.time()
        with self._lock:
            expired = [ip for ip, exp in self._cache.items() if now > exp]
            for ip in expired:
                del self._cache[ip]
        return len(expired)


SEEN = SeenCache(ttl_hours=SEEN_TTL_HOURS)


def _seen_cleanup_loop():
    while True:
        time.sleep(SEEN_CLEANUP_INTERVAL)
        removed = SEEN.cleanup()
        if removed:
            print(f"[seen] evicted {removed} expired entries", flush=True)


# ── IP Helpers ─────────────────────────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_ignored(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _IGNORE_NETWORKS)


def strip_mapped_ipv4(ip: str) -> str:
    """Convert ::ffff:1.2.3.4 → 1.2.3.4.  Returns ip unchanged otherwise."""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
    except ValueError:
        pass
    return ip


def extract_ip(raw: str) -> str | None:
    """
    Normalize a raw log token into a submittable IP string.

    Handles all forms seen in Apache/nginx/HAProxy logs:
      - Bare IPv4:             1.2.3.4
      - Bare IPv6:             2001:db8::1
      - IPv4-mapped IPv6:      ::ffff:1.2.3.4  → returned as 1.2.3.4
      - Bracketed IPv6:        [2001:db8::1]   (some Apache/nginx configs)
      - Bracketed IPv4-mapped: [::ffff:1.2.3.4]

    Returns a validated IP string, or None if not recognisable.
    """
    if not raw:
        return None
    # Strip surrounding brackets that some servers wrap IPv6 with.
    raw = raw.strip("[]").strip()
    # Unwrap IPv4-mapped IPv6 (::ffff:x.x.x.x → x.x.x.x).
    raw = strip_mapped_ipv4(raw)
    return raw if is_valid_ip(raw) else None

# ── Submission ─────────────────────────────────────────────────────────────────

def submit_ip(ip: str) -> None:
    """Validate, deduplicate, ignore-check, then submit ip to BigBanFan."""
    ip = ip.strip()
    if not ip:
        return
    ip = strip_mapped_ipv4(ip)
    if not is_valid_ip(ip):
        return
    if is_ignored(ip):
        print(f"[skip] {ip} matches ignore_ranges", flush=True)
        return
    if SEEN.has(ip):
        return
    SEEN.add(ip)
    print(f"[+] submitting {ip}", flush=True)
    try:
        subprocess.run(
            ["nc", "-U", BIGBANFAN_SOCK],
            input=ip + "\n",
            text=True,
            timeout=5,
            check=False,
        )
    except Exception as e:
        print(f"[!] nc error for {ip}: {e}", flush=True)


# ── Log Parsing ────────────────────────────────────────────────────────────────

def parse_ip(line: str, pattern) -> str | None:
    """
    Extract an IP from a log line according to the given pattern.

    pattern=1  IPv4-mapped IPv6 in field 0:  ::ffff:1.2.3.4 - - [...]
    pattern=2  Bare IP in field 0:            1.2.3.4 - - [...]
    pattern=3  Proxy log, real IP in field 2: cdn_ip - real_ip - - [...]
    callable   Custom parser: fn(line) -> ip_str | None
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split()
    if not parts:
        return None

    if callable(pattern):
        return pattern(line)

    if pattern == 1:
        # Field 0: bare IPv4, proper IPv6, or IPv4-mapped IPv6 (::ffff:x.x.x.x).
        # Some servers bracket IPv6: [2001:db8::1] — extract_ip handles all cases.
        return extract_ip(parts[0])

    if pattern == 2:
        # Standard Apache/nginx: client IP is the first field.
        # Works for bare IPv4, bare IPv6, and bracketed forms.
        return extract_ip(parts[0])

    if pattern == 3:
        # Reverse-proxy / HAProxy: CDN IP - real_client_ip - -
        # Real client is the third field (index 2).
        if len(parts) < 3:
            return None
        return extract_ip(parts[2])

    return None


# ── Custom Parser Examples (callable pattern) ──────────────────────────────────
#
# Any function with signature  fn(line: str) -> str | None  can be passed as
# log_pattern= to monitor_web_trap().  Return the raw IP string (or None to
# skip the line).  extract_ip() and strip_mapped_ipv4() will still be applied
# in submit_ip(), so you don't need to worry about brackets or ::ffff: here.
#
# Usage:
#   monitor_web_trap(logfile="...", log_pattern=parse_nginx_combined)
#   monitor_web_trap(logfile="...", log_pattern=lambda line: line.split()[4])

def parse_nginx_combined(line: str) -> str | None:
    """
    Parse nginx 'combined' or 'main' log format where the real client IP
    is forwarded via X-Forwarded-For and logged as the LAST ip-like token
    before the first '['.

    Example:
      1.2.3.4 - - [05/Mar/2026:22:47:01 +0000] "GET / HTTP/1.1" 200 512 "-" "-"
    → returns field 0 (same as pattern 2, kept here as a named reference).
    """
    parts = line.split()
    return extract_ip(parts[0]) if parts else None


def parse_x_forwarded_for(line: str) -> str | None:
    """
    For logs that emit the X-Forwarded-For chain as a field, pick the first
    (leftmost / original client) IP from a comma-separated list.

    Example field value:  203.0.113.5, 10.0.0.1, 192.168.1.1
    → returns 203.0.113.5
    """
    parts = line.split()
    for part in parts:
        if "," in part:
            candidate = part.split(",")[0].strip("[]")
            if is_valid_ip(candidate):
                return candidate
    # Fall back to first field.
    return extract_ip(parts[0]) if parts else None


def parse_field(n: int):
    """
    Factory: returns a parser that extracts field n (0-indexed) from a
    whitespace-split log line.

    Example — grab field 4:
      monitor_web_trap(logfile="...", log_pattern=parse_field(4))
    """
    def _parser(line: str) -> str | None:
        parts = line.split()
        if len(parts) <= n:
            return None
        return extract_ip(parts[n])
    return _parser

# ── File Tailer ────────────────────────────────────────────────────────────────

def follow(filepath: str):
    """Yield new lines from filepath, handling log rotation gracefully."""
    while True:
        try:
            fh = open(filepath, "r")
        except FileNotFoundError:
            print(f"[!] waiting for {filepath} to appear...", flush=True)
            time.sleep(5)
            continue

        fh.seek(0, os.SEEK_END)
        inode = os.fstat(fh.fileno()).st_ino

        try:
            while True:
                line = fh.readline()
                if line:
                    yield line
                    continue

                # No new data — check for rotation.
                time.sleep(0.5)
                try:
                    new_inode = os.stat(filepath).st_ino
                except FileNotFoundError:
                    new_inode = None

                if new_inode != inode:
                    print(f"[*] rotation detected on {filepath}", flush=True)
                    break  # reopen outer loop
        finally:
            fh.close()


# ── Monitor Threads ────────────────────────────────────────────────────────────

def monitor_web_trap(logfile: str = LOG_FILE, log_pattern=2):
    """
    Monitor a web honeypot / access log file.

    log_pattern controls line parsing — see parse_ip() for details.
    Default is pattern 2 (bare IPv4 as first field, standard Apache/nginx).
    """
    print(f"[*] monitoring web trap: {logfile} (pattern={log_pattern})", flush=True)
    for line in follow(logfile):
        ip = parse_ip(line, log_pattern)
        if ip:
            submit_ip(ip)


def monitor_dns_queries(logfile: str = DNS_LOG_FILE, patterns: list[str] | None = None):
    """
    Monitor syslog/named log for abusive DNS queries and ban the source.
    patterns is a list of substrings; any matching line triggers extraction.
    """
    if patterns is None:
        patterns = [
            "query (cache) 'sl/ANY/IN' denied",
            "query (cache) 'ru/ANY/IN' denied",
            "query (cache) 'cn/ANY/IN' denied",
            "query (cache) 'gsa.gov/ANY/IN' denied",
        ]
    print(f"[*] monitoring DNS log: {logfile}", flush=True)
    for line in follow(logfile):
        if not any(p in line for p in patterns):
            continue
        # Source IP appears as host#port, e.g. "1.2.3.4#52304"
        for part in line.split():
            if "#" in part:
                ip = part.split("#")[0]
                if is_valid_ip(ip):
                    submit_ip(ip)
                    break


def monitor_ssh_honeypot(logfile: str = "/var/log/ssh-honeypot.log"):
    """Monitor SSH honeypot log for [ALERT] lines and ban the source IP."""
    print(f"[*] monitoring SSH honeypot: {logfile}", flush=True)
    for line in follow(logfile):
        if "[ALERT]" not in line:
            continue
        parts = line.split()
        if len(parts) >= 2 and is_valid_ip(parts[1]):
            submit_ip(parts[1])


# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting BotCatcher9000...", flush=True)

    # Background SEEN cache cleanup thread.
    threading.Thread(target=_seen_cleanup_loop, daemon=True, name="seen-cleanup").start()

    # DNS and SSH monitors.
    threading.Thread(target=monitor_dns_queries, daemon=True, name="dns").start()
    threading.Thread(target=monitor_ssh_honeypot, daemon=True, name="ssh").start()

    # Web trap logs — adjust log_pattern per log format:
    #   1 = IPv4-mapped IPv6 prefix (::ffff:x.x.x.x)
    #   2 = bare IPv4 first field (standard Apache/nginx)
    #   3 = proxy log, real IP in field 2
    threading.Thread(
        target=monitor_web_trap,
        kwargs={"logfile": LOG_FILE, "log_pattern": 2},
        daemon=True,
        name="web-bunnycalls",
    ).start()
    threading.Thread(
        target=monitor_web_trap,
        kwargs={"logfile": "/mnt/logs/bunnycalls-cdn/trap_ips.log", "log_pattern": 2},
        daemon=True,
        name="web-cdn",
    ).start()

    # Keep the main thread alive.
    while True:
        time.sleep(60)