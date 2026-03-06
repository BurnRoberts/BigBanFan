#!/usr/bin/env python3
"""
ipwatch.py — Single-file IP log watcher for BigBanFan
======================================================
Tails LOG_FILE (one raw IP per line) and submits each unique IP to the
local BigBanFan Unix socket. IPs are deduplicated for SEEN_TTL_HOURS before
being re-eligible.

Log line format (any of these work):
    ::ffff:207.244.239.45
    ::ffff:207.244.239.45:60884
    157.230.249.233
    2604:4300:a:27a::188
"""

import ipaddress
import os
import subprocess
import threading
import time

# ── Configuration ──────────────────────────────────────────────────────────────

LOG_FILE        = "/mnt/logs/example/ips.log"   # ← change me
BIGBANFAN_SOCK  = "/run/bigbanfan.sock"
SEEN_TTL_HOURS  = 12
SEEN_CLEANUP_INTERVAL = 3600   # seconds between cache eviction sweeps

IGNORE_RANGES = [
    "127.0.0.0/8",
    "::1/128",
    "192.168.0.0/16",      # Kubernetes pod subnet
    "10.96.0.0/16",        # Kubernetes service subnet
]
_IGNORE_NETS = [ipaddress.ip_network(r, strict=False) for r in IGNORE_RANGES]

# ── Seen Cache ─────────────────────────────────────────────────────────────────

class SeenCache:
    def __init__(self, ttl_hours=SEEN_TTL_HOURS):
        self._ttl = ttl_hours * 3600
        self._cache: dict[str, float] = {}
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
        now = time.time()
        with self._lock:
            expired = [k for k, v in self._cache.items() if now > v]
            for k in expired:
                del self._cache[k]
        return len(expired)

SEEN = SeenCache()

# ── IP Helpers ─────────────────────────────────────────────────────────────────

def normalize(raw: str) -> str | None:
    """
    Normalize a raw line into a submittable IP string.

    Handles:
      ::ffff:1.2.3.4          → 1.2.3.4
      ::ffff:1.2.3.4:56789    → 1.2.3.4   (strip port)
      [::ffff:1.2.3.4]        → 1.2.3.4   (brackets)
      2001:db8::1             → 2001:db8::1
      1.2.3.4                 → 1.2.3.4
    """
    ip = raw.strip().strip("[]")
    if not ip:
        return None

    # Strip ::ffff: prefix.
    if ip.lower().startswith("::ffff:"):
        ip = ip[7:]
        # Strip trailing :port from IPv4 (e.g. 1.2.3.4:56789).
        import re
        m = re.match(r'^(\d+\.\d+\.\d+\.\d+):\d+$', ip)
        if m:
            ip = m.group(1)

    try:
        addr = ipaddress.ip_address(ip)
        # Unwrap IPv4-mapped that survived (shouldn't happen but be safe).
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return None

def is_ignored(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _IGNORE_NETS)
    except ValueError:
        return False

# ── Submission ─────────────────────────────────────────────────────────────────

def submit(ip: str) -> None:
    if SEEN.has(ip):
        return
    if is_ignored(ip):
        return
    SEEN.add(ip)
    print(f"[+] {ip}", flush=True)
    try:
        subprocess.run(
            ["nc", "-U", BIGBANFAN_SOCK],
            input=ip + "\n",
            text=True,
            timeout=5,
            check=False,
        )
    except Exception as e:
        print(f"[!] socket error for {ip}: {e}", flush=True)

# ── File Tailer ────────────────────────────────────────────────────────────────

def follow(path: str):
    """Yield new lines from path, surviving log rotation."""
    while True:
        try:
            fh = open(path, "r")
        except FileNotFoundError:
            print(f"[!] waiting for {path}...", flush=True)
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
                time.sleep(0.5)
                try:
                    new_inode = os.stat(path).st_ino
                except FileNotFoundError:
                    new_inode = None
                if new_inode != inode:
                    print(f"[*] log rotation on {path}", flush=True)
                    break
        finally:
            fh.close()

# ── Entry Point ────────────────────────────────────────────────────────────────

def _cleanup_loop():
    while True:
        time.sleep(SEEN_CLEANUP_INTERVAL)
        n = SEEN.cleanup()
        if n:
            print(f"[seen] evicted {n} expired entries", flush=True)

if __name__ == "__main__":
    print(f"ipwatch starting — tailing {LOG_FILE}", flush=True)
    threading.Thread(target=_cleanup_loop, daemon=True, name="seen-cleanup").start()

    for line in follow(LOG_FILE):
        ip = normalize(line)
        if ip:
            submit(ip)
