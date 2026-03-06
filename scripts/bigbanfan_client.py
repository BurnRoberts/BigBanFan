#!/usr/bin/env python3
"""
bigbanfan_client.py — Report a bad-actor IP to a BigBanFan node,
                      or lift an existing ban.

Usage:
    python3 bigbanfan_client.py <host> <port> <client_key_hex> <ip>       # ban
    python3 bigbanfan_client.py <host> <port> <client_key_hex> -u <ip>    # unban
    python3 bigbanfan_client.py <host> <port> <client_key_hex> --unban <ip>

The client_key_hex must be the 32-byte (64 hex chars) client key configured
in BigBanFan's client_key field — NOT the node_key.

Communication is identical to the inter-node protocol:
    Frame = [4-byte length][32-byte HMAC-SHA256][AES-256-GCM ciphertext]
"""

import sys
import os
import socket
import struct
import json
import time
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def usage():
    print(__doc__)
    sys.exit(1)

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt.  Returns nonce+ciphertext."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def sign(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 signature."""
    return hmac.new(key, data, hashlib.sha256).digest()

def write_frame(sock: socket.socket, key: bytes, plaintext: bytes) -> None:
    """Encrypt, sign, and write a length-prefixed frame."""
    ciphertext = encrypt(key, plaintext)
    sig = sign(key, ciphertext)
    payload = sig + ciphertext
    length = struct.pack(">I", len(payload))
    sock.sendall(length + payload)

def main():
    args = sys.argv[1:]

    if len(args) < 4:
        usage()

    host    = args[0]
    port    = int(args[1])
    key_hex = args[2]

    # Detect -u / --unban flag.
    unban = False
    if args[3] in ("-u", "--unban"):
        unban = True
        if len(args) < 5:
            usage()
        ip = args[4]
    else:
        ip = args[3]

    if len(key_hex) != 64:
        print(f"ERROR: client_key_hex must be 64 hex chars (32 bytes), got {len(key_hex)}", file=sys.stderr)
        sys.exit(1)

    key = bytes.fromhex(key_hex)

    if not ip.strip():
        print("ERROR: IP address cannot be empty", file=sys.stderr)
        sys.exit(1)

    msg_type = "UNBAN" if unban else "BAN"
    msg = {
        "type":      msg_type,
        "node_id":   "python-client",
        "ip":        ip,
        "dedupe_id": "",
        "ts":        int(time.time()),
    }
    payload = json.dumps(msg).encode("utf-8")

    action = "UNBAN" if unban else "BAN"
    print(f"Connecting to {host}:{port} ...")
    with socket.create_connection((host, port), timeout=10) as sock:
        write_frame(sock, key, payload)
        print(f"  ✓ {action} request sent for {ip}")

if __name__ == "__main__":
    main()
