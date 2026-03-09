<?php
/**
 * bigbanfan_client.php — Report a bad-actor IP to a BigBanFan node,
 *                        or lift an existing ban.
 *
 * Usage:
 *   php bigbanfan_client.php <host> <port> <client_key_hex> <ip>           # ban
 *   php bigbanfan_client.php <host> <port> <client_key_hex> -u <ip>        # unban
 *   php bigbanfan_client.php <host> <port> <client_key_hex> --unban <ip>
 *
 * Optional trailing argument (ban only):
 *   php bigbanfan_client.php <host> <port> <client_key_hex> <ip> "reason text"
 *
 * Requires PHP 8.0+ with OpenSSL extension.
 * The client_key_hex must be the 32-byte (64 hex chars) client key configured
 * in BigBanFan's client_key field — NOT the node_key.
 *
 * Wire protocol:
 *   TLS 1.3 transport (self-signed cert OK — HMAC provides mutual auth)
 *   Frame = [4-byte big-endian length][32-byte HMAC-SHA256][AES-256-GCM ciphertext]
 *   Ciphertext format: [12-byte nonce][encrypted+tag bytes]
 */

// ── Argument parsing ──────────────────────────────────────────────────────────

if ($argc < 5) {
    fwrite(STDERR, "Usage: php bigbanfan_client.php <host> <port> <client_key_hex> [-u|--unban] <ip> [reason]\n");
    exit(1);
}

$host = $argv[1];
$port = (int) $argv[2];
$keyHex = $argv[3];

// Detect -u / --unban flag.
$unban = false;
$reason = '';
if ($argv[4] === '-u' || $argv[4] === '--unban') {
    $unban = true;
    if ($argc < 6) {
        fwrite(STDERR, "Usage: php bigbanfan_client.php <host> <port> <client_key_hex> --unban <ip>\n");
        exit(1);
    }
    $ipToBan = $argv[5];
    // No reason on unbans.
} else {
    $ipToBan = $argv[4];
    $reason = $argc >= 6 ? implode(' ', array_slice($argv, 5)) : '';
}

if (strlen($keyHex) !== 64) {
    fwrite(STDERR, "ERROR: client_key_hex must be 64 hex chars (32 bytes)\n");
    exit(1);
}

$key = hex2bin($keyHex);

// ── Crypto helpers ────────────────────────────────────────────────────────────

/**
 * AES-256-GCM encrypt.
 * Returns 12-byte nonce + ciphertext + 16-byte GCM tag.
 */
function bbf_encrypt(string $key, string $plaintext): string
{
    $nonce = random_bytes(12);
    $tag = '';
    $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
    if ($ct === false) {
        throw new RuntimeException("AES-GCM encrypt failed: " . openssl_error_string());
    }
    return $nonce . $ct . $tag;
}

/**
 * HMAC-SHA256 signature.
 */
function bbf_sign(string $key, string $data): string
{
    return hash_hmac('sha256', $data, $key, true);
}

/**
 * Build a length-prefixed, signed, encrypted frame.
 */
function bbf_write_frame(string $key, string $plaintext): string
{
    $ciphertext = bbf_encrypt($key, $plaintext);
    $sig = bbf_sign($key, $ciphertext);
    $payload = $sig . $ciphertext;
    $length = pack('N', strlen($payload)); // big-endian uint32
    return $length . $payload;
}

/**
 * Generate a UUIDv4 string.
 */
function uuid4(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40); // version 4
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80); // variant RFC 4122
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
}

// ── Build the message ─────────────────────────────────────────────────────────

$msgType = $unban ? 'UNBAN' : 'BAN';
$msgData = [
    'type' => $msgType,
    'node_id' => 'php-client',
    'ip' => $ipToBan,
    'dedupe_id' => uuid4(),   // must be unique per request — empty string causes server-side dedupe/SQLite conflict
    'reason' => $reason,
    'ts' => time(),
];
$msg = json_encode($msgData);
$frame = bbf_write_frame($key, $msg);

// ── TLS connect and send ──────────────────────────────────────────────────────

$action = $unban ? 'UNBAN' : 'BAN';
echo "Connecting to {$host}:{$port} (TLS 1.3) ...\n";

// Use TLS stream context. BigBanFan uses self-signed certs — skip peer verification.
// Frame-level HMAC provides mutual authentication.
$ctx = stream_context_create([
    'ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
        'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
    ],
]);

$sock = stream_socket_client(
    "tls://{$host}:{$port}",
    $errno,
    $errstr,
    10,
    STREAM_CLIENT_CONNECT,
    $ctx
);
if (!$sock) {
    fwrite(STDERR, "ERROR: TLS connect failed: {$errstr} ({$errno})\n");
    exit(1);
}

// Send the frame.
$written = fwrite($sock, $frame);
if ($written !== strlen($frame)) {
    fwrite(STDERR, "ERROR: incomplete write ({$written} of " . strlen($frame) . " bytes)\n");
    fclose($sock);
    exit(1);
}

// Graceful shutdown: send FIN (not RST) so the server can finish reading
// the frame before the connection tears down. Without this, fclose() may
// send a TCP RST which races with the server's length-prefix read.
stream_socket_shutdown($sock, STREAM_SHUT_WR);

// Drain any response the server might send before closing.
while (!feof($sock)) {
    fread($sock, 4096);
}
fclose($sock);

echo "  ✓ {$action} request sent for {$ipToBan}\n";
exit(0);
