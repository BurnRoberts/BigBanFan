<?php
/**
 * bigbanfan_client.php — Report a bad-actor IP to a BigBanFan node.
 *
 * Usage:
 *   php bigbanfan_client.php <host> <port> <client_key_hex> <ip>
 *
 * Example:
 *   php bigbanfan_client.php cdn12.example.com 7778 \
 *       aabbccddeeff00112233445566778899aabbccddeeff001122334455667788 9.9.9.9
 *
 * Requires PHP 8.0+ with OpenSSL extension.
 * The client_key_hex must be the 32-byte (64 hex chars) client key configured
 * in BigBanFan's client_key field — NOT the node_key.
 *
 * Wire protocol (identical to Go client):
 *   Frame = [4-byte big-endian length][32-byte HMAC-SHA256][AES-256-GCM ciphertext]
 *   Ciphertext format: [12-byte nonce][encrypted+tag bytes]
 */

if ($argc !== 5) {
    fwrite(STDERR, "Usage: php bigbanfan_client.php <host> <port> <client_key_hex> <ip>\n");
    exit(1);
}

$host       = $argv[1];
$port       = (int)$argv[2];
$keyHex     = $argv[3];
$ipToBan    = $argv[4];

if (strlen($keyHex) !== 64) {
    fwrite(STDERR, "ERROR: client_key_hex must be 64 hex chars (32 bytes)\n");
    exit(1);
}

$key = hex2bin($keyHex);

/**
 * AES-256-GCM encrypt.
 * Returns 12-byte nonce + ciphertext + 16-byte GCM tag.
 */
function bbf_encrypt(string $key, string $plaintext): string {
    $nonce = random_bytes(12);
    $tag   = '';
    $ct    = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
    if ($ct === false) {
        throw new RuntimeException("AES-GCM encrypt failed: " . openssl_error_string());
    }
    return $nonce . $ct . $tag;
}

/**
 * HMAC-SHA256 signature.
 */
function bbf_sign(string $key, string $data): string {
    return hash_hmac('sha256', $data, $key, true);
}

/**
 * Build a length-prefixed, signed, encrypted frame.
 */
function bbf_write_frame(string $key, string $plaintext): string {
    $ciphertext = bbf_encrypt($key, $plaintext);
    $sig        = bbf_sign($key, $ciphertext);
    $payload    = $sig . $ciphertext;
    $length     = pack('N', strlen($payload)); // big-endian uint32
    return $length . $payload;
}

// Build the BAN message.
$msg = json_encode([
    'type'      => 'BAN',
    'node_id'   => 'php-client',
    'ip'        => $ipToBan,
    'dedupe_id' => '',
    'ts'        => time(),
]);

$frame = bbf_write_frame($key, $msg);

// Connect and send.
$errno  = 0;
$errstr = '';
echo "Connecting to {$host}:{$port} ...\n";
$sock = fsockopen($host, $port, $errno, $errstr, 10);
if (!$sock) {
    fwrite(STDERR, "ERROR: connect failed: {$errstr} ({$errno})\n");
    exit(1);
}

$written = fwrite($sock, $frame);
fclose($sock);

if ($written !== strlen($frame)) {
    fwrite(STDERR, "ERROR: incomplete write\n");
    exit(1);
}

echo "  ✓ BAN request sent for {$ipToBan}\n";
exit(0);
