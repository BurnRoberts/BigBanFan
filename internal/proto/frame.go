package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame wire format (per direction):
//
//  ┌────────────┬──────────────┬──────────────────────────┐
//  │ 4 bytes    │ 32 bytes     │ N bytes                  │
//  │ length (N) │ HMAC-SHA256  │ AES-256-GCM ciphertext   │
//  └────────────┴──────────────┴──────────────────────────┘
//
// Both the HMAC and the ciphertext length are included in N.
// The HMAC covers only the ciphertext bytes.

const hmacSize = 32

// WriteFrame encrypts plaintext, signs it, and writes a framed message to w.
// encryptFn and signFn are provided by the caller (bound to the session key).
func WriteFrame(w io.Writer, plaintext []byte, encryptFn func([]byte) ([]byte, error), signFn func([]byte) []byte) error {
	ct, err := encryptFn(plaintext)
	if err != nil {
		return fmt.Errorf("frame write: encrypt: %w", err)
	}
	sig := signFn(ct)

	payload := make([]byte, hmacSize+len(ct))
	copy(payload[:hmacSize], sig)
	copy(payload[hmacSize:], ct)

	length := uint32(len(payload))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return fmt.Errorf("frame write: length prefix: %w", err)
	}
	_, err = w.Write(payload)
	return err
}

// ReadFrame reads a framed message from r, verifies it, and returns the plaintext.
func ReadFrame(r io.Reader, decryptFn func([]byte) ([]byte, error), verifyFn func(data, sig []byte) bool) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("frame read: length prefix: %w", err)
	}
	// 4 MB hard cap: enough for a SYNC_REPLY with tens of thousands of bans.
	// The original 64 MB cap allowed a single malicious peer to force a 64 MB
	// heap allocation per connection — a trivial OOM DoS vector.
	const maxFrameSize = 4 * 1024 * 1024 // 4 MB
	if length > maxFrameSize {
		return nil, fmt.Errorf("frame read: frame too large (%d bytes, max %d)", length, maxFrameSize)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("frame read: body: %w", err)
	}
	if len(payload) < hmacSize {
		return nil, fmt.Errorf("frame read: payload too short for HMAC")
	}
	sig := payload[:hmacSize]
	ct := payload[hmacSize:]

	if !verifyFn(ct, sig) {
		return nil, fmt.Errorf("frame read: HMAC verification failed")
	}
	plain, err := decryptFn(ct)
	if err != nil {
		return nil, fmt.Errorf("frame read: decrypt: %w", err)
	}
	return plain, nil
}
