/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// AuthPayloadSize is the total size of the auth payload embedded in handshake padding.
	// 24 (nonce) + 16 (encrypted UUID) + 16 (Poly1305 tag) = 56 bytes
	AuthPayloadSize = chacha20poly1305.NonceSizeX + 16 + chacha20poly1305.Overhead

	// UUIDBinarySize is the size of a UUID in binary form (16 bytes).
	UUIDBinarySize = 16

	// AuthSeedSize is the size of the shared seed (32 bytes).
	AuthSeedSize = 32

	hkdfSalt = "awg-auth-kdf-v1"
	hkdfInfo = "wg-private-key"
)

// AuthConfig holds the authentication configuration for a device.
type AuthConfig struct {
	// UUID is the user's hybrid UUID in binary form (16 bytes). Client-side only.
	UUID [UUIDBinarySize]byte

	// Seed is the shared secret used for key derivation and payload encryption (32 bytes).
	Seed [AuthSeedSize]byte

	// TowerEndpoint is the tower API URL for validation. Server-side only.
	// When set, the device operates in "dynamic peer" mode.
	TowerEndpoint string

	// HasUUID indicates whether a UUID has been configured (client mode).
	HasUUID bool

	// HasSeed indicates whether a seed has been configured.
	HasSeed bool
}

// DeriveKeypairFromUUID derives a WireGuard private key from a seed and UUID using HKDF.
// Returns the private key (clamped for Curve25519) and the corresponding public key.
func DeriveKeypairFromUUID(seed [AuthSeedSize]byte, uuid [UUIDBinarySize]byte) (NoisePrivateKey, NoisePublicKey, error) {
	// Build input key material: seed || uuid
	ikm := make([]byte, AuthSeedSize+UUIDBinarySize)
	copy(ikm[:AuthSeedSize], seed[:])
	copy(ikm[AuthSeedSize:], uuid[:])

	// HKDF-Extract + HKDF-Expand
	hkdfReader := hkdf.New(sha256.New, ikm, []byte(hkdfSalt), []byte(hkdfInfo))

	var privKey NoisePrivateKey
	if _, err := io.ReadFull(hkdfReader, privKey[:]); err != nil {
		return NoisePrivateKey{}, NoisePublicKey{}, fmt.Errorf("HKDF expand failed: %w", err)
	}

	// Curve25519 clamping
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	// Derive public key
	var pubKey NoisePublicKey
	pub, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return NoisePrivateKey{}, NoisePublicKey{}, fmt.Errorf("curve25519 failed: %w", err)
	}
	copy(pubKey[:], pub)

	return privKey, pubKey, nil
}

// encryptionKeyFromSeed derives the XChaCha20-Poly1305 key used to encrypt/decrypt
// the auth payload in the handshake padding.
func encryptionKeyFromSeed(seed [AuthSeedSize]byte) [32]byte {
	return sha256.Sum256(append([]byte("awg-auth-enc-v1-"), seed[:]...))
}

// EncryptAuthPayload encrypts a UUID into an auth payload suitable for embedding
// in handshake padding. Returns exactly AuthPayloadSize bytes.
//
// Format: [nonce (24 bytes)] [ciphertext (16 bytes UUID + 16 bytes tag)]
func EncryptAuthPayload(seed [AuthSeedSize]byte, uuid [UUIDBinarySize]byte) ([]byte, error) {
	key := encryptionKeyFromSeed(seed)

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt UUID
	ciphertext := aead.Seal(nil, nonce, uuid[:], nil)

	// Assemble: nonce || ciphertext
	payload := make([]byte, 0, AuthPayloadSize)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	return payload, nil
}

// DecryptAuthPayload decrypts an auth payload from handshake padding and returns the UUID.
func DecryptAuthPayload(seed [AuthSeedSize]byte, payload []byte) ([UUIDBinarySize]byte, error) {
	var uuid [UUIDBinarySize]byte

	if len(payload) < AuthPayloadSize {
		return uuid, errors.New("auth payload too short")
	}

	key := encryptionKeyFromSeed(seed)

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return uuid, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	nonce := payload[:chacha20poly1305.NonceSizeX]
	ciphertext := payload[chacha20poly1305.NonceSizeX:AuthPayloadSize]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return uuid, fmt.Errorf("auth payload decryption failed: %w", err)
	}

	if len(plaintext) != UUIDBinarySize {
		return uuid, fmt.Errorf("unexpected UUID size: %d", len(plaintext))
	}

	copy(uuid[:], plaintext)
	return uuid, nil
}

// UUIDToString converts a binary UUID to its string representation.
// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
func UUIDToString(uuid [UUIDBinarySize]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(uuid[0:4]),
		binary.BigEndian.Uint16(uuid[4:6]),
		binary.BigEndian.Uint16(uuid[6:8]),
		binary.BigEndian.Uint16(uuid[8:10]),
		uuid[10:16],
	)
}

// UUIDFromString parses a UUID string into binary form.
func UUIDFromString(s string) ([UUIDBinarySize]byte, error) {
	var uuid [UUIDBinarySize]byte

	// Remove hyphens
	clean := make([]byte, 0, 32)
	for _, c := range s {
		if c != '-' {
			clean = append(clean, byte(c))
		}
	}

	if len(clean) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d", len(clean))
	}

	// Parse hex pairs
	for i := 0; i < 16; i++ {
		hi, ok1 := hexVal(clean[i*2])
		lo, ok2 := hexVal(clean[i*2+1])
		if !ok1 || !ok2 {
			return uuid, fmt.Errorf("invalid hex at position %d", i*2)
		}
		uuid[i] = hi<<4 | lo
	}

	return uuid, nil
}

// TunnelIPFromUUID derives a unique /32 tunnel IP from a UUID.
// Uses SHA-256 of the full UUID to ensure uniform distribution even when
// UUIDs share a common prefix (hybrid UUIDs share the first 12 bytes).
// Returns an IP in the 10.128-255.X.X range to avoid conflicts with static peers.
func TunnelIPFromUUID(uuid [UUIDBinarySize]byte) [4]byte {
	h := sha256.Sum256(uuid[:])
	return [4]byte{10, h[0] | 0x80, h[1], h[2]}
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
