/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 NovusOrdo. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"testing"
)

func TestDeriveKeypairDeterministic(t *testing.T) {
	var seed [AuthSeedSize]byte
	var uuid [UUIDBinarySize]byte
	rand.Read(seed[:])
	rand.Read(uuid[:])

	priv1, pub1, err := DeriveKeypairFromUUID(seed, uuid)
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := DeriveKeypairFromUUID(seed, uuid)
	if err != nil {
		t.Fatal(err)
	}

	if priv1 != priv2 {
		t.Fatal("private keys differ for same inputs")
	}
	if pub1 != pub2 {
		t.Fatal("public keys differ for same inputs")
	}
}

func TestDeriveKeypairDifferentUUIDs(t *testing.T) {
	var seed [AuthSeedSize]byte
	var uuid1, uuid2 [UUIDBinarySize]byte
	rand.Read(seed[:])
	rand.Read(uuid1[:])
	rand.Read(uuid2[:])

	_, pub1, _ := DeriveKeypairFromUUID(seed, uuid1)
	_, pub2, _ := DeriveKeypairFromUUID(seed, uuid2)

	if pub1 == pub2 {
		t.Fatal("different UUIDs produced same public key")
	}
}

func TestDeriveKeypairClamping(t *testing.T) {
	var seed [AuthSeedSize]byte
	var uuid [UUIDBinarySize]byte
	rand.Read(seed[:])
	rand.Read(uuid[:])

	priv, _, err := DeriveKeypairFromUUID(seed, uuid)
	if err != nil {
		t.Fatal(err)
	}

	if priv[0]&7 != 0 {
		t.Fatal("low 3 bits of first byte not cleared")
	}
	if priv[31]&128 != 0 {
		t.Fatal("high bit of last byte not cleared")
	}
	if priv[31]&64 == 0 {
		t.Fatal("bit 6 of last byte not set")
	}
}

func TestEncryptDecryptAuthPayload(t *testing.T) {
	var seed [AuthSeedSize]byte
	var uuid [UUIDBinarySize]byte
	rand.Read(seed[:])
	rand.Read(uuid[:])

	payload, err := EncryptAuthPayload(seed, uuid)
	if err != nil {
		t.Fatal(err)
	}

	if len(payload) != AuthPayloadSize {
		t.Fatalf("payload size %d, want %d", len(payload), AuthPayloadSize)
	}

	got, err := DecryptAuthPayload(seed, payload)
	if err != nil {
		t.Fatal(err)
	}

	if got != uuid {
		t.Fatal("decrypted UUID does not match original")
	}
}

func TestDecryptWrongSeed(t *testing.T) {
	var seed1, seed2 [AuthSeedSize]byte
	var uuid [UUIDBinarySize]byte
	rand.Read(seed1[:])
	rand.Read(seed2[:])
	rand.Read(uuid[:])

	payload, _ := EncryptAuthPayload(seed1, uuid)
	_, err := DecryptAuthPayload(seed2, payload)
	if err == nil {
		t.Fatal("expected decryption failure with wrong seed")
	}
}

func TestUUIDRoundTrip(t *testing.T) {
	input := "550e8400-e29b-41d4-a716-446655440000"
	uuid, err := UUIDFromString(input)
	if err != nil {
		t.Fatal(err)
	}
	output := UUIDToString(uuid)
	if output != input {
		t.Fatalf("got %q, want %q", output, input)
	}
}

func TestUUIDFromStringNoDashes(t *testing.T) {
	_, err := UUIDFromString("550e8400e29b41d4a716446655440000")
	if err != nil {
		t.Fatal("should accept UUID without dashes")
	}
}

func TestUUIDFromStringInvalid(t *testing.T) {
	_, err := UUIDFromString("not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid UUID")
	}
}
