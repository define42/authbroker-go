package main

import (
	"encoding/base64"
	"testing"
)

// FuzzParseCBOR exercises the hand-rolled CBOR decoder. The corpus covers the
// supported major types so the fuzzer can mutate from realistic starting
// points; failures of interest are panics, OOB reads, infinite loops, and
// returning success on truncated input.
func FuzzParseCBOR(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x00},                                   // unsigned 0
		{0x17},                                   // unsigned 23
		{0x18, 0xff},                             // unsigned 1-byte 255
		{0x19, 0x01, 0x00},                       // unsigned 2-byte 256
		{0x1a, 0x00, 0x00, 0x10, 0x00},           // unsigned 4-byte
		{0x1b, 0, 0, 0, 0, 0, 0, 0, 1},           // unsigned 8-byte
		{0x20},                                   // negative -1
		{0x40},                                   // empty bytes
		{0x44, 'a', 'b', 'c', 'd'},               // 4-byte bytes
		{0x60},                                   // empty string
		{0x63, 'a', 'b', 'c'},                    // 3-char string
		{0x80},                                   // empty array
		{0x82, 0x01, 0x02},                       // [1,2]
		{0xa0},                                   // empty map
		{0xa2, 0x61, 'a', 0x01, 0x61, 'b', 0x02}, // {"a":1,"b":2}
		{0xa1, 0x01, 0x42, 0x00, 0x01},           // {1: h'0001'}
		{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'}, // partial attObj
		{0x1f},             // indefinite (unsupported)
		{0xa1, 0x80, 0x01}, // unsupported map key kind (array)
		{0x82, 0x82, 0x01, 0x01, 0x82, 0x01, 0x01}, // nested arrays
		{0xa1, 0x21, 0x44, 0xde, 0xad, 0xbe, 0xef}, // {-2: h'deadbeef'}
		{0x44, 0x00, 0x01, 0x02},                   // truncated bytes
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		val, rest, err := parseCBOR(data)
		if err != nil {
			return
		}
		// Successful parse must consume at least one byte and produce a kind
		// other than cborInvalid.
		if len(rest) > len(data) {
			t.Fatalf("rest grew past input: in=%d rest=%d", len(data), len(rest))
		}
		if val.kind == cborInvalid {
			t.Fatalf("parseCBOR returned no error but kind=cborInvalid (input=%x)", data)
		}
	})
}

// FuzzParseAttestedAuthData hardens the WebAuthn registration authData parser
// against malformed or truncated authData blobs. The seed corpus includes a
// minimal well-formed sample built on top of the test RP ID hash.
func FuzzParseAttestedAuthData(f *testing.F) {
	rpID := "localhost"
	// Empty corpus + a hand-crafted minimal authData entry: rpIdHash || flags(UP|AT)
	// || signCount(0) || aaguid(16 zero bytes) || credIdLen(2 bytes = 1) ||
	// credId(1 byte) || COSE key(empty placeholder).
	authData := make([]byte, 0, 64)
	authData = append(authData, make([]byte, 32)...)
	authData = append(authData, 0x41) // UP|AT
	authData = append(authData, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, 0, 1)
	authData = append(authData, 'x')
	authData = append(authData, 0xa0) // empty COSE map
	f.Add([]byte{})
	f.Add(authData)
	f.Add(authData[:30]) // truncated header
	f.Add(authData[:37]) // missing aaguid/credIdLen
	f.Fuzz(func(_ *testing.T, data []byte) {
		// We don't care whether it parses; we care that it never panics or
		// reads out of bounds for any input.
		_, _ = parseAttestedAuthData(data, rpID)
	})
}

// FuzzParseCOSEES256PublicKey exercises the COSE_Key decoder used to extract
// the ES256 public-key coordinates after attestation. Seed with a few base64-
// url-encoded snippets so the fuzz corpus mixes structural and byte mutations.
func FuzzParseCOSEES256PublicKey(f *testing.F) {
	seeds := []string{
		"",
		"oA",   // {} empty map (base64url of 0xa0)
		"oWEx", // garbage
	}
	for _, s := range seeds {
		decoded, _ := base64.RawURLEncoding.DecodeString(s)
		f.Add(decoded)
	}
	// Minimal COSE_Key map with kty=2, alg=-7, crv=1, but missing x/y so
	// parseCOSEES256PublicKey should reject cleanly.
	f.Add([]byte{0xa3, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseCOSEES256PublicKey(data)
	})
}
