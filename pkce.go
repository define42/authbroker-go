package main

import (
	"crypto/sha256"
	"crypto/subtle"
)

// RFC 7636 §4.1: code_verifier = 43*128 unreserved characters
// (ALPHA / DIGIT / "-" / "." / "_" / "~").
const (
	pkceVerifierMinLen = 43
	pkceVerifierMaxLen = 128
)

func verifyPKCE(expectedChallenge, method, verifier string) bool {
	if method != "S256" || expectedChallenge == "" {
		return false
	}
	if !validPKCEVerifier(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	actual := base64RawURL(sum[:])
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expectedChallenge)) == 1
}

func validPKCEVerifier(verifier string) bool {
	if len(verifier) < pkceVerifierMinLen || len(verifier) > pkceVerifierMaxLen {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		c := verifier[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}
