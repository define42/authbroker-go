package main

import (
	"crypto/sha256"
	"crypto/subtle"
)

func verifyPKCE(expectedChallenge, method, verifier string) bool {
	if method != "S256" || verifier == "" || expectedChallenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	actual := base64RawURL(sum[:])
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expectedChallenge)) == 1
}
