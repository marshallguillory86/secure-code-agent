package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"os/exec"
)

func commandWithArgv(arg string) { exec.Command("/usr/bin/git", "status", arg) }
func strongHash(data []byte) []byte {
	h := sha256.New()
	return h.Sum(data)
}
func strongCipher(key []byte)          { aes.NewCipher(key) }
func tlsVerified() *tls.Config         { return &tls.Config{MinVersion: tls.VersionTLS13} }
func unpredictable(b []byte) (int, error) { return rand.Read(b) }
