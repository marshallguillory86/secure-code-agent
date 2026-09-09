package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/tls"
	"math/rand"
	"os/exec"
)

func commandInjection(userInput string) { exec.Command("sh", "-c", userInput) }
func weakHash(data []byte) []byte       { h := md5.New(); return h.Sum(data) }
func weakCipher(key []byte)             { des.NewCipher(key); rc4.NewCipher(key) }
func tlsDisabled() *tls.Config          { return &tls.Config{InsecureSkipVerify: true} }
func predictable() int                  { return rand.Intn(100) }
