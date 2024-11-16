package main

import (
	"encoding/hex"
	"testing"
)

func TestDerivePrivateKey(t *testing.T) {
	seed, err := NewSeedWithErrorCheck(mnemonic, "")
	if err != nil {
		t.Fatalf("mneonic to seed failed: %s", err)
		return
	}

	master, err := NewMasterKey(seed)
	if err != nil {
		t.Fatalf("seed to master key failed: %s", err)
		return
	}

	path := "m/44'/51'/0'/0/0"
	key, err := DerivePrivateKey(master, path)
	if err != nil {
		t.Fatalf("derive priavte key failed: %s", err)
		return
	}

	public := key.PublicKey()
	expect := "03e2fbc4703b2abcf3109d4941dfe8c5ee3bc22b9c120f1b64593e568562dd564e"
	if expect != hex.EncodeToString(public.Key) {
		t.Fatalf("derive wrong key from path: %s", path)
		return
	}
}
