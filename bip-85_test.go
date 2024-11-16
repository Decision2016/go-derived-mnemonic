package main

import (
	"encoding/hex"
	"testing"
)

func TestDeriveEntropy(t *testing.T) {
	masterKeyB58 := "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
	key, err := Base58DecodeToKey(masterKeyB58)
	if err != nil {
		t.Fatalf("decode master to key failed: %s", err)
		return
	}

	entropy, err := DeriveEntropy(key)
	if err != nil {
		t.Fatalf("derive key to entropy failed")
		return
	}

	expect := "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"

	if expect != hex.EncodeToString(entropy) {
		t.Fatalf("get wrong entropy from master key")
		return
	}
}
