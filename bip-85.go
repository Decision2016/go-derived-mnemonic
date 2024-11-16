package mderive

import (
	"crypto/hmac"
	"crypto/sha512"
)

var b85Path = "m/83696968'/0'/0'"

func DeriveEntropyForMnemonic(key *Key, path string) ([]byte, error) {
	derivedKey, err := DerivePrivateKey(key, path)
	if err != nil {
		return nil, err
	}

	h := hmac.New(sha512.New, []byte("bip-entropy-from-k"))
	h.Write(derivedKey.Key)
	output := h.Sum(nil)

	return output, nil
}
