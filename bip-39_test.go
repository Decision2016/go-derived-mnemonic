package mderive

import (
	"encoding/hex"
	"testing"
)

func TestNewSeedWithErrorCheck(t *testing.T) {
	seed, err := NewSeedWithErrorCheck(mnemonic, "")
	if err != nil {
		t.Fatalf("mneonic to seed failed: %s", err)
		return
	}

	seedHex := hex.EncodeToString(seed)
	expect := "0f218c2706b677329373b9fef485db3c35129de40e4f9c6a6e9d6c767087c974586ce939197b0fd64ebe1c8077102539b889b1851ea2bffdc5436f059bb74dd2"
	if seedHex != expect {
		t.Fatalf("mneonic to seed error")
		return
	}
}
