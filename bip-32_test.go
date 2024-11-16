package mderive

import (
	"encoding/hex"
	"testing"
)

const mnemonic = "wedding dizzy input hollow steak pig rural chimney foam sketch survey coyote ready material bulb"

func TestKey_NewChild(t *testing.T) {

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

	child, err := master.NewChild(FirstHardenedChild)
	if err != nil {
		t.Fatalf("generate new child failed: %s", err)
		return
	}

	child, err = child.NewChild(0)
	if err != nil {
		t.Fatalf("generate new child failed: %s", err)
		return
	}

	expect := "3c67bf0fcc2bd64e6dec7872a50e713bd44f146e78fcf64bca8415dfcc513e88"
	if expect != hex.EncodeToString(child.Key) {
		t.Fatalf("child key generate by m/0'/0 failed")
		return
	}
}

func TestKey_Base58(t *testing.T) {
	mnemonic := "wedding dizzy input hollow steak pig rural chimney foam sketch survey coyote ready material bulb"

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

	expect := "xprv9s21ZrQH143K32mLvbGNtzZsMdpY2bHJo5v5Eh6yxgbSLYHWT8kj7imgkDh7WjCByYsmu18vZcqTjbUVP2HxNMqGNqKdWM76PvxiYzYJ5hK"
	if expect != master.String() {
		t.Fatalf("get wrong master key by mneonic")
		return
	}
}

func TestDeserialize(t *testing.T) {
	b58 := "xprv9s21ZrQH143K32mLvbGNtzZsMdpY2bHJo5v5Eh6yxgbSLYHWT8kj7imgkDh7WjCByYsmu18vZcqTjbUVP2HxNMqGNqKdWM76PvxiYzYJ5hK"

	master, err := Base58Decode(b58)
	if err != nil {
		t.Fatalf("decode base58 to key failed: %s", err)
		return
	}

	if b58 != master.String() {
		t.Fatalf("get wrong master key by mneonic")
		return
	}
}
