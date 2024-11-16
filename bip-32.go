// reference: https://github.com/tyler-smith/go-bip32/blob/master/bip32.go

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
)

const (
	FirstHardenedChild = uint32(0x80000000)

	PublicKeyCompressedLength = 33
)

var (
	PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")

	PublicWalletVersion, _ = hex.DecodeString("0488B21E")
)

type Key struct {
	Key         []byte
	Version     []byte
	ChildNumber []byte
	FingerPrint []byte
	ChainCode   []byte
	Depth       byte
	IsPrivate   bool
}

func NewMasterKey(seed []byte) (*Key, error) {
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, err := h.Write(seed)

	if err != nil {
		return nil, err
	}
	output := h.Sum(nil)

	keyBytes := output[:32]
	chainCode := output[32:]

	key := &Key{
		Key:         keyBytes,
		Version:     PrivateWalletVersion,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		ChainCode:   chainCode,
		Depth:       0x0,
		IsPrivate:   true,
	}

	return key, nil
}

func (key *Key) PublicKey() *Key {
	keyBytes := key.Key

	if key.IsPrivate {
		keyBytes = publicKeyForPrivateKey(keyBytes)
	}

	return &Key{
		Version:     PublicWalletVersion,
		Key:         keyBytes,
		Depth:       key.Depth,
		ChildNumber: key.ChildNumber,
		FingerPrint: key.FingerPrint,
		ChainCode:   key.ChainCode,
		IsPrivate:   false,
	}
}

func (key *Key) NewChild(childIndex uint32) (*Key, error) {
	if !key.IsPrivate && childIndex >= FirstHardenedChild {
		return nil, ErrHardnedChildPublicKey
	}

	intermediary, err := key.getIntermediary(childIndex)
	if err != nil {
		return nil, err
	}

	child := &Key{
		ChildNumber: uint32Bytes(childIndex),
		ChainCode:   intermediary[32:],
		Depth:       key.Depth + 1,
		IsPrivate:   key.IsPrivate,
	}

	if key.IsPrivate {
		child.Version = PrivateWalletVersion
		fingerprint, err := hash160(publicKeyForPrivateKey(key.Key))
		if err != nil {
			return nil, err
		}
		child.FingerPrint = fingerprint[:4]
		child.Key = addPrivateKeys(intermediary[:32], key.Key)
	} else {
		keyBytes := publicKeyForPrivateKey(intermediary[:32])

		err := validateChildPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}

		child.Version = PublicWalletVersion
		fingerprint, err := hash160(key.Key)
		if err != nil {
			return nil, err
		}
		child.FingerPrint = fingerprint[:4]
		child.Key = addPublicKeys(keyBytes, key.Key)
	}

	return child, nil
}

func (key *Key) getIntermediary(childIndex uint32) ([]byte, error) {
	childIndexBytes := uint32Bytes(childIndex)
	var data []byte
	if childIndex >= FirstHardenedChild {
		data = append([]byte{0x0}, key.Key...)
	} else {
		if key.IsPrivate {
			data = publicKeyForPrivateKey(key.Key)
		} else {
			data = key.Key
		}
	}
	data = append(data, childIndexBytes...)

	h := hmac.New(sha512.New, key.ChainCode)
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (key *Key) Serialize() ([]byte, error) {
	keyBytes := key.Key
	if key.IsPrivate {
		keyBytes = append([]byte{0x0}, keyBytes...)
	}

	buffer := new(bytes.Buffer)
	buffer.Write(key.Version)
	buffer.WriteByte(key.Depth)
	buffer.Write(key.FingerPrint)
	buffer.Write(key.ChildNumber)
	buffer.Write(key.ChainCode)
	buffer.Write(keyBytes)

	serializedKey, err := addChecksumToBytes(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	return serializedKey, nil
}

func (key *Key) Base58Encode() string {
	serializedKey, err := key.Serialize()
	if err != nil {
		return ""
	}

	return Encode(serializedKey)
}

func (key *Key) String() string {
	return key.Base58Encode()
}

func Deserialize(data []byte) (*Key, error) {
	if len(data) != 82 {
		return nil, ErrSerializedKeyWrongSize
	}
	var key = &Key{}
	key.Version = data[0:4]
	key.Depth = data[4]
	key.FingerPrint = data[5:9]
	key.ChildNumber = data[9:13]
	key.ChainCode = data[13:45]

	if data[45] == byte(0) {
		key.IsPrivate = true
		key.Key = data[46:78]
	} else {
		key.IsPrivate = false
		key.Key = data[45:78]
	}

	// validate checksum
	cs1, err := checksum(data[0 : len(data)-4])
	if err != nil {
		return nil, err
	}

	cs2 := data[len(data)-4:]
	for i := range cs1 {
		if cs1[i] != cs2[i] {
			return nil, ErrInvalidChecksum
		}
	}
	return key, nil
}

func Base58DecodeToKey(data string) (*Key, error) {
	b, err := Decode(data)
	if err != nil {
		return nil, err
	}
	return Deserialize(b)
}

func init() {
	initSecp256k1()
}
