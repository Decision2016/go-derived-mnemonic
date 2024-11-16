package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"golang.org/x/crypto/ripemd160"
	"io"
	"math/big"
)

// utils for bip-39

func checkEntropyBitsLength(size int) error {
	if size < 128 || size > 256 || size%32 != 0 {
		return ErrEntropyBitsLengthInvalid
	}

	return nil
}

func addChecksum(data []byte) []byte {
	sha2 := sha256.New()
	_, _ = sha2.Write(data)
	checksum := sha2.Sum(nil)

	checksumFirstByte := checksum[0]
	checksumBitLength := uint(len(checksum) / 4)

	dataNum := new(big.Int).SetBytes(data)

	for i := uint(0); i < checksumBitLength; i++ {
		dataNum.Mul(dataNum, bigInt2)

		if checksumFirstByte&(1<<(7-i)) > 0 {
			dataNum.Or(dataNum, bigInt1)
		}
	}

	return dataNum.Bytes()
}

func paddingZero(data []byte, length int) []byte {
	offset := length - len(data)
	if offset <= 0 {
		return data
	}

	newData := make([]byte, length)
	copy(newData[offset:], data)

	return newData
}

func checkInArr(arr []int, value int) bool {
	for _, item := range arr {
		if item == value {
			return true
		}
	}

	return false
}

func setupWordList(wordlist []string) {
	wordList = wordlist
	wordMap = make(map[string]int)

	for idx, word := range wordlist {
		wordMap[word] = idx
	}
}

// utils for bip32

func addChecksumToBytes(data []byte) ([]byte, error) {
	checksum, err := checksum(data)
	if err != nil {
		return nil, err
	}
	return append(data, checksum...), nil
}

func checksum(data []byte) ([]byte, error) {
	hash, err := hashDoubleSha256(data)
	if err != nil {
		return nil, err
	}

	return hash[:4], nil
}

func hashDoubleSha256(data []byte) ([]byte, error) {
	hash1, err := hashSha256(data)
	if err != nil {
		return nil, err
	}

	hash2, err := hashSha256(hash1)
	if err != nil {
		return nil, err
	}
	return hash2, nil
}

func hashSha256(data []byte) ([]byte, error) {
	sha2 := sha256.New()
	_, err := sha2.Write(data)
	if err != nil {
		return nil, err
	}
	return sha2.Sum(nil), nil
}

func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}

func publicKeyForPrivateKey(key []byte) []byte {
	return compressPublicKey(secp256k1.ScalarBaseMult(key))
}

func compressPublicKey(x *big.Int, y *big.Int) []byte {
	var key bytes.Buffer

	key.WriteByte(byte(0x2) + byte(y.Bit(0)))

	xBytes := x.Bytes()
	for i := 0; i < (PublicKeyCompressedLength - 1 - len(xBytes)); i++ {
		key.WriteByte(0x0)
	}
	key.Write(xBytes)

	return key.Bytes()
}

func hashRipeMD160(data []byte) ([]byte, error) {
	hasher := ripemd160.New()
	_, err := io.WriteString(hasher, string(data))
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func hash160(data []byte) ([]byte, error) {
	hash1, err := hashSha256(data)
	if err != nil {
		return nil, err
	}

	hash2, err := hashRipeMD160(hash1)
	if err != nil {
		return nil, err
	}

	return hash2, nil
}

func addPrivateKeys(key1 []byte, key2 []byte) []byte {
	var key1Int big.Int
	var key2Int big.Int
	key1Int.SetBytes(key1)
	key2Int.SetBytes(key2)

	key1Int.Add(&key1Int, &key2Int)
	key1Int.Mod(&key1Int, secp256k1.Params().N)

	b := key1Int.Bytes()
	if len(b) < 32 {
		extra := make([]byte, 32-len(b))
		b = append(extra, b...)
	}
	return b
}

func expandPublicKey(key []byte) (*big.Int, *big.Int) {
	Y := big.NewInt(0)
	X := big.NewInt(0)
	X.SetBytes(key[1:])

	// y^2 = x^3 + ax^2 + b
	// a = 0
	// => y^2 = x^3 + b
	ySquared := big.NewInt(0)
	ySquared.Exp(X, big.NewInt(3), nil)
	ySquared.Add(ySquared, secp256k1.B)

	Y.ModSqrt(ySquared, secp256k1.P)

	Ymod2 := big.NewInt(0)
	Ymod2.Mod(Y, big.NewInt(2))

	signY := uint64(key[0]) - 2
	if signY != Ymod2.Uint64() {
		Y.Sub(secp256k1.P, Y)
	}

	return X, Y
}

func addPublicKeys(key1 []byte, key2 []byte) []byte {
	x1, y1 := expandPublicKey(key1)
	x2, y2 := expandPublicKey(key2)
	return compressPublicKey(secp256k1.Add(x1, y1, x2, y2))
}

func validateChildPublicKey(key []byte) error {
	x, y := expandPublicKey(key)

	if x.Sign() == 0 || y.Sign() == 0 {
		return ErrInvalidPublicKey
	}

	return nil
}
