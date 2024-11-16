package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"github.io/decision2016/go-derived-mnemonic/wordlists"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
	"strings"
)

var (
	bigInt1 = big.NewInt(1)
	bigInt2 = big.NewInt(2)

	bigIntMask11 = big.NewInt(2047)
	bigInt2048   = big.NewInt(2048)

	mnemonicLengthToMask = map[int]*big.Int{
		12: big.NewInt(15),
		15: big.NewInt(31),
		18: big.NewInt(63),
		21: big.NewInt(127),
		24: big.NewInt(255),
	}

	wordLengthToChecksumShift = map[int]*big.Int{
		12: big.NewInt(16),
		15: big.NewInt(8),
		18: big.NewInt(4),
		21: big.NewInt(2),
	}
)

var (
	wordList             []string
	wordMap              map[string]int
	validMnemonicLengths = []int{12, 15, 18, 21, 24}
)

func NewEntropy(bitSize int) ([]byte, error) {
	if err := checkEntropyBitsLength(bitSize); err != nil {
		return nil, err
	}

	newEntropy := make([]byte, bitSize)
	if _, err := rand.Read(newEntropy); err != nil {
		return nil, err
	}

	return newEntropy, nil
}

func NewMnemonic(length int) (string, error) {
	if !checkInArr(validMnemonicLengths, length) {
		return "", ErrMnemonicLengthInvalid
	}

	entropyBitLength := length * 8
	entropy, err := NewEntropy(entropyBitLength)
	if err != nil {
		return "", err
	}

	return NewMnemonicByEntropy(entropy)
}

func NewMnemonicByEntropy(entropy []byte) (string, error) {
	// bip-39 step. 2
	// calculate entropy length, checksum length and mnemonic length = (entropy + checksum) / 11
	entropyBitsLength := len(entropy) * 8
	checkBitsLength := entropyBitsLength / 32
	mnemonicLength := (entropyBitsLength + checkBitsLength) / 11

	if err := checkEntropyBitsLength(entropyBitsLength); err != nil {
		return "", err
	}

	entropy = addChecksum(entropy)

	entropyInt := new(big.Int)
	entropyInt.SetBytes(entropy)

	words := make([]string, mnemonicLength)
	word := big.NewInt(0)

	for i := mnemonicLength - 1; i >= 0; i-- {
		word.And(entropyInt, bigIntMask11)
		entropyInt.Div(entropyInt, bigInt2048)

		wordBytes := paddingZero(word.Bytes(), 2)

		words[i] = wordList[binary.BigEndian.Uint16(wordBytes)]
	}

	return strings.Join(words, " "), nil
}

func EntropyFromMnemonic(mnemonic []string) ([]byte, error) {
	if !checkInArr(validMnemonicLengths, len(mnemonic)) {
		return nil, ErrMnemonicLengthInvalid
	}

	var wordBytes [2]byte
	var b = big.NewInt(0)

	for _, word := range mnemonic {
		index, exists := wordMap[word]
		if !exists {
			return nil, fmt.Errorf("word %s not exists in wordlist", word)
		}

		binary.BigEndian.PutUint16(wordBytes[:], uint16(index))
		wordInt := new(big.Int)
		wordInt.SetBytes(wordBytes[:])

		b.Mul(b, bigInt2048)
		b.Or(b, wordInt)
	}

	checksum := big.NewInt(0)
	checksumMask := mnemonicLengthToMask[len(mnemonic)]
	checksum = checksum.And(b, checksumMask)

	t := new(big.Int)
	t.Add(checksumMask, bigInt1)
	b.Div(b, t)

	entropy := b.Bytes()
	entropy = paddingZero(entropy, len(mnemonic)/3*4)

	sha2 := sha256.New()
	sha2.Write(entropy)
	entropyChecksumByte := sha2.Sum(nil)
	entropyChecksum := big.NewInt(int64(entropyChecksumByte[0]))

	l := len(mnemonic)
	if l != 24 {
		checksumShift := wordLengthToChecksumShift[l]
		entropyChecksum.Div(entropyChecksum, checksumShift)
	}

	if checksum.Cmp(entropyChecksum) != 0 {
		return nil, ErrEntropyChecksumError
	}

	return entropy, nil
}

func MnemonicToByteArray(mnemonic string, raw ...bool) ([]byte, error) {
	splitMnemonic := strings.Fields(mnemonic)
	entropyBitsLength := len(splitMnemonic) * 11
	checksumLength := entropyBitsLength / 32
	fullByteSize := (entropyBitsLength-checksumLength)/8 + 1

	entropy, err := EntropyFromMnemonic(splitMnemonic)
	if err != nil {
		return nil, err
	}

	if len(raw) > 0 && raw[0] {
		return entropy, nil
	}

	return paddingZero(addChecksum(entropy), fullByteSize), nil
}

func NewSeedWithErrorCheck(mnemonic string, passphrase string) ([]byte, error) {
	words := strings.Fields(mnemonic)
	mnemonicWithSpace := strings.Join(words, " ")

	_, err := MnemonicToByteArray(mnemonicWithSpace)
	if err != nil {
		return nil, err
	}

	return NewSeedByMnemonic(mnemonicWithSpace, passphrase), nil
}

func NewSeedByMnemonic(mnemonic string, passphrase string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+passphrase), 2048, 64, sha512.New)
}

func init() {
	setupWordList(wordlists.English)
}
