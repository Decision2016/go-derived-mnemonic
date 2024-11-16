package mderive

import (
	"fmt"
)

var (
	ErrHardnedChildPublicKey  = fmt.Errorf("can't create hardened child for public key")
	ErrInvalidPublicKey       = fmt.Errorf("invalid public key")
	ErrSerializedKeyWrongSize = fmt.Errorf("serialized keys should by exactly 82 bytes")
	ErrInvalidChecksum        = fmt.Errorf("checksum doesn't match")

	ErrEntropyBitsLengthInvalid = fmt.Errorf("entropy bits length should in range [128, 256] and as a multiple of 32")
	ErrMnemonicLengthInvalid    = fmt.Errorf("mnemonic output length must be 12, 15, 18, 21 or 24")
	ErrEntropyChecksumError     = fmt.Errorf("entropy checksum is wrong")

	ErrDerivationPathInvalid = fmt.Errorf("derivation path invalid")
)
