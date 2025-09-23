package types

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// ParsePubKey converts the serialized public key into an ECDSA key.
func ParsePubKey(key PublicKey) (*ecdsa.PublicKey, error) {
	x := new(big.Int).SetBytes(key.X[:])
	y := new(big.Int).SetBytes(key.Y[:])
	check := secp256k1.S256().IsOnCurve(x, y)
	if !check {
		return nil, errors.New("invalid public key bytes")
	}

	return &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}, nil
}

// PubKeyToStruct converts an ECDSA public key into the fixed-size struct form.
func PubKeyToStruct(key *ecdsa.PublicKey) PublicKey {
	var newKey PublicKey
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	if len(xBytes) < 32 {
		xBytes = append(make([]byte, 32-len(xBytes)), xBytes...)
	}
	if len(yBytes) < 32 {
		yBytes = append(make([]byte, 32-len(yBytes)), yBytes...)
	}

	copy(newKey.X[:], xBytes)
	copy(newKey.Y[:], yBytes)

	return newKey
}

// PubKeyToBytes returns the concatenated x and y coordinates of the key.
func PubKeyToBytes(key *ecdsa.PublicKey) []byte {
	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	if len(xBytes) < 32 {
		xBytes = append(make([]byte, 32-len(xBytes)), xBytes...)
	}
	if len(yBytes) < 32 {
		yBytes = append(make([]byte, 32-len(yBytes)), yBytes...)
	}

	return append(xBytes, yBytes...)
}
