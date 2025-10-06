package wallets

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/xrpl/hash"
)

type Signer interface {
	Sign([]byte) ([]byte, error)
}

// signSHA512HalfSecp256k1ECDSA hashes the message using (XRPL's) SHA512Half and returns the recoverable ECDSA signature of the digest.
// It uses the curve Secp256k1.
// The signature has format [R || S || V] where V is 0 or 1, and R and S have 32 bytes each.
func signSHA512HalfSecp256k1ECDSA(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := hash.Sha512Half(msg)
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// signKeccak256Secp256k1ECDSA hashes the message using Keccak256 and returns the recoverable ECDSA signature of the digest.
// It uses the curve Secp256k1.
// The signature has format [R || S || V] where V is 0 or 1, and R and S have 32 bytes each.
func signKeccak256Secp256k1ECDSA(privateKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := crypto.Keccak256(msg)
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, err
	}
	return signature, nil
}
