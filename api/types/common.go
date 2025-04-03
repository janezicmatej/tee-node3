package types

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/pkg/errors"
)

// Something that is common to all/most responses
type ResponseBase struct {
	Status string
	Token  string
}

// // Implement the SetBase method directly on ResponseBase
// func (r *ResponseBase) SetBase(status, attestation string) {
// 	r.Status = status
// 	r.AttestationToken = attestation
// }

// type IResponseBase interface {
// 	SetBase(status, attestation string)
// }

type SignatureMessage struct {
	Signature []byte
	PublicKey *ECDSAPublicKey
}

type ECDSAPublicKey struct {
	X string
	Y string
}

func (key ECDSAPublicKey) ToPubKey() (*ecdsa.PublicKey, error) {
	x, check := new(big.Int).SetString(key.X, 10)
	if !check {
		return nil, errors.New("failed to unpack ecdsa key")
	}
	y, check := new(big.Int).SetString(key.Y, 10)
	if !check {
		return nil, errors.New("failed to unpack ecdsa key")
	}

	return &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}, nil
}

type ResponseMessage struct {
	Message          string
	ThresholdReached bool
	Token            string // Google OIDC token (Attestation token)
}

type GetRequestSigners struct {
	Message string
	Token   string // Google OIDC token (Attestation token)
}
