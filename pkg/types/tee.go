package types

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type TeeInfo struct {
	Challenge                [32]byte
	PublicKey                ECDSAPublicKey
	Status                   string
	InitialSigningPolicyId   uint32
	InitialSigningPolicyHash common.Hash
	LastSigningPolicyId      uint32
	LastSigningPolicyHash    common.Hash
	Nonce                    uint64
	PauseNonce               uint64
	TeeTimestamp             int64
}

func (teeInfo TeeInfo) Hash() (common.Hash, error) {
	encoded, err := json.Marshal(teeInfo)
	if err != nil {
		return common.Hash{}, err
	}
	hash := crypto.Keccak256(encoded)
	var res common.Hash
	copy(res[:], hash)

	return res, nil
}

type TeeInfoRequest struct {
	Challenge [32]byte
}

type TeeInfoResponse struct {
	TeeInfo
	Attestation []byte
}
