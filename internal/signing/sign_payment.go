package signing

import (
	"crypto/ecdsa"
	"encoding/hex"
	"slices"

	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
)

func SignXrpPayment(paymentHash string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	paymentHashBytes, err := hex.DecodeString(paymentHash)
	if err != nil {
		return nil, err
	}

	if len(paymentHashBytes) > 32 {
		return nil, errors.New("payment hash is too long")
	}

	txnSignature := utils.XrpSign(paymentHashBytes, privateKey)

	return txnSignature, nil
}

func CheckCosigners(signers []common.Address, isSignerDataProvider []bool, walletCosigners []common.Address, threshold uint64) (bool, error) {
	countCosigners := uint64(0)
	for _, cosigner := range walletCosigners {
		if ok := slices.Contains(signers, cosigner); ok {
			countCosigners++
		}
	}

	for i, signer := range signers {
		if isCosigner := slices.Contains(walletCosigners, signer); !isCosigner && !isSignerDataProvider[i] {
			return false, errors.New("signed by an entity that is nether data provider or cosigner")
		}
	}

	return countCosigners >= threshold, nil
}
