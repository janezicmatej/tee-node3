package signing

import (
	"crypto/ecdsa"
	"encoding/hex"

	"github.com/flare-foundation/tee-node/pkg/utils"

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
