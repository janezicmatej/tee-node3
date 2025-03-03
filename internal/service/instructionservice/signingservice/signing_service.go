package signingservice

import (
	api "tee-node/api/types"
	"tee-node/internal/signing"
	"tee-node/internal/utils"
	"tee-node/internal/wallets"

	"github.com/pkg/errors"
)

func SignPaymentTransaction(instructionData *api.InstructionData) ([]byte, error) {
	signPaymentRequest, err := api.ParseSignPaymentRequest(instructionData)
	if err != nil {
		return nil, err
	}

	signingWallet, err := wallets.GetWallet(signPaymentRequest.WalletName)
	if err != nil {
		return nil, err
	}

	txnSignature, err := signing.SignXrpPayment(signPaymentRequest.PaymentHash, signingWallet.PrivateKey)
	if err != nil {
		return nil, err
	}

	return txnSignature, nil
}

func XrpReissue(instructionData *api.InstructionData) ([]byte, error) {
	return nil, errors.New("XRP RESISSUE command not implemented yet")
}

func GetPaymentSignature(instructionData *api.InstructionData, result []byte) (*api.GetPaymentSignatureResponse, error) {
	signPaymentRequest, err := api.ParseSignPaymentRequest(instructionData)
	if err != nil {
		return nil, err
	}

	signingWallet, err := wallets.GetWallet(signPaymentRequest.WalletName)
	if err != nil {
		return nil, err
	}

	xrpAccountAddress, _ := wallets.GetXrpAddress(signPaymentRequest.WalletName)
	signingPubKey := utils.SerializeCompressed(&signingWallet.PrivateKey.PublicKey)

	return &api.GetPaymentSignatureResponse{
		Account:       xrpAccountAddress,
		TxnSignature:  result,
		PaymentHash:   signPaymentRequest.PaymentHash,
		SigningPubKey: signingPubKey}, nil
}
