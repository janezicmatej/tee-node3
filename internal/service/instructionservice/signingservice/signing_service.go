package signingservice

import (
	api "tee-node/api/types"
	"tee-node/internal/signing"
	"tee-node/internal/utils"
	"tee-node/internal/wallets"

	"github.com/pkg/errors"
)

func SignPaymentTransaction(instructionData *api.InstructionDataBase) ([]byte, error) {
	signPaymentRequest, err := api.ParseSignPaymentRequest(instructionData)
	if err != nil {
		return nil, err
	}

	signingWallet, err := wallets.GetWallet(wallets.WalletKeyIdPair{WalletId: signPaymentRequest.WalletId, KeyId: signPaymentRequest.KeyId})
	if err != nil {
		return nil, err
	}

	txnSignature, err := signing.SignXrpPayment(signPaymentRequest.PaymentHash, signingWallet.PrivateKey)
	if err != nil {
		return nil, err
	}

	return txnSignature, nil
}

func XrpReissue(instructionData *api.InstructionDataBase) ([]byte, error) {
	return nil, errors.New("XRP RESISSUE command not implemented yet")
}

func GetPaymentSignature(instructionData *api.InstructionDataBase, result []byte) (*api.GetPaymentSignatureResponse, error) {
	signPaymentRequest, err := api.ParseSignPaymentRequest(instructionData)
	if err != nil {
		return nil, err
	}

	walletKeyIdPair := wallets.WalletKeyIdPair{WalletId: signPaymentRequest.WalletId, KeyId: signPaymentRequest.KeyId}
	signingWallet, err := wallets.GetWallet(walletKeyIdPair)
	if err != nil {
		return nil, err
	}

	xrpAccountAddress, _ := wallets.GetXrpAddress(walletKeyIdPair)
	signingPubKey := utils.SerializeCompressed(&signingWallet.PrivateKey.PublicKey)

	return &api.GetPaymentSignatureResponse{
		Account:       xrpAccountAddress,
		TxnSignature:  result,
		PaymentHash:   signPaymentRequest.PaymentHash,
		SigningPubKey: signingPubKey}, nil
}
