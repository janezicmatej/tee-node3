package types

import "encoding/json"

// * ——————————————— POST Requests ——————————————— * //
// These will only be available through the InstructionService (not directly)

// * Requests * //

type SignPaymentRequest struct {
	WalletId    string
	KeyId       string
	PaymentHash string
}

func ParseSignPaymentRequest(instructionData *InstructionDataBase) (SignPaymentRequest, error) {
	// TODO: Decode properly
	var signPaymentRequest SignPaymentRequest
	err := json.Unmarshal(instructionData.OriginalMessage, &signPaymentRequest)
	if err != nil {
		return SignPaymentRequest{}, err
	}

	return signPaymentRequest, nil
}

// * Responses * //

type SignPaymentResponse struct {
	ResponseBase
	Finalized bool
}

type GetPaymentSignatureResponse struct {
	PaymentHash   string
	TxnSignature  []byte
	SigningPubKey []byte
	Account       string
}
