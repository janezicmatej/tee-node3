package types

import "encoding/json"

// * ——————————————— POST Requests ——————————————— * //
// These will only be available through the InstructionService (not directly)

// * Requests * //

type NewWalletRequest struct {
	Name string
}

func ParseNewWalletRequest(instructionData *InstructionData) (NewWalletRequest, error) {

	// TODO: I am not sure how this OriginalMessage is going to be encoded/decoded (abi.EncodePacked?)
	var newWalletRequest NewWalletRequest
	err := json.Unmarshal(instructionData.OriginalMessage, &newWalletRequest)
	if err != nil {
		return NewWalletRequest{}, err
	}

	return newWalletRequest, nil
}

// ----- ----- ----- ------

type DeleteWalletRequest struct {
	Name string
}

func NewDeleteWalletRequest(instructionData *InstructionData) (DeleteWalletRequest, error) {

	// TODO: Decode properly
	var delWalletRequest DeleteWalletRequest
	err := json.Unmarshal(instructionData.OriginalMessage, &delWalletRequest)
	if err != nil {
		return DeleteWalletRequest{}, err
	}

	return delWalletRequest, nil
}

type SplitWalletRequest struct {
	Name       string
	TeeIds     []string
	Hosts      []string
	PublicKeys []string
	Threshold  int64
}

func NewSplitWalletRequest(instructionData *InstructionData) (SplitWalletRequest, error) {

	// TODO: Decode properly
	var splitWalletRequest SplitWalletRequest
	err := json.Unmarshal(instructionData.OriginalMessage, &splitWalletRequest)
	if err != nil {
		return SplitWalletRequest{}, err
	}

	return splitWalletRequest, nil
}

type RecoverWalletRequest struct {
	Name      string
	TeeIds    []string
	Hosts     []string
	ShareIds  []string
	PublicKey string
	Address   string
	Threshold int64
}

func NewRecoverWalletRequest(instructionData *InstructionData) (RecoverWalletRequest, error) {

	// TODO: Decode properly
	var recoverWalletRequest RecoverWalletRequest
	err := json.Unmarshal(instructionData.OriginalMessage, &recoverWalletRequest)
	if err != nil {
		return RecoverWalletRequest{}, err
	}

	return recoverWalletRequest, nil
}

// * Responses * //

// * ——————————————— GET Requests ——————————————— * //

type WalletInfoRequest struct {
	Name      string
	Challenge string
}

type WalletInfoResponse struct {
	EthPublicKey ECDSAPublicKey // Full ECDSA public key
	EthAddress   string
	XrpPublicKey string // SEC1 encoded public key (x-coordinate)
	XrpAddress   string
	Token        string
}
