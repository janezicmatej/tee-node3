package types

import "encoding/json"

type InitializePolicyRequest struct {
	InitialPolicyBytes []byte
	NewPolicyRequests  []MultiSignedPolicy
	Challenge          string
}

type MultiSignedPolicy struct {
	PolicyBytes []byte
	Signatures  []*SignatureMessage
}

type SignNewPolicyRequest struct {
	PolicyBytes []byte // The new policy bytes being proposed/signed
	Signature   *SignatureMessage
	Challenge   string
}

type InitializePolicyResponse struct {
	Token string
}

type SignNewPolicyResponse struct {
	ActivePolicy     string // Note: This doesn't really make sense, do we need it?
	ThresholdReached bool
	Token            string
}

type GetActivePolicyRequest struct {
	Challenge string
}

type GetActivePolicyResponse struct {
	ActivePolicy     []byte // The current active policy
	ActivePolicyHash string // The hash of the current active policy
	Token            string
}

func ParseMultiSignedPolicyRequest(instructionData *InstructionDataBase) (MultiSignedPolicy, error) {
	// TODO: Decode properly
	var multiSignedPolicy MultiSignedPolicy
	err := json.Unmarshal(instructionData.OriginalMessage, &multiSignedPolicy)
	if err != nil {
		return MultiSignedPolicy{}, err
	}

	return multiSignedPolicy, nil
}
