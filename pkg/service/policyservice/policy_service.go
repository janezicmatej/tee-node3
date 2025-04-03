package policyservice

import (
	"encoding/hex"
	"tee-node/pkg/attestation"
	"tee-node/pkg/policy"
	"tee-node/pkg/requests"

	api "tee-node/api/types"

	"github.com/pkg/errors"
)

func InitializePolicy(req *api.InitializePolicyRequest) (*api.InitializePolicyResponse, error) {
	err := policy.InitializePolicyRequest(req.InitialPolicyBytes, req.NewPolicyRequests, req.LatestPolicyPublicKeys)
	if err != nil {
		return nil, err
	}

	// Register the validators from the latest policy for the ratelimiter
	requests.UpdateRateLimiter(policy.GetActiveSigningPolicy().Voters)

	return &api.InitializePolicyResponse{}, nil
}

// GetActivePolicy handles the GetActivePolicy request
func GetActivePolicy(req *api.GetActivePolicyRequest) (*api.GetActivePolicyResponse, error) {
	activeSigningPolicy := policy.GetActiveSigningPolicy()
	if activeSigningPolicy == nil {
		return nil, errors.New("no active policy")
	}
	activePolicyBytes, err := policy.EncodeSigningPolicy(activeSigningPolicy)
	if err != nil {
		return nil, err
	}
	activePolicyHash := policy.SigningPolicyBytesToHash(activePolicyBytes)

	// Get the attestation token
	nonces := []string{req.Challenge}
	var tokenBytes []byte
	tokenBytes, err = attestation.GetGoogleAttestationToken(nonces, attestation.OIDCTokenType)
	if err != nil {
		return nil, err
	}

	return &api.GetActivePolicyResponse{
		ActivePolicy:     activePolicyBytes,
		ActivePolicyHash: hex.EncodeToString(activePolicyHash),
		Token:            string(tokenBytes),
	}, nil
}
