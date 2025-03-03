package policyservice

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	api "tee-node/api/types"
	"tee-node/internal/config"
	"tee-node/internal/policy"
	"tee-node/internal/requests"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func InitializePolicyInternal(req *api.InitializePolicyRequest) error {
	if policy.ActiveSigningPolicy != nil {
		return status.Error(codes.InvalidArgument, "policy already initialized")
	}

	// Initialize the original signing policy and store it in the map
	currentPolicy, err := policy.DecodeSigningPolicy(req.InitialPolicyBytes)
	if err != nil {
		return status.Error(codes.InvalidArgument, "failed to decode the initial policy")
	}
	currentPolicyHash := policy.SigningPolicyHash(req.InitialPolicyBytes)

	// Check that the policy matches the initial policy in the config file
	if config.InitialPolicyHash != hex.EncodeToString(currentPolicyHash) {
		return status.Error(codes.InvalidArgument, "policy does not match the initial policy in the config file")
	} else {
		policy.SetSigningPolicy(currentPolicy, currentPolicyHash)
	}

	// Go through the policies for each reward epoch and update the current policy
	for _, policyRequest := range req.NewPolicyRequests {

		signPolicyRequest := policy.NewSignPaymentRequest(policyRequest.PolicyBytes)

		var requestCounter *requests.RequestCounter[policy.SignPolicyRequest]
		var thresholdReached bool

		for _, sig := range policyRequest.Signatures {

			pubKey := ecdsa.PublicKey{
				X: new(big.Int),
				Y: new(big.Int),
			}
			pubKey.X.SetString(sig.PublicKey.X, 10)
			pubKey.Y.SetString(sig.PublicKey.Y, 10)

			requestCounter, thresholdReached, err = requests.ProcessRequest(signPolicyRequest, sig.Signature)
			if err != nil {
				return err
			}
		}

		if thresholdReached && !requestCounter.Done {

			sigPolicy, err := policy.DecodeSigningPolicy(policyRequest.PolicyBytes)
			if err != nil {
				return status.Error(codes.InvalidArgument, "failed to decode the policy")
			}
			policyHash := policy.SigningPolicyHash(policyRequest.PolicyBytes)

			err = policy.VerifyPolicyFreshness(sigPolicy, policy.ActiveSigningPolicy.RewardEpochId, hex.EncodeToString(policyHash))
			if err != nil {
				return err
			}

			policy.SetSigningPolicy(sigPolicy, policyHash)
		}
	}

	return nil
}
