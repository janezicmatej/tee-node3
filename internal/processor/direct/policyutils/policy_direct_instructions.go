package policyutils

import (
	"crypto/ecdsa"
	"encoding/json"

	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

func InitializePolicy(message []byte) error {
	var req types.InitializePolicyRequest
	err := json.Unmarshal(message, &req)
	if err != nil {
		return err
	}

	var currentPolicy *policy.SigningPolicy
	var currentPolicyHash common.Hash
	var pubKeysMap map[common.Address]*ecdsa.PublicKey

	if len(req.LatestPolicyPublicKeys) == 0 {
		err = errors.New("no public keys given")
		goto finalize
	}

	// no other process should be touching signingPoliciesStorage during this execution
	policy.Storage.Lock()
	defer policy.Storage.Unlock()
	_, err = policy.Storage.GetActiveSigningPolicy()
	if err == nil {
		err = errors.New("policy already initialized")
		goto finalize
	}

	// Initialize the original signing policy and store it in the map
	currentPolicy, err = policy.DecodeSigningPolicy(req.InitialPolicyBytes)
	if err != nil {
		goto finalize
	}
	currentPolicyHash = policy.SigningPolicyBytesToHash(req.InitialPolicyBytes)
	// Check that the policy matches the initial policy in the config file
	if (settings.InitialPolicyHash != currentPolicyHash || settings.InitialPolicyId != currentPolicy.RewardEpochId) && settings.InitialPolicyCheck {
		err = errors.New("policy does not match the initial policy in the config file")
		goto finalize
	}

	policy.Storage.SetActiveSigningPolicy(currentPolicy)

	// Go through the policies for each reward epoch and update the current policy
	for _, policyRequest := range req.Policies {
		currentPolicy, err = processUpdatePolicyRequest(policyRequest)
		if err != nil {
			goto finalize
		}
		policy.Storage.SetActiveSigningPolicy(currentPolicy)
	}

	// Add public keys to the last policy
	pubKeysMap, err = processPolicyPublicKeys(req.LatestPolicyPublicKeys, currentPolicy)
	if err != nil {
		goto finalize
	}
	policy.Storage.SetActiveSigningPolicyPublicKeys(pubKeysMap)

finalize:
	if err != nil {
		policy.Storage.DestroyState()
		return err
	}

	return nil
}

func UpdatePolicy(message []byte) error {
	var updatePolicyRequest types.UpdatePolicyRequest
	err := json.Unmarshal(message, &updatePolicyRequest)
	if err != nil {
		return err
	}

	policy.Storage.Lock()
	defer policy.Storage.Unlock()
	newPolicy, err := processUpdatePolicyRequest(updatePolicyRequest.NewPolicy)
	if err != nil {
		return err
	}
	pubKeysMap, err := processPolicyPublicKeys(updatePolicyRequest.LatestPolicyPublicKeys, newPolicy)
	if err != nil {
		return err
	}

	policy.Storage.SetActiveSigningPolicy(newPolicy)
	policy.Storage.SetActiveSigningPolicyPublicKeys(pubKeysMap)

	return nil
}

// only called while signingPoliciesStorage is locked
func processUpdatePolicyRequest(policyRequest types.MultiSignedPolicy) (*policy.SigningPolicy, error) {
	sigPolicy, err := policy.DecodeSigningPolicy(policyRequest.PolicyBytes)
	if err != nil {
		return nil, err
	}

	activeSigningPolicy, err := policy.Storage.GetActiveSigningPolicy()
	if err != nil {
		return nil, err
	}
	if sigPolicy.RewardEpochId != activeSigningPolicy.RewardEpochId+1 {
		return nil, errors.New("policy is not active")
	}

	signers := make([]common.Address, len(policyRequest.Signatures))
	for i, sig := range policyRequest.Signatures {
		hash := policy.SigningPolicyBytesToHash(policyRequest.PolicyBytes)
		providerAddress, err := utils.CheckSignature(hash[:], sig.Signature, activeSigningPolicy.Voters)
		if err != nil {
			return nil, err
		}
		signers[i] = providerAddress
	}

	if policy.WeightOfSigners(signers, activeSigningPolicy) < activeSigningPolicy.Threshold {
		return nil, errors.New("threshold for updating policy not reached")
	}

	return sigPolicy, nil
}

func processPolicyPublicKeys(publicKeys []types.ECDSAPublicKey, sigPolicy *policy.SigningPolicy) (map[common.Address]*ecdsa.PublicKey, error) {
	if len(publicKeys) != len(sigPolicy.Voters) {
		return nil, errors.New("the number of public keys and the number of voters do not match")
	}
	pubKeysMap := make(map[common.Address]*ecdsa.PublicKey)
	for i, pubKey := range publicKeys {
		pubKeyECDSA, err := types.ParsePubKey(pubKey)
		if err != nil {
			return nil, err
		}
		address := crypto.PubkeyToAddress(*pubKeyECDSA)
		if address != sigPolicy.Voters[i] {
			return nil, errors.New("public key and address do not match")
		}

		pubKeysMap[address] = pubKeyECDSA
	}

	return pubKeysMap, nil
}
