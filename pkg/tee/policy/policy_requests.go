package policy

import (
	"crypto/ecdsa"
	"tee-node/api/types"
	"tee-node/pkg/tee/settings"
	"tee-node/pkg/tee/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

// todo: considering moving this file to policyactions.
func InitializePolicyRequest(initialPolicyBytes []byte, newPolicyRequests []types.MultiSignedPolicy, publicKeys []types.ECDSAPublicKey) error {
	var err error
	var currentPolicy *SigningPolicy
	var currentPolicyHash common.Hash
	var pubKeysMap map[common.Address]*ecdsa.PublicKey

	if len(publicKeys) == 0 {
		err = errors.New("no public keys given")
		goto finalize
	}

	// no other process should be touching signingPoliciesStorage during this execution
	Storage.Lock()
	defer Storage.Unlock()
	_, err = Storage.GetActiveSigningPolicy()
	if err == nil {
		err = errors.New("policy already initialized")
		goto finalize
	}

	// Initialize the original signing policy and store it in the map
	currentPolicy, err = DecodeSigningPolicy(initialPolicyBytes)
	if err != nil {
		goto finalize
	}
	currentPolicyHash = SigningPolicyBytesToHash(initialPolicyBytes)
	// Check that the policy matches the initial policy in the config file
	if (settings.InitialPolicyHash != currentPolicyHash || settings.InitialPolicyId != currentPolicy.RewardEpochId) && settings.InitialPolicyCheck {
		err = errors.New("policy does not match the initial policy in the config file")
		goto finalize
	}

	Storage.SetActiveSigningPolicy(currentPolicy)

	// Go through the policies for each reward epoch and update the current policy
	for _, policyRequest := range newPolicyRequests {
		currentPolicy, err = processUpdatePolicyRequest(policyRequest)
		if err != nil {
			goto finalize
		}
		Storage.SetActiveSigningPolicy(currentPolicy)
	}

	// Add public keys to the last policy
	pubKeysMap, err = processPolicyPublicKeys(publicKeys, Storage.activeSigningPolicy)
	if err != nil {
		goto finalize
	}
	Storage.SetActiveSigningPolicyPublicKeys(pubKeysMap)

finalize:
	if err != nil {
		Storage.DestroyState()
		return err
	}

	return nil
}

func UpdatePolicyRequest(newPolicyRequest types.MultiSignedPolicy, publicKeys []types.ECDSAPublicKey) error {
	Storage.Lock()
	defer Storage.Unlock()
	newPolicy, err := processUpdatePolicyRequest(newPolicyRequest)
	if err != nil {
		return err
	}
	pubKeysMap, err := processPolicyPublicKeys(publicKeys, newPolicy)
	if err != nil {
		return err
	}

	Storage.SetActiveSigningPolicy(newPolicy)
	Storage.SetActiveSigningPolicyPublicKeys(pubKeysMap)

	return nil
}

// only called while signingPoliciesStorage is locked
func processUpdatePolicyRequest(policyRequest types.MultiSignedPolicy) (*SigningPolicy, error) {
	sigPolicy, err := DecodeSigningPolicy(policyRequest.PolicyBytes)
	if err != nil {
		return nil, err
	}

	activeSigningPolicy, err := Storage.GetActiveSigningPolicy()
	if err != nil {
		return nil, err
	}
	if sigPolicy.RewardEpochId != activeSigningPolicy.RewardEpochId+1 {
		return nil, errors.New("policy is not active")
	}

	signers := make(map[common.Address][]byte)
	for _, sig := range policyRequest.Signatures {
		hash := SigningPolicyBytesToHash(policyRequest.PolicyBytes)
		providerAddress, err := utils.CheckSignature(hash[:], sig.Signature, activeSigningPolicy.Voters)
		if err != nil {
			return nil, err
		}
		signers[providerAddress] = sig.Signature
	}

	if WeightOfSigners(signers, activeSigningPolicy) < activeSigningPolicy.Threshold {
		return nil, errors.New("threshold for updating policy not reached")
	}

	return sigPolicy, nil
}

func processPolicyPublicKeys(publicKeys []types.ECDSAPublicKey, sigPolicy *SigningPolicy) (map[common.Address]*ecdsa.PublicKey, error) {
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
