package policy

import (
	"crypto/ecdsa"
	"slices"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

var Storage *SigningPoliciesStorage

func init() {
	Storage = InitSigningPoliciesStorage()
}

// SigningPoliciesStorage holds policies. Since policies are being added and the active policy is being modified,
// we need mutex. Note that when a policy is added in a the SigningPolicies map, it is never modified.
type SigningPoliciesStorage struct {
	activeSigningPolicy           *SigningPolicy // Current policy that is being used for signing
	activeSigningPolicyPublicKeys map[common.Address]*ecdsa.PublicKey
	signingPolicies               map[uint32]*SigningPolicy // map of rewardEpochId to policy

	sync.RWMutex
}

func InitSigningPoliciesStorage() *SigningPoliciesStorage {
	return &SigningPoliciesStorage{signingPolicies: make(map[uint32]*SigningPolicy)}
}

func (signingPoliciesStorage *SigningPoliciesStorage) GetActiveSigningPolicy() (*SigningPolicy, error) {
	if signingPoliciesStorage.activeSigningPolicy == nil {
		return nil, errors.New("signing policy not initialized")
	}

	// make a copy
	activeSigningPolicy := *signingPoliciesStorage.activeSigningPolicy

	return &activeSigningPolicy, nil
}

func (signingPoliciesStorage *SigningPoliciesStorage) GetSigningPolicy(epochId uint32) (*SigningPolicy, error) {
	policy, ok := signingPoliciesStorage.signingPolicies[epochId]
	if !ok {
		return nil, errors.New("policy of the given reward epoch not in the storage")
	}

	// make a copy
	returnPolicy := *policy

	return &returnPolicy, nil
}

func (signingPoliciesStorage *SigningPoliciesStorage) SetActiveSigningPolicy(policy *SigningPolicy) {
	signingPoliciesStorage.activeSigningPolicy = policy
	signingPoliciesStorage.signingPolicies[policy.RewardEpochId] = policy
}

func (signingPoliciesStorage *SigningPoliciesStorage) SetActiveSigningPolicyPublicKeys(addressesToPublicKeys map[common.Address]*ecdsa.PublicKey) {
	signingPoliciesStorage.activeSigningPolicyPublicKeys = addressesToPublicKeys
}

func (signingPoliciesStorage *SigningPoliciesStorage) GetActiveSigningPolicyPublicKeysSlice() ([]*ecdsa.PublicKey, error) {
	return toSigningPolicyPublicKeysSlice(signingPoliciesStorage.activeSigningPolicy, signingPoliciesStorage.activeSigningPolicyPublicKeys)
}

func toSigningPolicyPublicKeysSlice(policy *SigningPolicy, pubKeysMap map[common.Address]*ecdsa.PublicKey) ([]*ecdsa.PublicKey, error) {
	pubKeys := make([]*ecdsa.PublicKey, len(policy.Voters))
	var ok bool
	for i, address := range policy.Voters {
		pubKeys[i], ok = pubKeysMap[address]
		// this should never happen
		if !ok {
			return nil, errors.New("address not in policy public key map, internal error")
		}
	}

	return pubKeys, nil
}

func SigningPolicyBytesToHash(signingPolicy []byte) common.Hash {
	if len(signingPolicy)%32 != 0 {
		signingPolicy = append(signingPolicy, make([]byte, 32-len(signingPolicy)%32)...)
	}
	hash := crypto.Keccak256(signingPolicy[:32], signingPolicy[32:64])
	for i := 2; i < len(signingPolicy)/32; i++ {
		hash = crypto.Keccak256(hash, signingPolicy[i*32:(i+1)*32])
	}

	var res common.Hash
	copy(res[:], hash)

	return res
}

func (signingPolicy *SigningPolicy) Hash() (common.Hash, error) {
	signingPolicyBytes, err := EncodeSigningPolicy(signingPolicy)
	if err != nil {
		return common.Hash{}, err
	}

	return SigningPolicyBytesToHash(signingPolicyBytes), nil
}

func WeightOfSigners(signers []common.Address, signingPolicy *SigningPolicy) uint16 {
	currentWeight := uint16(0)
	for i, voter := range signingPolicy.Voters {
		if ok := slices.Contains(signers, voter); ok {
			currentWeight += signingPolicy.Weights[i]
		}
	}

	return currentWeight
}

func (signingPoliciesStorage *SigningPoliciesStorage) DestroyState() {
	signingPoliciesStorage.activeSigningPolicy = nil
	signingPoliciesStorage.signingPolicies = make(map[uint32]*SigningPolicy)
	signingPoliciesStorage.activeSigningPolicyPublicKeys = nil
}
