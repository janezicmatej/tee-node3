package utils

import (
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"testing"

	"tee-node/internal/policy"
	"tee-node/internal/utils"

	"github.com/ethereum/go-ethereum/common"

	pb "tee-node/gen/go/policy/v1"
)

func GenerateRandomValidPolicyAndSigners(t *testing.T, epochId uint32, randSeed int64) (*policy.SigningPolicy, []byte, []common.Address, []*ecdsa.PrivateKey, error) {

	t.Helper() // Mark this as a helper so line numbers in failures point to the test, not the helper

	// Generate random voters and corresponding private keys
	voters, privKeys := GenerateRandomVoters(t)

	initialPolicy := GenerateRandomPolicyData(t, epochId, voters, randSeed)

	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	if err != nil {
		t.Errorf("invalid signing policy hash length %v", err)
	}

	return &initialPolicy, initialPolicyBytes, voters, privKeys, nil
}

func GenerateRandomSignNewPolicyRequestArrays(t *testing.T, epochId uint32, randSeed int64, voters []common.Address, privKeys []*ecdsa.PrivateKey, numPolicies int) ([]*pb.SignNewPolicyRequest, error) {

	t.Helper()

	// Generate a few more policies and their signatures
	policySignaturesArray := []*pb.SignNewPolicyRequest{}

	_epochId, _randSeed := epochId, randSeed

	for i := 0; i < numPolicies; i++ {

		_epochId++
		_randSeed++
		nextPolicy := GenerateRandomPolicyData(t, _epochId, voters, _randSeed)

		nextPolicyBytes, err := policy.EncodeSigningPolicy(&nextPolicy)
		if err != nil {
			t.Errorf("Failed to encode policy %v", err)
		}

		policySignatures := BuildPolicySignature(t, nextPolicyBytes, privKeys)
		policySignaturesArray = append(policySignaturesArray, policySignatures)
	}

	return policySignaturesArray, nil
}

func BuildPolicySignature(t *testing.T, policyBytes []byte, voterPrivKeys []*ecdsa.PrivateKey) *pb.SignNewPolicyRequest {

	t.Helper()

	PolicySignatureMessages := []*pb.PolicySignatureMessage{}

	for i, voterPrivKey := range voterPrivKeys {

		voterPubKey := voterPrivKey.PublicKey

		sig, err := policy.SignNewSigningPolicy(policy.SigningPolicyHash(policyBytes), voterPrivKeys[i])
		if err != nil {
			panic(err)
		}

		PolicySignatureMessages = append(PolicySignatureMessages, &pb.PolicySignatureMessage{
			PublicKey: &pb.ECDSAPublicKey{
				X: voterPubKey.X.String(),
				Y: voterPubKey.Y.String(),
			},
			Signature: sig,
		})

	}

	return &pb.SignNewPolicyRequest{
		PolicyBytes:             policyBytes,
		PolicySignatureMessages: PolicySignatureMessages,
	}
}

// Always returns the same voters and private keys
const NUM_VOTERS = 100

func GenerateRandomVoters(t *testing.T) ([]common.Address, []*ecdsa.PrivateKey) {

	t.Helper()

	Voters := make([]common.Address, NUM_VOTERS)
	privKeys := make([]*ecdsa.PrivateKey, NUM_VOTERS)

	for i := 0; i < NUM_VOTERS; i++ {
		voterPrivKey, err := utils.GenerateEthereumPrivateKey()
		if err != nil {
			panic(err)
		}
		voterPubKey := voterPrivKey.PublicKey

		privKeys[i] = voterPrivKey
		Voters[i] = utils.PubkeyToAddress(&voterPubKey)
	}

	return Voters, privKeys

}

const WEIGHT_DENOMINATION = 1<<16 - 1

func GenerateRandomPolicyData(t *testing.T, rewardEpochId uint32, voters []common.Address, seed int64) policy.SigningPolicy {

	t.Helper()

	// Use specific seed for deterministic results
	rgen := rand.New(rand.NewSource(seed))

	StartVotingRoundId := rgen.Uint32()

	Threshold := uint16((1 << 16) / 2)
	Seed := big.NewInt(rgen.Int63())
	Weights := []uint16{}

	normalizedWeights := RandomNormalizedArray(NUM_VOTERS, seed)
	for _, w := range normalizedWeights {
		Weights = append(Weights, uint16(w*WEIGHT_DENOMINATION))
	}

	return policy.SigningPolicy{
		RewardEpochId:      rewardEpochId,
		StartVotingRoundId: StartVotingRoundId,
		Threshold:          Threshold,
		Seed:               *Seed,
		Voters:             voters,
		Weights:            Weights,
	}
}

// RandomNormalizedArray generates an array of n random floats that sum to 1
func RandomNormalizedArray(n int, seed int64) []float64 {
	// Initialize random source with seed
	source := rand.NewSource(seed)
	r := rand.New(source)

	// Generate random numbers
	numbers := make([]float64, n)
	sum := 0.0

	for i := 0; i < n; i++ {
		// Generate random float between 0 and 1
		numbers[i] = r.Float64()
		sum += numbers[i]
	}

	// Normalize to sum to 1
	for i := 0; i < n; i++ {
		numbers[i] /= sum
	}

	return numbers
}

// Resets the state of the TEE between tests
func ResetSigningServiceState() {
	policy.ActiveSigningPolicy = nil
	policy.ActiveSigningPolicyHash = nil
	policy.SigningPolicies = make(map[uint32]*policy.SigningPolicy)

	policy.ValidVoterWeight = make(map[string]uint16)
	policy.ProcessedPubKeys = make(map[string](map[*ecdsa.PublicKey]bool))

}
