package policyservice

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"tee-node/internal/policy"
	"tee-node/internal/utils"

	"math/rand"
	pb "tee-node/gen/go/signing/v1"
)

func TestInitializePolicy(t *testing.T) {
	// Generate random voters and corresponding private keys
	voters, privKeys := generateRandomVoters()

	// Generate a random initial policy
	randSeed := int64(12345)
	epochId := uint32(1)
	initialPolicy := generateRandomPolicyData(epochId, voters, randSeed)

	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	if err != nil {
		t.Errorf("Failed to encode the policy")
	}

	// Generate a few more policies and their signatures
	policySignaturesArray := []*pb.PolicySignaturesArray{}

	numPolicies := 5 // Number of policies to generate
	for i := 0; i < numPolicies; i++ {

		epochId++
		randSeed++
		nextPolicy := generateRandomPolicyData(epochId, voters, randSeed)

		nextPolicyBytes, err := policy.EncodeSigningPolicy(&nextPolicy)
		if err != nil {
			t.Errorf("Failed to encode the policy")
		}

		policySignatures := buildPolicySignature(epochId, nextPolicyBytes, privKeys)
		policySignaturesArray = append(policySignaturesArray, policySignatures)

	}

	req := pb.InitializePolicyRequest{
		InitialPolicyBytes:    initialPolicyBytes,
		PolicySignaturesArray: policySignaturesArray,
	}

	signingService := NewService()

	response, err := signingService.InitializePolicy(context.Background(), &req)
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}

	fmt.Printf("Response: %v\n", response)
}

func TestSignNewPolicy(t *testing.T) {
	// Generate random voters and corresponding private keys
	voters, voterPrivKeys := generateRandomVoters()

	// Generate a random initial policy
	randSeed := int64(12345)
	epochId := uint32(1)
	initialPolicy := generateRandomPolicyData(epochId, voters, randSeed)

	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	if err != nil {
		t.Errorf("Failed to encode the policy")
	}

	// Generate a few more policies and their signatures
	policySignaturesArray := []*pb.PolicySignaturesArray{}

	req := pb.InitializePolicyRequest{
		InitialPolicyBytes:    initialPolicyBytes,
		PolicySignaturesArray: policySignaturesArray,
	}

	signingService := NewService()

	response, err := signingService.InitializePolicy(context.Background(), &req)
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}

	fmt.Printf("Response: %v\n", response)

	// Generate a new policy and sign it
	epochId++
	randSeed++
	nextPolicy := generateRandomPolicyData(epochId, voters, randSeed)

	nextPolicyBytes, err := policy.EncodeSigningPolicy(&nextPolicy)
	if err != nil {
		t.Errorf("Failed to encode the policy")
	}

	newPolicySigRequests := []*pb.SignNewPolicyRequest{}
	for i := 0; i < 60; i++ {

		sig, err := policy.SignNewSigningPolicy(policy.SigningPolicyHash(nextPolicyBytes), voterPrivKeys[i])
		if err != nil {
			panic(err)
		}

		req := pb.SignNewPolicyRequest{
			PolicyBytes: nextPolicyBytes,
			PublicKey: &pb.ECDSAPulicKey{
				X: voterPrivKeys[i].PublicKey.X.String(),
				Y: voterPrivKeys[i].PublicKey.Y.String(),
			},
			Signature: sig,
		}

		newPolicySigRequests = append(newPolicySigRequests, &req)

		res2, err := signingService.SignNewPolicy(context.Background(), newPolicySigRequests[0])
		if err != nil {
			t.Errorf("Failed to initialize the policy: %v", err)
		}

		fmt.Printf("Response2: %v\n", res2)

	}

}

// * UTILS ========================================== * //
// * ================================================ * //

func buildPolicySignature(rewardEpochId uint32, policyBytes []byte, voterPrivKeys []*ecdsa.PrivateKey) *pb.PolicySignaturesArray {

	PolicySignatures := []*pb.SignNewPolicyRequest{}

	for i, voterPrivKey := range voterPrivKeys {

		voterPubKey := voterPrivKey.PublicKey

		sig, err := policy.SignNewSigningPolicy(policy.SigningPolicyHash(policyBytes), voterPrivKeys[i])
		if err != nil {
			panic(err)
		}

		PolicySignatures = append(PolicySignatures, &pb.SignNewPolicyRequest{
			PolicyBytes: policyBytes,
			PublicKey: &pb.ECDSAPulicKey{
				X: voterPubKey.X.String(),
				Y: voterPubKey.Y.String(),
			},
			Signature: sig,
		})

	}

	return &pb.PolicySignaturesArray{
		PolicySignatures: PolicySignatures,
	}
}

// Always returns the same voters and private keys
const NUM_VOTERS = 100

func generateRandomVoters() ([]common.Address, []*ecdsa.PrivateKey) {

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

func generateRandomPolicyData(rewardEpochId uint32, voters []common.Address, seed int64) policy.SigningPolicy {
	// Use specific seed for deterministic results
	rgen := rand.New(rand.NewSource(seed))

	StartVotingRoundId := rgen.Uint32()
	Threshold := uint16(rgen.Uint32())
	Seed := big.NewInt(rgen.Int63())
	Weights := []uint16{}

	normalizedWeights := RandomNormalizedArray(NUM_VOTERS, seed)
	for _, w := range normalizedWeights {
		Weights = append(Weights, uint16(w*SIGNER_WEIGHT_DENOMINATION))
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
