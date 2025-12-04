package policyutils

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/tee-node/internal/testutils"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/policy"
	"github.com/flare-foundation/tee-node/pkg/types"
)

var numVoters int

func TestInitializePolicy(t *testing.T) {
	pStorage := policy.InitializeStorage()
	pp := NewProcessor(pStorage)

	// Generate random voters and corresponding private keys
	numVoters = 100
	voters, _, pubKeysMap := testutils.GenerateRandomKeys(t, numVoters)
	// Generate a random initial policy
	randSeed := int64(12345)
	epochID := uint32(1)
	initialPolicy := testutils.GenerateRandomPolicyData(t, epochID, voters, randSeed)

	pubKeys := make([]types.PublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicy.RawBytes(),
		PublicKeys:         pubKeys,
	}

	message, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}
	_, err = pp.InitializePolicy(&types.DirectInstruction{Message: message})
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}
}

func TestInitializingThePolicyTwice(t *testing.T) {
	pStorage := policy.InitializeStorage()
	pp := NewProcessor(pStorage)

	epochID, randSeed := uint32(1), int64(12345)

	numVoters := 100
	initialPolicy, _, _, pubKeys := testutils.GenerateRandomValidPolicyAndSigners(t, epochID, randSeed, numVoters)

	req := &types.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicy.RawBytes(),
		PublicKeys:         pubKeys,
	}
	message, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}
	_, err = pp.InitializePolicy(&types.DirectInstruction{Message: message})
	if err != nil {
		t.Errorf("Failed to initialize the policy: %v", err)
	}

	// & Try to initialize the policy again ------------------------------------------- //
	epochID2, randSeed2 := uint32(2), int64(54321)

	initialPolicy2, _, _, pubKeys2 := testutils.GenerateRandomValidPolicyAndSigners(t, epochID2, randSeed2, numVoters)

	req2 := &types.InitializePolicyRequest{
		InitialPolicyBytes: initialPolicy2.RawBytes(),
		PublicKeys:         pubKeys2,
	}
	message2, err := json.Marshal(req2)
	if err != nil {
		t.Fatalf("Failed to build the mock initialize policy request: %v", err)
	}
	_, err = pp.InitializePolicy(&types.DirectInstruction{Message: message2})
	if err.Error() != "policy already initialized" {
		t.Errorf("expected 'policy already initialized', got %v", err)
	}
}

func TestUpdatePolicy(t *testing.T) {
	pStorage := policy.InitializeStorage()
	pp := NewProcessor(pStorage)

	_, err := node.Initialize(node.ZeroState{})
	require.NoError(t, err)

	// Generate random voters and corresponding private keys
	numVoters = 100
	voters, privKeys, pubKeysMap := testutils.GenerateRandomKeys(t, numVoters)
	// Generate a random initial policy
	randSeed := int64(12345)
	epochID := uint32(1)
	initialPolicy := testutils.GenerateRandomPolicyData(t, epochID, voters, randSeed)

	// Set the initial policy hash in the config
	err = pStorage.SetInitialPolicy(initialPolicy, pubKeysMap)
	require.NoError(t, err)

	epochID++
	randSeed++
	nextPolicy := testutils.GenerateRandomPolicyData(t, epochID, voters, randSeed)

	policySignatures := testutils.BuildMultiSignedPolicy(t, nextPolicy.RawBytes(), privKeys)

	pubKeys := make([]types.PublicKey, len(voters))
	for i, voter := range voters {
		pubKeys[i] = types.PubKeyToStruct(pubKeysMap[voter])
	}

	updatePolicyRequest := types.UpdatePolicyRequest{
		NewPolicy:  policySignatures,
		PublicKeys: pubKeys,
	}
	updatePolicyRequestBytes, err := json.Marshal(updatePolicyRequest)
	require.NoError(t, err)

	_, err = pp.UpdatePolicy(&types.DirectInstruction{Message: updatePolicyRequestBytes})
	require.NoError(t, err)

	// todo: check new policy
}
