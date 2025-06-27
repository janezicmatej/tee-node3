package regutils

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/verification"
	"github.com/flare-foundation/tee-node/internal/attestation"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/internal/policy"
	"github.com/flare-foundation/tee-node/internal/settings"
	pkgattestation "github.com/flare-foundation/tee-node/pkg/attestation"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/pkg/errors"
)

func TeeAttestation(instructionData *instruction.DataFixed) ([]byte, error) {
	teeAttestationRequest, err := types.ParseTeeAttestationRequest(instructionData)
	if err != nil {
		return nil, err
	}

	nodeInfo := node.GetNodeInfo()

	challenge, err := checkTeeAttestation(teeAttestationRequest, nodeInfo)
	if err != nil {
		return nil, err
	}

	policy.Storage.RLock()
	activePolicy, err := policy.Storage.GetActiveSigningPolicy()
	policy.Storage.RUnlock()
	if err != nil {
		return nil, err
	}
	activePolicyHash, err := activePolicy.Hash()
	if err != nil {
		return nil, err
	}

	teeInfo := types.TeeInfo{
		Challenge:                challenge,
		PublicKey:                nodeInfo.PublicKey,
		Status:                   nodeInfo.Status,
		InitialSigningPolicyId:   settings.InitialPolicyId,
		InitialSigningPolicyHash: settings.InitialPolicyHash,
		LastSigningPolicyId:      activePolicy.RewardEpochId,
		LastSigningPolicyHash:    activePolicyHash,
		Nonce:                    nodeInfo.Nonce,
		PauseNonce:               nodeInfo.PausingNonce,
		TeeTimestamp:             time.Now().Unix(),
	}
	teeInfoHash, err := teeInfo.Hash()
	if err != nil {
		return nil, err
	}

	attestationBytes, err := attestation.GetGoogleAttestationToken([]string{hex.EncodeToString(teeInfoHash[:])}, pkgattestation.PKITokenType)
	if err != nil {
		return nil, err
	}

	teeInfoResponse := types.TeeInfoResponse{
		TeeInfo:     teeInfo,
		Attestation: attestationBytes,
	}

	resultEncoded, err := json.Marshal(teeInfoResponse)
	if err != nil {
		return nil, err
	}

	return resultEncoded, nil
}

func checkTeeAttestation(teeAttestationRequest verification.ITeeVerificationTeeAttestation, nodeInfo node.NodeInfo) ([32]byte, error) {
	// todo: other checks?
	if teeAttestationRequest.TeeMachine.TeeId != nodeInfo.TeeId {
		return [32]byte{}, errors.New("TeeIds do not match")
	}
	if teeAttestationRequest.Challenge == nil {
		return [32]byte{}, errors.New("challenge not given")
	}
	challengeBytes := teeAttestationRequest.Challenge.Bytes()
	if len(challengeBytes) > 32 {
		return [32]byte{}, errors.New("challenge too long")
	}
	challengeBytes = append(make([]byte, 32-len(challengeBytes)), challengeBytes...)
	var challenge [32]byte
	copy(challenge[:], challengeBytes)

	return challenge, nil
}

func ValidateTeeAttestation(instructionData *instruction.DataFixed) error {
	teeAttestationRequest, err := types.ParseTeeAttestationRequest(instructionData)
	if err != nil {
		return err
	}

	nodeInfo := node.GetNodeInfo()

	_, err = checkTeeAttestation(teeAttestationRequest, nodeInfo)
	if err != nil {
		return err
	}

	return nil
}
