package getutils

import (
	"encoding/hex"
	"encoding/json"
	"tee-node/internal/attestation"
	"tee-node/internal/node"
	"tee-node/internal/policy"
	"tee-node/internal/settings"
	"time"

	commonattestation "tee-node/pkg/attestation"
	"tee-node/pkg/types"
)

func GetTeeInfo(getAction *types.DirectInstructionData) ([]byte, error) {
	var teeInfoRequest types.TeeInfoRequest
	err := json.Unmarshal(getAction.Message, &teeInfoRequest)
	if err != nil {
		return nil, err
	}

	nodeInfo := node.GetNodeInfo()

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
		Challenge:                teeInfoRequest.Challenge,
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

	attestationBytes, err := attestation.GetGoogleAttestationToken([]string{hex.EncodeToString(teeInfoHash[:])}, commonattestation.PKITokenType)
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
