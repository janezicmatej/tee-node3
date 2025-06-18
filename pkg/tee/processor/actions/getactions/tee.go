package getactions

import (
	"encoding/hex"
	"encoding/json"
	"tee-node/api/types"
	"tee-node/pkg/tee/attestation"
	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/policy"
	"tee-node/pkg/tee/settings"
	"time"
)

func GetTeeInfo(getAction *types.ActionData) ([]byte, error) {
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

	attestationBytes, err := attestation.GetGoogleAttestationToken([]string{hex.EncodeToString(teeInfoHash[:])}, attestation.PKITokenType)
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
