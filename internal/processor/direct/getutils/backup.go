package getutils

import (
	"encoding/json"

	"tee-node/internal/node"
	"tee-node/internal/policy"
	"tee-node/internal/wallets"
	"tee-node/internal/wallets/backup"
	"tee-node/pkg/types"
)

// todo: the returned backup should be uniquely identifiable
func GetBackupPackage(getAction *types.DirectInstructionData) ([]byte, error) {
	var walletKeyId wallets.WalletKeyIdPair
	err := json.Unmarshal(getAction.Message, &walletKeyId)
	if err != nil {
		return nil, err
	}
	myTeeId := node.GetTeeId()

	wallets.Storage.RLock()
	wallet, err := wallets.Storage.GetWallet(walletKeyId)
	wallets.Storage.RUnlock()
	if err != nil {
		return nil, err
	}

	policy.Storage.RLock()
	activePolicy, err := policy.Storage.GetActiveSigningPolicy()
	if err != nil {
		policy.Storage.RUnlock()
		return nil, err
	}
	activePolicyPublicKeys, err := policy.Storage.GetActiveSigningPolicyPublicKeysSlice()
	policy.Storage.RUnlock()
	if err != nil {
		return nil, err
	}

	walletBackup, err := backup.BackupWallet(
		wallet,
		activePolicyPublicKeys,
		activePolicy.Weights,
		activePolicy.RewardEpochId,
		myTeeId,
	)
	if err != nil {
		return nil, err
	}

	walletBackupBytes, err := json.Marshal(walletBackup)
	if err != nil {
		return nil, err
	}

	responseBytes, err := json.Marshal(
		types.WalletGetBackupResponse{WalletBackup: walletBackupBytes, BackupId: types.WalletBackupId(walletBackup.WalletBackupId)},
	)
	if err != nil {
		return nil, err
	}

	return responseBytes, nil
}
