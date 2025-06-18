package getactions

import (
	"encoding/json"
	"tee-node/api/types"
	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/policy"
	"tee-node/pkg/tee/wallets"
)

// todo: the returned backup should be uniquely identifiable
func GetBackupPackage(getAction *types.ActionData) ([]byte, error) {
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

	walletBackup, err := wallets.BackupWallet(
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
