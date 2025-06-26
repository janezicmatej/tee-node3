package backup

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"slices"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/internal/wallets"
	"github.com/flare-foundation/tee-node/pkg/backup"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/pkg/errors"
)

func BackupWallet(givenWallet *wallets.Wallet, providersPubKeys []*ecdsa.PublicKey, signingPolicyWeights []uint16, rewardEpochId uint32, teeId common.Address) (*backup.WalletBackup, error) {
	adminsPubKeys := make([]types.ECDSAPublicKey, len(givenWallet.AdminsPublicKeys))
	for i, pubKey := range givenWallet.AdminsPublicKeys {
		adminsPubKeys[i] = types.PubKeyToStruct(pubKey)
	}
	normalizedWeights := settings.WeightsNormalization(signingPolicyWeights)
	randomNonce, err := utils.GenerateRandom()
	if err != nil {
		return nil, err
	}

	metaData := backup.WalletBackupMetaData{
		WalletBackupId: backup.WalletBackupId{
			TeeId:         teeId,
			WalletId:      givenWallet.WalletId,
			KeyId:         givenWallet.KeyId,
			PublicKey:     types.PubKeyToStruct(&givenWallet.PrivateKey.PublicKey),
			OpType:        givenWallet.OpType,
			RewardEpochID: rewardEpochId,
			RandomNonce:   randomNonce,
		},
		AdminsPublicKeys:   adminsPubKeys,
		AdminsThreshold:    givenWallet.AdminsThreshold,
		ProvidersThreshold: settings.DataProvidersBackupThreshold,
		OpTypeConstants:    make([]byte, len(givenWallet.OpTypeConstants)),
		Cosigners:          make([]common.Address, len(givenWallet.Cosigners)),
		CosignersThreshold: givenWallet.CosignersThreshold,
	}
	copy(metaData.OpTypeConstants, givenWallet.OpTypeConstants)
	copy(metaData.Cosigners, givenWallet.Cosigners)

	splitKey, err := SplitPrivateKey(givenWallet.PrivateKey, 2)
	if err != nil {
		return nil, err
	}

	weightsOne := utils.ConstantSlice(1, len(givenWallet.AdminsPublicKeys))
	adminEncryptedParts, err := SplitAndEncrypt(splitKey[0], givenWallet.AdminsPublicKeys, givenWallet.AdminsThreshold, weightsOne, metaData.WalletBackupId, givenWallet.PrivateKey, true)
	if err != nil {
		return nil, err
	}

	providersEncryptedParts, err := SplitAndEncrypt(splitKey[1], providersPubKeys, settings.DataProvidersBackupThreshold, normalizedWeights, metaData.WalletBackupId, givenWallet.PrivateKey, false)
	if err != nil {
		return nil, err
	}

	walletBackup := &backup.WalletBackup{
		WalletBackupMetaData:    metaData,
		AdminEncryptedParts:     adminEncryptedParts,
		ProvidersEncryptedParts: providersEncryptedParts,
	}

	hash, err := walletBackup.HashForSigning()
	if err != nil {
		return nil, err
	}
	walletBackup.Signature, err = utils.Sign(hash[:], givenWallet.PrivateKey)
	if err != nil {
		return nil, err
	}

	return walletBackup, nil
}

func SplitAndEncrypt(key *ecdsa.PrivateKey, encryptionPubKeys []*ecdsa.PublicKey, threshold uint64,
	weights []uint16, backupId backup.WalletBackupId, sigPrivKey *ecdsa.PrivateKey, isAdmin bool) (*backup.EncryptedShares, error) {
	if len(encryptionPubKeys) != len(weights) {
		return nil, errors.New("number of encryption keys and weights do not match")
	}

	var numSplits = len(encryptionPubKeys)

	encryptionPubKeysApi := make([]types.ECDSAPublicKey, numSplits)
	for i, pubKey := range encryptionPubKeys {
		encryptionPubKeysApi[i] = types.PubKeyToStruct(pubKey)
	}
	encryptedShares := backup.EncryptedShares{
		Splits:           make([][]byte, numSplits),
		OwnersPublicKeys: encryptionPubKeysApi,
		Threshold:        threshold,
		PublicKey:        types.PubKeyToStruct(&key.PublicKey),
		Weights:          make([]uint16, numSplits),
	}
	copy(encryptedShares.Weights, weights)

	numShares := uint64(utils.Sum(weights))
	shamirShares, err := SplitToShamirShares(key.D, numShares, threshold)
	if err != nil {
		return nil, err
	}

	weightCounter := 0
	partialBackupId := backup.PartialWalletBackupId{
		WalletBackupId: backupId, PartialPubKey: encryptedShares.PublicKey, IsAdmin: isAdmin,
	}
	for i := range numSplits {
		keySplitData := backup.KeySplitData{
			Shares:                shamirShares[weightCounter : weightCounter+int(weights[i])],
			PartialWalletBackupId: partialBackupId,
			OwnerPublicKey:        types.PubKeyToStruct(encryptionPubKeys[i]),
		}
		sig, err := keySplitData.Sign(sigPrivKey)
		if err != nil {
			return nil, err
		}

		keySplit := backup.KeySplit{KeySplitData: keySplitData, Signature: sig}

		plaintext, err := json.Marshal(keySplit)
		if err != nil {
			return nil, err
		}

		pubKey := ecies.ImportECDSAPublic(encryptionPubKeys[i])
		cipher, err := ecies.Encrypt(rand.Reader, pubKey, plaintext, nil, nil)
		if err != nil {
			return nil, err
		}

		encryptedShares.Splits[i] = cipher
		weightCounter = weightCounter + int(weights[i])
	}

	return &encryptedShares, nil
}

func RecoverWallet(
	keyShares []*backup.KeySplit,
	backupMetaData *backup.WalletBackupMetaData,
) (*wallets.Wallet, error) {
	providersKeyShares := make([]*backup.KeySplit, 0)
	adminsKeyShares := make([]*backup.KeySplit, 0)
	for _, keySplit := range keyShares {
		if keySplit.IsAdmin {
			adminsKeyShares = append(adminsKeyShares, keySplit)
		} else {
			providersKeyShares = append(providersKeyShares, keySplit)
		}
	}

	err := CheckKeyShares(adminsKeyShares, backupMetaData)
	if err != nil {
		return nil, err
	}
	adminsKey, err := JoinKeyShares(adminsKeyShares, backupMetaData.AdminsThreshold)
	if err != nil {
		return nil, err
	}

	err = CheckKeyShares(providersKeyShares, backupMetaData)
	if err != nil {
		return nil, err
	}
	providersKey, err := JoinKeyShares(providersKeyShares, backupMetaData.ProvidersThreshold)
	if err != nil {
		return nil, err
	}

	key, err := JoinPrivateKeys([]*ecdsa.PrivateKey{adminsKey, providersKey})
	if err != nil {
		return nil, err
	}

	if types.PubKeyToStruct(&key.PublicKey) != backupMetaData.PublicKey {
		return nil, errors.New("private key reconstruction error: final result does not match address")
	}

	sec1PubKey := utils.SerializeCompressed(&key.PublicKey)
	xrpAddress, err := utils.GetXrpAddressFromPubkey(sec1PubKey)
	if err != nil {
		return nil, err
	}

	adminsPubKeys := make([]*ecdsa.PublicKey, len(backupMetaData.AdminsPublicKeys))
	for i, pubKey := range backupMetaData.AdminsPublicKeys {
		adminsPubKeys[i], err = types.ParsePubKey(pubKey)
		if err != nil {
			return nil, err
		}
	}

	return &wallets.Wallet{
		WalletId:   backupMetaData.WalletId,
		KeyId:      backupMetaData.KeyId,
		PrivateKey: key,
		Address:    crypto.PubkeyToAddress(key.PublicKey),
		XrpAddress: xrpAddress,
		Restored:   true,

		AdminsPublicKeys:   adminsPubKeys,
		AdminsThreshold:    backupMetaData.AdminsThreshold,
		Cosigners:          backupMetaData.Cosigners,
		CosignersThreshold: backupMetaData.CosignersThreshold,
		OpType:             backupMetaData.OpType,
		OpTypeConstants:    backupMetaData.OpTypeConstants,

		Status: &wallets.WalletStatus{Nonce: 0, StatusCode: 0},
	}, nil
}

func CheckKeyShares(splits []*backup.KeySplit, backupMetaData *backup.WalletBackupMetaData) error {
	if len(splits) == 0 {
		return errors.New("shares should not be empty")
	}
	partialBackupId := splits[0].PartialWalletBackupId
	for _, split := range splits {
		if split.PartialWalletBackupId != partialBackupId {
			return errors.New("one of key split's ids does not match expected id")
		}

		if split.IsAdmin {
			if !slices.Contains(backupMetaData.AdminsPublicKeys, split.OwnerPublicKey) {
				return errors.New("one of admins public keys is not in the backup metadata")
			}
		}
	}

	if partialBackupId.WalletBackupId != backupMetaData.WalletBackupId {
		return errors.New("backup metadata's id does not match expected id")
	}

	return nil
}

// JoinKeyShares assumes that all the splits have the same backup id and the signatures have been verified.
func JoinKeyShares(splits []*backup.KeySplit, threshold uint64) (*ecdsa.PrivateKey, error) {
	if threshold <= 0 {
		return nil, errors.New("threshold should be positive")
	}

	shares := make([]backup.ShamirShare, 0)
	for _, split := range splits {
		shares = append(shares, split.Shares...)
	}

	if uint64(len(shares)) < threshold {
		return nil, errors.New("threshold of shares is not reached")
	}
	shares = shares[:threshold]

	privateKeyBigInt, err := CombineShamirShares(shares)
	if err != nil {
		return nil, err
	}
	privateKey := crypto.ToECDSAUnsafe(privateKeyBigInt.Bytes())
	expectedPartialPublicKey := splits[0].PartialPubKey // at this point splits is checked to not be empty
	if types.PubKeyToStruct(&privateKey.PublicKey) != expectedPartialPublicKey {
		return nil, err
	}

	return privateKey, nil
}
