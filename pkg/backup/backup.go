package backup

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"
	"tee-node/pkg/types"
	"tee-node/pkg/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type WalletBackup struct {
	WalletBackupMetaData
	AdminEncryptedParts     *EncryptedShares
	ProvidersEncryptedParts *EncryptedShares
	Signature               []byte
}

type WalletBackupMetaData struct {
	WalletBackupId
	OpTypeConstants []byte

	AdminsPublicKeys   []types.ECDSAPublicKey
	AdminsThreshold    uint64
	ProvidersThreshold uint64
	Cosigners          []common.Address
	CosignersThreshold uint64
}

type WalletBackupId struct {
	TeeId     common.Address
	WalletId  common.Hash
	KeyId     uint64
	PublicKey types.ECDSAPublicKey

	OpType        [32]byte
	RewardEpochID uint32
	RandomNonce   [32]byte
}

type EncryptedShares struct {
	Splits           [][]byte
	OwnersPublicKeys []types.ECDSAPublicKey
	Threshold        uint64
	PublicKey        types.ECDSAPublicKey
	Weights          []uint16
}

type ShamirShare struct {
	X *big.Int
	Y *big.Int
}

func (s *ShamirShare) ID() string {
	return s.X.String()
}

type KeySplit struct {
	KeySplitData
	Signature []byte
}

type KeySplitData struct {
	Shares []ShamirShare
	PartialWalletBackupId
	OwnerPublicKey types.ECDSAPublicKey
}

type PartialWalletBackupId struct {
	WalletBackupId
	PartialPubKey types.ECDSAPublicKey
	IsAdmin       bool
}

func (backupId *WalletBackupId) Hash() common.Hash {
	backupIdBytes, _ := json.Marshal(backupId) // todo: check that this cannot be error
	hash := crypto.Keccak256Hash(backupIdBytes)

	return hash
}

func (keySplitData *KeySplitData) HashForSigning() (common.Hash, error) {
	keyDataBytes, err := json.Marshal(keySplitData)
	if err != nil {
		return common.Hash{}, err
	}
	hash := crypto.Keccak256Hash(keyDataBytes)

	return hash, nil
}

func (keySplitData *KeySplitData) Sign(privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash, err := keySplitData.HashForSigning()
	if err != nil {
		return nil, err
	}

	signature, err := utils.Sign(hash[:], privKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func (keySplitData *KeySplit) VerifySignature() error {
	hash, err := keySplitData.HashForSigning()
	if err != nil {
		return err
	}

	pubKeyParsed, err := types.ParsePubKey(keySplitData.PublicKey)
	if err != nil {
		return err
	}
	mainKeyAddress := crypto.PubkeyToAddress(*pubKeyParsed)

	err = utils.VerifySignature(hash[:], keySplitData.Signature, mainKeyAddress)

	return err
}

func (walletBackup *WalletBackup) HashForSigning() (common.Hash, error) {
	type WalletBackupForHashing struct {
		WalletBackupMetaData
		AdminEncryptedParts     *EncryptedShares
		ProvidersEncryptedParts *EncryptedShares
	}

	walletBackupBytes, err := json.Marshal(WalletBackupForHashing{
		WalletBackupMetaData:    walletBackup.WalletBackupMetaData,
		AdminEncryptedParts:     walletBackup.AdminEncryptedParts,
		ProvidersEncryptedParts: walletBackup.ProvidersEncryptedParts,
	})
	if err != nil {
		return common.Hash{}, err
	}
	hash := crypto.Keccak256Hash(walletBackupBytes)

	return hash, nil
}

func (walletBackup *WalletBackup) Check() error {
	err := walletBackup.AdminEncryptedParts.Check()
	if err != nil {
		return err
	}
	err = walletBackup.ProvidersEncryptedParts.Check()
	if err != nil {
		return err
	}

	if walletBackup.AdminsThreshold != walletBackup.AdminEncryptedParts.Threshold {
		return errors.New("admin threshold not matching given data")
	}

	if walletBackup.ProvidersThreshold != walletBackup.ProvidersEncryptedParts.Threshold {
		return errors.New("providers threshold not matching given data")
	}

	if len(walletBackup.AdminsPublicKeys) != len(walletBackup.AdminEncryptedParts.OwnersPublicKeys) {
		return errors.New("length of admin public keys not matching given data")
	}

	for i, pubKey := range walletBackup.AdminsPublicKeys {
		if pubKey != walletBackup.AdminEncryptedParts.OwnersPublicKeys[i] {
			return errors.New("admin public keys not matching")
		}
	}

	return nil
}

func (e *EncryptedShares) Check() error {
	if len(e.Splits) != len(e.OwnersPublicKeys) {
		return errors.New("the number of splits does not match the number of public keys")
	}
	if len(e.Splits) != len(e.Weights) {
		return errors.New("the number of splits does not match the number of weights")
	}
	if uint64(utils.Sum(e.Weights)) < e.Threshold {
		return errors.New("threshold too high")
	}

	return nil
}

func DecryptSplit(encryptedShare []byte, privKeyECDSA *ecdsa.PrivateKey) (*KeySplit, error) {
	privKeyDecryption := ecies.ImportECDSA(privKeyECDSA)
	shareBytes, err := privKeyDecryption.Decrypt(encryptedShare, nil, nil)
	if err != nil {
		return nil, err
	}

	var keySplit KeySplit
	err = json.Unmarshal(shareBytes, &keySplit)
	if err != nil {
		return nil, err
	}

	err = keySplit.VerifySignature()
	if err != nil {
		return nil, err
	}

	if keySplit.OwnerPublicKey != types.PubKeyToStruct(&privKeyECDSA.PublicKey) {
		return nil, errors.New("public key defined in the split does not match given public key")
	}

	return &keySplit, nil
}
