package policy

import (
	"context"
	"encoding/hex"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/relay"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/system"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	common_policy "github.com/flare-foundation/go-flare-common/pkg/policy"
	"gorm.io/gorm"
)

type PolicyHistoryParams struct {
	RelayContractAddress              common.Address
	FlareSystemManagerContractAddress common.Address
}

const signNewSigningPolicy = "signNewSigningPolicy"

var signingPolicyInitializedEventSel common.Hash
var AttestationRequestEventSel common.Hash
var systemABI *abi.ABI
var signNewSigningPolicyAbiArgs abi.Arguments
var signNewSigningPolicyFuncSel [4]byte

func init() {
	relayABI, err := relay.RelayMetaData.GetAbi()
	if err != nil {
		logger.Panic("cannot get relayAby:", err)
	}

	signingPolicyEvent, ok := relayABI.Events["SigningPolicyInitialized"]
	if !ok {
		logger.Panic("cannot get SigningPolicyInitialized event:", err)
	}
	signingPolicyInitializedEventSel = signingPolicyEvent.ID

	systemABI, err = system.FlareSystemsManagerMetaData.GetAbi()
	if err != nil {
		logger.Panic("cannot get submission ABI:", err)
	}
	copy(signNewSigningPolicyFuncSel[:], systemABI.Methods[signNewSigningPolicy].ID[:4])

	signNewSigningPolicyAbiArgs = systemABI.Methods[signNewSigningPolicy].Inputs
}

// FetchPolicyHistory extracts all the data involving policies from the database
func FetchPolicyHistory(ctx context.Context, params *PolicyHistoryParams, db *gorm.DB) ([]*relay.RelaySigningPolicyInitialized, map[string][]*system.IFlareSystemsManagerSignature, error) {
	logsParams := database.LogsParams{
		Address: params.RelayContractAddress,
		Topic0:  signingPolicyInitializedEventSel,
		From:    0,
		To:      100000000000000, // todo max
	}

	logs, err := database.FetchLogsByAddressAndTopic0Timestamp(
		ctx, db, logsParams,
	)
	if err != nil {
		return nil, nil, err
	}

	txsParams := database.TxParams{
		ToAddress:   params.FlareSystemManagerContractAddress,
		FunctionSel: signNewSigningPolicyFuncSel,
		From:        0,
		To:          100000000000000, // todo max
	}
	txs, err := database.FetchTransactionsByAddressAndSelectorTimestamp(
		ctx, db, txsParams,
	)
	if err != nil {
		return nil, nil, err
	}

	hashToSignatures := make(map[string][]*system.IFlareSystemsManagerSignature)
	for _, tx := range txs {
		inputBytes, err := hex.DecodeString(tx.Input)
		if err != nil {
			return nil, nil, err
		}
		inputBytes = inputBytes[4:]

		signNewSigningPolicyInputBytesArray, err := signNewSigningPolicyAbiArgs.Unpack(inputBytes)
		if err != nil {
			return nil, nil, err
		}
		// rewardEpochId := *abi.ConvertType(signNewSigningPolicyInputBytesArray[0], new(*big.Int)).(**big.Int)
		newSigningPolicyHashBytes := *abi.ConvertType(signNewSigningPolicyInputBytesArray[1], new([32]byte)).(*[32]byte)
		newSigningPolicyHash := hex.EncodeToString(newSigningPolicyHashBytes[:])
		signature := *abi.ConvertType(signNewSigningPolicyInputBytesArray[2], new(system.IFlareSystemsManagerSignature)).(*system.IFlareSystemsManagerSignature)

		if _, ok := hashToSignatures[newSigningPolicyHash]; !ok {
			hashToSignatures[newSigningPolicyHash] = make([]*system.IFlareSystemsManagerSignature, 0)
		}

		hashToSignatures[newSigningPolicyHash] = append(hashToSignatures[newSigningPolicyHash], &signature)

		// fmt.Println(rewardEpochId, newSigningPolicyHash, signature)
	}

	policies := make([]*relay.RelaySigningPolicyInitialized, len(logs))
	for i, log := range logs {
		policies[i], err = common_policy.ParseSigningPolicyInitializedEvent(log)
		if err != nil {
			return nil, nil, err
		}
	}

	return policies, hashToSignatures, nil
}
