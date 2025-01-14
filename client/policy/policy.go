package policy

import (
	"context"
	"fmt"
	"tee-node/internal/policy"

	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/relay"
	"github.com/flare-foundation/go-flare-common/pkg/contracts/system"
	"github.com/flare-foundation/go-flare-common/pkg/database"
	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"gorm.io/gorm"
)

type PolicyHistoryParams struct {
	StartingPolicyHash                []byte
	RelayContractAddress              common.Address
	FlareSystemManagerContractAddress common.Address
}

var signingPolicyInitializedEventSel common.Hash
var AttestationRequestEventSel common.Hash
var voterRegisteredEventSel common.Hash

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

	systemABI, err := system.FlareSystemsManagerMetaData.GetAbi()
	if err != nil {
		logger.Panic("cannot get submission ABI:", err)
	}
	copy(signNewSigningPolicyFuncSel[:], systemABI.Methods["signNewSigningPolicy"].ID[:4])
}

func FetchPolicyHistory(ctx context.Context, params *PolicyHistoryParams, db *gorm.DB) ([]policy.SigningPolicy, error) {
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
		return nil, err
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
		return nil, err
	}

	fmt.Println(logs)
	fmt.Println(txs)

	fmt.Println(len(logs), len(txs))

	return nil, nil
}
