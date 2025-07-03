package types

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flare-foundation/go-flare-common/pkg/tee/constants"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
)

func ParseFDCProve(instructionData *instruction.DataFixed) (connector.IFtdcHubFtdcProve, error) {
	arg := connector.MessageArguments[constants.Prove]

	var proveFDCRequest connector.IFtdcHubFtdcProve
	err := structs.DecodeTo(arg, instructionData.OriginalMessage, &proveFDCRequest)
	if err != nil {
		return connector.IFtdcHubFtdcProve{}, err
	}

	return proveFDCRequest, nil
}

type FdcProveResponse struct {
	ResponseData           hexutil.Bytes
	Signature              hexutil.Bytes
	CosignerSignatures     []hexutil.Bytes
	DataProviderSignatures []hexutil.Bytes
}
