package direct

import (
	"github.com/pkg/errors"

	"github.com/flare-foundation/tee-node/internal/processor/direct/getutils"
	"github.com/flare-foundation/tee-node/internal/processor/direct/policyutils"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

func ProcessDirectInstruction(directInstructionData *types.DirectInstructionData) ([]byte, error) {
	var err error
	var result []byte
	switch utils.OpHashToString(directInstructionData.OPType) {
	case "POLICY":
		result, err = executePolicyDirectInstruction(directInstructionData)
	case "GET":
		result, err = getData(directInstructionData)
	default:
		return nil, errors.New("invalid action type")
	}
	if err != nil {
		return nil, err
	}

	return result, nil
}

func executePolicyDirectInstruction(directInstructionData *types.DirectInstructionData) ([]byte, error) {
	var err error
	response := []byte{}
	switch utils.OpHashToString(directInstructionData.OPCommand) {
	case "INITIALIZE_POLICY":
		err = policyutils.InitializePolicy(directInstructionData.Message)
	case "UPDATE_POLICY":
		err = policyutils.UpdatePolicy(directInstructionData.Message)
	default:
		return nil, errors.New("invalid action type")
	}
	if err != nil {
		return nil, err
	}

	return response, nil
}

func getData(directInstructionData *types.DirectInstructionData) ([]byte, error) {
	switch utils.OpHashToString(directInstructionData.OPCommand) {
	case "TEE_INFO":
		return getutils.GetTeeInfo(directInstructionData)

	case "KEY_INFO":
		return getutils.GetKeyInfoPackage()

	case "TEE_BACKUP":
		return getutils.GetBackupPackage(directInstructionData)

	default:
		return nil, errors.New("unknown OpCommand for WALLET OpType")
	}
}
