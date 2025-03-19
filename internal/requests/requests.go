package requests

import (
	"crypto/ecdsa"
	api "tee-node/api/types"
	"tee-node/internal/config"
	"tee-node/internal/node"
	"tee-node/internal/policy"
	"tee-node/internal/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Sign(r *api.InstructionData, privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := r.Hash()
	signature, err := utils.Sign(hash, privKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func CheckSignature(r *api.InstructionData, signature []byte, requestPolicy *policy.SigningPolicy) (common.Address, error) {
	hash := r.Hash()

	return utils.CheckSignature(hash, signature, requestPolicy.Voters)
}

func CheckSigner(request *api.InstructionData, signature []byte) (common.Address, error) {
	requestPolicy := policy.GetSigningPolicy(request.RewardEpochID)
	if requestPolicy == nil {
		return common.Address{}, nil
	}

	providerAddress, err := CheckSignature(request, signature, requestPolicy)
	if err != nil {
		return common.Address{}, err
	}

	return providerAddress, nil
}

func CheckRequest(instructionData *api.InstructionData) error {
	nodeId := node.GetNodeId()
	if instructionData.TeeId != nodeId.Id {
		return errors.New("invalid TEE id")
	}

	if policy.ActiveSigningPolicy.RewardEpochId < instructionData.RewardEpochID {
		return errors.New("reward epoch not started yet")
	}
	if policy.ActiveSigningPolicy.RewardEpochId-instructionData.RewardEpochID > config.ACTIVE_POLICY_COUNT {
		return errors.New("reward epoch id too old")
	}

	// Check the command is valid
	valid := isValidCommand(instructionData.OpType, instructionData.OpCommand)
	if !valid {
		return status.Error(codes.InvalidArgument, "invalid command for operation type")
	}

	return nil
}

// IsValidSubCommand checks if the OpType and Command is valid for a given operation type
func isValidCommand(op, command string) bool {
	validCommands, exists := config.InstructionOperations[op]
	if !exists {
		return false
	}

	for _, cmd := range validCommands {
		if cmd == command {
			return true
		}
	}
	return false
}
