package policyservice
// todo: maybe rename to policyinstruction ?
import (
	api "tee-node/api/types"
	"tee-node/internal/policy"
)

func UpdatePolicy(instructionData *api.InstructionDataBase) error {
	multiSignedPolicy, err := api.ParseMultiSignedPolicyRequest(instructionData)
	if err != nil {
		return err
	}

	err = policy.UpdatePolicyRequest(multiSignedPolicy)
	if err != nil {
		return err
	}

	return nil
}
