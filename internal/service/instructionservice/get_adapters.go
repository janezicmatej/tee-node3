package instructionservice

import (
	"encoding/json"
	api "tee-node/api/types"
	"tee-node/internal/service/instructionservice/signingservice"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// * ----- REG OpType ----- * //

// TODO: Implement this service and APIs
func handleRegGetRequest(instructionData *api.InstructionData, result []byte) ([]byte, error) {
	switch instructionData.OpCommand {
	case "AVAILABILITY_CHECK":
		return nil, status.Error(codes.Unimplemented, "REG AVAILABILITY_CHECK command not implemented yet")

	case "TO_PAUSE_FOR_UPGRADE":
		return nil, status.Error(codes.Unimplemented, "REG TO_PAUSE_FOR_UPGRADE command not implemented yet")

	case "REPLICATE_FROM":
		return nil, status.Error(codes.Unimplemented, "REG REPLICATE_FROM command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}

}

// * ----- WALLET OpType ----- * //

func handleWalletGetRequest(instructionData *api.InstructionData, result []byte) ([]byte, error) {
	switch instructionData.OpCommand {

	case "KEY_GENERATE":

		// TODO:
		return nil, nil

	case "KEY_DELETE":

		// TODO:
		return nil, nil

	case "KEY_MACHINE_BACKUP":

		// TODO:
		return nil, nil

	case "KEY_MACHINE_RESTORE":

		// TODO:
		return nil, nil

	case "KEY_MACHINE_BACKUP_REMOVE":

		return nil, status.Error(codes.Unimplemented, "WALLET KEY_MACHINE_BACKUP_REMOVE command not implemented yet")

	case "KEY_CUSTODIAN_BACKUP":

		return nil, status.Error(codes.Unimplemented, "WALLET KEY_CUSTODIAN_BACKUP command not implemented yet")

	case "KEY_CUSTODIAN_RESTORE":

		return nil, status.Error(codes.Unimplemented, "WALLET KEY_CUSTODIAN_RESTORE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for WALLET OpType")
	}
}

// * ----- XRP OpType ----- * //

func handleXrpGetRequest(instructionData *api.InstructionData, requestResult []byte) ([]byte, error) {

	switch instructionData.OpCommand {
	case "PAY":

		response, err := signingservice.GetPaymentSignature(instructionData, requestResult)
		if err != nil {
			return nil, err
		}

		encodedResponse, err := json.Marshal(response)
		if err != nil {
			return nil, err
		}

		return encodedResponse, nil

	case "REISSUE":
		return nil, status.Error(codes.Unimplemented, "XRP RESISSUE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for XRP OpType")
	}

}

func handleBtcGetRequest(instructionData *api.InstructionData, result []byte) ([]byte, error) {
	switch instructionData.OpCommand {
	case "PAY":
		return nil, status.Error(codes.Unimplemented, "BTC PAY command not implemented yet")

	case "REISSUE":
		return nil, status.Error(codes.Unimplemented, "BTC REISSUE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for BTC OpType")

	}
}

func handleFdcGetRequest(instructionData *api.InstructionData, result []byte) ([]byte, error) {
	switch instructionData.OpCommand {
	case "PROVE":
		return nil, status.Error(codes.Unimplemented, "FDC PROVE command not implemented yet")

	default:
		return nil, status.Error(codes.Unknown, "Unknown OpCommand for FDC OpType")
	}
}
