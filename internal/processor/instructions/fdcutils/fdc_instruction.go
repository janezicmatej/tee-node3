package fdcutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/instruction"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/flare-foundation/tee-node/internal/node"
	"github.com/flare-foundation/tee-node/pkg/types"
	"github.com/flare-foundation/tee-node/pkg/utils"
)

const fdcAttestationResponseAbi = "{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"attestationType\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"sourceId\",\"type\":\"bytes32\"},{\"internalType\":\"uint16\",\"name\":\"thresholdBIPS\",\"type\":\"uint16\"},{\"internalType\":\"uint64\",\"name\":\"timestamp\",\"type\":\"uint64\"},{\"internalType\":\"address[]\",\"name\":\"cosigners\",\"type\":\"address[]\"},{\"internalType\":\"uint64\",\"name\":\"cosignersThreshold\",\"type\":\"uint64\"}],\"internalType\":\"structFDC.Response\",\"name\":\"data\",\"type\":\"tuple\"}"

var fdcAttestationResponseArg abi.Argument

func init() {
	err := fdcAttestationResponseArg.UnmarshalJSON([]byte(fdcAttestationResponseAbi))
	if err != nil {
		panic(fmt.Sprintf("error getting tee data connector abi: %v", err))
	}
}

type FdcAttestationResponse struct {
	AttestationType    [32]byte
	SourceId           [32]byte
	ThresholdBIPS      uint16
	Timestamp          uint64
	Cosigners          []common.Address
	CosignersThreshold uint64
}

func ValidateFdcProve(instructionData *instruction.DataFixed, variableMessages []hexutil.Bytes, signers []common.Address, isSignerDataProvider []bool) ([]byte, error) {
	fdcProveRequest, err := types.ParseFDCProve(instructionData)
	if err != nil {
		return nil, err
	}

	isSignerCosigner, err := utils.CheckCosigners(signers, isSignerDataProvider, fdcProveRequest.Cosigners, fdcProveRequest.CosignersThreshold)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(fdcProveRequest.TeeIds, node.GetTeeId()) {
		return nil, errors.New("tee not among requested tees")
	}

	encodedFdcResponse := instructionData.AdditionalFixedMessage
	err = checkFdcAttestationResponse(encodedFdcResponse, fdcProveRequest)
	if err != nil {
		return nil, err
	}

	dataProviderSignatures, cosignerSignatures, err := checkResponseSignatures(
		encodedFdcResponse, variableMessages, signers, isSignerDataProvider, isSignerCosigner,
	)
	if err != nil {
		return nil, err
	}

	hash := crypto.Keccak256Hash(encodedFdcResponse)
	signature, err := node.Sign(hash[:])
	if err != nil {
		return nil, err
	}

	result := types.FdcProveResponse{
		ResponseData:           encodedFdcResponse,
		Signature:              signature,
		DataProviderSignatures: dataProviderSignatures,
		CosignerSignatures:     cosignerSignatures,
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	return resultBytes, nil
}

func checkFdcAttestationResponse(responseBytes hexutil.Bytes, proveRequest connector.IFtdcHubFtdcProve) error {
	response, err := abiDecodeFdcAttestationResponse(responseBytes)
	if err != nil {
		return err
	}

	if response.ThresholdBIPS != proveRequest.ThresholdBIPS {
		return errors.New("data providers threshold in request and response do not match")
	}
	if response.CosignersThreshold != proveRequest.CosignersThreshold {
		return errors.New("cosigners threshold in request and response do not match")
	}
	if len(response.Cosigners) != len(proveRequest.Cosigners) {
		return errors.New("number of cosigners in request and response do not match")
	}
	for i := range response.Cosigners {
		if response.Cosigners[i] != proveRequest.Cosigners[i] {
			return errors.New("cosigners in request and response do not match")
		}
	}

	return nil
}

func abiDecodeFdcAttestationResponse(responseBytes hexutil.Bytes) (response FdcAttestationResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(error)
			if ok {
				err = fmt.Errorf("recovered panic: %w", e)
			} else {
				err = fmt.Errorf("recovered panic non error: %w", e)
			}
		}
	}()

	decodedSlice, err := abi.Arguments{fdcAttestationResponseArg}.Unpack(responseBytes)
	if err != nil {
		return response, err
	}

	x := abi.ConvertType(decodedSlice[0], new(FdcAttestationResponse))

	tp, ok := x.(*FdcAttestationResponse)
	if !ok {
		return response, errors.New("invalid type assertion")
	}
	response = *tp

	return response, err
}

func checkResponseSignatures(
	responseBytes hexutil.Bytes,
	signatures []hexutil.Bytes,
	signers []common.Address,
	isSignerDataProvider,
	isSignerCosigner []bool,
) ([]hexutil.Bytes, []hexutil.Bytes, error) {
	// this two checks should never happen, but just in case
	if len(signatures) != len(signers) {
		return nil, nil, errors.New("the number of signers does not match the number of signatures")
	}
	if len(signatures) != len(isSignerDataProvider) || len(signatures) != len(isSignerCosigner) {
		return nil, nil, errors.New("the number of signers does not match the length of signers info")
	}
	hash := crypto.Keccak256Hash(responseBytes)

	dataProviderSignatures := make([]hexutil.Bytes, 0)
	cosignerSignatures := make([]hexutil.Bytes, 0)
	for i, signature := range signatures {
		err := utils.VerifySignature(hash[:], signature, signers[i])
		if err != nil {
			return nil, nil, err
		}
		if isSignerDataProvider[i] {
			dataProviderSignatures = append(dataProviderSignatures, signature)
		}
		if isSignerCosigner[i] {
			cosignerSignatures = append(cosignerSignatures, signature)
		}
	}

	return dataProviderSignatures, cosignerSignatures, nil
}
