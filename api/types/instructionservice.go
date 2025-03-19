package types

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/crypto"
)

type Instruction struct {
	Challenge string
	Data      *InstructionData
	Signature []byte
}

type InstructionDataBase struct {
	InstructionId string
	TeeId         string
	RewardEpochID uint32
	OpType        string
	OpCommand     string
	// Original binary message from smart contract event
	OriginalMessage []byte
	// Binary data, depending on operation type and instruction. Go JSON marshaled. (Fixed, because it's the same for all providers)
	AdditionalFixedMessage []byte
}

type InstructionData struct {
	InstructionDataBase
	// Binary data, —||—. (Variable, because it's different for each provider. Example: signature of AdditionalFixedMessage, or price prediction)
	AdditionalVariableMessage []byte
}

func (d InstructionData) Identifier() string {
	return d.InstructionId
}

func (data InstructionData) Hash() []byte {
	result, err := json.Marshal(data) // Encode without the field
	if err != nil {
		return nil
	}

	return crypto.Keccak256(result)
}

func (data InstructionDataBase) Hash() []byte {
	result, err := json.Marshal(data) // Encode without the field
	if err != nil {
		return nil
	}

	return crypto.Keccak256(result)
}

type InstructionResponse struct {
	ResponseBase
	Data      []byte // TODO: is it needed?
	Finalized bool   // Note: leaving this in for now, because it's used in the tests
}

// * ——————————————— GET Requests ——————————————— * //

type InstructionResultRequest struct {
	Challenge     string
	InstructionId string
}

type InstructionResultResponse struct {
	ResponseBase
	Data []byte
}

type InstructionStatusResponse struct {
	ResponseBase
	Data InstructionStatusData
}

type InstructionStatusData struct {
	VoteResults []VoteResult
	Status      string
	ErrorLog    string
}

type VoteResult struct {
	NumberOfVotes uint16
	TotalWeight   uint16
}

type RewardingDataResponse struct {
	ResponseBase
	Data []byte
}
