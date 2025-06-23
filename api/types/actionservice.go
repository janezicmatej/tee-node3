package types

import (
	"github.com/ethereum/go-ethereum/common"
)

const (
	ThresholdReachedSubmissionTag SubmissionTag = "ThresholdReached"
	VotingClosedSubmissionTag     SubmissionTag = "VotingClosed"

	// Action types
	InstructionType = "instruction"
	ActionType      = "action"
)

type SignedAction struct {
	Data       ActionData `json:"data"`
	Signatures [][]byte   `json:"signatures"`
}

type ActionData struct {
	OPType    common.Hash `json:"opType"`
	OPCommand common.Hash `json:"opCommand"`
	Message   []byte      `json:"message"`
}

type QueuedAction struct {
	Data                       QueueActionData `json:"data"`
	AdditionalVariableMessages [][]byte        `json:"additionalVariableMessages"`
	Timestamps                 []uint64        `json:"timestamps"`
	AdditionalActionData       [][]byte        `json:"additionalActionData"`
	Signatures                 [][]byte        `json:"signatures"`
}

type SubmissionTag string

type QueueActionData struct {
	ActionId      common.Hash   `json:"actionId"`
	Type          string        `json:"type"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
	Message       []byte        `json:"message"`
}

// The response received after queuing the action
type QueueActionResponse struct {
	ActionId      common.Hash   `json:"actionId"`
	SubmissionTag SubmissionTag `json:"submissionTag"`

	Result QueueActionResult `json:"result"`
}

type QueueActionResult struct {
	Status                 bool        `json:"status"`
	Log                    string      `json:"log"`
	OPType                 common.Hash `json:"opType"`
	OPCommand              common.Hash `json:"opCommand"`
	AdditionalResultStatus []byte      `json:"additionalResultStatus"`

	ResultData QueueActionResultData `json:"resultData"`
}

type QueueActionResultData struct {
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}

type QueuedActionInfo struct {
	QueueId       string        `json:"queueId"`
	ActionId      common.Hash   `json:"actionId"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
}

type SignerSequence struct {
	Data      SignerSequenceData `json:"data"`
	Signature []byte             `json:"signature"` // TEE signature of QueueHash
}

type SignerSequenceData struct {
	VoteHash                   common.Hash    `json:"queueHash"`
	InstructionId              common.Hash    `json:"instructionId"`
	InstructionHash            common.Hash    `json:"instructionHash"`
	RewardEpochId              uint32         `json:"rewardEpochId"`
	TeeId                      common.Address `json:"teeId"`
	Signatures                 [][]byte       `json:"signatures"` // Signatures of the signers and cosigners
	AdditionalVariableMessages [][]byte       `json:"additionalVariableMessages"`
	Timestamps                 []uint64       `json:"timestamps"`
}
