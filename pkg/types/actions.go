package types

import (
	"github.com/ethereum/go-ethereum/common"
)

const (
	// Action types
	InstructionType = "instruction"
	DirectType      = "direct"

	// Submission tags for instruction action
	ThresholdReachedSubmissionTag SubmissionTag = "ThresholdReached"
	VotingClosedSubmissionTag     SubmissionTag = "VotingClosed"
)

type SubmissionTag string

type Action struct {
	Data                       ActionData `json:"data"`
	AdditionalVariableMessages [][]byte   `json:"additionalVariableMessages"`
	Timestamps                 []uint64   `json:"timestamps"`
	AdditionalActionData       [][]byte   `json:"additionalActionData"`
	Signatures                 [][]byte   `json:"signatures"`
}

type ActionData struct {
	ActionId      common.Hash   `json:"actionId"`
	Type          string        `json:"type"`
	SubmissionTag SubmissionTag `json:"submissionTag"`
	Message       []byte        `json:"message"`
}

// The response received after queuing an action
type ActionResponse struct {
	ActionId      common.Hash   `json:"actionId"`
	SubmissionTag SubmissionTag `json:"submissionTag"`

	Result ActionResult `json:"result"`
}

type ActionResult struct {
	Status                 bool        `json:"status"`
	Log                    string      `json:"log"`
	OPType                 common.Hash `json:"opType"`
	OPCommand              common.Hash `json:"opCommand"`
	AdditionalResultStatus []byte      `json:"additionalResultStatus"`

	ResultData ActionResultData `json:"resultData"`
}

type ActionResultData struct {
	Message   []byte `json:"message"`
	Signature []byte `json:"signature"`
}

type ActionInfo struct {
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
