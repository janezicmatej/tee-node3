package types

import "github.com/ethereum/go-ethereum/common"

type DirectInstruction struct {
	Data       DirectInstructionData `json:"data"`
	Signatures [][]byte              `json:"signatures"`
}

type DirectInstructionData struct {
	OPType    common.Hash `json:"opType"`
	OPCommand common.Hash `json:"opCommand"`
	Message   []byte      `json:"message"`
}
