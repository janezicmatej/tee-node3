package requests

import (
	"encoding/hex"
	"sync"
	api "tee-node/api/types"

	"golang.org/x/exp/slices"
)

// instructionIdToHash handles the mapping needed to find all the instructions
// based on instruction Id
var instructionIdToHash = InitInstructionIdToHashes()

type InstructionIdToHashes struct {
	Map map[string][]string

	sync.Mutex
}

func InitInstructionIdToHashes() *InstructionIdToHashes {
	return &InstructionIdToHashes{Map: make(map[string][]string)}
}

func GetHashesWithId(instructionId string) ([]string, bool) {
	instructionIdToHash.Lock()
	defer instructionIdToHash.Unlock()
	requestsWithId, ok := instructionIdToHash.Map[instructionId]
	if !ok {
		return nil, false
	}
	requestsWithIdCopy := make([]string, len(requestsWithId))
	copy(requestsWithIdCopy, requestsWithId)

	return requestsWithIdCopy, true
}

func ProcessInstructionIdMapping(instructionData *api.InstructionDataBase) {
	instructionIdToHash.Lock()
	defer instructionIdToHash.Unlock()

	if _, ok := instructionIdToHash.Map[instructionData.InstructionId]; !ok {
		instructionIdToHash.Map[instructionData.InstructionId] = make([]string, 0)
	}

	instructionHash := hex.EncodeToString(instructionData.Hash())

	// If the instruction hash is already in the list, we don't need to add it again
	if slices.Contains(instructionIdToHash.Map[instructionData.InstructionId], instructionHash) {
		return
	}

	instructionIdToHash.Map[instructionData.InstructionId] = append(instructionIdToHash.Map[instructionData.InstructionId], instructionHash)
}
