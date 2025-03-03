package requests_test

import (
	"encoding/hex"
	"tee-node/internal/requests"
	"tee-node/internal/utils"
	testutils "tee-node/tests"
	"testing"

	api "tee-node/api/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const walletName = "wallet1"

func TestInvalidRequestSignature(t *testing.T) {

	numVoters, randSeed, epochId := 100, int64(12345), uint32(1)
	_, _, privKeys := testutils.GenerateAndSetInitialPolicy(numVoters, randSeed, epochId)

	instructionIdBytes, _ := utils.GenerateRandomBytes(32)

	instruction, err := testutils.BuildMockInstruction(
		"WALLET",
		"KEY_GENERATE",
		api.NewWalletRequest{Name: walletName},
		privKeys[0],
		hex.EncodeToString(instructionIdBytes),
	)
	require.NoError(t, err)

	wrongPrivKey, err := utils.GenerateEthereumPrivateKey()
	require.NoError(t, err)

	wrongSig, err := requests.Sign(instruction.Data, wrongPrivKey)
	require.NoError(t, err)

	_, err = requests.CheckSignature(instruction.Data, wrongSig)

	if assert.Error(t, err) {
		assert.Equal(t, "not a voter", err.Error())
	}

}
