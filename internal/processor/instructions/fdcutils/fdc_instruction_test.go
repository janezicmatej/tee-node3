package fdcutils

import (
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/connector"
	"github.com/stretchr/testify/require"
)

func TestAbiDecodeFdcAttestationResponse(t *testing.T) {
	originalMessage := connector.ITeeAvailabilityCheckResponse{
		ThresholdBIPS:      100,
		Timestamp:          2,
		Cosigners:          []common.Address{common.HexToAddress("aaaa"), common.HexToAddress("bbbb")},
		CosignersThreshold: 1,
		RequestBody: connector.ITeeAvailabilityCheckRequestBody{
			Challenge: common.Big1,
		},
		ResponseBody: connector.ITeeAvailabilityCheckResponseBody{
			RewardEpochId: common.Big1,
		},
	}
	originalMessage.AttestationType[5] = 5
	originalMessage.SourceId[4] = 4

	originalMessageEncoded, err := abi.Arguments{connector.AttestationTypeArguments[connector.AvailabilityCheck].Response}.Pack(originalMessage)
	require.NoError(t, err)

	response, err := abiDecodeFdcAttestationResponse(originalMessageEncoded)
	require.NoError(t, err)

	require.Equal(t, response.CosignersThreshold, originalMessage.CosignersThreshold)
	require.Equal(t, response.ThresholdBIPS, originalMessage.ThresholdBIPS)
	require.Equal(t, response.Timestamp, originalMessage.Timestamp)
	require.Equal(t, response.Cosigners, originalMessage.Cosigners)
	require.Equal(t, response.SourceId, originalMessage.SourceId)
	require.Equal(t, response.AttestationType, originalMessage.AttestationType)
}
