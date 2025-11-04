package attestation

import (
	"crypto/x509"
	"encoding/hex"
	"time"

	"github.com/ethereum/go-ethereum/common"
	googlecloud "github.com/flare-foundation/go-flare-common/pkg/tee/attestation/google_cloud"
	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/attestation"
	"github.com/flare-foundation/tee-node/pkg/node"
	"github.com/flare-foundation/tee-node/pkg/types"
)

var GoogleCert *x509.Certificate

// SetGoogleCert loads the Google root certificate into memory for attestation
// validation.
func SetGoogleCert() error {
	var err error
	GoogleCert, err = attestation.LoadRootCert(settings.GoogleCertLoc)
	if err != nil {
		return err
	}

	return nil
}

// ConstructTEEInfoResponse creates a tee info attestation response for the given challenge
func ConstructTEEInfoResponse(challenge common.Hash, nodeInfo *node.Info, initialID uint32, initialHash common.Hash, activeID uint32, activeHash common.Hash) (*types.TeeInfoResponse, error) {
	state, err := nodeInfo.State.State()
	if err != nil {
		return nil, err
	}

	teeInfo := types.TeeInfo{
		Challenge:                challenge,
		PublicKey:                nodeInfo.PublicKey,
		InitialSigningPolicyID:   initialID,
		InitialSigningPolicyHash: initialHash,
		LastSigningPolicyID:      activeID,
		LastSigningPolicyHash:    activeHash,
		State:                    state,
		TeeTimestamp:             uint64(time.Now().Unix()),
	}

	h, err := teeInfo.Hash()
	if err != nil {
		return nil, err
	}

	attestationBytes, err := GetGoogleAttestationToken([]string{hex.EncodeToString(h)}, attestation.PKITokenType)
	if err != nil {
		return nil, err
	}

	cHash := common.HexToHash("4743505f494e54454c5f54445800000000000000000000000000000000000000")
	platform := common.HexToHash("194844cf417dde867073e5ab7199fa4d21fd82b5dbe2bdea8b3d7fc18d10fdc2")

	if settings.Mode == 0 {
		claims := &attestation.NeededClaims{}
		_, claims, err := googlecloud.ParsePKITokenUnverifiedClaims(string(attestationBytes), claims)
		if err != nil {
			return nil, err
		}

		cHash, err = claims.CodeHash()
		if err != nil {
			return nil, err
		}

		platform, err = claims.Platform()
		if err != nil {
			return nil, err
		}
	}

	mData := types.MachineData{
		ExtensionID:  nodeInfo.ExtensionID,
		InitialOwner: nodeInfo.InitialOwner,
		CodeHash:     cHash,
		Platform:     platform,
		PublicKey:    nodeInfo.PublicKey,
	}

	teeInfoResponse := types.TeeInfoResponse{
		TeeInfo:     teeInfo,
		MachineData: mData,
		Attestation: attestationBytes,
	}

	return &teeInfoResponse, nil
}
