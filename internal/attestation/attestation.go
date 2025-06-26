package attestation

import (
	"crypto/x509"

	"github.com/flare-foundation/tee-node/internal/settings"
	"github.com/flare-foundation/tee-node/pkg/attestation"

	"github.com/pkg/errors"
)

var GoogleCert *x509.Certificate

func SetGoogleCert() error {
	var err error
	GoogleCert, err = attestation.LoadRootCert(settings.GoogleCertLoc) // todo
	if err != nil {
		return err
	}

	return nil
}

func SelfAttest() error {
	tokeBytes, err := GetGoogleAttestationToken([]string{}, "PKI")
	if err != nil {
		return err
	}

	token, err := attestation.ValidatePKIToken(GoogleCert, string(tokeBytes))
	if err != nil {
		return err
	}
	ok, err := attestation.ValidateClaims(token, []string{})
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("failed validating token")
	}

	return nil
}
