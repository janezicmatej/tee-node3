package types

type GetAttestationTokenRequest struct {
	Nonces []string
}

type GetAttestationTokenResponse struct {
	JwtBytes string
}

type GetHardwareAttestationRequest struct {
	Nonce string
}

type GetHardwareAttestationResponse struct {
	JsonAttestation string
}

type AttestationRequset struct {
	Challenge string
}

type AttestationResponse struct {
	Status      string
	Data        AttestationData
	Attestation string
}

type AttestationData struct {
	IdentityPublicKey       string
	TLSCertificate          string
	Status                  string
	LatestSigningPolicyId   uint32
	LatestSigningPolicyHash string
}
