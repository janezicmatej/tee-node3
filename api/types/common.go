package types

// Something that is common to all/most responses
type ResponseBase struct {
	Status string
	Token  string
}

// // Implement the SetBase method directly on ResponseBase
// func (r *ResponseBase) SetBase(status, attestation string) {
// 	r.Status = status
// 	r.AttestationToken = attestation
// }

// type IResponseBase interface {
// 	SetBase(status, attestation string)
// }

type SignatureMessage struct {
	Signature []byte
	PublicKey *ECDSAPublicKey
}

type ECDSAPublicKey struct {
	X string
	Y string
}

type ResponseMessage struct {
	Message          string
	ThresholdReached bool
	Token            string // Google OIDC token (Attestation token)
}

type GetRequestSigners struct {
	Message string
	Token   string // Google OIDC token (Attestation token)
}
