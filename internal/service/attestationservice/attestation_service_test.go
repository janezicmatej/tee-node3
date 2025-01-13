package attestationservice

import (
	"context"
	"fmt"
	pb "tee-node/gen/go/attestation/v1"
	"testing"
)

func TestGetAttestationToken(t *testing.T) {
	req := pb.GetAttestationTokenRequest{
		Nonces: []string{"bla"},
	}

	attestationService := NewService()

	response, err := attestationService.GetAttestationToken(context.Background(), &req)
	if err != nil {
		// t.Errorf("Failed to initialize the policy: %v", err)
		println("!!!This only works if the server is running in a GCP confidential space")
	}

	fmt.Printf("Response: %v\n", response)
}
