package main

import (
	"tee-node/internal/attestation"
	"tee-node/internal/node"
	"tee-node/internal/processor"
	"tee-node/internal/settings"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
)

func main() {
	err := node.InitNode()
	if err != nil {
		logger.Fatalf("failed to initialize: %v", err)
	}

	err = attestation.SetGoogleCert()
	if err != nil {
		logger.Fatalf("failed to load certificate: %v", err)
	}
	err = attestation.SelfAttest()
	if err != nil {
		logger.Fatalf("self attestation failed: %v", err)
	}

	// Launch the json rpc server
	processor.RunTeeProcessor(settings.ProxyUrl)
}
