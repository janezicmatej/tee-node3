package main

import (
	"tee-node/internal/service"
)

func main() {
	// Launch the gRPC server
	service.LaunchServer(50051)
}
