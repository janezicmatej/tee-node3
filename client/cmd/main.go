package main

import (
	"context"
	"log"
	"time"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	at "tee-node/gen/go/attestation/v1"
	walletsv1 "tee-node/gen/go/wallets/v1"
)

const GCP_INSTANCE_IP = "localhost"

// TODO: make cli configurable calls
func main() {
	// Create a connection to the server using grpc.NewClient
	clientConn, err := NewGRPCClient(GCP_INSTANCE_IP + ":50051")
	if err != nil {
		log.Fatalf("failed to create client connection: %v", err)
	}
	defer clientConn.Close()

	ctx := context.Background()

	// Create a gRPC wallet client
	walletClient := walletsv1.NewWalletsServiceClient(clientConn)

	walletName := "test_wallet"
	_, err = walletClient.NewWallet(ctx, &walletsv1.WalletRequest{Name: walletName})
	if err != nil {
		log.Fatalf("could not create a new wallet: %v", err)
	}

	pubKeyResp, err := walletClient.PublicKey(ctx, &walletsv1.WalletRequest{Name: walletName})
	if err != nil {
		log.Fatalf("could not create a new wallet: %v", err)
	}
	logger.Infof("created a wallet with public key: %s", pubKeyResp.Address)

	// Create the gRPC attestation client
	attestationClient := at.NewAttestationServiceClient(clientConn)

	// Make OICD token request
	tokenResp, err := attestationClient.GetAttestationToken(ctx, &at.GetAttestationTokenRequest{
		Nonces: []string{"123456789987654321"},
	})
	if err != nil {
		log.Fatalf("could not sign: %v", err)
	}

	log.Printf("Google OICD JWT bytes: %v", tokenResp.JwtBytes)

	// // Make Hardware Attestation request
	// hardwareResp, err := attestationClient.GetHardwareAttestation(ctx, &at.GetHardwareAttestationRequest{
	// 	Nonce: "12345678998765432123456789987654",
	// })
	// if err != nil {
	// 	log.Fatalf("could not sign: %v", err)
	// }

	// log.Printf("Hardware Attestation response: %v", hardwareResp.JsonAttestation)

}

func NewGRPCClient(target string) (*grpc.ClientConn, error) {
	// Create slice for dial options
	var opts []grpc.DialOption

	// 1. Basic options
	opts = append(opts,
		grpc.WithTransportCredentials(insecure.NewCredentials()), // Only for development
		grpc.WithIdleTimeout(60*time.Second),                     // Idle timeout (close connection if idle)
		grpc.WithUnaryInterceptor(ClientLoggingInterceptor),      // Log requests
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
			Timeout:             5 * time.Second,  // wait 5 seconds for ping response
			PermitWithoutStream: true,             // allow pings even without active streams
		}),
		grpc.WithDefaultServiceConfig(`{  
            "methodConfig": [{  
                 "name": [  
                {"service": "signing.SigningService"},  
                {"service": "attestation.AttestationService"}  
            ],  
                "waitForReady": true,  
                "retryPolicy": {  
                    "MaxAttempts": 3,  
                    "InitialBackoff": "0.1s",  
                    "MaxBackoff": "1s",  
                    "BackoffMultiplier": 2.0,  
                    "RetryableStatusCodes": ["UNAVAILABLE"]  
                }  
            }]  
        }`), // Retry policy
	)

	// Connect to the server
	return grpc.NewClient(target, opts...)
}

// ClientLoggingInterceptor logs client requests
func ClientLoggingInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	start := time.Now()
	err := invoker(ctx, method, req, reply, cc, opts...)
	log.Printf("method: %s, duration: %v, error: %v", method, time.Since(start), err)
	return err
}
