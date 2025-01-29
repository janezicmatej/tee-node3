package service

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/flare-foundation/go-flare-common/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection" // Helpful for debugging

	pb "tee-node/gen/go/policy/v1"
	walletsv1 "tee-node/gen/go/wallets/v1"
	"tee-node/internal/service/attestationservice"
	"tee-node/internal/service/policyservice"
	"tee-node/internal/service/walletsservice"

	at "tee-node/gen/go/attestation/v1"
)

func LaunchServer(port int) {
	// Create listener
	lis, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		logger.Errorf("failed to listen: %v", err)
	}

	// Create gRPC server with options
	var opts []grpc.ServerOption // TODO make configurable in config
	opts = append(opts, grpc.Creds(insecure.NewCredentials()), grpc.ConnectionTimeout(30*time.Second), grpc.UnaryInterceptor(LoggingInterceptor), grpc.KeepaliveParams(keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Minute,
		MaxConnectionAge:      30 * time.Minute,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               1 * time.Second,
	}), grpc.MaxRecvMsgSize(50*1024*1024), // 50 MB
		grpc.MaxSendMsgSize(50*1024*1024), // 50 MB
	)

	grpcServer := grpc.NewServer(
		opts...,
	)

	// Initialize your services
	signingService := policyservice.NewService()
	attestationService := attestationservice.NewService()
	walletsService := walletsservice.NewService()

	// Register services
	pb.RegisterPolicyServiceServer(grpcServer, signingService)
	at.RegisterAttestationServiceServer(grpcServer, attestationService)
	walletsv1.RegisterWalletsServiceServer(grpcServer, walletsService)

	reflection.Register(grpcServer) // Enables server reflection

	// Gracefuly shutdown server on SIGINT or SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		logger.Infof("gRPC server started on %s", lis.Addr().String())

		if err := grpcServer.Serve(lis); err != nil {
			logger.Errorf("failed to serve, %v", err)
		}
	}()

	<-sigChan
	logger.Info("shutting down gRPC server...")
	grpcServer.GracefulStop()
	logger.Info("Server stopped")
}

func LoggingInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	log.Printf("method: %s, request: %v", info.FullMethod, req)
	resp, err := handler(ctx, req)
	if err != nil {
		log.Printf("error: %v", err)
	}
	return resp, err
}
