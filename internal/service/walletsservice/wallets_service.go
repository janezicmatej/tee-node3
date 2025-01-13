package walletsservice

import (
	"context"
	pb "tee-node/gen/go/wallets/v1"
	"tee-node/internal/wallets"
)

// Service implements the generated SigningServiceServer interface
type Service struct {
	// Embed the generated UnimplementedSigningServiceServer
	pb.UnimplementedWalletsServiceServer
	// Add any dependencies your service needs
}

// NewService creates a new signing service
func NewService() *Service {
	return &Service{}
}

// todo: add attestation
func (s *Service) NewWallet(ctx context.Context, req *pb.WalletRequest) (*pb.NewWalletResponse, error) {
	_, err := wallets.CreateNewWallet(req.Name)
	if err != nil {
		return nil, err
	}

	return &pb.NewWalletResponse{
		Success: true,
	}, nil
}

func (s *Service) PublicKey(ctx context.Context, req *pb.WalletRequest) (*pb.PublicKeyResponse, error) {
	address, err := wallets.GetPublicKey(req.Name)
	if err != nil {
		return nil, err
	}

	return &pb.PublicKeyResponse{
		Success: true,
		Address: address,
	}, nil
}
