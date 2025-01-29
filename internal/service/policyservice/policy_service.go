package policyservice

import (
	"context"

	pb "tee-node/gen/go/policy/v1"
	"tee-node/internal/policy"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service implements the generated SigningServiceServer interface
type Service struct {
	// Embed the generated UnimplementedSigningServiceServer
	pb.UnimplementedPolicyServiceServer
	// Add any dependencies your service needs
}

// NewService creates a new signing service
func NewService() *Service {
	return &Service{}
}

// Implement the Sign method defined in your proto
func (s *Service) InitializePolicy(ctx context.Context, req *pb.InitializePolicyRequest) (*pb.InitializePolicyResponse, error) {

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	err := policy.InitializePolicyInternal(req)
	if err != nil {
		return nil, err
	}

	return &pb.InitializePolicyResponse{}, nil
}

func (s *Service) SignNewPolicy(ctx context.Context, req *pb.SignNewPolicyRequest) (*pb.SignNewPolicyResponse, error) {

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	err := policy.SignNewPolicyInternal(req)
	if err != nil {
		return nil, err
	}

	return &pb.SignNewPolicyResponse{
		ActivePolicy: policy.EncodeToHex(policy.ActiveSigningPolicyHash),
	}, nil

}

func (s *Service) GetActivePolicy(ctx context.Context, req *pb.GetActivePolicyRequest) (*pb.GetActivePolicyResponse, error) {
	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	if policy.ActiveSigningPolicy == nil {
		return nil, status.Error(codes.NotFound, "No active policy found")
	}

	activePolicyBytes, err := policy.EncodeSigningPolicy(policy.ActiveSigningPolicy)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to encode the active policy")
	}

	return &pb.GetActivePolicyResponse{
		ActivePolicy:     activePolicyBytes,
		ActivePolicyHash: policy.EncodeToHex(policy.ActiveSigningPolicyHash),
	}, nil
}
