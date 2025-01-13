package policyservice

import (
	"context"

	// Import your generated proto package

	pb "tee-node/gen/go/signing/v1"
	"tee-node/internal/policy"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const SIGNATURE_THRESHOLD_PERCENTAGE = 50
const SIGNER_WEIGHT_DENOMINATION = 50_000 // TODO: Figure this out

// Service implements the generated SigningServiceServer interface
type Service struct {
	// Embed the generated UnimplementedSigningServiceServer
	pb.UnimplementedSigningServiceServer
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

	// Initialize the original signig policy and store it in the map
	currentPolicy, err := policy.DecodeSigningPolicy(req.InitialPolicyBytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to decode the initial policy")
	}
	currentPolicyHash := policy.SigningPolicyHash(req.InitialPolicyBytes)
	policy.SigningPolicies[currentPolicy.RewardEpochId] = *currentPolicy

	// Go through the policies for each reward epoch and update the current policy
	for _, sigArray := range req.PolicySignaturesArray {

		sigPolicy, policyHash, validSignatureCount, err := policy.CountValidSignatures(sigArray.PolicySignatures, currentPolicy)
		if err != nil {
			// Todo: Do we want to return an error or an unsuccessful result?
			return nil, err
		}

		// Check if the number of valid signatures is less than the threshold
		if int(validSignatureCount) < SIGNATURE_THRESHOLD_PERCENTAGE*SIGNER_WEIGHT_DENOMINATION/100 {
			return nil, status.Error(codes.InvalidArgument, "Not enough valid signatures")
		}

		// Update the current policy and policy hash
		currentPolicy = sigPolicy
		currentPolicyHash = policyHash

		// Store the policy in the map
		policy.SigningPolicies[sigPolicy.RewardEpochId] = *sigPolicy
	}

	// Set the active policy and policy hash (This is the latest policy, that will be used for signing)
	policy.ActiveSigningPolicy = *currentPolicy
	policy.ActiveSigningPolicyHash = currentPolicyHash

	return &pb.InitializePolicyResponse{
		Sucess:  true,
		Message: "Signing Policy Initialized Successfully",
	}, nil
}

func (s *Service) SignNewPolicy(ctx context.Context, req *pb.SignNewPolicyRequest) (*pb.SignNewPolicyResponse, error) {

	// Check if context is cancelled
	select {
	case <-ctx.Done():
		return nil, status.Error(codes.Canceled, "request cancelled")
	default:
	}

	// Verify the signature against the active policy
	proposedPolicy, proposedPolicyHash, pubKey, err := policy.VerifySignatureAgainstActivePolicy(req)
	if err != nil {
		return nil, err
	}
	weight := policy.GetSignerWeight(pubKey, policy.ActiveSigningPolicy)

	// Get the rewardEpochId from the policy
	rewardEpochId := proposedPolicy.RewardEpochId

	// Check if the policy for that epochId is already registered
	if _, ok := policy.SigningPolicies[rewardEpochId]; ok {
		return nil, status.Error(codes.InvalidArgument, "policy already exists for the reward epoch")
	}

	// Count the number of signatures for the proposed policy
	policyProposalSignatures, totalWeight, err := policy.CountPolicyProposalSignatures(rewardEpochId, proposedPolicyHash, req.PolicyBytes, pubKey, weight)
	if err != nil {
		return nil, err
	}

	if totalWeight > SIGNATURE_THRESHOLD_PERCENTAGE*SIGNER_WEIGHT_DENOMINATION/100 {
		// If the weight is greater than the threshold, update the active policy

		policy.ActiveSigningPolicy = *proposedPolicy
		policy.ActiveSigningPolicyHash = proposedPolicyHash
		policy.SigningPolicies[rewardEpochId] = *proposedPolicy
	} else {
		// If not add the signature to the array

		policyProposalSignatures = append(policyProposalSignatures, &policy.PolicyProposalSig{
			VoterPublicKey: pubKey,
			Signature:      req.Signature,
			Weight:         weight,
		})
		policy.NewPolicyProposals[rewardEpochId][policy.EncodeToHex(proposedPolicyHash)] = policyProposalSignatures
	}

	return &pb.SignNewPolicyResponse{
		Sucess:  true,
		Message: "Sucessfully signed the policy",
	}, nil
}
