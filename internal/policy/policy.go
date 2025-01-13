package policy

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "tee-node/gen/go/signing/v1"
	"tee-node/internal/utils"
)

var ActiveSigningPolicy SigningPolicy
var ActiveSigningPolicyHash []byte
var SigningPolicies map[uint32]SigningPolicy = make(map[uint32]SigningPolicy)

type SigningPolicyPrefix struct {
	NumVoters          uint16
	RewardEpochId      uint32
	StartVotingRoundId uint32
	Threshold          uint16
	Seed               *big.Int
}

type PolicyProposalSig struct {
	VoterPublicKey *ecdsa.PublicKey
	Signature      []byte
	Weight         uint16
}

// map(epochId -> map(policyHash -> signaturesArray))
var NewPolicyProposals map[uint32]map[string][]*PolicyProposalSig = make(map[uint32]map[string][]*PolicyProposalSig)

// map(policyHash -> policyBytes)
var PolicyHash2Bytes map[string][]byte = make(map[string][]byte)

func DecodeSignPolicyRequest(request *pb.SignNewPolicyRequest) ([]byte, []byte, *ecdsa.PublicKey, error) {
	_policyHash := SigningPolicyHash(request.PolicyBytes)

	policySignature := request.Signature
	_pubKey := request.PublicKey

	X, success1 := new(big.Int).SetString(_pubKey.X, 10)
	Y, success2 := new(big.Int).SetString(_pubKey.Y, 10)
	if !success1 || !success2 {
		return nil, nil, nil, fmt.Errorf("failed to decode the public key")
	}

	pubKey := ecdsa.PublicKey{
		X: X,
		Y: Y,
	}

	return _policyHash, policySignature, &pubKey, nil

}

func GetSignerWeight(pubKey *ecdsa.PublicKey, policy SigningPolicy) uint16 {

	// Convert the public key to an Ethereum address
	address := crypto.PubkeyToAddress(*pubKey)

	// Find the index of the voter in the policy
	voterIndex := -1
	for i, addr := range policy.Voters {
		if addr == address {
			voterIndex = i
		}
	}

	if voterIndex == -1 {
		return 0
	}

	return policy.Weights[voterIndex]

}

func VerifySigningPolicySignature(signingPolicyHash []byte, signature []byte, pubKey *ecdsa.PublicKey) bool {

	// publicKeyBytes := crypto.FromECDSAPub(pubKey)

	// println("B: Public Key: ", pubKey.X.String(), pubKey.Y.String())
	// println("B: signature: ", utils.EncodeToHex(signature))
	// println("B: signingPolicyHash: ", utils.EncodeToHex(signingPolicyHash))
	// println("B: signingPolicyHash: ", utils.EncodeToHex(accounts.TextHash(signingPolicyHash)))

	return crypto.VerifySignature(crypto.CompressPubkey(pubKey), accounts.TextHash(signingPolicyHash), signature[:len(signature)-1])
}

func SignNewSigningPolicy(signingPolicyHash []byte, privKey *ecdsa.PrivateKey) ([]byte, error) {

	if len(signingPolicyHash) != 32 {
		return nil, fmt.Errorf("invalid signing policy hash length")
	}

	hashSignature, err := crypto.Sign(accounts.TextHash(signingPolicyHash), privKey)
	if err != nil {
		return nil, err
	}

	// println("A: Public Key: ", privKey.PublicKey.X.String(), privKey.PublicKey.Y.String())
	// println("A: signature: ", utils.EncodeToHex(hashSignature))
	// println("A: signingPolicyHash: ", utils.EncodeToHex(signingPolicyHash))
	// println("A: signingPolicyHash: ", utils.EncodeToHex(accounts.TextHash(signingPolicyHash)))

	return hashSignature, nil
}

func SigningPolicyHash(signingPolicy []byte) []byte {
	if len(signingPolicy)%32 != 0 {
		signingPolicy = append(signingPolicy, make([]byte, 32-len(signingPolicy)%32)...)
	}
	hash := crypto.Keccak256(signingPolicy[:32], signingPolicy[32:64])
	for i := 2; i < len(signingPolicy)/32; i++ {
		hash = crypto.Keccak256(hash, signingPolicy[i*32:(i+1)*32])
	}
	return hash
}

// * InitializePolicy -------------------------------------------------------------------
func CountValidSignatures(policySignatures []*pb.SignNewPolicyRequest, prevSigningPolicy *SigningPolicy) (*SigningPolicy, []byte, uint16, error) {
	var policy SigningPolicy
	var policyHash []byte
	var validSignaturesCount uint16 = 0
	for i, policySigReq := range policySignatures {

		_policyHash, _signature, _pubKey, error := DecodeSignPolicyRequest(policySigReq)
		if error != nil {
			continue // Ignore Invalid signatures and continue
		}

		isValid := VerifySigningPolicySignature(_policyHash, _signature, _pubKey)
		if !isValid {
			continue // Ignore Invalid signatures and continue
		}

		voterWeight := GetSignerWeight(_pubKey, *prevSigningPolicy)
		if voterWeight == 0 {
			continue // Ignore Invalid signatures and continue
		}

		if i == 0 {
			_policy, err := DecodeSigningPolicy(policySigReq.PolicyBytes)
			if err != nil {
				// TODO: Do we want to try again from the second policy or is it fine to just return an error.
				return nil, nil, 0, status.Error(codes.InvalidArgument, "Failed to Decode the signing policy")
			}

			policy = *_policy
			policyHash = _policyHash
		}

		if bytes.Equal(policyHash, _policyHash) {
			validSignaturesCount += voterWeight
		}
	}

	return &policy, policyHash, uint16(validSignaturesCount), nil

}

// * SignNewPolicy -------------------------------------------------------------------

func VerifySignatureAgainstActivePolicy(req *pb.SignNewPolicyRequest) (*SigningPolicy, []byte, *ecdsa.PublicKey, error) {

	// Decode the policy and hash it
	proposedPolicy, err := DecodeSigningPolicy(req.PolicyBytes)
	if err != nil {
		return nil, nil, nil, status.Error(codes.InvalidArgument, "failed to decode the proposed policy")
	}
	proposedPolicyHash := SigningPolicyHash(req.PolicyBytes)

	// Get the public key
	pubKeyX, success1 := new(big.Int).SetString(req.PublicKey.X, 10)
	pubKeyY, success2 := new(big.Int).SetString(req.PublicKey.Y, 10)
	if !success1 || !success2 {
		return nil, nil, nil, status.Error(codes.InvalidArgument, "failed to decode the public key")
	}
	pubKey := ecdsa.PublicKey{
		X: pubKeyX,
		Y: pubKeyY,
	}

	// Get the currrent active Policy and verify the publicKey is a signer
	isSigner := false
	for _, addr := range ActiveSigningPolicy.Voters {
		if addr == utils.PubkeyToAddress(&pubKey) {
			isSigner = true
			break
		}
	}
	if !isSigner {
		return nil, nil, nil, status.Error(codes.InvalidArgument, "public key is not a signer")
	}

	// Verify the signature and get voter Weight
	if !VerifySigningPolicySignature(proposedPolicyHash, req.Signature, &pubKey) {
		return nil, nil, nil, status.Error(codes.InvalidArgument, "signature verification failed")
	}

	return proposedPolicy, proposedPolicyHash, &pubKey, nil
}

func CountPolicyProposalSignatures(rewardEpochId uint32, proposedPolicyHash []byte, policyBytes []byte, pubKey *ecdsa.PublicKey, weight uint16) ([]*PolicyProposalSig, uint16, error) {

	// Get the array of signatures for the proposed policy (if not proposed yet create empty array)
	policyProposalSignatures, ok := NewPolicyProposals[rewardEpochId][EncodeToHex(proposedPolicyHash)]
	if !ok {
		policyProposalSignatures = []*PolicyProposalSig{}
		PolicyHash2Bytes[EncodeToHex(proposedPolicyHash)] = policyBytes
		NewPolicyProposals[rewardEpochId] = make(map[string][]*PolicyProposalSig)
	}

	// Loop over the array of signatures
	var totalWeight uint16 = 0
	for _, sig := range policyProposalSignatures {
		// Check if the signature is already validated
		if sig.VoterPublicKey == pubKey {
			return nil, 0, status.Error(codes.InvalidArgument, "signature already validated")
		}

		// Sum the weights of all the signatures
		totalWeight += sig.Weight
	}

	// Add the new weight to the sum
	totalWeight += weight

	return policyProposalSignatures, totalWeight, nil
}
