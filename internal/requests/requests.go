package requests

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"sync"
	"tee-node/internal/policy"
	"tee-node/internal/utils"

	"tee-node/api/types"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"
)

// The following is the main storage, holding requests that need to reach a threshold
// before being executed.
var storage = make(map[types.RequestType]any)

// Initialize storages for each request type
func init() {
	storage[types.InstructionRequest] = InitRequestCounterStorage[types.InstructionData]()
	storage[types.SignPolicyRequest] = InitRequestCounterStorage[policy.SignPolicyRequest]()
}

type RequestCounter[T Request] struct {
	Request T

	RequestSigners map[common.Address]bool
	PolicyHash     string
	Done           bool
	Result         []byte
}

type RequestCounterStorage[T Request] struct {
	Storage map[string]*RequestCounter[T]

	sync.Mutex
}

func InitRequestCounterStorage[T Request]() *RequestCounterStorage[T] {
	return &RequestCounterStorage[T]{Storage: make(map[string]*RequestCounter[T])}
}

// todo: not sure if this makes sense, just trying to unify
type Request interface {
	Identifier() string // A unique identifier for the request
	Hash() []byte       // Note: Policies need to be signed a specific way, the same way they are onchain
	RequestType() types.RequestType
	// Check() error  // Todo: Removing this for now and we can add it back after
}

func Sign(r Request, privKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := r.Hash()
	signature, err := utils.Sign(hash, privKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func CheckSignature(r Request, signature []byte) (common.Address, error) {
	hash := r.Hash()
	pubKey, err := crypto.SigToPub(accounts.TextHash(hash), signature)
	if err != nil {
		return common.Address{}, err
	}
	address := crypto.PubkeyToAddress(*pubKey)
	if !slices.Contains(policy.ActiveSigningPolicy.Voters, address) {
		return common.Address{}, errors.New("not a voter")
	}

	return address, nil
}

func ProcessRequest[T Request](request T, signature []byte) (*RequestCounter[T], bool, error) {

	requestCounterStorage, err := getRequestCounterStorage[T](request.RequestType())
	if err != nil {
		fmt.Printf("2\n")
		return nil, false, err
	}

	requestHash := hex.EncodeToString(request.Hash())

	requestCounterStorage.Lock()
	if _, ok := requestCounterStorage.Storage[requestHash]; !ok {
		requestCounterStorage.Storage[requestHash] = newRequestCounter(request)
	}

	requestCounter := requestCounterStorage.Storage[requestHash]
	if !requestCounter.CheckActive() {
		requestCounterStorage.Unlock()

		return nil, false, errors.New("not active")
	}

	providerAddress, err := CheckSignature(request, signature)
	if err != nil {
		requestCounterStorage.Unlock()

		return nil, false, err
	}

	requestCounter.AddRequestSigner(providerAddress)

	thresholdReached := requestCounter.ThresholdReached()
	requestCounterStorage.Unlock()

	return requestCounter, thresholdReached, nil
}

func GetRequestCounter[T Request](requestHash string, requestType types.RequestType) (*RequestCounter[T], error) {
	requestCounterStorage, err := getRequestCounterStorage[T](requestType)
	if err != nil {
		return nil, err
	}

	requestCounterStorage.Lock()
	requestCounter, ok := requestCounterStorage.Storage[requestHash]
	if !ok {
		requestCounterStorage.Unlock()

		return nil, errors.New("request not found")
	}

	// Todo: Do we need this?
	// if !requestCounter.CheckActive() {
	// 	return nil, errors.New("not active")
	// }

	requestCounterStorage.Unlock()

	return requestCounter, nil
}

func newRequestCounter[T Request](request T) *RequestCounter[T] {
	return &RequestCounter[T]{
		Request:        request,
		RequestSigners: make(map[common.Address]bool),
		PolicyHash:     hex.EncodeToString(policy.ActiveSigningPolicyHash), // todo, maybe make requestSigner specify this
	}
}

func (r *RequestCounter[T]) CheckActive() bool {
	// Note: What if we initialize the request with a policy, but then the active signing policy changes?
	// Note: Then this would fail, but it probably shouldn't, or we should have a way to handle it.
	return hex.EncodeToString(policy.ActiveSigningPolicyHash) == r.PolicyHash
}

func (r *RequestCounter[T]) Threshold() uint16 {
	return policy.ActiveSigningPolicy.Threshold
}

func (r *RequestCounter[T]) CurrentWeight() uint16 {
	currentWeight := uint16(0)
	for i, voter := range policy.ActiveSigningPolicy.Voters {
		if _, ok := r.RequestSigners[voter]; ok {
			currentWeight += policy.ActiveSigningPolicy.Weights[i]
		}
	}

	return currentWeight
}

func (r *RequestCounter[T]) ThresholdReached() bool {
	currentWeight := r.CurrentWeight()
	threshold := r.Threshold()

	return currentWeight >= threshold
}

func (r *RequestCounter[T]) AddRequestSigner(reqSigner common.Address) {
	r.RequestSigners[reqSigner] = true
}

// Note: We need this for distributing rewards to the signers
// Note: Not sure yet what API this should have, but this is a start
func (r *RequestCounter[T]) GetRequestSigners() []*common.Address {

	var signers []*common.Address = make([]*common.Address, 0)
	for signer := range r.RequestSigners {
		signers = append(signers, &signer)
	}
	return signers
}

func getRequestCounterStorage[T Request](requestType types.RequestType) (*RequestCounterStorage[T], error) {
	rawStorage, ok := storage[requestType]
	if !ok {
		return nil, errors.New("storage not found")
	}

	// Perform a type assertion to ensure the storage is of the expected type
	counterStorage, ok := rawStorage.(*RequestCounterStorage[T])
	if !ok {
		return counterStorage, errors.New("storage type mismatch")
	}

	return counterStorage, nil
}

// Note: This is useful for tests, but it would also be useful for upgrades, where a TEE get's shutdown.
func DestoryState() {
	delete(storage, types.InstructionRequest)
	delete(storage, types.SignPolicyRequest)

	storage[types.InstructionRequest] = InitRequestCounterStorage[types.InstructionData]()
	storage[types.SignPolicyRequest] = InitRequestCounterStorage[policy.SignPolicyRequest]()
}
