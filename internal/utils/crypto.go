package utils

import (
	"crypto/ecdsa"
	"encoding/binary"
	"math/rand"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateRandomUint32 generates a cryptographically secure random uint32
func GenerateRandomUint32() (uint32, error) {
	var b [4]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// GenerateRandomUint16 generates a cryptographically secure random uint16
func GenerateRandomUint16() (uint16, error) {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

// GenerateEthereumPrivateKey generates a new Ethereum private key
func GenerateEthereumPrivateKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

// GenerateEthereumPublicKey generates the public key for an Ethereum private key
func GenerateEthereumPublicKey(privateKey *ecdsa.PrivateKey) *ecdsa.PublicKey {
	return &privateKey.PublicKey
}

// PubkeyToAddress converts an Ethereum public key to an Ethereum address
func PubkeyToAddress(pubkey *ecdsa.PublicKey) common.Address {
	return crypto.PubkeyToAddress(*pubkey)
}

func RandomNormalizedArray(n int, seed int64) []float64 {
	// Initialize random source with seed
	r := rand.New(rand.NewSource(seed))

	// Generate random numbers
	numbers := make([]float64, n)
	sum := 0.0

	for i := 0; i < n; i++ {
		// Generate random float between 0 and 1
		numbers[i] = r.Float64()
		sum += numbers[i]
	}

	// Normalize to sum to 1
	for i := 0; i < n; i++ {
		numbers[i] /= sum
	}

	return numbers
}
