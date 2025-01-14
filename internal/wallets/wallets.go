package wallets

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

type Wallet struct {
	PublicKey  *ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
}

var wallets map[string]Wallet = make(map[string]Wallet)

func CreateNewWallet(name string) (string, error) {
	skBytes := make([]byte, 32)
	n, err := io.ReadFull(rand.Reader, skBytes)
	if err != nil || n != 32 {
		return "", err
	}

	sk, err := crypto.HexToECDSA(hex.EncodeToString(skBytes))
	if err != nil {
		return "", err
	}

	newWallet := Wallet{PrivateKey: sk, PublicKey: &sk.PublicKey, Address: crypto.PubkeyToAddress(sk.PublicKey)}
	wallets[name] = newWallet

	return newWallet.Address.Hex(), nil
}

// todo: add attestation
func GetPublicKey(name string) (string, error) {
	wallet, ok := wallets[name]
	if !ok {
		return "", errors.New("wallet non-existent")
	}

	return wallet.Address.Hex(), nil
}
