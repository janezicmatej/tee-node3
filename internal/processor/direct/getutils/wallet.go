package getutils

import (
	"encoding/json"
	"tee-node/internal/node"
	"tee-node/internal/wallets"

	"tee-node/pkg/types"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
)

func GetKeyInfoPackage() ([]byte, error) {
	myTeeId := node.GetTeeId()

	wallets.Storage.RLock()
	storedWallets := wallets.Storage.GetWallets()
	wallets.Storage.RUnlock()

	signedProofs := make([]types.WalletSignedKeyExistenceProof, len(storedWallets))
	for i, storedWallet := range storedWallets {
		existenceProof := wallets.WalletToKeyExistenceProof(storedWallet, myTeeId)
		existenceProofEncoded, err := structs.Encode(wallet.KeyExistenceStructArg, existenceProof)
		if err != nil {
			return nil, err
		}
		hash := crypto.Keccak256Hash(existenceProofEncoded)
		signature, err := node.Sign(hash[:])
		if err != nil {
			return nil, err
		}

		signedProofs[i] = types.WalletSignedKeyExistenceProof{
			KeyExistenceProof: existenceProofEncoded,
			Signature:         signature,
		}
	}

	resultEncoded, err := json.Marshal(signedProofs)
	if err != nil {
		return nil, err
	}

	return resultEncoded, nil
}
