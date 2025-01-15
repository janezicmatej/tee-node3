package policy

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/flare-foundation/go-flare-common/pkg/database"
)

// TestFetchPolicyHistory assumes that a DB with indexed txs and logs
// needed to obtain policies.
func TestFetchPolicyHistory(t *testing.T) {
	dbConfig := &database.Config{Host: "localhost", Port: 3306, Database: "flare_ftso_indexer_tee_node", Username: "root", Password: "root"}

	db, err := database.Connect(dbConfig)
	require.NoError(t, err)

	params := PolicyHistoryParams{RelayContractAddress: common.HexToAddress("0x97702e350CaEda540935d92aAf213307e9069784"), FlareSystemManagerContractAddress: common.HexToAddress("0xA90Db6D10F856799b10ef2A77EBCbF460aC71e52")}

	policies, signatures, err := FetchPolicyHistory(context.Background(), &params, db)
	require.NoError(t, err)
	_ = policies
	_ = signatures
}
