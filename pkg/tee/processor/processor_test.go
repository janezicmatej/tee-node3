package processor

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"tee-node/api/types"
	"tee-node/pkg/tee/node"
	"tee-node/pkg/tee/policy"
	"tee-node/pkg/tee/utils"
	"tee-node/pkg/tee/wallets"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/payment"
	"github.com/flare-foundation/go-flare-common/pkg/tee/structs/wallet"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"tee-node/testutils"
)

const proxyPort = 5500

// todo: add cosigners to wallet, check xrp signature, verify signer sequence data (vote hash)
func TestProcessorEndToEnd(t *testing.T) {
	err := node.InitNode()
	require.NoError(t, err)

	numVoters, numPolicies, startingEpochId := 100, 10, uint32(1)
	finalEpochId := startingEpochId + uint32(numPolicies)

	providersAddresses, providersPrivKeys, _ := testutils.GenerateRandomKeys(numVoters)

	numAdmins := 3
	adminsPubKeys := make([]*ecdsa.PublicKey, numAdmins)
	adminsPrivKeys := make([]*ecdsa.PrivateKey, numAdmins)
	for i := range numAdmins - 1 {
		adminsPrivKeys[i], err = crypto.GenerateKey()
		require.NoError(t, err)
		adminsPubKeys[i] = &adminsPrivKeys[i].PublicKey
	}

	// make one provider also admin
	adminsPrivKeys[numAdmins-1] = providersPrivKeys[0]
	adminsPubKeys[numAdmins-1] = &providersPrivKeys[0].PublicKey

	// change type
	adminsWalletPublicKeys := make([]wallet.PublicKey, len(adminsPubKeys))
	for i, pubKey := range adminsPubKeys {
		adminsWalletPublicKeys[i] = wallet.PublicKey(types.PubKeyToStruct(pubKey))
	}

	mainActionInfoChan := make(chan *types.QueuedActionInfo, 100)
	readActionInfoChan := make(chan *types.QueuedActionInfo, 100)
	actionResponseChan := make(chan *types.QueueActionResponse, 100)
	actionMap := make(map[types.QueuedActionInfo]*types.QueuedAction)
	go MockProxy(t, mainActionInfoChan, readActionInfoChan, actionMap, actionResponseChan)

	go RunTeeProcessor("http://localhost:" + strconv.Itoa(proxyPort))

	time.Sleep(1 * time.Second)

	actionId := big.NewInt(0)
	initializePolicy(t, mainActionInfoChan, actionMap, actionResponseChan, providersPrivKeys, providersAddresses,
		actionId, numPolicies, startingEpochId)

	teeId, teePubKey := getTeeInfo(t, readActionInfoChan, actionMap, actionResponseChan, actionId)
	actionId.Add(actionId, common.Big1)

	var walletId = common.HexToHash("0xabcdef")
	var keyId = uint64(1)
	walletProof := generateWallet(t, mainActionInfoChan, actionMap, actionResponseChan, teeId, walletId, keyId,
		providersPrivKeys, adminsWalletPublicKeys, finalEpochId, actionId)
	require.Equal(t, walletProof.Restored, false)
	actionId.Add(actionId, common.Big1)

	paymentHash := "560ccd6e79ba7166e82dbf2a5b9a52283a509b63c39d4a4cc7164db3e43484c4"
	signTransaction(t, mainActionInfoChan, actionMap, actionResponseChan, teeId, walletId, keyId, providersPrivKeys, finalEpochId, actionId, paymentHash)
	actionId.Add(actionId, common.Big1)

	walletBackup := getBackup(t, readActionInfoChan, actionMap, actionResponseChan, teeId, walletId, keyId, actionId)
	actionId.Add(actionId, common.Big1)

	nonce := big.NewInt(1)
	deleteWallet(t, mainActionInfoChan, actionMap, actionResponseChan, teeId, walletId, keyId, providersPrivKeys, finalEpochId, actionId, nonce)
	actionId.Add(actionId, common.Big1)
	nonce.Add(actionId, common.Big1)

	recoveredWalletProof := recoverWallet(t, mainActionInfoChan, actionMap, actionResponseChan, teeId, teePubKey, walletId, keyId,
		providersPrivKeys, adminsPrivKeys, finalEpochId, actionId, nonce, walletBackup)
	walletProof.Restored = true
	actionId.Add(actionId, common.Big1)

	walletProof.Nonce = nonce
	require.Equal(t, walletProof, recoveredWalletProof)

	// todo: update policy
}

func initializePolicy(t *testing.T, actionInfoChan chan *types.QueuedActionInfo, actionMap map[types.QueuedActionInfo]*types.QueuedAction,
	actionResponseChan chan *types.QueueActionResponse, privKeys []*ecdsa.PrivateKey, addresses []common.Address,
	actionId *big.Int, numPolicies int, startingEpochId uint32) {
	// initialize policy
	randSeed := int64(12345)
	initialPolicy := testutils.GenerateRandomPolicyData(startingEpochId, addresses, randSeed)
	initialPolicyBytes, err := policy.EncodeSigningPolicy(&initialPolicy)
	require.NoError(t, err)

	policySignaturesArray, err := testutils.GenerateRandomMultiSignedPolicyArray(startingEpochId, randSeed, addresses, privKeys, numPolicies)
	require.NoError(t, err, "could not generate random policy policy")
	pubKeys := make([]types.ECDSAPublicKey, len(privKeys))
	for i, voter := range privKeys {
		pubKeys[i] = types.PubKeyToStruct(&voter.PublicKey)
	}
	req := &types.InitializePolicyRequest{
		InitialPolicyBytes:     initialPolicyBytes,
		Policies:               policySignaturesArray,
		LatestPolicyPublicKeys: pubKeys,
	}

	action, err := testutils.BuildMockQueuedActionAction("POLICY", "INITIALIZE_POLICY", req)
	require.NoError(t, err)

	actionInfo := &types.QueuedActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
}

func getTeeInfo(t *testing.T, actionInfoChan chan *types.QueuedActionInfo, actionMap map[types.QueuedActionInfo]*types.QueuedAction,
	actionResponseChan chan *types.QueueActionResponse, actionId *big.Int) (common.Address, *ecdsa.PublicKey) {

	challenge, err := utils.GenerateRandom()
	require.NoError(t, err)
	req := &types.TeeInfoRequest{Challenge: challenge}
	action, err := testutils.BuildMockQueuedActionAction("GET", "TEE_INFO", req)

	require.NoError(t, err)

	actionInfo := &types.QueuedActionInfo{QueueId: "read", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)

	var teeInfoResponse types.TeeInfoResponse
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &teeInfoResponse)
	require.NoError(t, err)

	teePubKey, err := types.ParsePubKey(teeInfoResponse.PublicKey)
	require.NoError(t, err)

	teeId := crypto.PubkeyToAddress(*teePubKey)

	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	return teeId, teePubKey
}

func generateWallet(t *testing.T, actionInfoChan chan *types.QueuedActionInfo, actionMap map[types.QueuedActionInfo]*types.QueuedAction,
	actionResponseChan chan *types.QueueActionResponse, teeId common.Address, walletId [32]byte, keyId uint64, privKeys []*ecdsa.PrivateKey,
	adminsWalletPublicKeys []wallet.PublicKey, rewardEpochId uint32, actionId *big.Int) *wallet.ITeeWalletKeyManagerKeyExistence {
	originalMessage := wallet.ITeeWalletKeyManagerKeyGenerate{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		OpType:   utils.StringToOpHash("WALLET"),
		ConfigConstants: wallet.ITeeWalletKeyManagerKeyConfigConstants{
			OpTypeConstants:    make([]byte, 0),
			AdminsPublicKeys:   adminsWalletPublicKeys,
			AdminsThreshold:    uint64(len(adminsWalletPublicKeys)),
			Cosigners:          make([]common.Address, 0), // todo: add cosigners
			CosignersThreshold: 0,
		},
	}
	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyGenerate]}.Pack(originalMessage)
	require.NoError(t, err)

	// generate action sent when threshold reached
	action, err := testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_GENERATE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.ThresholdReachedSubmissionTag,
	)
	require.NoError(t, err)

	actionInfo := &types.QueuedActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	walletExistenceProof, err := structs.Decode[wallet.ITeeWalletKeyManagerKeyExistence](wallet.KeyExistenceStructArg, actionResponse.Result.ResultData.Message)
	require.NoError(t, err)

	newWallet, err := wallets.Storage.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.NoError(t, err)

	require.Equal(t, newWallet.XrpAddress, walletExistenceProof.AddressStr)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_GENERATE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.VotingClosedSubmissionTag,
	)
	require.NoError(t, err)

	actionInfo = &types.QueuedActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.SignerSequence
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.Data.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)

	return &walletExistenceProof
}

func signTransaction(t *testing.T, actionInfoChan chan *types.QueuedActionInfo,
	actionMap map[types.QueuedActionInfo]*types.QueuedAction, actionResponseChan chan *types.QueueActionResponse,
	teeId common.Address, walletId [32]byte, keyId uint64, privKeys []*ecdsa.PrivateKey,
	rewardEpochId uint32, actionId *big.Int, paymentHash string) {
	originalMessage := payment.ITeePaymentsPaymentInstructionMessage{
		WalletId:         walletId,
		TeeIdKeyIdPairs:  []payment.TeeIdKeyIdPair{{TeeId: teeId, KeyId: keyId}},
		SenderAddress:    "0x123",
		RecipientAddress: "0x456",
		Amount:           big.NewInt(1000000000),
		Fee:              big.NewInt(10),
		PaymentReference: [32]byte{},
		Nonce:            0,
		SubNonce:         0,
		BatchEndTs:       0,
	}

	originalMessageEncoded, err := abi.Arguments{payment.MessageArguments[payment.Pay]}.Pack(originalMessage)
	require.NoError(t, err)

	additionalFixedMessage := types.SignPaymentAdditionalFixedMessage{
		PaymentHash: paymentHash,
		KeyId:       keyId,
	}

	action, err := testutils.BuildMockQueuedActionInstruction(
		"XRP", "PAY", originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessage, nil, types.ThresholdReachedSubmissionTag,
	)
	require.NoError(t, err)

	actionInfo := &types.QueuedActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signatureData types.GetPaymentSignatureResponse
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signatureData)
	require.NoError(t, err)

	// todo: check result
	// fmt.Println("check sig", signatureData)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"XRP", "PAY", originalMessageEncoded, privKeys, teeId, rewardEpochId, additionalFixedMessage, nil, types.VotingClosedSubmissionTag,
	)
	require.NoError(t, err)

	actionInfo = &types.QueuedActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.SignerSequence
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.Data.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func deleteWallet(t *testing.T, actionInfoChan chan *types.QueuedActionInfo, actionMap map[types.QueuedActionInfo]*types.QueuedAction,
	actionResponseChan chan *types.QueueActionResponse, teeId common.Address, walletId [32]byte, keyId uint64,
	privKeys []*ecdsa.PrivateKey, rewardEpochId uint32, actionId, nonce *big.Int) {
	originalMessage := wallet.ITeeWalletKeyManagerKeyDelete{
		TeeId:    teeId,
		WalletId: walletId,
		KeyId:    keyId,
		Nonce:    nonce,
	}
	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyDelete]}.Pack(originalMessage)
	require.NoError(t, err)

	action, err := testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DELETE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.ThresholdReachedSubmissionTag,
	)
	require.NoError(t, err)

	actionInfo := &types.QueuedActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)

	_, err = wallets.Storage.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.Error(t, err)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DELETE", originalMessageEncoded, privKeys, teeId, rewardEpochId, nil, nil, types.VotingClosedSubmissionTag,
	)
	require.NoError(t, err)

	actionInfo = &types.QueuedActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.SignerSequence
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.Data.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)
}

func getBackup(t *testing.T, actionInfoChan chan *types.QueuedActionInfo, actionMap map[types.QueuedActionInfo]*types.QueuedAction,
	actionResponseChan chan *types.QueueActionResponse, teeId common.Address, walletId [32]byte, keyId uint64, actionId *big.Int) *wallets.WalletBackup {
	message := wallets.WalletKeyIdPair{
		WalletId: walletId,
		KeyId:    keyId,
	}

	action, err := testutils.BuildMockQueuedActionAction(
		"GET", "TEE_BACKUP", message,
	)
	require.NoError(t, err)

	actionInfo := &types.QueuedActionInfo{QueueId: "read", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var backupResponse types.WalletGetBackupResponse
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &backupResponse)
	require.NoError(t, err)

	// fmt.Println("backup size", len(backupResponse.WalletBackup))

	var backup wallets.WalletBackup
	err = json.Unmarshal(backupResponse.WalletBackup, &backup)
	require.NoError(t, err)

	return &backup
}

func recoverWallet(t *testing.T, actionInfoChan chan *types.QueuedActionInfo, actionMap map[types.QueuedActionInfo]*types.QueuedAction,
	actionResponseChan chan *types.QueueActionResponse, teeId common.Address, teePubKey *ecdsa.PublicKey, walletId [32]byte, keyId uint64,
	providersPrivKeys, adminsPrivKeys []*ecdsa.PrivateKey, rewardEpochId uint32, actionId, nonce *big.Int,
	backup *wallets.WalletBackup) *wallet.ITeeWalletKeyManagerKeyExistence {
	originalMessage := wallet.ITeeWalletBackupManagerKeyDataProviderRestore{
		TeeId:     teeId,
		BackupUrl: "blabla",
		Nonce:     nonce,
		BackupId: wallet.ITeeWalletBackupManagerBackupId{
			TeeId:         teeId,
			WalletId:      walletId,
			KeyId:         keyId,
			OpType:        utils.StringToOpHash("WALLET"),
			PublicKey:     append(backup.PublicKey.X[:], backup.PublicKey.Y[:]...),
			RewardEpochId: big.NewInt(int64(rewardEpochId)),
			RandomNonce:   new(big.Int).SetBytes(backup.RandomNonce[:]),
		},
	}

	originalMessageEncoded, err := abi.Arguments{wallet.MessageArguments[wallet.KeyDataProviderRestore]}.Pack(originalMessage)
	require.NoError(t, err)

	additionalFixedMessage := backup.WalletBackupMetaData

	adminAndProvider := make(map[common.Address]int)
	for j, privKey1 := range adminsPrivKeys {
		address := crypto.PubkeyToAddress(privKey1.PublicKey)
		for _, privKey2 := range providersPrivKeys {
			if address == crypto.PubkeyToAddress(privKey2.PublicKey) {
				adminAndProvider[address] = j
			}
		}
	}

	teeEciesPubKey := ecies.ImportECDSAPublic(teePubKey)
	additionalVariableMessages := make([]interface{}, 0)
	privKeys := make([]*ecdsa.PrivateKey, 0)
	for i, privKey := range providersPrivKeys {
		keySplit, err := wallets.DecryptSplit(backup.ProvidersEncryptedParts.Splits[i], privKey)
		require.NoError(t, err)

		address := crypto.PubkeyToAddress(privKey.PublicKey)
		j, check := adminAndProvider[address]
		var plaintext []byte
		if !check {
			plaintext, err = json.Marshal(keySplit)
			require.NoError(t, err)
		} else {
			keySplitAdmin, err := wallets.DecryptSplit(backup.AdminEncryptedParts.Splits[j], privKey)
			require.NoError(t, err)
			var twoKeySplits [2]wallets.KeySplit
			twoKeySplits[0] = *keySplit
			twoKeySplits[1] = *keySplitAdmin
			plaintext, err = json.Marshal(twoKeySplits)
			require.NoError(t, err)
		}

		cipher, err := ecies.Encrypt(rand.Reader, teeEciesPubKey, plaintext, nil, nil)
		require.NoError(t, err)

		additionalVariableMessages = append(additionalVariableMessages, cipher)
		privKeys = append(privKeys, privKey)
	}

	for i, privKey := range adminsPrivKeys {
		address := crypto.PubkeyToAddress(privKey.PublicKey)
		_, check := adminAndProvider[address]
		if check {
			continue
		}

		keySplit, err := wallets.DecryptSplit(backup.AdminEncryptedParts.Splits[i], privKey)
		require.NoError(t, err)

		plaintext, err := json.Marshal(keySplit)
		require.NoError(t, err)

		cipher, err := ecies.Encrypt(rand.Reader, teeEciesPubKey, plaintext, nil, nil)
		require.NoError(t, err)

		additionalVariableMessages = append(additionalVariableMessages, cipher)
		privKeys = append(privKeys, privKey)
	}

	action, err := testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DATA_PROVIDER_RESTORE", originalMessageEncoded, privKeys, teeId,
		rewardEpochId, additionalFixedMessage, additionalVariableMessages,
		types.ThresholdReachedSubmissionTag,
	)
	require.NoError(t, err)

	actionInfo := &types.QueuedActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse := <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	walletExistenceProof, err := structs.Decode[wallet.ITeeWalletKeyManagerKeyExistence](wallet.KeyExistenceStructArg, actionResponse.Result.ResultData.Message)
	require.NoError(t, err)

	// check that wallet is actually on the tee
	wallet, err := wallets.Storage.GetWallet(wallets.WalletKeyIdPair{WalletId: walletId, KeyId: keyId})
	require.NoError(t, err)
	require.Equal(t, walletId[:], wallet.WalletId[:])
	require.Equal(t, keyId, wallet.KeyId)

	// generate action sent when voting closed
	action, err = testutils.BuildMockQueuedActionInstruction(
		"WALLET", "KEY_DATA_PROVIDER_RESTORE", originalMessageEncoded, privKeys, teeId,
		rewardEpochId, additionalFixedMessage, additionalVariableMessages,
		types.VotingClosedSubmissionTag,
	)
	require.NoError(t, err)

	actionInfo = &types.QueuedActionInfo{QueueId: "main", ActionId: common.BigToHash(actionId)}

	actionMap[*actionInfo] = action
	actionInfoChan <- actionInfo

	actionResponse = <-actionResponseChan
	require.True(t, actionResponse.Result.Status)
	err = utils.VerifySignature(crypto.Keccak256(actionResponse.Result.ResultData.Message), actionResponse.Result.ResultData.Signature, teeId)
	require.NoError(t, err)

	var signerSequence types.SignerSequence
	err = json.Unmarshal(actionResponse.Result.ResultData.Message, &signerSequence)
	require.NoError(t, err)

	err = utils.VerifySignature(signerSequence.Data.VoteHash[:], signerSequence.Signature, teeId)
	require.NoError(t, err)

	return &walletExistenceProof
}

func MockProxy(t *testing.T, mainActionInfoChan, readActionInfoChan chan *types.QueuedActionInfo,
	actionMap map[types.QueuedActionInfo]*types.QueuedAction, actionResponseChan chan *types.QueueActionResponse) {
	router := mux.NewRouter()

	router.HandleFunc("/queue/main", func(w http.ResponseWriter, r *http.Request) {
		var actionInfo types.QueuedActionInfo
		select {
		case x := <-mainActionInfoChan:
			actionInfo = *x
		default:
			actionInfo = types.QueuedActionInfo{}
		}

		response, err := json.Marshal(actionInfo)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	}).Methods("GET")

	router.HandleFunc("/queue/read", func(w http.ResponseWriter, r *http.Request) {
		var actionInfo types.QueuedActionInfo
		select {
		case x := <-readActionInfoChan:
			actionInfo = *x
		default:
			actionInfo = types.QueuedActionInfo{}
		}

		response, err := json.Marshal(actionInfo)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
	}).Methods("GET")

	router.HandleFunc("/dequeue", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var actionInfo types.QueuedActionInfo
		err = json.Unmarshal(body, &actionInfo)
		require.NoError(t, err)

		action, ok := actionMap[actionInfo]
		require.True(t, ok)

		response, err := json.Marshal(action)
		require.NoError(t, err)

		_, err = w.Write(response)
		require.NoError(t, err)
		err = r.Body.Close()
		require.NoError(t, err)
	}).Methods("POST")

	router.HandleFunc("/result", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var actionResponse types.QueueActionResponse
		err = json.Unmarshal(body, &actionResponse)
		require.NoError(t, err)

		actionResponseChan <- &actionResponse
		err = r.Body.Close()
		require.NoError(t, err)
	}).Methods("POST")

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", proxyPort), router))
}
