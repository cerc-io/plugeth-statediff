// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package statediff_test

import (
	"context"
	"errors"
	"math/big"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	statediff "github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/test_helpers"
	"github.com/cerc-io/plugeth-statediff/test_helpers/mocks"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
)

func init() {
	test_helpers.SilenceLogs()
}

func TestServiceLoop(t *testing.T) {
	t.Run("error in chain event loop", testErrorInChainEventLoop)
	t.Run("error in block loop", testErrorInBlockLoop)
}

var (
	eventsChannel = make(chan core.ChainEvent, 1)

	parentRoot1   = common.HexToHash("0x01")
	parentRoot2   = common.HexToHash("0x02")
	parentHeader1 = types.Header{Number: big.NewInt(rand.Int63()), Root: parentRoot1}
	parentHeader2 = types.Header{Number: big.NewInt(rand.Int63()), Root: parentRoot2}

	parentBlock1 = types.NewBlock(&parentHeader1, nil, nil, nil, trie.NewEmpty(nil))
	parentBlock2 = types.NewBlock(&parentHeader2, nil, nil, nil, trie.NewEmpty(nil))

	parentHash1 = parentBlock1.Hash()
	parentHash2 = parentBlock2.Hash()

	testRoot1 = common.HexToHash("0x03")
	testRoot2 = common.HexToHash("0x04")
	testRoot3 = common.HexToHash("0x04")
	header1   = types.Header{ParentHash: parentHash1, Root: testRoot1, Number: big.NewInt(1)}
	header2   = types.Header{ParentHash: parentHash2, Root: testRoot2, Number: big.NewInt(2)}
	header3   = types.Header{ParentHash: common.HexToHash("parent hash"), Root: testRoot3, Number: big.NewInt(3)}

	testBlock1 = types.NewBlock(&header1, nil, nil, nil, trie.NewEmpty(nil))
	testBlock2 = types.NewBlock(&header2, nil, nil, nil, trie.NewEmpty(nil))
	testBlock3 = types.NewBlock(&header3, nil, nil, nil, trie.NewEmpty(nil))

	receiptRoot1  = common.HexToHash("0x05")
	receiptRoot2  = common.HexToHash("0x06")
	receiptRoot3  = common.HexToHash("0x07")
	testReceipts1 = []*types.Receipt{types.NewReceipt(receiptRoot1.Bytes(), false, 1000), types.NewReceipt(receiptRoot2.Bytes(), false, 2000)}
	testReceipts2 = []*types.Receipt{types.NewReceipt(receiptRoot3.Bytes(), false, 3000)}

	event1 = core.ChainEvent{Block: testBlock1}
	event2 = core.ChainEvent{Block: testBlock2}
	event3 = core.ChainEvent{Block: testBlock3}

	defaultParams = statediff.Params{
		IncludeBlock:     true,
		IncludeReceipts:  true,
		IncludeTD:        true,
		WatchedAddresses: []common.Address{},
	}
)

func init() {
	defaultParams.ComputeWatchedAddressesLeafPaths()
}

func testErrorInChainEventLoop(t *testing.T) {
	//the first chain event causes and error (in blockchain mock)
	builder := mocks.Builder{}
	blockChain := mocks.BlockChain{}
	serviceQuit := make(chan bool)
	service := statediff.Service{
		Builder:           &builder,
		BlockChain:        &blockChain,
		QuitChan:          serviceQuit,
		Subscriptions:     make(map[common.Hash]map[statediff.SubID]statediff.Subscription),
		SubscriptionTypes: make(map[common.Hash]statediff.Params),
		BlockCache:        statediff.NewBlockCache(1),
	}
	payloadChan := make(chan statediff.Payload, 2)
	quitChan := make(chan bool)
	service.Subscribe(payloadChan, quitChan, defaultParams)
	// FIXME why is this here?
	testRoot2 = common.HexToHash("0xTestRoot2")
	blockMapping := make(map[common.Hash]*types.Block)
	blockMapping[parentBlock1.Hash()] = parentBlock1
	blockMapping[parentBlock2.Hash()] = parentBlock2
	blockChain.SetBlocksForHashes(blockMapping)
	blockChain.SetChainEvents([]core.ChainEvent{event1, event2, event3})
	blockChain.SetReceiptsForHash(testBlock1.Hash(), testReceipts1)
	blockChain.SetReceiptsForHash(testBlock2.Hash(), testReceipts2)

	payloads := make([]statediff.Payload, 0, 2)
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		for i := 0; i < 2; i++ {
			select {
			case payload := <-payloadChan:
				payloads = append(payloads, payload)
			case <-quitChan:
			}
		}
		wg.Done()
	}()
	service.PublishLoop(eventsChannel)
	wg.Wait()
	require.Equal(t, 2, len(payloads), "number of payloads")

	testReceipts1Rlp, err := rlp.EncodeToBytes(&testReceipts1)
	if err != nil {
		t.Error(err)
	}
	testReceipts2Rlp, err := rlp.EncodeToBytes(&testReceipts2)
	if err != nil {
		t.Error(err)
	}
	expectedReceiptsRlp := [][]byte{testReceipts1Rlp, testReceipts2Rlp, nil}
	for i, payload := range payloads {
		require.Equal(t, expectedReceiptsRlp[i], payload.ReceiptsRlp, "payload %d", i)
	}

	require.Equal(t, builder.Params, defaultParams)
	require.Equal(t, testBlock2.Hash(), builder.Args.BlockHash)
	require.Equal(t, parentBlock2.Root(), builder.Args.OldStateRoot)
	require.Equal(t, testBlock2.Root(), builder.Args.NewStateRoot)
	//look up the parent block from its hash
	expectedHashes := []common.Hash{testBlock1.ParentHash(), testBlock2.ParentHash()}
	require.Equal(t, expectedHashes, blockChain.HashesLookedUp)
}

func testErrorInBlockLoop(t *testing.T) {
	//second block's parent block can't be found
	builder := mocks.Builder{}
	blockChain := mocks.BlockChain{}
	service := statediff.Service{
		Builder:           &builder,
		BlockChain:        &blockChain,
		QuitChan:          make(chan bool),
		Subscriptions:     make(map[common.Hash]map[statediff.SubID]statediff.Subscription),
		SubscriptionTypes: make(map[common.Hash]statediff.Params),
		BlockCache:        statediff.NewBlockCache(1),
	}
	payloadChan := make(chan statediff.Payload)
	quitChan := make(chan bool)
	service.Subscribe(payloadChan, quitChan, defaultParams)
	blockMapping := make(map[common.Hash]*types.Block)
	blockMapping[parentBlock1.Hash()] = parentBlock1
	blockChain.SetBlocksForHashes(blockMapping)
	blockChain.SetChainEvents([]core.ChainEvent{event1, event2})
	// Need to have listeners on the channels or the subscription will be closed and the processing halted
	go func() {
		select {
		case <-payloadChan:
		case <-quitChan:
		}
	}()
	service.PublishLoop(eventsChannel)

	require.Equal(t, defaultParams, builder.Params)
	require.Equal(t, testBlock1.Hash(), builder.Args.BlockHash)
	require.Equal(t, parentBlock1.Root(), builder.Args.OldStateRoot)
	require.Equal(t, testBlock1.Root(), builder.Args.NewStateRoot)
}

func TestGetStateDiffAt(t *testing.T) {
	mockStateDiff := sdtypes.StateObject{
		BlockNumber: testBlock1.Number(),
		BlockHash:   testBlock1.Hash(),
	}
	expectedStateDiffRlp, err := rlp.EncodeToBytes(&mockStateDiff)
	if err != nil {
		t.Error(err)
	}
	expectedReceiptsRlp, err := rlp.EncodeToBytes(&testReceipts1)
	if err != nil {
		t.Error(err)
	}
	expectedBlockRlp, err := rlp.EncodeToBytes(testBlock1)
	if err != nil {
		t.Error(err)
	}
	expectedStateDiffPayload := statediff.Payload{
		StateObjectRlp: expectedStateDiffRlp,
		ReceiptsRlp:    expectedReceiptsRlp,
		BlockRlp:       expectedBlockRlp,
	}
	expectedStateDiffPayloadRlp, err := rlp.EncodeToBytes(&expectedStateDiffPayload)
	if err != nil {
		t.Error(err)
	}
	builder := mocks.Builder{}
	builder.SetStateDiffToBuild(mockStateDiff)
	blockChain := mocks.BlockChain{}
	blockMapping := make(map[common.Hash]*types.Block)
	blockMapping[parentBlock1.Hash()] = parentBlock1
	blockChain.SetBlocksForHashes(blockMapping)
	blockChain.SetBlockForNumber(testBlock1, testBlock1.NumberU64())
	blockChain.SetReceiptsForHash(testBlock1.Hash(), testReceipts1)
	service := statediff.Service{
		Builder:           &builder,
		BlockChain:        &blockChain,
		QuitChan:          make(chan bool),
		Subscriptions:     make(map[common.Hash]map[statediff.SubID]statediff.Subscription),
		SubscriptionTypes: make(map[common.Hash]statediff.Params),
		BlockCache:        statediff.NewBlockCache(1),
	}
	stateDiffPayload, err := service.StateDiffAt(testBlock1.NumberU64(), defaultParams)
	if err != nil {
		t.Error(err)
	}
	stateDiffPayloadRlp, err := rlp.EncodeToBytes(stateDiffPayload)
	if err != nil {
		t.Error(err)
	}

	require.Equal(t, defaultParams, builder.Params)
	require.Equal(t, testBlock1.Hash(), builder.Args.BlockHash)
	require.Equal(t, parentBlock1.Root(), builder.Args.OldStateRoot)
	require.Equal(t, testBlock1.Root(), builder.Args.NewStateRoot)
	require.Equal(t, stateDiffPayloadRlp, expectedStateDiffPayloadRlp)
}

type writeSub struct {
	ch          <-chan statediff.JobStatus
	unsubscribe func()
}

func subscribeWritesService(t *testing.T, api *statediff.PublicAPI) writeSub {
	ctx, cancel := context.WithCancel(context.Background())
	sub, err := api.StreamWrites(ctx)
	require.NoError(t, err)
	return writeSub{sub, cancel}
}

func (ws writeSub) awaitStatus(job statediff.JobID, timeout time.Duration) (bool, error) {
	deadline := time.After(timeout)
	for {
		select {
		case status := <-ws.ch:
			if status.Err != nil {
				return false, status.Err
			}
			if status.ID == job {
				return true, nil
			}
		case <-deadline:
			return false, errors.New("timeout")
		}
	}
}

func TestWriteStateDiffAt(t *testing.T) {
	builder := mocks.Builder{}
	indexer := mocks.StateDiffIndexer{}
	blockChain := mocks.BlockChain{}
	blockMapping := make(map[common.Hash]*types.Block)
	blockMapping[parentBlock1.Hash()] = parentBlock1
	blockChain.SetBlocksForHashes(blockMapping)
	blockChain.SetBlockForNumber(testBlock1, testBlock1.NumberU64())
	blockChain.SetReceiptsForHash(testBlock1.Hash(), testReceipts1)

	service, err := statediff.NewService(statediff.Config{}, &blockChain, &mocks.Backend{}, &indexer)
	require.NoError(t, err)
	service.Builder = &builder
	api := statediff.NewPublicAPI(service)

	// delay to avoid subscription request being sent after statediff is written
	writeDelay := 200 * time.Millisecond
	// timeout to prevent hanging just in case it still happens
	jobTimeout := 2 * time.Second

	ws := subscribeWritesService(t, api)
	time.Sleep(writeDelay)
	job := service.WriteStateDiffAt(testBlock1.NumberU64(), defaultParams)
	ok, err := ws.awaitStatus(job, jobTimeout)
	require.NoError(t, err)
	require.True(t, ok)

	require.Equal(t, defaultParams, builder.Params)
	require.Equal(t, testBlock1.Hash(), builder.Args.BlockHash)
	require.Equal(t, parentBlock1.Root(), builder.Args.OldStateRoot)
	require.Equal(t, testBlock1.Root(), builder.Args.NewStateRoot)

	// verify we get nothing after unsubscribing
	ws.unsubscribe()
	job = service.WriteStateDiffAt(testBlock1.NumberU64(), defaultParams)
	ok, _ = ws.awaitStatus(job, jobTimeout)
	require.False(t, ok)

	// re-subscribe and test again
	ws = subscribeWritesService(t, api)
	time.Sleep(writeDelay)
	job = service.WriteStateDiffAt(testBlock1.NumberU64(), defaultParams)
	ok, err = ws.awaitStatus(job, jobTimeout)
	require.NoError(t, err)
	require.True(t, ok)
}

// This function will create a backend and service object which includes a generic Backend
func createServiceWithMockBackend(t *testing.T, curBlock uint64, highestBlock uint64) (*mocks.Backend, *statediff.Service) {
	builder := mocks.Builder{}
	blockChain := mocks.BlockChain{}
	backend := mocks.NewBackend(t, ethereum.SyncProgress{
		StartingBlock:       1,
		CurrentBlock:        curBlock,
		HighestBlock:        highestBlock,
		SyncedAccounts:      5,
		SyncedAccountBytes:  5,
		SyncedBytecodes:     5,
		SyncedBytecodeBytes: 5,
		SyncedStorage:       5,
		SyncedStorageBytes:  5,
		HealedTrienodes:     5,
		HealedTrienodeBytes: 5,
		HealedBytecodes:     5,
		HealedBytecodeBytes: 5,
		HealingTrienodes:    5,
		HealingBytecode:     5,
	})

	service := &statediff.Service{
		Builder:           &builder,
		BlockChain:        &blockChain,
		QuitChan:          make(chan bool),
		Subscriptions:     make(map[common.Hash]map[statediff.SubID]statediff.Subscription),
		SubscriptionTypes: make(map[common.Hash]statediff.Params),
		BlockCache:        statediff.NewBlockCache(1),
		BackendAPI:        backend,
		ShouldWaitForSync: true,
	}
	return backend, service
}

// TestWaitForSync ensures that the service waits until the blockchain has caught up to head
func TestWaitForSync(t *testing.T) {
	// Trivial case
	_, service := createServiceWithMockBackend(t, 10, 10)
	service.WaitForSync()

	// Catching-up case
	var highestBlock uint64 = 5
	// Create a service and a backend that is lagging behind the sync.
	backend, service := createServiceWithMockBackend(t, 0, highestBlock)
	syncComplete := make(chan int, 1)

	go func() {
		service.WaitForSync()
		syncComplete <- 0
	}()

	// Iterate blocks, updating the current synced block
	for currentBlock := uint64(0); currentBlock <= highestBlock; currentBlock++ {
		backend.SetCurrentBlock(currentBlock)
		if currentBlock < highestBlock {
			// Ensure we are still waiting if we haven't actually reached head
			require.Equal(t, len(syncComplete), 0)
		}
	}

	timeout := time.After(time.Second)
	for {
		select {
		case <-syncComplete:
			return
		case <-timeout:
			t.Fatal("timed out waiting for sync to complete")
		}
	}
}
