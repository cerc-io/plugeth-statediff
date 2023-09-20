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

package statediff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	plugeth "github.com/openrelayxyz/plugeth-utils/core"
	"github.com/thoas/go-funk"

	"github.com/cerc-io/plugeth-statediff/indexer/database/metrics"
	"github.com/cerc-io/plugeth-statediff/indexer/interfaces"
	types2 "github.com/cerc-io/plugeth-statediff/types"
	"github.com/cerc-io/plugeth-statediff/utils/log"
)

const (
	chainEventChanSize = 20000
	genesisBlockNumber = 0
	defaultRetryLimit  = 3                   // default retry limit once deadlock is detected.
	pgDeadlockDetected = "deadlock detected" // 40P01 https://www.postgresql.org/docs/current/errcodes-appendix.html
)

var (
	errTypeAssertionFailed = errors.New("type assertion failed")
	errUnexpectedOperation = errors.New("unexpected operation")
)

var defaultWriteLoopParams = Params{
	IncludeBlock:    true,
	IncludeReceipts: true,
	IncludeTD:       true,
	IncludeCode:     true,
}

// Service is the underlying struct for the state diffing service
type Service struct {
	// Used to build the state diff objects
	Builder Builder
	// Used to subscribe to chain events (blocks)
	BlockChain BlockChain
	// Cache the last block so that we can avoid having to lookup the next block's parent
	BlockCache BlockCache
	// The publicBackendAPI which provides useful information about the current state
	BackendAPI plugeth.Backend
	// Used to signal shutdown of the service
	QuitChan chan bool
	// Interface for publishing statediffs as PG-IPLD objects
	indexer interfaces.StateDiffIndexer

	// Should the statediff service wait for geth to sync to head?
	ShouldWaitForSync bool
	// Whether to enable writing state diffs directly to track blockchain head.
	enableWriteLoop bool
	// Parameters to use in the service write loop, if enabled
	writeLoopParams ParamsWithMutex
	// Settings to use for backfilling state diffs (plugging gaps when tracking head)
	backfillMaxDepth        uint64
	backfillCheckPastBlocks uint64
	// Size of the worker pool
	numWorkers uint
	// Number of retry for aborted transactions due to deadlock.
	maxRetry uint

	// Sequential ID for RPC subscriptions
	lastSubID uint64

	// A mapping of RpcIDs to their subscription channels, mapped to their subscription type (hash
	// of the Params RLP)
	Subscriptions map[common.Hash]map[SubID]Subscription
	// A mapping of subscription params rlp hash to the corresponding subscription params
	SubscriptionTypes map[common.Hash]Params
	// Number of current subscribers
	subscribers int32
	// Used to sync access to the Subscriptions
	subscriptionsMutex sync.Mutex

	// Write job status subscriptions
	jobStatusSubs      map[SubID]jobStatusSubscription
	jobStatusSubsMutex sync.RWMutex
	// Sequential ID for write jobs
	lastJobID uint64
	// Map of block number to in-flight jobs (for WriteStateDiffAt)
	currentJobs      map[uint64]JobID
	currentJobsMutex sync.Mutex
	// All in-progress statediff jobs
	currentBlocks      map[string]bool
	currentBlocksMutex sync.Mutex
}

// ID for identifying client subscriptions
type SubID uint64

// ID used for tracking in-progress jobs (0 for invalid)
type JobID uint64

// JobStatus represents the status of a completed job
type JobStatus struct {
	ID  JobID
	Err error
}

type jobStatusSubscription struct {
	statusChan chan<- JobStatus
	quitChan   chan<- bool
}

// Utility type for showing the relative positions of the blockchain and the statediff indexer.
type servicePosition struct {
	chainBlockNumber   uint64
	indexerBlockNumber uint64
}

// BlockCache caches the last block for safe access from different service loops
type BlockCache struct {
	sync.Mutex
	blocks  map[common.Hash]*types.Block
	maxSize uint
}

type workerParams struct {
	blockCh <-chan *types.Block
	wg      *sync.WaitGroup
	id      uint
}

func NewBlockCache(max uint) BlockCache {
	return BlockCache{
		blocks:  make(map[common.Hash]*types.Block),
		maxSize: max,
	}
}

// NewService creates a new state diffing service with the given config and backend
func NewService(cfg Config, blockChain BlockChain, backend plugeth.Backend, indexer interfaces.StateDiffIndexer) (*Service, error) {
	workers := cfg.NumWorkers
	if workers == 0 {
		workers = 1
	}

	quitCh := make(chan bool)
	sds := &Service{
		BlockChain:              blockChain,
		Builder:                 NewBuilder(blockChain.StateCache()),
		QuitChan:                quitCh,
		Subscriptions:           make(map[common.Hash]map[SubID]Subscription),
		SubscriptionTypes:       make(map[common.Hash]Params),
		BlockCache:              NewBlockCache(workers),
		BackendAPI:              backend,
		ShouldWaitForSync:       cfg.WaitForSync,
		indexer:                 indexer,
		enableWriteLoop:         cfg.EnableWriteLoop,
		backfillMaxDepth:        cfg.BackfillMaxDepth,
		backfillCheckPastBlocks: cfg.BackfillCheckPastBlocks,
		numWorkers:              workers,
		maxRetry:                defaultRetryLimit,
		jobStatusSubs:           map[SubID]jobStatusSubscription{},
		currentJobs:             map[uint64]JobID{},
		currentBlocks:           map[string]bool{},
		writeLoopParams:         ParamsWithMutex{Params: defaultWriteLoopParams},
	}

	if indexer != nil {
		err := loadWatchedAddresses(indexer, &sds.writeLoopParams)
		if err != nil {
			return nil, err
		}
		indexer.ReportDBMetrics(10*time.Second, quitCh)
	}
	return sds, nil
}

// Return the parent block of currentBlock, using the cached block if available;
// and cache the passed block
func (lbc *BlockCache) getParentBlock(currentBlock *types.Block, bc BlockChain) *types.Block {
	lbc.Lock()
	parentHash := currentBlock.ParentHash()
	var parentBlock *types.Block
	if block, ok := lbc.blocks[parentHash]; ok {
		parentBlock = block
		if len(lbc.blocks) > int(lbc.maxSize) {
			delete(lbc.blocks, parentHash)
		}
	} else {
		parentBlock = bc.GetBlockByHash(parentHash)
	}
	lbc.blocks[currentBlock.Hash()] = currentBlock
	lbc.Unlock()
	return parentBlock
}

// WriteLoop event loop for progressively processing and writing diffs directly to DB
func (sds *Service) WriteLoop(chainEventCh chan core.ChainEvent) {
	initialPos := sds.currentPosition()
	log.Info(
		"WriteLoop: initial positions",
		"chain", initialPos.chainBlockNumber,
		"indexer", initialPos.indexerBlockNumber,
	)
	log := log.New("context", "statediff writing")
	sub := sds.BlockChain.SubscribeChainEvent(chainEventCh)
	defer sub.Unsubscribe()

	var wg sync.WaitGroup
	blockFwd := make(chan *types.Block, chainEventChanSize)
	defer func() {
		log.Info("Quitting")
		close(blockFwd)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case event := <-chainEventCh:
				// First process metrics for chain events, then forward to workers
				lastHeight := uint64(defaultStatediffMetrics.lastEventHeight.Value())
				if lastHeight == 0 {
					lastHeight = initialPos.indexerBlockNumber
				}
				block := event.Block
				log.Debug("Chain event received", "number", block.Number(), "hash", event.Hash)
				nextHeight := block.Number().Uint64()
				if nextHeight > lastHeight {
					distance := nextHeight - lastHeight
					if distance == 1 {
						log.Info("WriteLoop: received expected block",
							"block number", nextHeight, "last number", lastHeight)
					} else {
						log.Warn("WriteLoop: received unexpected block from the future",
							"block number", nextHeight, "last number", lastHeight)
					}
					blockFwd <- block
					defaultStatediffMetrics.lastEventHeight.Update(int64(nextHeight))
				} else {
					log.Warn("WriteLoop: received unexpected block from the past",
						"block number", nextHeight, "last number", lastHeight)
					blockFwd <- block
				}
				defaultStatediffMetrics.writeLoopChannelLen.Update(int64(len(chainEventCh)))
			case err := <-sub.Err():
				if err != nil {
					log.Error("Error from subscription", "error", err)
				}
				close(sds.QuitChan)
				return
			case <-sds.QuitChan:
				return
			}
		}
	}()
	wg.Add(int(sds.numWorkers))
	for worker := uint(0); worker < sds.numWorkers; worker++ {
		params := workerParams{blockCh: blockFwd, wg: &wg, id: worker}
		go sds.writeLoopWorker(params)
	}
	wg.Wait()
}

func (sds *Service) writeGenesisStateDiff(currBlock *types.Block, logger log.Logger) {
	// For genesis block we need to return the entire state trie hence we diff it with an empty trie.
	log.Info("Writing genesis state diff", "number", genesisBlockNumber)

	err := sds.writeStateDiffWithRetry(currBlock, common.Hash{}, sds.writeLoopParams.CopyParams())
	if err != nil {
		log.Error("failed to write state diff", "number",
			genesisBlockNumber, "error", err)
		return
	}
	defaultStatediffMetrics.lastStatediffHeight.Update(genesisBlockNumber)
}

func (sds *Service) writeLoopWorker(params workerParams) {
	log := log.New("context", "statediff writing", "worker", params.id)
	defer params.wg.Done()

	// statediffs the indicated block, and while maxBackfill > 0, backfills missing parent blocks.
	var writeBlockWithParents func(*types.Block, uint64, Params) error
	writeBlockWithParents = func(block *types.Block, maxBackfill uint64, writeParams Params) error {
		parentBlock := sds.BlockCache.getParentBlock(block, sds.BlockChain)
		if parentBlock == nil {
			return errors.New("Parent block is nil, skipping this block")
		}

		parentIsGenesis := parentBlock.Number().Uint64() == genesisBlockNumber

		// chainEvent streams block from block 1, but we also need to include data from the genesis block.
		if parentIsGenesis {
			sds.writeGenesisStateDiff(parentBlock, log)
		}

		log.Info("Writing state diff", "number", block.Number())
		err := sds.writeStateDiffWithRetry(block, parentBlock.Root(), writeParams)
		if err != nil {
			return err
		}

		if parentIsGenesis {
			return nil
		}
		// We do this _after_ indexing the requested block.  This makes sure that if a child of ours arrives for
		// statediffing while we are still working on missing ancestors, its regress stops at us, and only we
		// continue working backward.
		parentIndexed, err := sds.indexedOrInProgress(parentBlock)
		if err != nil {
			log.Error("Error checking for indexing status of parent block.",
				"number", block.Number(), "hash", block.Hash(),
				"parent number", parentBlock.Number(), "parent hash", parentBlock.Hash(),
				"error", err)
			return err
		}
		if parentIndexed {
			return nil
		}
		if maxBackfill > 0 {
			log.Info("Parent block not indexed. Indexing now.",
				"number", block.Number(), "hash", block.Hash(),
				"parent number", parentBlock.Number(), "parent hash", parentBlock.Hash())
			err = writeBlockWithParents(parentBlock, maxBackfill-1, writeParams)
			if err != nil {
				log.Error("Error indexing parent block.",
					"number", block.Number(), "hash", block.Hash(),
					"parent number", parentBlock.Number(), "parent hash", parentBlock.Hash(),
					"error", err)
			}
		} else {
			log.Error("Parent block not indexed but max backfill depth exceeded. Index MUST be corrected manually.",
				"number", block.Number(), "hash", block.Hash(),
				"parent number", parentBlock.Number(), "parent hash", parentBlock.Hash())
		}
		return nil
	}

	for {
		select {
		case block := <-params.blockCh:
			log.Debug("Block received", "number", block.Number())
			err := writeBlockWithParents(block, sds.backfillMaxDepth, sds.writeLoopParams.CopyParams())
			if err != nil {
				log.Error("Error processing statediff",
					"number", block.Number(),
					"hash", block.Hash(),
					"error", err)
				continue
			}

			// FIXME: reported height will be non-monotonic with concurrent workers
			defaultStatediffMetrics.lastStatediffHeight.Update(int64(block.Number().Uint64()))
		case <-sds.QuitChan:
			log.Info("Quitting")
			return
		}
	}
}

// PublishLoop processes and publishes statediff payloads to subscribed clients
func (sds *Service) PublishLoop(chainEventCh chan core.ChainEvent) {
	log.Info("Starting statediff publish loop")
	log := log.New("context", "statediff publishing")

	sub := sds.BlockChain.SubscribeChainEvent(chainEventCh)
	defer func() {
		log.Info("Quitting")
		sds.close()
		sub.Unsubscribe()
	}()

	for {
		select {
		//Notify chain event channel of events
		case event := <-chainEventCh:
			defaultStatediffMetrics.serviceLoopChannelLen.Update(int64(len(chainEventCh)))
			block := event.Block
			log.Debug("Chain event received", "number", block.Number(), "hash", event.Hash)
			// if we don't have any subscribers, do not process a statediff
			if atomic.LoadInt32(&sds.subscribers) == 0 {
				log.Debug("Currently no subscribers, skipping block")
				continue
			}

			parent := sds.BlockCache.getParentBlock(block, sds.BlockChain)
			if parent == nil {
				log.Error("Parent block is nil, skipping block", "number", block.Number())
				continue
			}

			// chainEvent streams block from block 1, but we also need to include data from the genesis block.
			if parent.Number().Uint64() == genesisBlockNumber {
				// For genesis block we need to return the entire state trie hence we diff it with an empty trie.
				sds.streamStateDiff(parent, common.Hash{})
			}
			sds.streamStateDiff(block, parent.Root())
		case err := <-sub.Err():
			if err != nil {
				log.Error("error from subscription", "error", err)
			}
			close(sds.QuitChan)
			return
		case <-sds.QuitChan:
			return
		}
	}
}

// streamStateDiff builds and delivers diff payloads for each subscription according to their
// subscription type
func (sds *Service) streamStateDiff(currentBlock *types.Block, parentRoot common.Hash) {
	sds.subscriptionsMutex.Lock()
	for ty, subs := range sds.Subscriptions {
		params, ok := sds.SubscriptionTypes[ty]
		if !ok {
			log.Error("no parameter set associated with this subscription", "sub.type", ty.String())
			sds.closeType(ty)
			continue
		}
		// create payload for this subscription type
		payload, err := sds.processStateDiff(currentBlock, parentRoot, params)
		if err != nil {
			log.Error("statediff processing error",
				"number", currentBlock.Number(), "parameters", params, "error", err)
			continue
		}
		for id, sub := range subs {
			select {
			case sub.PayloadChan <- *payload:
				log.Debug("sending statediff payload at head", "number", currentBlock.Number(), "sub.id", id)
			default:
				log.Info("unable to send statediff payload; channel has no receiver", "sub.id", id)
			}
		}
	}
	sds.subscriptionsMutex.Unlock()
}

// StateDiffAt returns a state diff object payload at the specific blockheight
// This operation cannot be performed back past the point of db pruning; it requires an archival
// node for historical data
func (sds *Service) StateDiffAt(blockNumber uint64, params Params) (*Payload, error) {
	log.Info("Sending state diff", "number", blockNumber)

	currentBlock := sds.BlockChain.GetBlockByNumber(blockNumber)
	parentRoot := common.Hash{}
	if blockNumber != 0 {
		parentRoot = sds.BlockChain.GetBlockByHash(currentBlock.ParentHash()).Root()
	}
	return sds.processStateDiff(currentBlock, parentRoot, sds.maybeReplaceWatchedAddresses(params))
}

// StateDiffFor returns a state diff object payload for the specific blockhash
// This operation cannot be performed back past the point of db pruning; it requires an archival
// node for historical data
func (sds *Service) StateDiffFor(blockHash common.Hash, params Params) (*Payload, error) {
	log.Info("Sending state diff", "hash", blockHash)

	currentBlock := sds.BlockChain.GetBlockByHash(blockHash)
	parentRoot := common.Hash{}
	if currentBlock.NumberU64() != 0 {
		parentRoot = sds.BlockChain.GetBlockByHash(currentBlock.ParentHash()).Root()
	}
	return sds.processStateDiff(currentBlock, parentRoot, sds.maybeReplaceWatchedAddresses(params))
}

// use watched addresses from statediffing write loop if not provided
// compute leaf paths of watched addresses in the params
func (sds *Service) maybeReplaceWatchedAddresses(params Params) Params {
	if params.WatchedAddresses == nil && sds.writeLoopParams.WatchedAddresses != nil {
		sds.writeLoopParams.RLock()
		params.WatchedAddresses = make([]common.Address, len(sds.writeLoopParams.WatchedAddresses))
		copy(params.WatchedAddresses, sds.writeLoopParams.WatchedAddresses)
		sds.writeLoopParams.RUnlock()
	}
	params.ComputeWatchedAddressesLeafPaths()
	return params
}

// processStateDiff method builds the state diff payload from the current block, parent state root, and provided params
func (sds *Service) processStateDiff(currentBlock *types.Block, parentRoot common.Hash, params Params) (*Payload, error) {
	stateDiff, err := sds.Builder.BuildStateDiffObject(Args{
		NewStateRoot: currentBlock.Root(),
		OldStateRoot: parentRoot,
		BlockHash:    currentBlock.Hash(),
		BlockNumber:  currentBlock.Number(),
	}, params)
	stateDiffRlp, err := rlp.EncodeToBytes(&stateDiff)
	if err != nil {
		return nil, err
	}
	log.Debug("statediff RLP payload for block",
		"number", currentBlock.Number(), "byte size", len(stateDiffRlp))
	return sds.newPayload(stateDiffRlp, currentBlock, params)
}

func (sds *Service) newPayload(stateObject []byte, block *types.Block, params Params) (*Payload, error) {
	payload := &Payload{
		StateObjectRlp: stateObject,
	}
	if params.IncludeBlock {
		blockBuff := new(bytes.Buffer)
		if err := block.EncodeRLP(blockBuff); err != nil {
			return nil, err
		}
		payload.BlockRlp = blockBuff.Bytes()
	}
	if params.IncludeTD {
		payload.TotalDifficulty = sds.BlockChain.GetTd(block.Hash(), block.NumberU64())
	}
	if params.IncludeReceipts {
		receiptBuff := new(bytes.Buffer)
		receipts := sds.BlockChain.GetReceiptsByHash(block.Hash())
		if err := rlp.Encode(receiptBuff, receipts); err != nil {
			return nil, err
		}
		payload.ReceiptsRlp = receiptBuff.Bytes()
	}
	return payload, nil
}

// Subscribe is used by the API to subscribe to the service loop
func (sds *Service) Subscribe(sub chan<- Payload, quitChan chan<- bool, params Params) SubID {
	log.Info("Subscribing to the statediff service")
	if atomic.CompareAndSwapInt32(&sds.subscribers, 0, 1) {
		log.Info("State diffing subscription received; beginning statediff processing")
	}

	// compute leaf paths of watched addresses in the params
	params.ComputeWatchedAddressesLeafPaths()

	// Subscription type is defined as the hash of the rlp-serialized subscription params
	by, err := rlp.EncodeToBytes(&params)
	if err != nil {
		log.Error("State diffing params need to be rlp-serializable")
		return 0
	}
	subscriptionType := crypto.Keccak256Hash(by)
	id := SubID(atomic.AddUint64(&sds.lastSubID, 1))
	// Add subscriber
	sds.subscriptionsMutex.Lock()
	if sds.Subscriptions[subscriptionType] == nil {
		sds.Subscriptions[subscriptionType] = make(map[SubID]Subscription)
	}
	sds.Subscriptions[subscriptionType][id] = Subscription{
		PayloadChan: sub,
		QuitChan:    quitChan,
	}
	sds.SubscriptionTypes[subscriptionType] = params
	sds.subscriptionsMutex.Unlock()
	return id
}

// Unsubscribe is used to unsubscribe from the service loop
func (sds *Service) Unsubscribe(id SubID) error {
	log.Info("Unsubscribing from the statediff service", "sub.id", id)
	sds.subscriptionsMutex.Lock()
	for ty := range sds.Subscriptions {
		delete(sds.Subscriptions[ty], id)
		if len(sds.Subscriptions[ty]) == 0 {
			// If we removed the last subscription of this type, remove the subscription type outright
			delete(sds.Subscriptions, ty)
			delete(sds.SubscriptionTypes, ty)
		}
	}
	if len(sds.Subscriptions) == 0 {
		if atomic.CompareAndSwapInt32(&sds.subscribers, 1, 0) {
			log.Info("No more subscriptions; halting statediff processing")
		}
	}
	sds.subscriptionsMutex.Unlock()
	return nil
}

// IsSyncing returns true if geth is still syncing, and false if it has caught up to head.
func (sds *Service) IsSyncing() bool {
	progress := sds.BackendAPI.Downloader().Progress()
	return progress.CurrentBlock() < progress.HighestBlock()
}

// WaitForSync continuously checks the status of geth syncing, only returning once it has caught
// up to head.
func (sds *Service) WaitForSync() {
	synced := false
	for !synced {
		if !sds.IsSyncing() {
			log.Debug("Geth has completed syncing")
			synced = true
		} else {
			time.Sleep(1 * time.Second)
		}
	}
}

// Start is used to begin the service
func (sds *Service) Start() error {
	log.Info("Starting statediff service")

	if sds.ShouldWaitForSync {
		log.Info("Statediff service waiting until geth has caught up to the head of the chain")
		sds.WaitForSync()
	}
	chainEventCh := make(chan core.ChainEvent, chainEventChanSize)
	go sds.PublishLoop(chainEventCh)

	if sds.enableWriteLoop {
		log.Info("Starting statediff DB backfill", "params", sds.writeLoopParams.Params)
		go sds.Backfill()
		log.Debug("Starting statediff DB write loop", "params", sds.writeLoopParams.Params)
		chainEventCh := make(chan core.ChainEvent, chainEventChanSize)
		go sds.WriteLoop(chainEventCh)
	}
	return nil
}

// Stop is used to close down the service
func (sds *Service) Stop() error {
	log.Info("Stopping statediff service")
	close(sds.QuitChan)
	var err error
	if sds.indexer != nil {
		if err = sds.indexer.Close(); err != nil {
			log.Error("Error closing indexer", "error", err)
		}
	}
	return err
}

// close is used to close all listening subscriptions
func (sds *Service) close() {
	sds.subscriptionsMutex.Lock()
	for ty, subs := range sds.Subscriptions {
		for id, sub := range subs {
			select {
			case sub.QuitChan <- true:
				log.Info("closing subscription", "sub.id", id)
			default:
				log.Info("unable to close subscription; channel has no receiver", "sub.id", id)
			}
			delete(sds.Subscriptions[ty], id)
		}
		delete(sds.Subscriptions, ty)
		delete(sds.SubscriptionTypes, ty)
	}
	sds.subscriptionsMutex.Unlock()
}

// closeType is used to close all subscriptions of given type
// NOTE: this needs to be called with subscription access locked
func (sds *Service) closeType(subType common.Hash) {
	subs := sds.Subscriptions[subType]
	for id, sub := range subs {
		sendNonBlockingQuit(id, sub)
	}
	delete(sds.Subscriptions, subType)
	delete(sds.SubscriptionTypes, subType)
}

func sendNonBlockingQuit(id SubID, sub Subscription) {
	select {
	case sub.QuitChan <- true:
		log.Info("closing subscription", "sub.id", id)
	default:
		log.Info("unable to close subscription; channel has no receiver", "sub.id", id)
	}
}

// WriteStateDiffAt writes a state diff at the specific blockheight directly to the database
// This operation cannot be performed back past the point of db pruning; it requires an archival node
// for historical data
func (sds *Service) WriteStateDiffAt(blockNumber uint64, params Params) JobID {
	sds.currentJobsMutex.Lock()
	defer sds.currentJobsMutex.Unlock()
	if id, has := sds.currentJobs[blockNumber]; has {
		return id
	}
	sds.lastJobID++
	id := JobID(sds.lastJobID)
	sds.currentJobs[blockNumber] = id

	go func() {
		err := sds.writeStateDiffAt(blockNumber, params)
		if err != nil {
			log.Error("failed to write state diff", "error", err)
		}
		sds.currentJobsMutex.Lock()
		delete(sds.currentJobs, blockNumber)
		sds.currentJobsMutex.Unlock()

		sds.jobStatusSubsMutex.RLock()
		defer sds.jobStatusSubsMutex.RUnlock()
		for _, sub := range sds.jobStatusSubs {
			sub.statusChan <- JobStatus{id, err}
		}
	}()
	return id
}

func (sds *Service) writeStateDiffAt(blockNumber uint64, params Params) error {
	log.Info("Writing state diff at", "number", blockNumber)

	currentBlock := sds.BlockChain.GetBlockByNumber(blockNumber)
	parentRoot := common.Hash{}
	if blockNumber != 0 {
		parentBlock := sds.BlockChain.GetBlockByHash(currentBlock.ParentHash())
		parentRoot = parentBlock.Root()
	}
	return sds.writeStateDiffWithRetry(currentBlock, parentRoot, sds.maybeReplaceWatchedAddresses(params))
}

// WriteStateDiffFor writes a state diff for the specific blockhash directly to the database
// This operation cannot be performed back past the point of db pruning; it requires an archival node
// for historical data
func (sds *Service) WriteStateDiffFor(blockHash common.Hash, params Params) error {
	log.Info("Writing state diff for", "hash", blockHash)

	currentBlock := sds.BlockChain.GetBlockByHash(blockHash)
	parentRoot := common.Hash{}
	if currentBlock.NumberU64() != 0 {
		parentBlock := sds.BlockChain.GetBlockByHash(currentBlock.ParentHash())
		parentRoot = parentBlock.Root()
	}
	return sds.writeStateDiffWithRetry(currentBlock, parentRoot, sds.maybeReplaceWatchedAddresses(params))
}

// indexedOrInProgress returns true if the block has already been statediffed or is in progress, else false.
func (sds *Service) indexedOrInProgress(block *types.Block) (bool, error) {
	if sds.statediffInProgress(block) {
		return true, nil
	}
	return sds.indexer.HasBlock(block.Hash(), block.NumberU64())
}

// statediffInProgress returns true if statediffing is currently in progress for the block, else false.
func (sds *Service) statediffInProgress(block *types.Block) bool {
	sds.currentBlocksMutex.Lock()
	defer sds.currentBlocksMutex.Unlock()

	key := fmt.Sprintf("%s,%d", block.Hash().Hex(), block.NumberU64())
	return sds.currentBlocks[key]
}

// Claim exclusive access for state diffing the specified block.
// Returns true and a function to release access if successful, else false, nil.
func (sds *Service) claimExclusiveAccess(block *types.Block) (bool, func()) {
	sds.currentBlocksMutex.Lock()
	defer sds.currentBlocksMutex.Unlock()

	key := fmt.Sprintf("%s,%d", block.Hash().Hex(), block.NumberU64())
	if sds.currentBlocks[key] {
		return false, nil
	}
	sds.currentBlocks[key] = true
	return true, func() {
		sds.currentBlocksMutex.Lock()
		defer sds.currentBlocksMutex.Unlock()
		delete(sds.currentBlocks, key)
	}
}

// Writes a state diff from the current block, parent state root, and provided params
func (sds *Service) writeStateDiff(block *types.Block, parentRoot common.Hash, params Params) error {
	log := log.New("hash", block.Hash(), "number", block.Number())
	if granted, relinquish := sds.claimExclusiveAccess(block); granted {
		defer relinquish()
	} else {
		log.Info("Not writing, statediff in progress.")
		return nil
	}
	if done, _ := sds.indexer.HasBlock(block.Hash(), block.NumberU64()); done {
		log.Info("Not writing, statediff already done.")
		return nil
	}

	var totalDifficulty = big.NewInt(0)
	var receipts types.Receipts
	var err error
	var tx interfaces.Batch

	start := countStateDiffBegin(block, log)
	defer countStateDiffEnd(start, log, &err)
	if sds.indexer == nil {
		return fmt.Errorf("indexer is not set; cannot write indexed diffs")
	}

	if params.IncludeTD {
		totalDifficulty = sds.BlockChain.GetTd(block.Hash(), block.NumberU64())
	}
	if params.IncludeReceipts {
		receipts = sds.BlockChain.GetReceiptsByHash(block.Hash())
	}
	tx, err = sds.indexer.PushBlock(block, receipts, totalDifficulty)
	if err != nil {
		return err
	}

	nodeSink := func(node types2.StateLeafNode) error {
		defer metrics.ReportAndUpdateDuration("statediff output", time.Now(), log,
			metrics.IndexerMetrics.OutputTimer)
		return sds.indexer.PushStateNode(tx, node, block.Hash().String())
	}
	ipldSink := func(c types2.IPLD) error {
		defer metrics.ReportAndUpdateDuration("statediff ipldOutput", time.Now(), log,
			metrics.IndexerMetrics.IPLDOutputTimer)
		return sds.indexer.PushIPLD(tx, c)
	}

	err = sds.Builder.WriteStateDiff(Args{
		NewStateRoot: block.Root(),
		OldStateRoot: parentRoot,
		BlockHash:    block.Hash(),
		BlockNumber:  block.Number(),
	}, params, nodeSink, ipldSink)

	// TODO this anti-pattern needs to be sorted out eventually
	if err = tx.Submit(err); err != nil {
		return fmt.Errorf("batch transaction submission failed: %w", err)
	}
	return nil
}

// Wrapper function on writeStateDiff to retry when the deadlock is detected.
func (sds *Service) writeStateDiffWithRetry(block *types.Block, parentRoot common.Hash, params Params) error {
	var err error
	for i := uint(0); i < sds.maxRetry; i++ {
		err = sds.writeStateDiff(block, parentRoot, params)
		if err != nil && strings.Contains(err.Error(), pgDeadlockDetected) {
			// Retry only when the deadlock is detected.
			if i+1 < sds.maxRetry {
				log.Warn("deadlock detected while writing statediff", "error", err, "retry number", i)
			}
			continue
		}
		break
	}
	return err
}

// SubscribeWriteStatus is used by the API to subscribe to the job status updates
func (sds *Service) SubscribeWriteStatus(sub chan<- JobStatus) SubID {
	id := SubID(atomic.AddUint64(&sds.lastSubID, 1))
	log.Info("Subscribing to job status updates", "sub.id", id)
	sds.jobStatusSubsMutex.Lock()
	sds.jobStatusSubs[id] = jobStatusSubscription{
		statusChan: sub,
	}
	sds.jobStatusSubsMutex.Unlock()
	return id
}

// UnsubscribeWriteStatus is used to unsubscribe from job status updates
func (sds *Service) UnsubscribeWriteStatus(id SubID) {
	log.Info("Unsubscribing from job status updates", "sub.id", id)
	sds.jobStatusSubsMutex.Lock()
	delete(sds.jobStatusSubs, id)
	sds.jobStatusSubsMutex.Unlock()
}

// WatchAddress performs one of following operations on the watched addresses in sds.writeLoopParams and the db:
// add | remove | set | clear
func (sds *Service) WatchAddress(operation types2.OperationType, args []types2.WatchAddressArg) error {
	sds.writeLoopParams.Lock()
	defer sds.writeLoopParams.Unlock()

	// get the current block number
	currentBlockNumber := sds.BlockChain.CurrentBlock().Number

	switch operation {
	case types2.Add:
		// filter out args having an already watched address with a warning
		filteredArgs, ok := funk.Filter(args, func(arg types2.WatchAddressArg) bool {
			if funk.Contains(sds.writeLoopParams.WatchedAddresses, plugeth.HexToAddress(arg.Address)) {
				log.Warn("Address already being watched", "address", arg.Address)
				return false
			}
			return true
		}).([]types2.WatchAddressArg)
		if !ok {
			return fmt.Errorf("add: filtered args %w", errTypeAssertionFailed)
		}

		// get addresses from the filtered args
		filteredAddresses, err := MapWatchAddressArgsToAddresses(filteredArgs)
		if err != nil {
			return fmt.Errorf("add: filtered addresses %w", err)
		}

		// update the db
		if sds.indexer != nil {
			err = sds.indexer.InsertWatchedAddresses(filteredArgs, currentBlockNumber)
			if err != nil {
				return err
			}
		}

		// update in-memory params
		sds.writeLoopParams.WatchedAddresses = append(sds.writeLoopParams.WatchedAddresses, filteredAddresses...)
		sds.writeLoopParams.ComputeWatchedAddressesLeafPaths()
	case types2.Remove:
		// get addresses from args
		argAddresses, err := MapWatchAddressArgsToAddresses(args)
		if err != nil {
			return fmt.Errorf("remove: mapped addresses %w", err)
		}

		// remove the provided addresses from currently watched addresses
		addresses, ok := funk.Subtract(sds.writeLoopParams.WatchedAddresses, argAddresses).([]common.Address)
		if !ok {
			return fmt.Errorf("remove: filtered addresses %w", errTypeAssertionFailed)
		}

		// update the db
		if sds.indexer != nil {
			err = sds.indexer.RemoveWatchedAddresses(args)
			if err != nil {
				return err
			}
		}

		// update in-memory params
		sds.writeLoopParams.WatchedAddresses = addresses
		sds.writeLoopParams.ComputeWatchedAddressesLeafPaths()
	case types2.Set:
		// get addresses from args
		argAddresses, err := MapWatchAddressArgsToAddresses(args)
		if err != nil {
			return fmt.Errorf("set: mapped addresses %w", err)
		}

		// update the db
		if sds.indexer != nil {
			err = sds.indexer.SetWatchedAddresses(args, currentBlockNumber)
			if err != nil {
				return err
			}
		}

		// update in-memory params
		sds.writeLoopParams.WatchedAddresses = argAddresses
		sds.writeLoopParams.ComputeWatchedAddressesLeafPaths()
	case types2.Clear:
		// update the db
		if sds.indexer != nil {
			err := sds.indexer.ClearWatchedAddresses()
			if err != nil {
				return err
			}
		}

		// update in-memory params
		sds.writeLoopParams.WatchedAddresses = []common.Address{}
		sds.writeLoopParams.ComputeWatchedAddressesLeafPaths()

	default:
		return fmt.Errorf("%w: %v", errUnexpectedOperation, operation)
	}

	return nil
}

// loadWatchedAddresses loads watched addresses from an indexer to params
func loadWatchedAddresses(indexer interfaces.StateDiffIndexer, params *ParamsWithMutex) error {
	watchedAddresses, err := indexer.LoadWatchedAddresses()
	if err != nil {
		return err
	}
	params.Lock()
	defer params.Unlock()

	params.WatchedAddresses = watchedAddresses
	params.ComputeWatchedAddressesLeafPaths()
	return nil
}

// MapWatchAddressArgsToAddresses maps []WatchAddressArg to corresponding []core.Address
func MapWatchAddressArgsToAddresses(args []types2.WatchAddressArg) ([]common.Address, error) {
	addresses, ok := funk.Map(args, func(arg types2.WatchAddressArg) common.Address {
		return common.HexToAddress(arg.Address)
	}).([]common.Address)
	if !ok {
		return nil, errTypeAssertionFailed
	}

	return addresses, nil
}

// Backfill is executed on startup to make sure there are no gaps in the recent past when tracking head.
func (sds *Service) Backfill() {
	pos := sds.currentPosition()
	if pos.chainBlockNumber == 0 {
		log.Info("Backfill: At start of chain, nothing to backfill.")
		return
	}

	log.Info(
		"Backfill: initial positions",
		"chain", pos.chainBlockNumber,
		"indexer", pos.indexerBlockNumber,
	)

	if sds.backfillCheckPastBlocks > 0 {
		var gapCheckBeginNumber uint64 = 0
		if pos.indexerBlockNumber > sds.backfillCheckPastBlocks {
			gapCheckBeginNumber = pos.indexerBlockNumber - sds.backfillCheckPastBlocks
		}
		blockGaps, err := sds.indexer.DetectGaps(gapCheckBeginNumber, pos.chainBlockNumber)
		if nil != err {
			log.Error("Backfill error", "error", err)
			return
		}

		if nil != blockGaps && len(blockGaps) > 0 {
			gapsMsg, _ := json.Marshal(blockGaps)
			log.Info("Backfill: detected gaps in range",
				"begin", gapCheckBeginNumber, "end", pos.chainBlockNumber, "gaps", string(gapsMsg))
			sds.backfillDetectedGaps(blockGaps)
			log.Info("Backfill: done processing detected gaps in range",
				"begin", gapCheckBeginNumber, "end", pos.chainBlockNumber, "gaps", string(gapsMsg))
		} else {
			log.Info("Backfill: no gaps detected in range",
				"begin", gapCheckBeginNumber, "end", pos.chainBlockNumber)
		}
	}
}

// backfillDetectedGaps fills gaps which have occurred in the recent past.  These gaps can happen because of
// transient errors, such as DB errors that are later corrected (so head statediffing continues, but with a hole)
// a missed ChainEvent (happens sometimes when debugging), or if the process is terminated when an earlier block
// is still in-flight, but a later block was already written.
func (sds *Service) backfillDetectedGaps(blockGaps []*interfaces.BlockGap) {
	var ch = make(chan uint64)
	var wg sync.WaitGroup
	for i := uint(0); i < sds.numWorkers; i++ {
		wg.Add(1)
		go func(w uint) {
			defer wg.Done()
			for {
				select {
				case num, ok := <-ch:
					if !ok {
						log.Info("Backfill: detected gap fill done", "worker", w)
						return
					}
					log.Info("Backfill: backfilling detected gap", "block", num, "worker", w)
					err := sds.writeStateDiffAt(num, sds.writeLoopParams.CopyParams())
					if err != nil {
						log.Error("Backfill error: ", err)
					}
				case <-sds.QuitChan:
					log.Info("Backfill: quitting before finish", "worker", w)
					return
				}
			}
		}(i)
	}

	for _, gap := range blockGaps {
		for num := gap.FirstMissing; num <= gap.LastMissing; num++ {
			ch <- num
		}
	}
	close(ch)
	wg.Wait()
}

// currentPosition returns the current block height for both the BlockChain and the statediff indexer.
func (sds *Service) currentPosition() servicePosition {
	ret := servicePosition{}
	chainBlock := sds.BlockChain.CurrentBlock()
	if nil != chainBlock {
		ret.chainBlockNumber = chainBlock.Number.Uint64()
	}

	indexerBlock, _ := sds.indexer.CurrentBlock()
	if nil != indexerBlock {
		indexerBlockNumber, err := strconv.ParseUint(indexerBlock.BlockNumber, 10, 64)
		if nil == err {
			ret.indexerBlockNumber = indexerBlockNumber
		} else {
			log.Error("Error parsing indexer block number", "block", indexerBlock.BlockNumber)
		}
	}

	return ret
}
