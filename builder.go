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

// Contains a batch of utility type declarations used by the tests. As the node
// operates on unique types, a lot of them are needed to check various features.

package statediff

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	iterutils "github.com/cerc-io/eth-iterator-utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"golang.org/x/sync/errgroup"

	"github.com/cerc-io/plugeth-statediff/adapt"
	"github.com/cerc-io/plugeth-statediff/indexer/database/metrics"
	"github.com/cerc-io/plugeth-statediff/indexer/ipld"
	"github.com/cerc-io/plugeth-statediff/indexer/shared"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
	"github.com/cerc-io/plugeth-statediff/utils"
	"github.com/cerc-io/plugeth-statediff/utils/log"
)

var (
	emptyNode, _      = rlp.EncodeToBytes(&[]byte{})
	emptyContractRoot = crypto.Keccak256Hash(emptyNode)
	nullCodeHash      = crypto.Keccak256([]byte{})
	zeroHash          common.Hash

	defaultSubtrieWorkers uint = 1
)

// Builder interface exposes the method for building a state diff between two blocks
type Builder interface {
	BuildStateDiffObject(Args, Params) (sdtypes.StateObject, error)
	WriteStateDiff(Args, Params, sdtypes.StateNodeSink, sdtypes.IPLDSink) error
}

type StateDiffBuilder struct {
	// state cache is safe for concurrent reads
	stateCache     adapt.StateView
	subtrieWorkers uint
}

type accountUpdate struct {
	new     sdtypes.AccountWrapper
	oldRoot common.Hash
}
type accountUpdateMap map[string]*accountUpdate

func appender[T any](to *[]T) func(T) error {
	return func(a T) error {
		*to = append(*to, a)
		return nil
	}
}

func syncedAppender[T any](to *[]T) func(T) error {
	var mtx sync.Mutex
	return func(a T) error {
		mtx.Lock()
		*to = append(*to, a)
		mtx.Unlock()
		return nil
	}
}

// NewBuilder is used to create a statediff builder
func NewBuilder(stateCache adapt.StateView) *StateDiffBuilder {
	return &StateDiffBuilder{
		stateCache:     stateCache,
		subtrieWorkers: defaultSubtrieWorkers,
	}
}

// SetSubtrieWorkers sets the number of disjoint subtries to divide among parallel workers.
// Passing 0 will reset this to the default value.
func (sdb *StateDiffBuilder) SetSubtrieWorkers(n uint) {
	if n == 0 {
		n = defaultSubtrieWorkers
	}
	sdb.subtrieWorkers = n
}

// BuildStateDiffObject builds a statediff object from two blocks and the provided parameters
func (sdb *StateDiffBuilder) BuildStateDiffObject(args Args, params Params) (sdtypes.StateObject, error) {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.BuildStateDiffObjectTimer)
	var stateNodes []sdtypes.StateLeafNode
	var iplds []sdtypes.IPLD
	err := sdb.WriteStateDiff(args, params, syncedAppender(&stateNodes), syncedAppender(&iplds))
	if err != nil {
		return sdtypes.StateObject{}, err
	}
	return sdtypes.StateObject{
		BlockHash:   args.BlockHash,
		BlockNumber: args.BlockNumber,
		Nodes:       stateNodes,
		IPLDs:       iplds,
	}, nil
}

// WriteStateDiff writes a statediff object to output sinks
func (sdb *StateDiffBuilder) WriteStateDiff(
	args Args, params Params,
	nodeSink sdtypes.StateNodeSink,
	ipldSink sdtypes.IPLDSink,
) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.WriteStateDiffTimer)
	// Load tries for old and new states
	triea, err := sdb.stateCache.OpenTrie(args.OldStateRoot)
	if err != nil {
		return fmt.Errorf("error opening old state trie: %w", err)
	}
	trieb, err := sdb.stateCache.OpenTrie(args.NewStateRoot)
	if err != nil {
		return fmt.Errorf("error opening new state trie: %w", err)
	}
	subitersA := iterutils.SubtrieIterators(triea.NodeIterator, uint(sdb.subtrieWorkers))
	subitersB := iterutils.SubtrieIterators(trieb.NodeIterator, uint(sdb.subtrieWorkers))

	logger := log.New("hash", args.BlockHash, "number", args.BlockNumber)
	// errgroup will cancel if any gr fails
	g, ctx := errgroup.WithContext(context.Background())
	for i := uint(0); i < sdb.subtrieWorkers; i++ {
		func(subdiv uint) {
			g.Go(func() error {
				a, b := subitersA[subdiv], subitersB[subdiv]
				return sdb.processAccounts(ctx,
					a, b, params.watchedAddressesLeafPaths,
					nodeSink, ipldSink, logger,
				)
			})
		}(i)
	}
	return g.Wait()
}

// processAccounts processes account creations and deletions, and returns a set of updated
// existing accounts, indexed by leaf key.
func (sdb *StateDiffBuilder) processAccounts(
	ctx context.Context,
	a, b trie.NodeIterator, watchedAddressesLeafPaths [][]byte,
	nodeSink sdtypes.StateNodeSink, ipldSink sdtypes.IPLDSink,
	logger log.Logger,
) error {
	logger.Trace("statediff/processAccounts BEGIN")
	defer metrics.ReportAndUpdateDuration("statediff/processAccounts END",
		time.Now(), logger, metrics.IndexerMetrics.ProcessAccountsTimer)

	updates := make(accountUpdateMap)
	// Cache the RLP of the previous node. When we hit a value node this will be the parent blob.
	var prevBlob []byte
	it, itCount := utils.NewSymmetricDifferenceIterator(a, b)
	prevBlob = it.NodeBlob()
	for it.Next(true) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// ignore node if it is not along paths of interest
		if !isWatchedPathPrefix(watchedAddressesLeafPaths, it.Path()) {
			continue
		}
		if it.FromA() { // Node exists in the old trie
			if it.Leaf() {
				var account types.StateAccount
				if err := rlp.DecodeBytes(it.LeafBlob(), &account); err != nil {
					return err
				}
				leafKey := make([]byte, len(it.LeafKey()))
				copy(leafKey, it.LeafKey())

				if it.CommonPath() {
					// If B also contains this leaf node, this is the old state of an updated account.
					if update, ok := updates[string(leafKey)]; ok {
						update.oldRoot = account.Root
					} else {
						updates[string(leafKey)] = &accountUpdate{oldRoot: account.Root}
					}
				} else {
					// This node was removed, meaning the account was deleted.  Emit empty
					// "removed" records for the state node and all storage all storage slots.
					err := sdb.processAccountDeletion(leafKey, account, nodeSink)
					if err != nil {
						return err
					}
				}
			}
			continue
		}
		// Node exists in the new trie
		if it.Leaf() {
			accountW, err := sdb.decodeStateLeaf(it, prevBlob)
			if err != nil {
				return err
			}

			if it.CommonPath() {
				// If A also contains this leaf node, this is the new state of an updated account.
				if update, ok := updates[string(accountW.LeafKey)]; ok {
					update.new = *accountW
				} else {
					updates[string(accountW.LeafKey)] = &accountUpdate{new: *accountW}
				}
			} else { // account was created
				err := sdb.processAccountCreation(accountW, ipldSink, nodeSink)
				if err != nil {
					return err
				}
			}
		} else {
			// New trie nodes will be written to blockstore only.
			// Reminder: this includes leaf nodes, since the geth iterator.Leaf() actually
			// signifies a "value" node.
			if it.Hash() == zeroHash {
				continue
			}
			// TODO - this can be handled when value node is (craeted?)
			nodeVal := make([]byte, len(it.NodeBlob()))
			copy(nodeVal, it.NodeBlob())
			// if doing a selective diff, we need to ensure this is a watched path
			if len(watchedAddressesLeafPaths) > 0 {
				var elements []interface{}
				if err := rlp.DecodeBytes(nodeVal, &elements); err != nil {
					return err
				}
				ok, err := isLeaf(elements)
				if err != nil {
					return err
				}
				if ok {
					partialPath := utils.CompactToHex(elements[0].([]byte))
					valueNodePath := append(it.Path(), partialPath...)
					if !isWatchedPath(watchedAddressesLeafPaths, valueNodePath) {
						continue
					}
				}
			}
			if err := ipldSink(sdtypes.IPLD{
				CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, it.Hash().Bytes()).String(),
				Content: nodeVal,
			}); err != nil {
				return err
			}
			prevBlob = nodeVal
		}
	}

	for key, update := range updates {
		var storageDiff []sdtypes.StorageLeafNode
		err := sdb.processStorageUpdates(
			update.oldRoot, update.new.Account.Root,
			appender(&storageDiff), ipldSink,
		)
		if err != nil {
			return fmt.Errorf("error processing incremental storage diffs for account with leafkey %x\r\nerror: %w", key, err)
		}

		if err = nodeSink(sdtypes.StateLeafNode{
			AccountWrapper: update.new,
			StorageDiff:    storageDiff,
		}); err != nil {
			return err
		}
	}

	metrics.IndexerMetrics.DifferenceIteratorCounter.Inc(int64(*itCount))
	return it.Error()
}

func (sdb *StateDiffBuilder) processAccountDeletion(
	leafKey []byte, account types.StateAccount, nodeSink sdtypes.StateNodeSink,
) error {
	diff := sdtypes.StateLeafNode{
		AccountWrapper: sdtypes.AccountWrapper{
			LeafKey: leafKey,
			CID:     shared.RemovedNodeStateCID,
		},
		Removed: true,
	}
	err := sdb.processRemovedAccountStorage(account.Root, appender(&diff.StorageDiff))
	if err != nil {
		return fmt.Errorf("failed building storage diffs for removed state account with key %x\r\nerror: %w", leafKey, err)
	}
	return nodeSink(diff)
}

func (sdb *StateDiffBuilder) processAccountCreation(
	accountW *sdtypes.AccountWrapper, ipldSink sdtypes.IPLDSink, nodeSink sdtypes.StateNodeSink,
) error {
	diff := sdtypes.StateLeafNode{
		AccountWrapper: *accountW,
	}
	if !bytes.Equal(accountW.Account.CodeHash, nullCodeHash) {
		// For contract creations, any storage node contained is a diff
		err := sdb.processStorageCreations(accountW.Account.Root, appender(&diff.StorageDiff), ipldSink)
		if err != nil {
			return fmt.Errorf("failed building eventual storage diffs for node with leaf key %x\r\nerror: %w", accountW.LeafKey, err)
		}
		// emit codehash => code mappings for contract
		codeHash := common.BytesToHash(accountW.Account.CodeHash)
		code, err := sdb.stateCache.ContractCode(codeHash)
		if err != nil {
			return fmt.Errorf("failed to retrieve code for codehash %s\r\n error: %w", codeHash, err)
		}
		if err := ipldSink(sdtypes.IPLD{
			CID:     ipld.Keccak256ToCid(ipld.RawBinary, codeHash.Bytes()).String(),
			Content: code,
		}); err != nil {
			return err
		}
	}
	return nodeSink(diff)
}

// decodes account at leaf and encodes RLP data to CID
// reminder: it.Leaf() == true when the iterator is positioned at a "value node" (which is not something
// that actually exists in an MMPT), therefore we pass the parent node blob as the leaf RLP.
func (sdb *StateDiffBuilder) decodeStateLeaf(it trie.NodeIterator, parentBlob []byte) (*sdtypes.AccountWrapper, error) {
	var account types.StateAccount
	if err := rlp.DecodeBytes(it.LeafBlob(), &account); err != nil {
		return nil, fmt.Errorf("error decoding account at leaf key %x: %w", it.LeafKey(), err)
	}

	leafKey := make([]byte, len(it.LeafKey()))
	copy(leafKey, it.LeafKey())
	return &sdtypes.AccountWrapper{
		LeafKey: it.LeafKey(),
		Account: &account,
		CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(parentBlob)).String(),
	}, nil
}

// processStorageCreations processes the storage node records for a newly created account
// i.e. it returns all the storage nodes at this state, since there is no previous state.
func (sdb *StateDiffBuilder) processStorageCreations(
	sr common.Hash, storageSink sdtypes.StorageNodeSink, ipldSink sdtypes.IPLDSink,
) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.ProcessStorageCreationsTimer)
	if sr == emptyContractRoot {
		return nil
	}
	log.Debug("Storage root for eventual diff", "root", sr)
	sTrie, err := sdb.stateCache.OpenTrie(sr)
	if err != nil {
		log.Info("error in build storage diff eventual", "error", err)
		return err
	}

	var prevBlob []byte
	it := sTrie.NodeIterator(make([]byte, 0))
	for it.Next(true) {
		if it.Leaf() {
			storageLeafNode := sdb.decodeStorageLeaf(it, prevBlob)
			if err := storageSink(storageLeafNode); err != nil {
				return err
			}
		} else {
			nodeVal := make([]byte, len(it.NodeBlob()))
			copy(nodeVal, it.NodeBlob())
			if err := ipldSink(sdtypes.IPLD{
				CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, it.Hash().Bytes()).String(),
				Content: nodeVal,
			}); err != nil {
				return err
			}
			prevBlob = nodeVal
		}
	}
	return it.Error()
}

// processStorageUpdates builds the storage diff node objects for all nodes that exist in a different state at B than A
func (sdb *StateDiffBuilder) processStorageUpdates(
	oldroot common.Hash, newroot common.Hash,
	storageSink sdtypes.StorageNodeSink,
	ipldSink sdtypes.IPLDSink,
) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.ProcessStorageUpdatesTimer)
	if newroot == oldroot {
		return nil
	}
	log.Trace("Storage roots for incremental diff", "old", oldroot, "new", newroot)
	oldTrie, err := sdb.stateCache.OpenTrie(oldroot)
	if err != nil {
		return err
	}
	newTrie, err := sdb.stateCache.OpenTrie(newroot)
	if err != nil {
		return err
	}

	var prevBlob []byte
	a, b := oldTrie.NodeIterator(nil), newTrie.NodeIterator(nil)
	it, _ := utils.NewSymmetricDifferenceIterator(a, b)
	for it.Next(true) {
		if it.FromA() {
			if it.Leaf() && !it.CommonPath() {
				// If this node's leaf key is absent from B, the storage slot was vacated.
				// In that case, emit an empty "removed" storage node record.
				if err := storageSink(sdtypes.StorageLeafNode{
					CID:     shared.RemovedNodeStorageCID,
					Removed: true,
					LeafKey: []byte(it.LeafKey()),
					Value:   []byte{},
				}); err != nil {
					return err
				}
			}
			continue
		}
		if it.Leaf() {
			storageLeafNode := sdb.decodeStorageLeaf(it, prevBlob)
			if err := storageSink(storageLeafNode); err != nil {
				return err
			}
		} else {
			if it.Hash() == zeroHash {
				continue
			}
			nodeVal := make([]byte, len(it.NodeBlob()))
			copy(nodeVal, it.NodeBlob())
			if err := ipldSink(sdtypes.IPLD{
				CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, it.Hash().Bytes()).String(),
				Content: nodeVal,
			}); err != nil {
				return err
			}
			prevBlob = nodeVal
		}
	}
	return it.Error()
}

// processRemovedAccountStorage builds the "removed" diffs for all the storage nodes for a destroyed account
func (sdb *StateDiffBuilder) processRemovedAccountStorage(
	sr common.Hash, storageSink sdtypes.StorageNodeSink,
) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.ProcessRemovedAccountStorageTimer)
	if sr == emptyContractRoot {
		return nil
	}
	log.Debug("Storage root for removed diffs", "root", sr)
	sTrie, err := sdb.stateCache.OpenTrie(sr)
	if err != nil {
		log.Info("error in build removed account storage diffs", "error", err)
		return err
	}
	it := sTrie.NodeIterator(nil)
	for it.Next(true) {
		if it.Leaf() { // only leaf values are indexed, don't need to demarcate removed intermediate nodes
			leafKey := make([]byte, len(it.LeafKey()))
			copy(leafKey, it.LeafKey())
			if err := storageSink(sdtypes.StorageLeafNode{
				CID:     shared.RemovedNodeStorageCID,
				Removed: true,
				LeafKey: leafKey,
				Value:   []byte{},
			}); err != nil {
				return err
			}
		}
	}
	return it.Error()
}

// decodes slot at leaf and encodes RLP data to CID
// reminder: it.Leaf() == true when the iterator is positioned at a "value node" (which is not something
// that actually exists in an MMPT), therefore we pass the parent node blob as the leaf RLP.
func (sdb *StateDiffBuilder) decodeStorageLeaf(it trie.NodeIterator, parentBlob []byte) sdtypes.StorageLeafNode {
	leafKey := make([]byte, len(it.LeafKey()))
	copy(leafKey, it.LeafKey())
	value := make([]byte, len(it.LeafBlob()))
	copy(value, it.LeafBlob())

	return sdtypes.StorageLeafNode{
		LeafKey: leafKey,
		Value:   value,
		CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(parentBlob)).String(),
	}
}

// isWatchedPathPrefix checks if a node path is a prefix (ancestor) to one of the watched addresses.
// An empty watch list means all paths are watched.
func isWatchedPathPrefix(watchedLeafPaths [][]byte, path []byte) bool {
	if len(watchedLeafPaths) == 0 {
		return true
	}
	for _, watched := range watchedLeafPaths {
		if bytes.HasPrefix(watched, path) {
			return true
		}
	}
	return false
}

// isWatchedPath checks if a node path corresponds to one of the watched addresses
func isWatchedPath(watchedLeafPaths [][]byte, leafPath []byte) bool {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.IsWatchedAddressTimer)
	for _, watched := range watchedLeafPaths {
		if bytes.Equal(watched, leafPath) {
			return true
		}
	}
	return false
}

// isLeaf checks if the node we are at is a leaf
func isLeaf(elements []interface{}) (bool, error) {
	if len(elements) > 2 {
		return false, nil
	}
	if len(elements) < 2 {
		return false, fmt.Errorf("node cannot be less than two elements in length")
	}
	switch elements[0].([]byte)[0] / 16 {
	case '\x00':
		return false, nil
	case '\x01':
		return false, nil
	case '\x02':
		return true, nil
	case '\x03':
		return true, nil
	default:
		return false, fmt.Errorf("unknown hex prefix")
	}
}
