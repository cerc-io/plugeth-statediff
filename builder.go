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
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/cerc-io/plugeth-statediff/adapt"
	"github.com/cerc-io/plugeth-statediff/indexer/database/metrics"
	"github.com/cerc-io/plugeth-statediff/indexer/ipld"
	"github.com/cerc-io/plugeth-statediff/indexer/shared"
	"github.com/cerc-io/plugeth-statediff/trie_helpers"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
	"github.com/cerc-io/plugeth-statediff/utils"
	"github.com/cerc-io/plugeth-statediff/utils/log"
)

var (
	emptyNode, _      = rlp.EncodeToBytes(&[]byte{})
	emptyContractRoot = crypto.Keccak256Hash(emptyNode)
	nullCodeHash      = crypto.Keccak256Hash([]byte{}).Bytes()
	zeroHash          common.Hash
)

// Builder interface exposes the method for building a state diff between two blocks
type Builder interface {
	BuildStateDiffObject(args Args, params Params) (sdtypes.StateObject, error)
	WriteStateDiffObject(args Args, params Params, output sdtypes.StateNodeSink, ipldOutput sdtypes.IPLDSink) error
}

type StateDiffBuilder struct {
	StateCache adapt.StateView
}

type IterPair struct {
	Older, Newer trie.NodeIterator
}

func StateNodeAppender(nodes *[]sdtypes.StateLeafNode) sdtypes.StateNodeSink {
	return func(node sdtypes.StateLeafNode) error {
		*nodes = append(*nodes, node)
		return nil
	}
}
func StorageNodeAppender(nodes *[]sdtypes.StorageLeafNode) sdtypes.StorageNodeSink {
	return func(node sdtypes.StorageLeafNode) error {
		*nodes = append(*nodes, node)
		return nil
	}
}
func IPLDMappingAppender(iplds *[]sdtypes.IPLD) sdtypes.IPLDSink {
	return func(c sdtypes.IPLD) error {
		*iplds = append(*iplds, c)
		return nil
	}
}

// NewBuilder is used to create a statediff builder
func NewBuilder(stateCache adapt.StateView) Builder {
	return &StateDiffBuilder{
		StateCache: stateCache, // state cache is safe for concurrent reads
	}
}

// BuildStateDiffObject builds a statediff object from two blocks and the provided parameters
func (sdb *StateDiffBuilder) BuildStateDiffObject(args Args, params Params) (sdtypes.StateObject, error) {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.BuildStateDiffObjectTimer)
	var stateNodes []sdtypes.StateLeafNode
	var iplds []sdtypes.IPLD
	err := sdb.WriteStateDiffObject(args, params, StateNodeAppender(&stateNodes), IPLDMappingAppender(&iplds))
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

// WriteStateDiffObject writes a statediff object to output sinks
func (sdb *StateDiffBuilder) WriteStateDiffObject(args Args, params Params, output sdtypes.StateNodeSink,
	ipldOutput sdtypes.IPLDSink) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.WriteStateDiffObjectTimer)
	// Load tries for old and new states
	oldTrie, err := sdb.StateCache.OpenTrie(args.OldStateRoot)
	if err != nil {
		return fmt.Errorf("error creating trie for oldStateRoot: %w", err)
	}
	newTrie, err := sdb.StateCache.OpenTrie(args.NewStateRoot)
	if err != nil {
		return fmt.Errorf("error creating trie for newStateRoot: %w", err)
	}

	// we do two state trie iterations:
	// 		one for new/updated nodes,
	// 		one for deleted/updated nodes;
	// prepare 2 iterator instances for each task
	iterPairs := []IterPair{
		{
			Older: oldTrie.NodeIterator([]byte{}),
			Newer: newTrie.NodeIterator([]byte{}),
		},
		{
			Older: oldTrie.NodeIterator([]byte{}),
			Newer: newTrie.NodeIterator([]byte{}),
		},
	}

	logger := log.New("hash", args.BlockHash.String(), "number", args.BlockNumber)
	return sdb.BuildStateDiff(iterPairs, params, output, ipldOutput, logger, nil)
}

func (sdb *StateDiffBuilder) BuildStateDiff(iterPairs []IterPair, params Params,
	output sdtypes.StateNodeSink, ipldOutput sdtypes.IPLDSink, logger log.Logger, prefixPath []byte) error {
	logger.Trace("statediff BEGIN BuildStateDiff")
	defer metrics.ReportAndUpdateDuration("statediff END BuildStateDiff", time.Now(), logger, metrics.IndexerMetrics.BuildStateDiffTimer)
	// collect a slice of all the nodes that were touched and exist at B (B-A)
	// a map of their leafkey to all the accounts that were touched and exist at B
	// and a slice of all the paths for the nodes in both of the above sets
	diffAccountsAtB, err := sdb.createdAndUpdatedState(
		iterPairs[0].Older, iterPairs[0].Newer, params.watchedAddressesLeafPaths, ipldOutput, logger, prefixPath)
	if err != nil {
		return fmt.Errorf("error collecting createdAndUpdatedNodes: %w", err)
	}

	// collect a slice of all the nodes that existed at a path in A that doesn't exist in B
	// a map of their leafkey to all the accounts that were touched and exist at A
	diffAccountsAtA, err := sdb.deletedOrUpdatedState(
		iterPairs[1].Older, iterPairs[1].Newer, diffAccountsAtB,
		params.watchedAddressesLeafPaths, output, logger, prefixPath)
	if err != nil {
		return fmt.Errorf("error collecting deletedOrUpdatedNodes: %w", err)
	}

	// collect and sort the leafkey keys for both account mappings into a slice
	t := time.Now()
	createKeys := trie_helpers.SortKeys(diffAccountsAtB)
	deleteKeys := trie_helpers.SortKeys(diffAccountsAtA)
	logger.Debug("statediff BuildStateDiff sort", "duration", time.Since(t))

	// and then find the intersection of these keys
	// these are the leafkeys for the accounts which exist at both A and B but are different
	// this also mutates the passed in createKeys and deleteKeys, removing the intersection keys
	// and leaving the truly created or deleted keys in place
	t = time.Now()
	updatedKeys := trie_helpers.FindIntersection(createKeys, deleteKeys)
	logger.Debug("statediff BuildStateDiff intersection",
		"count", len(updatedKeys),
		"duration", time.Since(t))

	// build the diff nodes for the updated accounts using the mappings at both A and B as directed by the keys found as the intersection of the two
	err = sdb.buildAccountUpdates(diffAccountsAtB, diffAccountsAtA, updatedKeys, output, ipldOutput, logger)
	if err != nil {
		return fmt.Errorf("error building diff for updated accounts: %w", err)
	}
	// build the diff nodes for created accounts
	err = sdb.buildAccountCreations(diffAccountsAtB, output, ipldOutput, logger)
	if err != nil {
		return fmt.Errorf("error building diff for created accounts: %w", err)
	}
	return nil
}

// createdAndUpdatedState returns
// a slice of all the intermediate nodes that exist in a different state at B than A
// a mapping of their leafkeys to all the accounts that exist in a different state at B than A
// and a slice of the paths for all of the nodes included in both
func (sdb *StateDiffBuilder) createdAndUpdatedState(a, b trie.NodeIterator,
	watchedAddressesLeafPaths [][]byte, output sdtypes.IPLDSink, logger log.Logger, prefixPath []byte) (sdtypes.AccountMap, error) {
	logger.Trace("statediff BEGIN createdAndUpdatedState")
	defer metrics.ReportAndUpdateDuration("statediff END createdAndUpdatedState", time.Now(), logger, metrics.IndexerMetrics.CreatedAndUpdatedStateTimer)
	diffAccountsAtB := make(sdtypes.AccountMap)

	// cache the RLP of the previous node, so when we hit a leaf we have the parent (containing) node
	var prevBlob []byte
	it, itCount := trie.NewDifferenceIterator(a, b)
	for it.Next(true) {
		// ignore node if it is not along paths of interest
		if !isWatchedPathPrefix(watchedAddressesLeafPaths, it.Path()) {
			continue
		}
		// index values by leaf key
		if it.Leaf() {
			// if it is a "value" node, we will index the value by leaf key
			accountW, err := sdb.processStateValueNode(it, prevBlob)
			if err != nil {
				return nil, err
			}
			if accountW == nil {
				continue
			}
			// for now, just add it to diffAccountsAtB
			// we will compare to diffAccountsAtA to determine which diffAccountsAtB
			// were creations and which were updates and also identify accounts that were removed going A->B
			diffAccountsAtB[hex.EncodeToString(accountW.LeafKey)] = *accountW
		} else {
			// trie nodes will be written to blockstore only
			// reminder that this includes leaf nodes, since the geth iterator.Leaf() actually
			// signifies a "value" node
			if it.Hash() == zeroHash {
				continue
			}
			nodeVal := make([]byte, len(it.NodeBlob()))
			copy(nodeVal, it.NodeBlob())
			// if doing a selective diff, we need to ensure this is a watched path
			if len(watchedAddressesLeafPaths) > 0 {
				var elements []interface{}
				if err := rlp.DecodeBytes(nodeVal, &elements); err != nil {
					return nil, err
				}
				ok, err := isLeaf(elements)
				if err != nil {
					return nil, err
				}
				partialPath := utils.CompactToHex(elements[0].([]byte))
				valueNodePath := append(it.Path(), partialPath...)
				if ok && !isWatchedPath(watchedAddressesLeafPaths, valueNodePath) {
					continue
				}
			}
			if err := output(sdtypes.IPLD{
				CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, it.Hash().Bytes()).String(),
				Content: nodeVal,
			}); err != nil {
				return nil, err
			}
			prevBlob = nodeVal
		}
	}
	logger.Debug("statediff COUNTS createdAndUpdatedState", "it", itCount, "diffAccountsAtB", len(diffAccountsAtB))
	metrics.IndexerMetrics.DifferenceIteratorCounter.Inc(int64(*itCount))
	return diffAccountsAtB, it.Error()
}

// decodes account at leaf and encodes RLP data to CID
// reminder: it.Leaf() == true when the iterator is positioned at a "value node" (which is not something
// that actually exists in an MMPT), therefore we pass the parent node blob as the leaf RLP.
func (sdb *StateDiffBuilder) processStateValueNode(it trie.NodeIterator, parentBlob []byte) (*sdtypes.AccountWrapper, error) {
	var account types.StateAccount
	if err := rlp.DecodeBytes(it.LeafBlob(), &account); err != nil {
		return nil, fmt.Errorf("error decoding account at leaf key %x: %w", it.LeafKey(), err)
	}

	return &sdtypes.AccountWrapper{
		LeafKey: it.LeafKey(),
		Account: &account,
		CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(parentBlob)).String(),
	}, nil
}

// deletedOrUpdatedState returns a slice of all the paths that are emptied at B
// and a mapping of their leafkeys to all the accounts that exist in a different state at A than B
func (sdb *StateDiffBuilder) deletedOrUpdatedState(a, b trie.NodeIterator, diffAccountsAtB sdtypes.AccountMap,
	watchedAddressesLeafPaths [][]byte, output sdtypes.StateNodeSink, logger log.Logger, prefixPath []byte) (sdtypes.AccountMap, error) {
	logger.Trace("statediff BEGIN deletedOrUpdatedState")
	defer metrics.ReportAndUpdateDuration("statediff END deletedOrUpdatedState", time.Now(), logger, metrics.IndexerMetrics.DeletedOrUpdatedStateTimer)
	diffAccountAtA := make(sdtypes.AccountMap)

	var prevBlob []byte
	it, _ := trie.NewDifferenceIterator(b, a)
	for it.Next(true) {
		if !isWatchedPathPrefix(watchedAddressesLeafPaths, it.Path()) {
			continue
		}

		if it.Leaf() {
			accountW, err := sdb.processStateValueNode(it, prevBlob)
			if err != nil {
				return nil, err
			}
			if accountW == nil {
				continue
			}
			leafKey := hex.EncodeToString(accountW.LeafKey)
			diffAccountAtA[leafKey] = *accountW
			// if this node's leaf key did not show up in diffAccountsAtB
			// that means the account was deleted
			// in that case, emit an empty "removed" diff state node
			// include empty "removed" diff storage nodes for all the storage slots
			if _, ok := diffAccountsAtB[leafKey]; !ok {
				diff := sdtypes.StateLeafNode{
					AccountWrapper: sdtypes.AccountWrapper{
						Account: nil,
						LeafKey: accountW.LeafKey,
						CID:     shared.RemovedNodeStateCID,
					},
					Removed: true,
				}

				storageDiff := make([]sdtypes.StorageLeafNode, 0)
				err := sdb.buildRemovedAccountStorageNodes(accountW.Account.Root, StorageNodeAppender(&storageDiff))
				if err != nil {
					return nil, fmt.Errorf("failed building storage diffs for removed state account with key %x\r\nerror: %w", leafKey, err)
				}
				diff.StorageDiff = storageDiff
				if err := output(diff); err != nil {
					return nil, err
				}
			}
		} else {
			prevBlob = make([]byte, len(it.NodeBlob()))
			copy(prevBlob, it.NodeBlob())
		}
	}
	return diffAccountAtA, it.Error()
}

// buildAccountUpdates uses the account diffs maps for A => B and B => A and the known intersection of their leafkeys
// to generate the statediff node objects for all of the accounts that existed at both A and B but in different states
// needs to be called before building account creations and deletions as this mutates
// those account maps to remove the accounts which were updated
func (sdb *StateDiffBuilder) buildAccountUpdates(creations, deletions sdtypes.AccountMap, updatedKeys []string,
	output sdtypes.StateNodeSink, ipldOutput sdtypes.IPLDSink, logger log.Logger) error {
	logger.Trace("statediff BEGIN buildAccountUpdates",
		"creations", len(creations), "deletions", len(deletions), "updated", len(updatedKeys))
	defer metrics.ReportAndUpdateDuration("statediff END buildAccountUpdates ",
		time.Now(), logger, metrics.IndexerMetrics.BuildAccountUpdatesTimer)
	var err error
	for _, key := range updatedKeys {
		createdAcc := creations[key]
		deletedAcc := deletions[key]
		storageDiff := make([]sdtypes.StorageLeafNode, 0)
		if deletedAcc.Account != nil && createdAcc.Account != nil {
			err = sdb.buildStorageNodesIncremental(
				deletedAcc.Account.Root, createdAcc.Account.Root,
				StorageNodeAppender(&storageDiff), ipldOutput,
			)
			if err != nil {
				return fmt.Errorf("failed building incremental storage diffs for account with leafkey %x\r\nerror: %w", key, err)
			}
		}
		if err = output(sdtypes.StateLeafNode{
			AccountWrapper: createdAcc,
			Removed:        false,
			StorageDiff:    storageDiff,
		}); err != nil {
			return err
		}
		delete(creations, key)
		delete(deletions, key)
	}

	return nil
}

// buildAccountCreations returns the statediff node objects for all the accounts that exist at B but not at A
// it also returns the code and codehash for created contract accounts
func (sdb *StateDiffBuilder) buildAccountCreations(accounts sdtypes.AccountMap, output sdtypes.StateNodeSink,
	ipldOutput sdtypes.IPLDSink, logger log.Logger) error {
	logger.Trace("statediff BEGIN buildAccountCreations")
	defer metrics.ReportAndUpdateDuration("statediff END buildAccountCreations",
		time.Now(), logger, metrics.IndexerMetrics.BuildAccountCreationsTimer)
	for _, val := range accounts {
		diff := sdtypes.StateLeafNode{
			AccountWrapper: val,
			Removed:        false,
		}
		if !bytes.Equal(val.Account.CodeHash, nullCodeHash) {
			// For contract creations, any storage node contained is a diff
			storageDiff := make([]sdtypes.StorageLeafNode, 0)
			err := sdb.buildStorageNodesEventual(val.Account.Root, StorageNodeAppender(&storageDiff), ipldOutput)
			if err != nil {
				return fmt.Errorf("failed building eventual storage diffs for node with leaf key %x\r\nerror: %w", val.LeafKey, err)
			}
			diff.StorageDiff = storageDiff
			// emit codehash => code mappings for contract
			codeHash := common.BytesToHash(val.Account.CodeHash)
			code, err := sdb.StateCache.ContractCode(codeHash)
			if err != nil {
				return fmt.Errorf("failed to retrieve code for codehash %x\r\n error: %w", codeHash, err)
			}
			if err := ipldOutput(sdtypes.IPLD{
				CID:     ipld.Keccak256ToCid(ipld.RawBinary, codeHash.Bytes()).String(),
				Content: code,
			}); err != nil {
				return err
			}
		}
		if err := output(diff); err != nil {
			return err
		}
	}

	return nil
}

// buildStorageNodesEventual builds the storage diff node objects for a created account
// i.e. it returns all the storage nodes at this state, since there is no previous state
func (sdb *StateDiffBuilder) buildStorageNodesEventual(sr common.Hash, output sdtypes.StorageNodeSink,
	ipldOutput sdtypes.IPLDSink) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.BuildStorageNodesEventualTimer)
	if sr == emptyContractRoot {
		return nil
	}
	log.Debug("Storage root for eventual diff", "root", sr.String())
	sTrie, err := sdb.StateCache.OpenTrie(sr)
	if err != nil {
		log.Info("error in build storage diff eventual", "error", err)
		return err
	}
	it := sTrie.NodeIterator(make([]byte, 0))
	return sdb.buildStorageNodesFromTrie(it, output, ipldOutput)
}

// buildStorageNodesFromTrie returns all the storage diff node objects in the provided node iterator
func (sdb *StateDiffBuilder) buildStorageNodesFromTrie(it trie.NodeIterator, output sdtypes.StorageNodeSink,
	ipldOutput sdtypes.IPLDSink) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.BuildStorageNodesFromTrieTimer)

	var prevBlob []byte
	for it.Next(true) {
		if it.Leaf() {
			storageLeafNode := sdb.processStorageValueNode(it, prevBlob)
			if err := output(storageLeafNode); err != nil {
				return err
			}
		} else {
			nodeVal := make([]byte, len(it.NodeBlob()))
			copy(nodeVal, it.NodeBlob())
			if err := ipldOutput(sdtypes.IPLD{
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

// decodes account at leaf and encodes RLP data to CID
// reminder: it.Leaf() == true when the iterator is positioned at a "value node" (which is not something
// that actually exists in an MMPT), therefore we pass the parent node blob as the leaf RLP.
func (sdb *StateDiffBuilder) processStorageValueNode(it trie.NodeIterator, parentBlob []byte) sdtypes.StorageLeafNode {
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

// buildRemovedAccountStorageNodes builds the "removed" diffs for all the storage nodes for a destroyed account
func (sdb *StateDiffBuilder) buildRemovedAccountStorageNodes(sr common.Hash, output sdtypes.StorageNodeSink) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.BuildRemovedAccountStorageNodesTimer)
	if sr == emptyContractRoot {
		return nil
	}
	log.Debug("Storage root for removed diffs", "root", sr.String())
	sTrie, err := sdb.StateCache.OpenTrie(sr)
	if err != nil {
		log.Info("error in build removed account storage diffs", "error", err)
		return err
	}
	it := sTrie.NodeIterator(make([]byte, 0))
	return sdb.buildRemovedStorageNodesFromTrie(it, output)
}

// buildRemovedStorageNodesFromTrie returns diffs for all the storage nodes in the provided node interator
func (sdb *StateDiffBuilder) buildRemovedStorageNodesFromTrie(it trie.NodeIterator, output sdtypes.StorageNodeSink) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.BuildRemovedStorageNodesFromTrieTimer)
	for it.Next(true) {
		if it.Leaf() { // only leaf values are indexed, don't need to demarcate removed intermediate nodes
			leafKey := make([]byte, len(it.LeafKey()))
			copy(leafKey, it.LeafKey())
			if err := output(sdtypes.StorageLeafNode{
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

// buildStorageNodesIncremental builds the storage diff node objects for all nodes that exist in a different state at B than A
func (sdb *StateDiffBuilder) buildStorageNodesIncremental(oldroot common.Hash, newroot common.Hash, output sdtypes.StorageNodeSink,
	ipldOutput sdtypes.IPLDSink) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.BuildStorageNodesIncrementalTimer)
	if newroot == oldroot {
		return nil
	}
	log.Trace("Storage roots for incremental diff", "old", oldroot.String(), "new", newroot.String())
	oldTrie, err := sdb.StateCache.OpenTrie(oldroot)
	if err != nil {
		return err
	}
	newTrie, err := sdb.StateCache.OpenTrie(newroot)
	if err != nil {
		return err
	}

	diffSlotsAtB, err := sdb.createdAndUpdatedStorage(
		oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}), output, ipldOutput)
	if err != nil {
		return err
	}
	return sdb.deletedOrUpdatedStorage(oldTrie.NodeIterator([]byte{}), newTrie.NodeIterator([]byte{}),
		diffSlotsAtB, output)
}

func (sdb *StateDiffBuilder) createdAndUpdatedStorage(a, b trie.NodeIterator, output sdtypes.StorageNodeSink,
	ipldOutput sdtypes.IPLDSink) (map[string]bool, error) {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.CreatedAndUpdatedStorageTimer)
	diffSlotsAtB := make(map[string]bool)

	var prevBlob []byte
	it, _ := trie.NewDifferenceIterator(a, b)
	for it.Next(true) {
		if it.Leaf() {
			storageLeafNode := sdb.processStorageValueNode(it, prevBlob)
			if err := output(storageLeafNode); err != nil {
				return nil, err
			}
			diffSlotsAtB[hex.EncodeToString(storageLeafNode.LeafKey)] = true
		} else {
			if it.Hash() == zeroHash {
				continue
			}
			nodeVal := make([]byte, len(it.NodeBlob()))
			copy(nodeVal, it.NodeBlob())
			nodeHash := make([]byte, len(it.Hash().Bytes()))
			copy(nodeHash, it.Hash().Bytes())
			if err := ipldOutput(sdtypes.IPLD{
				CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, nodeHash).String(),
				Content: nodeVal,
			}); err != nil {
				return nil, err
			}
			prevBlob = nodeVal
		}
	}
	return diffSlotsAtB, it.Error()
}

func (sdb *StateDiffBuilder) deletedOrUpdatedStorage(a, b trie.NodeIterator, diffSlotsAtB map[string]bool, output sdtypes.StorageNodeSink) error {
	defer metrics.UpdateDuration(time.Now(), metrics.IndexerMetrics.DeletedOrUpdatedStorageTimer)
	it, _ := trie.NewDifferenceIterator(b, a)
	for it.Next(true) {
		if it.Leaf() {
			leafKey := make([]byte, len(it.LeafKey()))
			copy(leafKey, it.LeafKey())
			// if this node's leaf key did not show up in diffSlotsAtB
			// that means the storage slot was vacated
			// in that case, emit an empty "removed" diff storage node
			if _, ok := diffSlotsAtB[hex.EncodeToString(leafKey)]; !ok {
				if err := output(sdtypes.StorageLeafNode{
					CID:     shared.RemovedNodeStorageCID,
					Removed: true,
					LeafKey: leafKey,
					Value:   []byte{},
				}); err != nil {
					return err
				}
			}
		}
	}
	return it.Error()
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
