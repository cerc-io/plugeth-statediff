// Copyright 2022 The go-ethereum Authors
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

package mocks

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/cerc-io/plugeth-statediff/indexer/interfaces"
	"github.com/cerc-io/plugeth-statediff/indexer/models"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
)

var _ interfaces.StateDiffIndexer = &StateDiffIndexer{}
var _ interfaces.Batch = &batch{}

// StateDiffIndexer is a mock state diff indexer
type StateDiffIndexer struct{}

func (sdi *StateDiffIndexer) DetectGaps(beginBlock uint64, endBlock uint64) ([]*interfaces.BlockGap, error) {
	return nil, nil
}

func (sdi *StateDiffIndexer) CurrentBlock() (*models.HeaderModel, error) {
	return nil, nil
}

type batch struct{}

func (sdi *StateDiffIndexer) HasBlock(hash common.Hash, number uint64) (bool, error) {
	return false, nil
}

func (sdi *StateDiffIndexer) PushBlock(block *types.Block, receipts types.Receipts, totalDifficulty *big.Int) (interfaces.Batch, error) {
	return &batch{}, nil
}

func (sdi *StateDiffIndexer) PushStateNode(txi interfaces.Batch, stateNode sdtypes.StateLeafNode, headerID string) error {
	return nil
}

func (sdi *StateDiffIndexer) PushIPLD(txi interfaces.Batch, ipld sdtypes.IPLD) error {
	return nil
}

func (sdi *StateDiffIndexer) ReportDBMetrics(delay time.Duration, quit <-chan bool) {}

func (sdi *StateDiffIndexer) LoadWatchedAddresses() ([]common.Address, error) { return nil, nil }

func (sdi *StateDiffIndexer) InsertWatchedAddresses(addresses []sdtypes.WatchAddressArg, currentBlock *big.Int) error {
	return nil
}

func (sdi *StateDiffIndexer) RemoveWatchedAddresses(addresses []sdtypes.WatchAddressArg) error {
	return nil
}

func (sdi *StateDiffIndexer) SetWatchedAddresses(args []sdtypes.WatchAddressArg, currentBlockNumber *big.Int) error {
	return nil
}

func (sdi *StateDiffIndexer) ClearWatchedAddresses() error {
	return nil
}

func (sdi *StateDiffIndexer) Close() error {
	return nil
}

func (tx *batch) Submit(err error) error {
	return nil
}
