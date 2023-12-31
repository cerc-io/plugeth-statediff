// VulcanizeDB
// Copyright © 2021 Vulcanize

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package interfaces

import (
	"context"
	"math/big"
	"time"

	"github.com/cerc-io/plugeth-statediff/indexer/models"
	"github.com/cerc-io/plugeth-statediff/indexer/shared"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// StateDiffIndexer interface required to index statediff data
type StateDiffIndexer interface {
	DetectGaps(beginBlock uint64, endBlock uint64) ([]*BlockGap, error)
	CurrentBlock() (*models.HeaderModel, error)
	HasBlock(hash common.Hash, number uint64) (bool, error)
	PushBlock(block *types.Block, receipts types.Receipts, totalDifficulty *big.Int) (Batch, error)
	PushHeader(batch Batch, header *types.Header, reward, td *big.Int) (string, error)
	PushStateNode(tx Batch, stateNode sdtypes.StateLeafNode, headerID string) error
	PushIPLD(tx Batch, ipld sdtypes.IPLD) error
	ReportDBMetrics(delay time.Duration, quit <-chan bool)

	BeginTx(number *big.Int, ctx context.Context) Batch

	// Methods used by WatchAddress API/functionality
	LoadWatchedAddresses() ([]common.Address, error)
	InsertWatchedAddresses(addresses []sdtypes.WatchAddressArg, currentBlock *big.Int) error
	RemoveWatchedAddresses(addresses []sdtypes.WatchAddressArg) error
	SetWatchedAddresses(args []sdtypes.WatchAddressArg, currentBlockNumber *big.Int) error
	ClearWatchedAddresses() error

	Close() error
}

// Batch required for indexing data atomically
type Batch interface {
	// Submit commits the batch transaction
	Submit() error
	// BlockNumber is the block number of the header this batch contains
	BlockNumber() string
	// RollbackOnFailure rolls back the batch transaction if the error is not nil
	RollbackOnFailure(error)
}

// Config used to configure different underlying implementations
type Config interface {
	Type() shared.DBType
}

// Used to represent a gap in statediffed blocks
type BlockGap struct {
	FirstMissing uint64 `json:"firstMissing"`
	LastMissing  uint64 `json:"lastMissing"`
}
