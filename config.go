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

package statediff

import (
	"context"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/cerc-io/plugeth-statediff/indexer/interfaces"
	"github.com/cerc-io/plugeth-statediff/utils"
)

// Config contains instantiation parameters for the state diffing service
type Config struct {
	// The configuration used for the stateDiff Indexer
	IndexerConfig interfaces.Config
	// A unique ID used for this service
	ID string
	// Name for the client this service is running
	ClientName string
	// Whether to enable writing state diffs directly to track blockchain head
	EnableWriteLoop bool
	// The maximum number of blocks to backfill when tracking head.
	BackfillMaxDepth uint64
	// The maximum number of blocks behind the startup position to check for gaps.
	BackfillCheckPastBlocks uint64
	// Size of the worker pool
	NumWorkers uint
	// Should the statediff service wait until geth has synced to the head of the blockchain?
	WaitForSync bool
	// Context used during DB initialization
	Context context.Context
}

// Params contains config parameters for the state diff builder
type Params struct {
	IncludeBlock              bool
	IncludeReceipts           bool
	IncludeTD                 bool
	IncludeCode               bool
	WatchedAddresses          []common.Address
	watchedAddressesLeafPaths [][]byte
}

func (p *Params) Copy() Params {
	ret := Params{
		IncludeBlock:    p.IncludeBlock,
		IncludeReceipts: p.IncludeReceipts,
		IncludeTD:       p.IncludeTD,
		IncludeCode:     p.IncludeCode,
	}
	ret.WatchedAddresses = make([]common.Address, len(p.WatchedAddresses))
	copy(ret.WatchedAddresses, p.WatchedAddresses)

	return ret
}

// ComputeWatchedAddressesLeafPaths populates a slice with paths (hex_encoding(Keccak256)) of each of the WatchedAddresses
func (p *Params) ComputeWatchedAddressesLeafPaths() {
	p.watchedAddressesLeafPaths = make([][]byte, len(p.WatchedAddresses))
	for i, address := range p.WatchedAddresses {
		p.watchedAddressesLeafPaths[i] = utils.KeybytesToHex(crypto.Keccak256(address[:]))
	}
}

// ParamsWithMutex allows to lock the parameters while they are being updated | read from
type ParamsWithMutex struct {
	Params
	sync.RWMutex
}

// CopyParams returns a defensive copy of the Params
func (p *ParamsWithMutex) CopyParams() Params {
	p.RLock()
	copy := p.Params.Copy()
	p.RUnlock()

	copy.ComputeWatchedAddressesLeafPaths()
	return copy
}

// Args bundles the arguments for the state diff builder
type Args struct {
	OldStateRoot, NewStateRoot common.Hash
	BlockHash                  common.Hash
	BlockNumber                *big.Int
}
