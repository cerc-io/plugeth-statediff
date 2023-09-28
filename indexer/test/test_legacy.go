// VulcanizeDB
// Copyright © 2022 Vulcanize

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

package test

import (
	"context"
	"testing"

	"github.com/cerc-io/plugeth-statediff/indexer/database/sql"
	"github.com/cerc-io/plugeth-statediff/indexer/interfaces"
	"github.com/cerc-io/plugeth-statediff/indexer/ipld"
	"github.com/cerc-io/plugeth-statediff/indexer/mocks"
	"github.com/cerc-io/plugeth-statediff/indexer/node"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/stretchr/testify/require"
)

var (
	LegacyConfig    = params.MainnetChainConfig
	legacyData      = mocks.NewLegacyData(LegacyConfig)
	mockLegacyBlock *types.Block
	legacyHeaderCID cid.Cid
	// Mainnet node info
	LegacyNodeInfo = node.Info{
		GenesisBlock: "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
		NetworkID:    "1",
		ChainID:      1,
		ID:           "mockNodeID",
		ClientName:   "go-ethereum",
	}
)

func SetupLegacyTestData(t *testing.T, ind interfaces.StateDiffIndexer) {
	mockLegacyBlock = legacyData.MockBlock
	legacyHeaderCID, _ = ipld.RawdataToCid(ipld.MEthHeader, legacyData.MockHeaderRlp, multihash.KECCAK_256)

	var tx interfaces.Batch
	tx, err = ind.PushBlock(
		mockLegacyBlock,
		legacyData.MockReceipts,
		legacyData.MockBlock.Difficulty())
	require.NoError(t, err)

	defer func() {
		if err := tx.Submit(); err != nil {
			t.Fatal(err)
		}
	}()
	for _, node := range legacyData.StateDiffs {
		err = ind.PushStateNode(tx, node, mockLegacyBlock.Hash().String())
		require.NoError(t, err)
	}

	require.Equal(t, legacyData.BlockNumber.String(), tx.BlockNumber())
}

func TestLegacyIndexer(t *testing.T, db sql.Database) {
	pgStr := `SELECT cid, cast(td AS TEXT), cast(reward AS TEXT), block_hash, coinbase
	FROM eth.header_cids
	WHERE block_number = $1`
	// check header was properly indexed
	type res struct {
		CID       string
		TD        string
		Reward    string
		BlockHash string `db:"block_hash"`
		Coinbase  string `db:"coinbase"`
	}
	header := new(res)
	err = db.QueryRow(context.Background(), pgStr, legacyData.BlockNumber.Uint64()).Scan(
		&header.CID,
		&header.TD,
		&header.Reward,
		&header.BlockHash,
		&header.Coinbase)
	require.NoError(t, err)

	require.Equal(t, legacyHeaderCID.String(), header.CID)
	require.Equal(t, legacyData.MockBlock.Difficulty().String(), header.TD)
	require.Equal(t, "5000000000000011250", header.Reward)
	require.Equal(t, legacyData.MockHeader.Coinbase.String(), header.Coinbase)
	require.Nil(t, legacyData.MockHeader.BaseFee)
}
