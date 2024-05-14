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
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"

	"github.com/cerc-io/plugeth-statediff/indexer/ipld"
	"github.com/cerc-io/plugeth-statediff/indexer/mocks"
	"github.com/cerc-io/plugeth-statediff/indexer/models"
	"github.com/cerc-io/plugeth-statediff/indexer/shared"
)

var (
	err       error
	ipfsPgGet = `SELECT data FROM ipld.blocks
					WHERE key = $1 AND block_number = $2`
	watchedAddressesPgGet = `SELECT *
					FROM eth_meta.watched_addresses`
	encodedTxs, encodedRcts                                          [][]byte
	wd1, wd2                                                         []byte
	nonCanonicalBlockRct1, nonCanonicalBlockRct2                     []byte
	nonCanonicalBlock2Rct1, nonCanonicalBlock2Rct2                   []byte
	mockBlock, mockNonCanonicalBlock, mockNonCanonicalBlock2         *types.Block
	headerCID, mockNonCanonicalHeaderCID, mockNonCanonicalHeader2CID cid.Cid
	txCIDs, rctCIDs                                                  []cid.Cid
	wd1CID, wd2CID                                                   cid.Cid
	nonCanonicalBlockRct1CID, nonCanonicalBlockRct2CID               cid.Cid
	nonCanonicalBlock2Rct1CID, nonCanonicalBlock2Rct2CID             cid.Cid
	state1CID, state2CID, storageCID                                 cid.Cid
)

func init() {
	// canonical block at LondonBlock height
	mockBlock = mocks.MockBlock
	txs, rcts := mocks.MockBlock.Transactions(), mocks.MockReceipts

	// non-canonical block at LondonBlock height
	mockNonCanonicalBlock = mocks.MockNonCanonicalBlock
	nonCanonicalBlockRcts := mocks.MockNonCanonicalBlockReceipts

	// non-canonical block at LondonBlock height + 1
	mockNonCanonicalBlock2 = mocks.MockNonCanonicalBlock2
	nonCanonicalBlock2Rcts := mocks.MockNonCanonicalBlock2Receipts

	// encode mock txs and receipts
	buf := new(bytes.Buffer)
	encodedTxs = make([][]byte, len(txs))
	encodedRcts = make([][]byte, len(rcts))

	for i := 0; i < len(txs); i++ {
		txs.EncodeIndex(i, buf)
		tx := make([]byte, buf.Len())
		copy(tx, buf.Bytes())
		buf.Reset()
		encodedTxs[i] = tx
	}

	for i := 0; i < len(rcts); i++ {
		rcts.EncodeIndex(i, buf)
		rct := make([]byte, buf.Len())
		copy(rct, buf.Bytes())
		buf.Reset()
		encodedRcts[i] = rct
	}

	// encode mock withdrawals
	mocks.MockWithdrawals.EncodeIndex(0, buf)
	wd1 = make([]byte, buf.Len())
	copy(wd1, buf.Bytes())
	buf.Reset()

	mocks.MockWithdrawals.EncodeIndex(1, buf)
	wd2 = make([]byte, buf.Len())
	copy(wd2, buf.Bytes())
	buf.Reset()

	// encode mock receipts for non-canonical blocks
	nonCanonicalBlockRcts.EncodeIndex(0, buf)
	nonCanonicalBlockRct1 = make([]byte, buf.Len())
	copy(nonCanonicalBlockRct1, buf.Bytes())
	buf.Reset()

	nonCanonicalBlockRcts.EncodeIndex(1, buf)
	nonCanonicalBlockRct2 = make([]byte, buf.Len())
	copy(nonCanonicalBlockRct2, buf.Bytes())
	buf.Reset()

	nonCanonicalBlock2Rcts.EncodeIndex(0, buf)
	nonCanonicalBlock2Rct1 = make([]byte, buf.Len())
	copy(nonCanonicalBlock2Rct1, buf.Bytes())
	buf.Reset()

	nonCanonicalBlock2Rcts.EncodeIndex(1, buf)
	nonCanonicalBlock2Rct2 = make([]byte, buf.Len())
	copy(nonCanonicalBlock2Rct2, buf.Bytes())
	buf.Reset()

	headerCID, _ = ipld.RawdataToCid(ipld.MEthHeader, mocks.MockHeaderRlp, multihash.KECCAK_256)
	mockNonCanonicalHeaderCID, _ = ipld.RawdataToCid(ipld.MEthHeader, mocks.MockNonCanonicalHeaderRlp, multihash.KECCAK_256)
	mockNonCanonicalHeader2CID, _ = ipld.RawdataToCid(ipld.MEthHeader, mocks.MockNonCanonicalHeader2Rlp, multihash.KECCAK_256)

	for i := 0; i < len(txs); i++ {
		tx, _ := ipld.RawdataToCid(ipld.MEthTx, encodedTxs[i], multihash.KECCAK_256)
		txCIDs = append(txCIDs, tx)
	}

	state1CID, _ = ipld.RawdataToCid(ipld.MEthStateTrie, mocks.ContractLeafNode, multihash.KECCAK_256)
	state2CID, _ = ipld.RawdataToCid(ipld.MEthStateTrie, mocks.AccountLeafNode, multihash.KECCAK_256)
	storageCID, _ = ipld.RawdataToCid(ipld.MEthStorageTrie, mocks.StorageLeafNode, multihash.KECCAK_256)

	for i := 0; i < len(rcts); i++ {
		rct, _ := ipld.RawdataToCid(ipld.MEthTxReceipt, encodedRcts[i], multihash.KECCAK_256)
		rctCIDs = append(rctCIDs, rct)
	}

	wd1CID, _ = ipld.RawdataToCid(ipld.MEthWithdrawal, wd1, multihash.KECCAK_256)
	wd2CID, _ = ipld.RawdataToCid(ipld.MEthWithdrawal, wd2, multihash.KECCAK_256)

	// create raw receipts for non-canonical blocks
	nonCanonicalBlockRct1CID, _ = ipld.RawdataToCid(ipld.MEthTxReceipt, nonCanonicalBlockRct1, multihash.KECCAK_256)
	nonCanonicalBlockRct2CID, _ = ipld.RawdataToCid(ipld.MEthTxReceipt, nonCanonicalBlockRct2, multihash.KECCAK_256)

	nonCanonicalBlock2Rct1CID, _ = ipld.RawdataToCid(ipld.MEthTxReceipt, nonCanonicalBlock2Rct1, multihash.KECCAK_256)
	nonCanonicalBlock2Rct2CID, _ = ipld.RawdataToCid(ipld.MEthTxReceipt, nonCanonicalBlock2Rct2, multihash.KECCAK_256)
}

// createRctModel creates a models.ReceiptModel object from a given ethereum receipt
func createRctModel(rct *types.Receipt, cid cid.Cid, blockNumber string) models.ReceiptModel {
	rctModel := models.ReceiptModel{
		BlockNumber: blockNumber,
		HeaderID:    rct.BlockHash.String(),
		TxID:        rct.TxHash.String(),
		CID:         cid.String(),
	}

	contract := shared.HandleZeroAddr(rct.ContractAddress)
	rctModel.Contract = contract

	if len(rct.PostState) == 0 {
		rctModel.PostStatus = rct.Status
	} else {
		rctModel.PostState = common.BytesToHash(rct.PostState).String()
	}

	return rctModel
}

func expectTrue(t *testing.T, value bool) {
	if !value {
		t.Fatalf("Assertion failed")
	}
}
