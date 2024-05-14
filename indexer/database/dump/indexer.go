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

package dump

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/multiformats/go-multihash"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/cerc-io/plugeth-statediff/indexer/database/metrics"
	"github.com/cerc-io/plugeth-statediff/indexer/interfaces"
	"github.com/cerc-io/plugeth-statediff/indexer/ipld"
	"github.com/cerc-io/plugeth-statediff/indexer/models"
	"github.com/cerc-io/plugeth-statediff/indexer/shared"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
)

var _ interfaces.StateDiffIndexer = &StateDiffIndexer{}

// StateDiffIndexer satisfies the indexer.StateDiffIndexer interface for ethereum statediff objects on top of a void
type StateDiffIndexer struct {
	dump        io.WriteCloser
	chainConfig *params.ChainConfig
}

// NewStateDiffIndexer creates a void implementation of interfaces.StateDiffIndexer
func NewStateDiffIndexer(chainConfig *params.ChainConfig, config Config) *StateDiffIndexer {
	return &StateDiffIndexer{
		dump:        config.Dump,
		chainConfig: chainConfig,
	}
}

// ReportDBMetrics has nothing to report for dump
func (sdi *StateDiffIndexer) ReportDBMetrics(time.Duration, <-chan bool) {}

// PushBlock pushes and indexes block data in sql, except state & storage nodes (includes header, uncles, transactions & receipts)
// Returns an initiated DB transaction which must be Closed via defer to commit or rollback
func (sdi *StateDiffIndexer) PushBlock(block *types.Block, receipts types.Receipts, totalDifficulty *big.Int) (interfaces.Batch, error) {
	t := time.Now()
	blockHash := block.Hash()
	blockHashStr := blockHash.String()
	height := block.NumberU64()
	traceMsg := fmt.Sprintf("indexer stats for statediff at %d with hash %s:\r\n", height, blockHashStr)

	var blobGasPrice *big.Int
	excessBlobGas := block.ExcessBlobGas()
	if excessBlobGas != nil {
		blobGasPrice = eip4844.CalcBlobFee(*excessBlobGas)
	}
	transactions := block.Transactions()

	// Derive any missing fields
	if err := receipts.DeriveFields(sdi.chainConfig, blockHash, height, block.Time(), block.BaseFee(), blobGasPrice, transactions); err != nil {
		return nil, err
	}

	// Generate the block iplds
	txNodes, rctNodes, logNodes, wdNodes, err := ipld.FromBlockAndReceipts(block, receipts)
	if err != nil {
		return nil, fmt.Errorf("error creating IPLD nodes from block and receipts: %v", err)
	}

	if len(txNodes) != len(rctNodes) {
		return nil, fmt.Errorf("expected number of transactions (%d), receipts (%d)", len(txNodes), len(rctNodes))
	}

	// Calculate reward
	var reward *big.Int
	// in PoA networks block reward is 0
	if sdi.chainConfig.Clique != nil {
		reward = big.NewInt(0)
	} else {
		reward = shared.CalcEthBlockReward(block.Header(), block.Uncles(), block.Transactions(), receipts)
	}

	blockTx := NewBatch(block.Number(), sdi.dump)
	t = time.Now()

	// Publish and index header, collect headerID
	var headerID string
	headerID, err = sdi.PushHeader(blockTx, block.Header(), reward, totalDifficulty)
	if err != nil {
		return nil, err
	}
	tDiff := time.Since(t)
	metrics.IndexerMetrics.HeaderProcessingTimer.Update(tDiff)
	traceMsg += fmt.Sprintf("header processing time: %s\r\n", tDiff.String())
	t = time.Now()
	// Publish and index uncles
	err = sdi.processUncles(blockTx, headerID, block.Number(), block.UncleHash(), block.Uncles())
	if err != nil {
		return nil, err
	}
	tDiff = time.Since(t)
	metrics.IndexerMetrics.UncleProcessingTimer.Update(tDiff)
	traceMsg += fmt.Sprintf("uncle processing time: %s\r\n", tDiff.String())
	t = time.Now()
	// Publish and index receipts and txs
	err = sdi.processObjects(blockTx, processArgs{
		headerID:    headerID,
		blockNumber: block.Number(),
		blockTime:   block.Time(),
		receipts:    receipts,
		txs:         transactions,
		withdrawals: block.Withdrawals(),
		rctNodes:    rctNodes,
		txNodes:     txNodes,
		logNodes:    logNodes,
		wdNodes:     wdNodes,
	})
	if err != nil {
		return nil, err
	}
	tDiff = time.Since(t)
	metrics.IndexerMetrics.TxAndRecProcessingTimer.Update(tDiff)
	traceMsg += fmt.Sprintf("tx and receipt processing time: %s\r\n", tDiff.String())
	t = time.Now()

	return blockTx, err
}

// PushHeader publishes and indexes a header IPLD in Postgres
// it returns the headerID
func (sdi *StateDiffIndexer) PushHeader(batch interfaces.Batch, header *types.Header, reward, td *big.Int) (string, error) {
	tx, ok := batch.(*BatchTx)
	if !ok {
		return "", fmt.Errorf("sql: batch is expected to be of type %T, got %T", &BatchTx{}, batch)
	}
	headerNode, err := ipld.EncodeHeader(header)
	if err != nil {
		return "", err
	}
	tx.cacheIPLD(headerNode)

	headerID := header.Hash().String()
	mod := models.HeaderModel{
		CID:             headerNode.Cid().String(),
		ParentHash:      header.ParentHash.String(),
		BlockNumber:     header.Number.String(),
		BlockHash:       headerID,
		TotalDifficulty: td.String(),
		Reward:          reward.String(),
		Bloom:           header.Bloom.Bytes(),
		StateRoot:       header.Root.String(),
		RctRoot:         header.ReceiptHash.String(),
		TxRoot:          header.TxHash.String(),
		UnclesHash:      header.UncleHash.String(),
		Timestamp:       header.Time,
		Coinbase:        header.Coinbase.String(),
		Canonical:       true,
		WithdrawalsRoot: shared.MaybeStringHash(header.WithdrawalsHash),
	}
	_, err = fmt.Fprintf(sdi.dump, "%+v\r\n", mod)
	return headerID, err
}

// processUncles publishes and indexes uncle IPLDs in Postgres
func (sdi *StateDiffIndexer) processUncles(tx *BatchTx, headerID string, blockNumber *big.Int, unclesHash common.Hash, uncles []*types.Header) error {
	// publish and index uncles
	uncleEncoding, err := rlp.EncodeToBytes(uncles)
	if err != nil {
		return err
	}
	preparedHash := crypto.Keccak256Hash(uncleEncoding)
	if preparedHash != unclesHash {
		return fmt.Errorf("derived uncles hash (%s) does not match the hash in the header (%s)", preparedHash.String(), unclesHash.String())
	}
	unclesCID, err := ipld.RawdataToCid(ipld.MEthHeaderList, uncleEncoding, multihash.KECCAK_256)
	if err != nil {
		return err
	}
	tx.cacheDirect(unclesCID.String(), uncleEncoding)
	for i, uncle := range uncles {
		var uncleReward *big.Int
		// in PoA networks uncle reward is 0
		if sdi.chainConfig.Clique != nil {
			uncleReward = big.NewInt(0)
		} else {
			uncleReward = shared.CalcUncleMinerReward(blockNumber.Uint64(), uncle.Number.Uint64())
		}
		uncle := models.UncleModel{
			BlockNumber: blockNumber.String(),
			HeaderID:    headerID,
			CID:         unclesCID.String(),
			ParentHash:  uncle.ParentHash.String(),
			BlockHash:   uncle.Hash().String(),
			Reward:      uncleReward.String(),
			Index:       int64(i),
		}
		if _, err := fmt.Fprintf(sdi.dump, "%+v\r\n", uncle); err != nil {
			return err
		}
	}
	return nil
}

// processArgs bundles arguments to processReceiptsAndTxs
type processArgs struct {
	headerID    string
	blockNumber *big.Int
	blockTime   uint64
	receipts    types.Receipts
	txs         types.Transactions
	withdrawals types.Withdrawals
	rctNodes    []ipld.IPLD
	txNodes     []ipld.IPLD
	logNodes    [][]ipld.IPLD
	wdNodes     []ipld.IPLD
}

// processObjects publishes and indexes receipt and transaction IPLDs in Postgres
func (sdi *StateDiffIndexer) processObjects(tx *BatchTx, args processArgs) error {
	// Process receipts and txs
	signer := types.MakeSigner(sdi.chainConfig, args.blockNumber, args.blockTime)
	for i, receipt := range args.receipts {
		txNode := args.txNodes[i]
		tx.cacheIPLD(txNode)

		// Indexing
		// index tx
		trx := args.txs[i]
		trxID := trx.Hash().String()

		var val string
		if trx.Value() != nil {
			val = trx.Value().String()
		}

		// derive sender for the tx that corresponds with this receipt
		from, err := types.Sender(signer, trx)
		if err != nil {
			return fmt.Errorf("error deriving tx sender: %v", err)
		}
		txModel := models.TxModel{
			BlockNumber: args.blockNumber.String(),
			HeaderID:    args.headerID,
			Dst:         shared.HandleZeroAddrPointer(trx.To()),
			Src:         shared.HandleZeroAddr(from),
			TxHash:      trxID,
			Index:       int64(i),
			CID:         txNode.Cid().String(),
			Type:        trx.Type(),
			Value:       val,
		}
		if _, err := fmt.Fprintf(sdi.dump, "%+v\r\n", txModel); err != nil {
			return err
		}

		if trx.Type() == types.BlobTxType {
			blobHashes := trx.BlobHashes()
			for i, hash := range blobHashes {
				bhModel := models.BlobHashModel{
					TxHash:   trxID,
					Index:    uint64(i),
					BlobHash: hash,
				}
				if _, err := fmt.Fprintf(sdi.dump, "%+v\r\n", bhModel); err != nil {
					return err
				}
			}
		}

		// this is the contract address if this receipt is for a contract creation tx
		contract := shared.HandleZeroAddr(receipt.ContractAddress)

		// index the receipt
		rctModel := &models.ReceiptModel{
			BlockNumber: args.blockNumber.String(),
			HeaderID:    args.headerID,
			TxID:        trxID,
			Contract:    contract,
			CID:         args.rctNodes[i].Cid().String(),
		}
		if len(receipt.PostState) == 0 {
			rctModel.PostStatus = receipt.Status
		} else {
			rctModel.PostState = hex.EncodeToString(receipt.PostState)
		}

		if _, err := fmt.Fprintf(sdi.dump, "%+v\r\n", rctModel); err != nil {
			return err
		}

		logDataSet := make([]*models.LogsModel, len(receipt.Logs))
		for idx, l := range receipt.Logs {
			topicSet := make([]string, 4)
			for ti, topic := range l.Topics {
				topicSet[ti] = topic.String()
			}

			logDataSet[idx] = &models.LogsModel{
				BlockNumber: args.blockNumber.String(),
				HeaderID:    args.headerID,
				ReceiptID:   trxID,
				Address:     l.Address.String(),
				Index:       int64(l.Index),
				CID:         args.logNodes[i][idx].Cid().String(),
				Topic0:      topicSet[0],
				Topic1:      topicSet[1],
				Topic2:      topicSet[2],
				Topic3:      topicSet[3],
			}
		}

		if _, err := fmt.Fprintf(sdi.dump, "%+v\r\n", logDataSet); err != nil {
			return err
		}
	}
	// Process withdrawals
	for i, withdrawal := range args.withdrawals {
		wdNode := args.wdNodes[i]
		tx.cacheIPLD(wdNode)
		wdModel := models.WithdrawalModel{
			BlockNumber: args.blockNumber.String(),
			HeaderID:    args.headerID,
			CID:         wdNode.Cid().String(),
			Index:       withdrawal.Index,
			Validator:   withdrawal.Validator,
			Address:     withdrawal.Address.String(),
			Amount:      withdrawal.Amount,
		}
		if _, err := fmt.Fprintf(sdi.dump, "%+v\r\n", wdModel); err != nil {
			return err
		}
	}

	return nil
}

// PushStateNode publishes and indexes a state diff node object (including any child storage nodes) in the IPLD sql
func (sdi *StateDiffIndexer) PushStateNode(batch interfaces.Batch, stateNode sdtypes.StateLeafNode, headerID string) error {
	tx, ok := batch.(*BatchTx)
	if !ok {
		return fmt.Errorf("dump: batch is expected to be of type %T, got %T", &BatchTx{}, batch)
	}
	// publish the state node
	var stateModel models.StateNodeModel
	if stateNode.Removed {
		// short circuit if it is a Removed node
		// this assumes the db has been initialized and a ipld.blocks entry for the Removed node is present
		stateModel = models.StateNodeModel{
			BlockNumber: tx.BlockNumber(),
			HeaderID:    headerID,
			StateKey:    common.BytesToHash(stateNode.AccountWrapper.LeafKey).String(),
			CID:         shared.RemovedNodeStateCID,
			Removed:     true,
		}
	} else {
		stateModel = models.StateNodeModel{
			BlockNumber: tx.BlockNumber(),
			HeaderID:    headerID,
			StateKey:    common.BytesToHash(stateNode.AccountWrapper.LeafKey).String(),
			CID:         stateNode.AccountWrapper.CID,
			Removed:     false,
			Balance:     stateNode.AccountWrapper.Account.Balance.String(),
			Nonce:       stateNode.AccountWrapper.Account.Nonce,
			CodeHash:    common.BytesToHash(stateNode.AccountWrapper.Account.CodeHash).String(),
			StorageRoot: stateNode.AccountWrapper.Account.Root.String(),
		}
	}

	// index the state node, collect the stateID to reference by FK
	if _, err := fmt.Fprintf(sdi.dump, "%+v\r\n", stateModel); err != nil {
		return err
	}

	// if there are any storage nodes associated with this node, publish and index them
	for _, storageNode := range stateNode.StorageDiff {
		if storageNode.Removed {
			// short circuit if it is a Removed node
			// this assumes the db has been initialized and a ipld.blocks entry for the Removed node is present
			storageModel := models.StorageNodeModel{
				BlockNumber: tx.BlockNumber(),
				HeaderID:    headerID,
				StateKey:    common.BytesToHash(stateNode.AccountWrapper.LeafKey).String(),
				StorageKey:  common.BytesToHash(storageNode.LeafKey).String(),
				CID:         shared.RemovedNodeStorageCID,
				Removed:     true,
			}
			if _, err := fmt.Fprintf(sdi.dump, "%+v\r\n", storageModel); err != nil {
				return err
			}
			continue
		}
		storageModel := models.StorageNodeModel{
			BlockNumber: tx.BlockNumber(),
			HeaderID:    headerID,
			StateKey:    common.BytesToHash(stateNode.AccountWrapper.LeafKey).String(),
			StorageKey:  common.BytesToHash(storageNode.LeafKey).String(),
			CID:         storageNode.CID,
			Removed:     false,
			Value:       storageNode.Value,
		}
		if _, err := fmt.Fprintf(sdi.dump, "%+v\r\n", storageModel); err != nil {
			return err
		}
	}

	return nil
}

// PushIPLD publishes iplds to ipld.blocks
func (sdi *StateDiffIndexer) PushIPLD(batch interfaces.Batch, ipld sdtypes.IPLD) error {
	tx, ok := batch.(*BatchTx)
	if !ok {
		return fmt.Errorf("dump: batch is expected to be of type %T, got %T", &BatchTx{}, batch)
	}
	tx.cacheDirect(ipld.CID, ipld.Content)
	return nil
}

// HasBlock checks whether the indicated block already exists in the output.
// In the "dump" case, this is presumed to be false.
func (sdi *StateDiffIndexer) HasBlock(hash common.Hash, number uint64) (bool, error) {
	return false, nil
}

// CurrentBlock returns the HeaderModel of the highest existing block in the output.
// In the "dump" case, this is always nil.
func (sdi *StateDiffIndexer) CurrentBlock() (*models.HeaderModel, error) {
	return nil, nil
}

// DetectGaps returns a list of gaps in the output found within the specified block range.
// In the "dump" case this is always nil.
func (sdi *StateDiffIndexer) DetectGaps(beginBlockNumber uint64, endBlockNumber uint64) ([]*interfaces.BlockGap, error) {
	return nil, nil
}

func (sdi *StateDiffIndexer) BeginTx(number *big.Int, _ context.Context) interfaces.Batch {
	return NewBatch(number, sdi.dump)
}

// Close satisfies io.Closer
func (sdi *StateDiffIndexer) Close() error {
	return sdi.dump.Close()
}

// LoadWatchedAddresses satisfies the interfaces.StateDiffIndexer interface
func (sdi *StateDiffIndexer) LoadWatchedAddresses() ([]common.Address, error) {
	return nil, nil
}

// InsertWatchedAddresses satisfies the interfaces.StateDiffIndexer interface
func (sdi *StateDiffIndexer) InsertWatchedAddresses(args []sdtypes.WatchAddressArg, currentBlockNumber *big.Int) error {
	return nil
}

// RemoveWatchedAddresses satisfies the interfaces.StateDiffIndexer interface
func (sdi *StateDiffIndexer) RemoveWatchedAddresses(args []sdtypes.WatchAddressArg) error {
	return nil
}

// SetWatchedAddresses satisfies the interfaces.StateDiffIndexer interface
func (sdi *StateDiffIndexer) SetWatchedAddresses(args []sdtypes.WatchAddressArg, currentBlockNumber *big.Int) error {
	return nil
}

// ClearWatchedAddresses satisfies the interfaces.StateDiffIndexer interface
func (sdi *StateDiffIndexer) ClearWatchedAddresses() error {
	return nil
}
