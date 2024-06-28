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

package file

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/lib/pq"
	"github.com/multiformats/go-multihash"

	"github.com/cerc-io/plugeth-statediff/indexer/database/metrics"
	"github.com/cerc-io/plugeth-statediff/indexer/interfaces"
	"github.com/cerc-io/plugeth-statediff/indexer/ipld"
	"github.com/cerc-io/plugeth-statediff/indexer/models"
	"github.com/cerc-io/plugeth-statediff/indexer/node"
	"github.com/cerc-io/plugeth-statediff/indexer/shared"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
	"github.com/cerc-io/plugeth-statediff/utils/log"
)

const defaultCSVOutputDir = "./statediff_output"
const defaultSQLFilePath = "./statediff.sql"
const defaultWatchedAddressesCSVFilePath = "./statediff-watched-addresses.csv"
const defaultWatchedAddressesSQLFilePath = "./statediff-watched-addresses.sql"

const watchedAddressesInsert = "INSERT INTO eth_meta.watched_addresses (address, created_at, watched_at) VALUES ('%s', '%d', '%d') ON CONFLICT (address) DO NOTHING;"

var _ interfaces.StateDiffIndexer = &StateDiffIndexer{}

// StateDiffIndexer satisfies the indexer.StateDiffIndexer interface for ethereum statediff objects on top of a void
type StateDiffIndexer struct {
	fileWriter       FileWriter
	chainConfig      *params.ChainConfig
	nodeID           string
	wg               *sync.WaitGroup
	removedCacheFlag uint32
}

// NewStateDiffIndexer creates a void implementation of interfaces.StateDiffIndexer
// `chainConfig` is used when processing chain state.
// `config` contains configuration specific to the indexer.
// `nodeInfo` contains metadata on the Ethereum node, which is inserted with the indexed state.
// `isDiff` means to mark state nodes as belonging to an incremental diff, as opposed to a full snapshot.
func NewStateDiffIndexer(chainConfig *params.ChainConfig, config Config, nodeInfo node.Info, isDiff bool) (*StateDiffIndexer, error) {
	var err error
	var writer FileWriter

	watchedAddressesFilePath := config.WatchedAddressesFilePath

	switch config.Mode {
	case CSV:
		outputDir := config.OutputDir
		if outputDir == "" {
			outputDir = defaultCSVOutputDir
		}

		if _, err := os.Stat(outputDir); !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("cannot create output directory, directory (%s) already exists", outputDir)
		}
		log.Info("Writing statediff CSV files", "directory", outputDir)

		if watchedAddressesFilePath == "" {
			watchedAddressesFilePath = defaultWatchedAddressesCSVFilePath
		}
		log.Info("Writing watched addresses to file", "file", watchedAddressesFilePath)

		writer, err = NewCSVWriter(outputDir, watchedAddressesFilePath, isDiff)
		if err != nil {
			return nil, err
		}
	case SQL:
		filePath := config.FilePath
		if filePath == "" {
			filePath = defaultSQLFilePath
		}
		if _, err := os.Stat(filePath); !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("cannot create file, file (%s) already exists", filePath)
		}
		file, err := os.Create(filePath)
		if err != nil {
			return nil, fmt.Errorf("unable to create file (%s), err: %v", filePath, err)
		}
		log.Info("Writing statediff SQL statements to file", "file", filePath)

		if watchedAddressesFilePath == "" {
			watchedAddressesFilePath = defaultWatchedAddressesSQLFilePath
		}
		log.Info("Writing watched addresses to file", "file", watchedAddressesFilePath)

		writer = NewSQLWriter(file, watchedAddressesFilePath, isDiff)
	default:
		return nil, fmt.Errorf("unrecognized file mode: %s", config.Mode)
	}

	wg := new(sync.WaitGroup)
	writer.Loop()
	writer.upsertNode(nodeInfo)

	return &StateDiffIndexer{
		fileWriter:  writer,
		chainConfig: chainConfig,
		nodeID:      nodeInfo.ID,
		wg:          wg,
	}, nil
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

	blockTx := &BatchTx{
		blockNum:   block.Number().String(),
		fileWriter: sdi.fileWriter,
	}
	t = time.Now()

	// write header, collect headerID
	headerID, err := sdi.PushHeader(blockTx, block.Header(), reward, totalDifficulty)
	if err != nil {
		return nil, err
	}
	tDiff := time.Since(t)
	metrics.IndexerMetrics.HeaderProcessingTimer.Update(tDiff)
	traceMsg += fmt.Sprintf("header processing time: %s\r\n", tDiff.String())
	t = time.Now()

	// write uncles
	sdi.processUncles(headerID, block.Number(), block.UncleHash(), block.Uncles())
	tDiff = time.Since(t)
	metrics.IndexerMetrics.UncleProcessingTimer.Update(tDiff)
	traceMsg += fmt.Sprintf("uncle processing time: %s\r\n", tDiff.String())
	t = time.Now()

	err = sdi.processObjects(processArgs{
		headerID:    headerID,
		blockNumber: block.Number(),
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

// PushHeader write a header IPLD insert SQL stmt to a file
// it returns the headerID
func (sdi *StateDiffIndexer) PushHeader(_ interfaces.Batch, header *types.Header, reward, td *big.Int) (string, error) {
	// Process the header
	headerNode, err := ipld.EncodeHeader(header)
	if err != nil {
		return "", err
	}
	sdi.fileWriter.upsertIPLDNode(header.Number.String(), headerNode)

	headerID := header.Hash().String()
	sdi.fileWriter.upsertHeaderCID(models.HeaderModel{
		NodeIDs:         pq.StringArray([]string{sdi.nodeID}),
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
	})
	return headerID, nil
}

// processUncles publishes and indexes uncle IPLDs in Postgres
func (sdi *StateDiffIndexer) processUncles(headerID string, blockNumber *big.Int, unclesHash common.Hash, uncles []*types.Header) error {
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
	sdi.fileWriter.upsertIPLDDirect(blockNumber.String(), unclesCID.String(), uncleEncoding)
	for i, uncle := range uncles {
		var uncleReward *big.Int
		// in PoA networks uncle reward is 0
		if sdi.chainConfig.Clique != nil {
			uncleReward = big.NewInt(0)
		} else {
			uncleReward = shared.CalcUncleMinerReward(blockNumber.Uint64(), uncle.Number.Uint64())
		}
		sdi.fileWriter.upsertUncleCID(models.UncleModel{
			BlockNumber: blockNumber.String(),
			HeaderID:    headerID,
			CID:         unclesCID.String(),
			ParentHash:  uncle.ParentHash.String(),
			BlockHash:   uncle.Hash().String(),
			Reward:      uncleReward.String(),
			Index:       int64(i),
		})
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

// processObjects writes receipt and tx IPLD insert SQL stmts to a file
func (sdi *StateDiffIndexer) processObjects(args processArgs) error {
	// Process receipts and txs
	signer := types.MakeSigner(sdi.chainConfig, args.blockNumber, args.blockTime)
	for i, receipt := range args.receipts {
		txNode := args.txNodes[i]
		sdi.fileWriter.upsertIPLDNode(args.blockNumber.String(), txNode)
		sdi.fileWriter.upsertIPLDNode(args.blockNumber.String(), args.rctNodes[i])

		// index tx
		trx := args.txs[i]
		txID := trx.Hash().String()

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
			TxHash:      txID,
			Index:       int64(i),
			CID:         txNode.Cid().String(),
			Type:        trx.Type(),
			Value:       val,
		}
		sdi.fileWriter.upsertTransactionCID(txModel)

		// this is the contract address if this receipt is for a contract creation tx
		contract := shared.HandleZeroAddr(receipt.ContractAddress)

		// index receipt
		rctModel := &models.ReceiptModel{
			BlockNumber: args.blockNumber.String(),
			HeaderID:    args.headerID,
			TxID:        txID,
			Contract:    contract,
			CID:         args.rctNodes[i].Cid().String(),
		}
		if len(receipt.PostState) == 0 {
			rctModel.PostStatus = receipt.Status
		} else {
			rctModel.PostState = common.BytesToHash(receipt.PostState).String()
		}
		sdi.fileWriter.upsertReceiptCID(rctModel)

		// index logs
		logDataSet := make([]*models.LogsModel, len(receipt.Logs))
		for idx, l := range receipt.Logs {
			sdi.fileWriter.upsertIPLDNode(args.blockNumber.String(), args.logNodes[i][idx])
			topicSet := make([]string, 4)
			for ti, topic := range l.Topics {
				topicSet[ti] = topic.String()
			}

			logDataSet[idx] = &models.LogsModel{
				BlockNumber: args.blockNumber.String(),
				HeaderID:    args.headerID,
				ReceiptID:   txID,
				Address:     l.Address.String(),
				Index:       int64(l.Index),
				CID:         args.logNodes[i][idx].Cid().String(),
				Topic0:      topicSet[0],
				Topic1:      topicSet[1],
				Topic2:      topicSet[2],
				Topic3:      topicSet[3],
			}
		}
		sdi.fileWriter.upsertLogCID(logDataSet)
	}
	// Process withdrawals
	for i, wd := range args.withdrawals {
		wdNode := args.wdNodes[i]
		sdi.fileWriter.upsertIPLDNode(args.blockNumber.String(), wdNode)
		wdModel := models.WithdrawalModel{
			BlockNumber: args.blockNumber.String(),
			HeaderID:    args.headerID,
			CID:         wdNode.Cid().String(),
			Index:       wd.Index,
			Validator:   wd.Validator,
			Address:     wd.Address.String(),
			Amount:      wd.Amount,
		}
		sdi.fileWriter.upsertWithdrawalCID(wdModel)
	}

	return nil
}

// PushStateNode writes a state diff node object (including any child storage nodes) IPLD insert SQL stmt to a file
func (sdi *StateDiffIndexer) PushStateNode(tx interfaces.Batch, stateNode sdtypes.StateLeafNode, headerID string) error {
	// publish the state node
	var stateModel models.StateNodeModel
	if stateNode.Removed {
		if atomic.LoadUint32(&sdi.removedCacheFlag) == 0 {
			atomic.StoreUint32(&sdi.removedCacheFlag, 1)
			sdi.fileWriter.upsertIPLDDirect(tx.BlockNumber(), shared.RemovedNodeStateCID, []byte{})
		}
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

	// index the state node
	sdi.fileWriter.upsertStateCID(stateModel)

	// if there are any storage nodes associated with this node, publish and index them
	for _, storageNode := range stateNode.StorageDiff {
		if storageNode.Removed {
			if atomic.LoadUint32(&sdi.removedCacheFlag) == 0 {
				atomic.StoreUint32(&sdi.removedCacheFlag, 1)
				sdi.fileWriter.upsertIPLDDirect(tx.BlockNumber(), shared.RemovedNodeStorageCID, []byte{})
			}
			storageModel := models.StorageNodeModel{
				BlockNumber: tx.BlockNumber(),
				HeaderID:    headerID,
				StateKey:    common.BytesToHash(stateNode.AccountWrapper.LeafKey).String(),
				StorageKey:  common.BytesToHash(storageNode.LeafKey).String(),
				CID:         shared.RemovedNodeStorageCID,
				Removed:     true,
				Value:       []byte{},
			}
			sdi.fileWriter.upsertStorageCID(storageModel)
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
		sdi.fileWriter.upsertStorageCID(storageModel)
	}

	return nil
}

// PushIPLD writes iplds to ipld.blocks
func (sdi *StateDiffIndexer) PushIPLD(tx interfaces.Batch, ipld sdtypes.IPLD) error {
	sdi.fileWriter.upsertIPLDDirect(tx.BlockNumber(), ipld.CID, ipld.Content)
	return nil
}

// CurrentBlock returns the HeaderModel of the highest existing block in the output.
// In the "file" case, this is always nil.
func (sdi *StateDiffIndexer) CurrentBlock() (*models.HeaderModel, error) {
	return nil, nil
}

// DetectGaps returns a list of gaps in the output found within the specified block range.
// In the "file" case this is always nil.
func (sdi *StateDiffIndexer) DetectGaps(beginBlockNumber uint64, endBlockNumber uint64) ([]*interfaces.BlockGap, error) {
	return nil, nil
}

// HasBlock checks whether the indicated block already exists in the output.
// In the "file" case this is presumed to be false.
func (sdi *StateDiffIndexer) HasBlock(hash common.Hash, number uint64) (bool, error) {
	return false, nil
}

func (sdi *StateDiffIndexer) BeginTx(number *big.Int, _ context.Context) interfaces.Batch {
	return &BatchTx{
		blockNum:   number.String(),
		fileWriter: sdi.fileWriter,
	}
}

// Close satisfies io.Closer
func (sdi *StateDiffIndexer) Close() error {
	return sdi.fileWriter.Close()
}

// LoadWatchedAddresses loads watched addresses from a file
func (sdi *StateDiffIndexer) LoadWatchedAddresses() ([]common.Address, error) {
	return sdi.fileWriter.loadWatchedAddresses()
}

// InsertWatchedAddresses inserts the given addresses in a file
func (sdi *StateDiffIndexer) InsertWatchedAddresses(args []sdtypes.WatchAddressArg, currentBlockNumber *big.Int) error {
	return sdi.fileWriter.insertWatchedAddresses(args, currentBlockNumber)
}

// RemoveWatchedAddresses removes the given watched addresses from a file
func (sdi *StateDiffIndexer) RemoveWatchedAddresses(args []sdtypes.WatchAddressArg) error {
	return sdi.fileWriter.removeWatchedAddresses(args)
}

// SetWatchedAddresses clears and inserts the given addresses in a file
func (sdi *StateDiffIndexer) SetWatchedAddresses(args []sdtypes.WatchAddressArg, currentBlockNumber *big.Int) error {
	return sdi.fileWriter.setWatchedAddresses(args, currentBlockNumber)
}

// ClearWatchedAddresses clears all the watched addresses from a file
func (sdi *StateDiffIndexer) ClearWatchedAddresses() error {
	return sdi.SetWatchedAddresses([]sdtypes.WatchAddressArg{}, big.NewInt(0))
}
