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

package sql

import (
	"context"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lib/pq"

	"github.com/cerc-io/plugeth-statediff/indexer/database/metrics"
	"github.com/cerc-io/plugeth-statediff/indexer/ipld"
	"github.com/cerc-io/plugeth-statediff/indexer/models"
	"github.com/cerc-io/plugeth-statediff/utils/log"
)

const startingCacheCapacity = 1024 * 24

// BatchTx wraps a sql tx with the state necessary for building the tx concurrently during trie difference iteration
type BatchTx struct {
	blockNum         string
	ctx              context.Context
	dbtx             Tx
	stm              string
	quit             chan (chan<- struct{})
	iplds            chan models.IPLDModel
	ipldCache        models.IPLDBatch
	removedCacheFlag *uint32
	// Tracks expected cache size and ensures cache is caught up before flush
	cacheWg sync.WaitGroup
}

func NewBatch(insertStm string, ctx context.Context, number *big.Int, tx Tx) *BatchTx {
	blockTx := &BatchTx{
		removedCacheFlag: new(uint32),
		ctx:              ctx,
		blockNum:         number.String(),
		stm:              insertStm,
		iplds:            make(chan models.IPLDModel),
		quit:             make(chan (chan<- struct{})),
		ipldCache: models.IPLDBatch{
			BlockNumbers: make([]string, 0, startingCacheCapacity),
			Keys:         make([]string, 0, startingCacheCapacity),
			Values:       make([][]byte, 0, startingCacheCapacity),
		},
		dbtx: tx,
	}
	go blockTx.cache()
	return blockTx
}

// Submit satisfies indexer.Batch
func (tx *BatchTx) Submit() error {
	defer tx.close()

	t := time.Now()
	if err := tx.flush(); err != nil {
		rollback(tx.ctx, tx.dbtx)
		return err
	}
	err := tx.dbtx.Commit(tx.ctx)
	metrics.IndexerMetrics.PostgresCommitTimer.Update(time.Since(t))
	return err
}

func (tx *BatchTx) BlockNumber() string {
	return tx.blockNum
}

func (tx *BatchTx) RollbackOnFailure(err error) {
	if p := recover(); p != nil {
		defer tx.close()
		log.Info("panic detected before tx submission, rolling back the tx", "panic", p)
		rollback(tx.ctx, tx.dbtx)
		panic(p)
	} else if err != nil {
		defer tx.close()
		log.Info("error detected before tx submission, rolling back the tx", "error", err)
		rollback(tx.ctx, tx.dbtx)
	}
}

func (tx *BatchTx) close() {
	if tx.quit == nil {
		return
	}
	confirm := make(chan struct{})
	tx.quit <- confirm
	close(tx.quit)
	<-confirm
	close(tx.iplds)
	tx.quit = nil
}

func (tx *BatchTx) flush() error {
	tx.cacheWg.Wait()
	_, err := tx.dbtx.Exec(tx.ctx, tx.stm, pq.Array(tx.ipldCache.BlockNumbers), pq.Array(tx.ipldCache.Keys),
		pq.Array(tx.ipldCache.Values))
	if err != nil {
		log.Debug(insertError{"ipld.blocks", err, tx.stm,
			struct {
				blockNumbers []string
				keys         []string
				values       [][]byte
			}{
				tx.ipldCache.BlockNumbers,
				tx.ipldCache.Keys,
				tx.ipldCache.Values,
			}}.Error())
		return insertError{"ipld.blocks", err, tx.stm, "too many arguments; use debug mode for full list"}
	}
	tx.ipldCache = models.IPLDBatch{}
	return nil
}

// run in background goroutine to synchronize concurrent appends to the ipldCache
func (tx *BatchTx) cache() {
	for {
		select {
		case i := <-tx.iplds:
			tx.ipldCache.BlockNumbers = append(tx.ipldCache.BlockNumbers, i.BlockNumber)
			tx.ipldCache.Keys = append(tx.ipldCache.Keys, i.Key)
			tx.ipldCache.Values = append(tx.ipldCache.Values, i.Data)
			tx.cacheWg.Done()
		case confirm := <-tx.quit:
			tx.ipldCache = models.IPLDBatch{}
			confirm <- struct{}{}
			return
		}
	}
}

func (tx *BatchTx) cacheDirect(key string, value []byte) {
	tx.cacheWg.Add(1)
	tx.iplds <- models.IPLDModel{
		BlockNumber: tx.BlockNumber(),
		Key:         key,
		Data:        value,
	}
}

func (tx *BatchTx) cacheIPLD(i ipld.IPLD) {
	tx.cacheWg.Add(1)
	tx.iplds <- models.IPLDModel{
		BlockNumber: tx.BlockNumber(),
		Key:         i.Cid().String(),
		Data:        i.RawData(),
	}
}

func (tx *BatchTx) cacheRemoved(key string, value []byte) {
	if atomic.LoadUint32(tx.removedCacheFlag) == 0 {
		atomic.StoreUint32(tx.removedCacheFlag, 1)
		tx.cacheWg.Add(1)
		tx.iplds <- models.IPLDModel{
			BlockNumber: tx.BlockNumber(),
			Key:         key,
			Data:        value,
		}
	}
}

// rollback sql transaction and log any error
func rollback(ctx context.Context, tx Tx) {
	if err := tx.Rollback(ctx); err != nil {
		log.Error("error during rollback", "error", err)
	}
}
