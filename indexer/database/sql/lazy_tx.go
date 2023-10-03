package sql

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/cerc-io/plugeth-statediff/indexer/database/metrics"
	"github.com/cerc-io/plugeth-statediff/utils/log"
)

// Changing this to 1 would make sure only sequential COPYs were combined.
const copyFromCheckLimit = 100

type DelayedTx struct {
	cache []interface{}
	db    Database
	sync.RWMutex
}
type cachedStmt struct {
	sql  string
	args []interface{}
}

type copyFrom struct {
	tableName   []string
	columnNames []string
	rows        [][]interface{}
}

type result int64

func (cf *copyFrom) appendRows(rows [][]interface{}) {
	cf.rows = append(cf.rows, rows...)
}

func (cf *copyFrom) matches(tableName []string, columnNames []string) bool {
	return reflect.DeepEqual(cf.tableName, tableName) && reflect.DeepEqual(cf.columnNames, columnNames)
}

func NewDelayedTx(db Database) *DelayedTx {
	return &DelayedTx{db: db}
}

func (tx *DelayedTx) QueryRow(ctx context.Context, sql string, args ...interface{}) ScannableRow {
	return tx.db.QueryRow(ctx, sql, args...)
}

func (tx *DelayedTx) findPrevCopyFrom(tableName []string, columnNames []string, limit int) (*copyFrom, int) {
	tx.RLock()
	defer tx.RUnlock()
	for pos, count := len(tx.cache)-1, 0; pos >= 0 && count < limit; pos, count = pos-1, count+1 {
		prevCopy, ok := tx.cache[pos].(*copyFrom)
		if ok && prevCopy.matches(tableName, columnNames) {
			return prevCopy, count
		}
	}
	return nil, -1
}

func (tx *DelayedTx) CopyFrom(ctx context.Context, tableName []string, columnNames []string, rows [][]interface{}) (int64, error) {
	if prevCopy, distance := tx.findPrevCopyFrom(tableName, columnNames, copyFromCheckLimit); nil != prevCopy {
		log.Trace("statediff lazy_tx : Appending to COPY", "table", tableName,
			"current", len(prevCopy.rows), "new", len(rows), "distance", distance)
		prevCopy.appendRows(rows)
	} else {
		tx.Lock()
		tx.cache = append(tx.cache, &copyFrom{tableName, columnNames, rows})
		tx.Unlock()
	}

	return 0, nil
}

func (tx *DelayedTx) Exec(ctx context.Context, sql string, args ...interface{}) (Result, error) {
	tx.Lock()
	tx.cache = append(tx.cache, cachedStmt{sql, args})
	defer tx.Unlock()
	return result(0), nil
}

func (tx *DelayedTx) Commit(ctx context.Context) error {
	t := time.Now()
	base, err := tx.db.Begin(ctx)
	if err != nil {
		return err
	}
	metrics.IndexerMetrics.FreePostgresTimer.Update(time.Since(t))
	defer func() {
		if p := recover(); p != nil {
			rollback(ctx, base)
			panic(p)
		} else if err != nil {
			rollback(ctx, base)
		}
	}()
	tx.Lock()
	defer tx.Unlock()
	for _, item := range tx.cache {
		switch item := item.(type) {
		case *copyFrom:
			_, err = base.CopyFrom(ctx, item.tableName, item.columnNames, item.rows)
			if err != nil {
				log.Error("COPY error", "table", item.tableName, "error", err)
				return err
			}
		case cachedStmt:
			_, err = base.Exec(ctx, item.sql, item.args...)
			if err != nil {
				return err
			}
		}
	}
	tx.cache = nil
	return base.Commit(ctx)
}

func (tx *DelayedTx) Rollback(ctx context.Context) error {
	tx.Lock()
	defer tx.Unlock()
	tx.cache = nil
	return nil
}

// RowsAffected satisfies sql.Result
func (r result) RowsAffected() (int64, error) {
	return int64(r), nil
}
