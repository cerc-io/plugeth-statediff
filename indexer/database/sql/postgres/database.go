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

package postgres

import (
	"fmt"

	"github.com/cerc-io/plugeth-statediff/indexer/database/sql"
	"github.com/cerc-io/plugeth-statediff/indexer/shared/schema"
)

var _ sql.Database = &DB{}

const (
	createNodeStm = `INSERT INTO nodes (genesis_block, network_id, node_id, client_name, chain_id) VALUES ($1, $2, $3, $4, $5)
					 ON CONFLICT (node_id) DO NOTHING`
)

// NewPostgresDB returns a postgres.DB using the provided driver
func NewPostgresDB(driver sql.Driver, upsert bool) *DB {
	return &DB{upsert, driver}
}

// DB implements sql.Database using a configured driver and Postgres statement syntax
type DB struct {
	upsert bool
	sql.Driver
}

// MaxHeaderStm satisfies the sql.Statements interface
func (db *DB) MaxHeaderStm() string {
	return fmt.Sprintf("SELECT block_number, block_hash, parent_hash, cid, td, node_ids, reward, state_root, tx_root, receipt_root, uncles_hash, bloom, timestamp, coinbase FROM %s ORDER BY block_number DESC LIMIT 1", schema.TableHeader.Name)
}

// ExistsHeaderStm satisfies the sql.Statements interface
func (db *DB) ExistsHeaderStm() string {
	return fmt.Sprintf("SELECT EXISTS(SELECT 1 from %s WHERE block_number = $1::BIGINT AND block_hash = $2::TEXT LIMIT 1)", schema.TableHeader.Name)
}

// DetectGapsStm satisfies the sql.Statements interface
func (db *DB) DetectGapsStm() string {
	return fmt.Sprintf("SELECT block_number + 1 AS first_missing, (next_bn - 1) AS last_missing FROM (SELECT block_number, LEAD(block_number) OVER (ORDER BY block_number) AS next_bn FROM %s WHERE block_number >= $1::BIGINT AND block_number <= $2::BIGINT) h WHERE next_bn > block_number + 1", schema.TableHeader.Name)
}

// InsertHeaderStm satisfies the sql.Statements interface
// Stm == Statement
func (db *DB) InsertHeaderStm() string {
	return schema.TableHeader.ToInsertStatement(db.upsert)
}

// InsertUncleStm satisfies the sql.Statements interface
func (db *DB) InsertUncleStm() string {
	return schema.TableUncle.ToInsertStatement(db.upsert)
}

// InsertTxStm satisfies the sql.Statements interface
func (db *DB) InsertTxStm() string {
	return schema.TableTransaction.ToInsertStatement(db.upsert)
}

// InsertRctStm satisfies the sql.Statements interface
func (db *DB) InsertRctStm() string {
	return schema.TableReceipt.ToInsertStatement(db.upsert)
}

// InsertLogStm satisfies the sql.Statements interface
func (db *DB) InsertLogStm() string {
	return schema.TableLog.ToInsertStatement(db.upsert)
}

// InsertStateStm satisfies the sql.Statements interface
func (db *DB) InsertStateStm() string {
	return schema.TableStateNode.ToInsertStatement(db.upsert)
}

// InsertStorageStm satisfies the sql.Statements interface
func (db *DB) InsertStorageStm() string {
	return schema.TableStorageNode.ToInsertStatement(db.upsert)
}

// InsertIPLDStm satisfies the sql.Statements interface
func (db *DB) InsertIPLDStm() string {
	return schema.TableIPLDBlock.ToInsertStatement(db.upsert)
}

// InsertIPLDsStm satisfies the sql.Statements interface
func (db *DB) InsertIPLDsStm() string {
	return `INSERT INTO ipld.blocks (block_number, key, data) VALUES (unnest($1::BIGINT[]), unnest($2::TEXT[]), unnest($3::BYTEA[])) ON CONFLICT DO NOTHING`
}

func (db *DB) LogTableName() []string {
	return []string{"eth", "log_cids"}
}

func (db *DB) LogColumnNames() []string {
	return []string{"block_number", "header_id", "cid", "rct_id", "address", "index", "topic0", "topic1", "topic2", "topic3"}
}

func (db *DB) RctTableName() []string {
	return []string{"eth", "receipt_cids"}
}

func (db *DB) RctColumnNames() []string {
	return []string{"block_number", "header_id", "tx_id", "cid", "contract", "post_state", "post_status"}
}

func (db *DB) StateTableName() []string {
	return []string{"eth", "state_cids"}
}

func (db *DB) StateColumnNames() []string {
	return []string{"block_number", "header_id", "state_leaf_key", "cid", "diff", "balance", "nonce", "code_hash", "storage_root", "removed"}
}

func (db *DB) StorageTableName() []string {
	return []string{"eth", "storage_cids"}
}

func (db *DB) StorageColumnNames() []string {
	return []string{"block_number", "header_id", "state_leaf_key", "storage_leaf_key", "cid", "diff", "val", "removed"}
}

func (db *DB) TxTableName() []string {
	return []string{"eth", "transaction_cids"}
}

func (db *DB) TxColumnNames() []string {
	return []string{"block_number", "header_id", "tx_hash", "cid", "dst", "src", "index", "tx_type", "value"}
}
