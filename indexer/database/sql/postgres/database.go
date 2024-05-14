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
	"strings"

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
	return fmt.Sprintf("SELECT %s FROM %s ORDER BY block_number DESC LIMIT 1",
		strings.Join(schema.TableHeader.ColumnNames(), ","),
		schema.TableHeader.Name)
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
	return schema.TableHeader.PreparedInsert(db.upsert)
}

// SetCanonicalHeaderStm satisfies the sql.Statements interface
// Stm == Statement
func (db *DB) SetCanonicalHeaderStm() string {
	return fmt.Sprintf("UPDATE %s SET canonical = false WHERE block_number = $1::BIGINT AND block_hash <> $2::TEXT AND canonical = true", schema.TableHeader.Name)
}

// InsertUncleStm satisfies the sql.Statements interface
func (db *DB) InsertUncleStm() string {
	return schema.TableUncle.PreparedInsert(db.upsert)
}

// InsertTxStm satisfies the sql.Statements interface
func (db *DB) InsertTxStm() string {
	return schema.TableTransaction.PreparedInsert(db.upsert)
}

// InsertBlobHashStm satisfies the sql.Statements interface
func (db *DB) InsertBlobHashStm() string {
	return schema.TableBlobHash.PreparedInsert(db.upsert)
}

// InsertRctStm satisfies the sql.Statements interface
func (db *DB) InsertRctStm() string {
	return schema.TableReceipt.PreparedInsert(db.upsert)
}

// InsertLogStm satisfies the sql.Statements interface
func (db *DB) InsertLogStm() string {
	return schema.TableLog.PreparedInsert(db.upsert)
}

// InsertLogStm satisfies the sql.Statements interface
func (db *DB) InsertWithdrawalStm() string {
	return schema.TableWithdrawal.PreparedInsert(db.upsert)
}

// InsertStateStm satisfies the sql.Statements interface
func (db *DB) InsertStateStm() string {
	return schema.TableStateNode.PreparedInsert(db.upsert)
}

// InsertStorageStm satisfies the sql.Statements interface
func (db *DB) InsertStorageStm() string {
	return schema.TableStorageNode.PreparedInsert(db.upsert)
}

// InsertIPLDStm satisfies the sql.Statements interface
func (db *DB) InsertIPLDStm() string {
	return schema.TableIPLDBlock.PreparedInsert(db.upsert)
}

// InsertIPLDsStm satisfies the sql.Statements interface
func (db *DB) InsertIPLDsStm() string {
	return `INSERT INTO ipld.blocks (block_number, key, data) VALUES (unnest($1::BIGINT[]), unnest($2::TEXT[]), unnest($3::BYTEA[])) ON CONFLICT DO NOTHING`
}
