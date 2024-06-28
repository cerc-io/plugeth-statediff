package schema_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	. "github.com/cerc-io/plugeth-statediff/indexer/shared/schema"
)

var (
	testTable = Table{
		Name: "test_table",
		Columns: []Column{
			{Name: "id", Type: Dbigint},
			{Name: "name", Type: Dvarchar},
			{Name: "age", Type: Dinteger},
		},
	}
	testTableWithConflictClause = Table{
		Name: "test_table_conflict",
		Columns: []Column{
			{Name: "id", Type: Dbigint},
			{Name: "name", Type: Dvarchar},
			{Name: "age", Type: Dinteger},
		},
		UpsertClause: OnConflict("id").Set("name", "age"),
	}
)

const (
	expectedHeaderPreparedWithUpsert = "INSERT INTO eth.header_cids (block_number, block_hash, parent_hash, cid, td, node_ids, reward, state_root, tx_root, receipt_root, uncles_hash, bloom, timestamp, coinbase, canonical, withdrawals_root) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) ON CONFLICT (block_number, block_hash) DO UPDATE SET (parent_hash, cid, td, node_ids, reward, state_root, tx_root, receipt_root, uncles_hash, bloom, timestamp, coinbase, canonical, withdrawals_root) = ROW(EXCLUDED.parent_hash, EXCLUDED.cid, EXCLUDED.td, EXCLUDED.node_ids, EXCLUDED.reward, EXCLUDED.state_root, EXCLUDED.tx_root, EXCLUDED.receipt_root, EXCLUDED.uncles_hash, EXCLUDED.bloom, EXCLUDED.timestamp, EXCLUDED.coinbase, EXCLUDED.canonical, EXCLUDED.withdrawals_root)"

	expectedHeaderPreparedWithoutUpsert = "INSERT INTO eth.header_cids (block_number, block_hash, parent_hash, cid, td, node_ids, reward, state_root, tx_root, receipt_root, uncles_hash, bloom, timestamp, coinbase, canonical, withdrawals_root) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) ON CONFLICT (block_number, block_hash) DO NOTHING"

	expectedHeaderFmtString = `INSERT INTO eth.header_cids (block_number, block_hash, parent_hash, cid, td, node_ids, reward, state_root, tx_root, receipt_root, uncles_hash, bloom, timestamp, coinbase, canonical, withdrawals_root) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '\x%x', '%s', '%s', %t, '%s');`
)

func TestTable(t *testing.T) {
	require.Equal(t,
		"INSERT INTO test_table (id, name, age) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
		testTable.PreparedInsert(true),
	)
	require.Equal(t,
		"INSERT INTO test_table (id, name, age) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
		testTable.PreparedInsert(false),
	)
	require.Equal(t, "INSERT INTO test_table (id, name, age) VALUES ('%s', '%s', %d);", testTable.FmtStringInsert())

	require.Equal(t,
		"INSERT INTO test_table_conflict (id, name, age) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET (name, age) = ROW(EXCLUDED.name, EXCLUDED.age)",
		testTableWithConflictClause.PreparedInsert(true),
	)
	require.Equal(t,
		"INSERT INTO test_table_conflict (id, name, age) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
		testTableWithConflictClause.PreparedInsert(false),
	)

	require.Equal(t, expectedHeaderPreparedWithUpsert, TableHeader.PreparedInsert(true))
	require.Equal(t, expectedHeaderPreparedWithoutUpsert, TableHeader.PreparedInsert(false))
	require.Equal(t, expectedHeaderFmtString, TableHeader.FmtStringInsert())
}
