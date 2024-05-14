package test_helpers

import (
	"fmt"

	"github.com/cerc-io/plugeth-statediff/indexer/test_helpers"
	"github.com/jmoiron/sqlx"
)

// ClearDB is used to empty the IPLD-ETH tables after tests
func ClearDB(db *sqlx.DB) error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	for _, stm := range test_helpers.TruncateStatements {
		if _, err = tx.Exec(stm); err != nil {
			return fmt.Errorf("error executing `%s`: %w", stm, err)
		}
	}
	return tx.Commit()
}
