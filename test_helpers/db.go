package test_helpers

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

// ClearDB is used to empty the IPLD-ETH tables after tests
func ClearDB(db *sqlx.DB) error {
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	statements := []string{
		`TRUNCATE nodes`,
		`TRUNCATE ipld.blocks`,
		`TRUNCATE eth.header_cids`,
		`TRUNCATE eth.uncle_cids`,
		`TRUNCATE eth.transaction_cids`,
		`TRUNCATE eth.receipt_cids`,
		`TRUNCATE eth.state_cids`,
		`TRUNCATE eth.storage_cids`,
		`TRUNCATE eth.log_cids`,
		`TRUNCATE eth.withdrawal_cids`,
		`TRUNCATE eth_meta.watched_addresses`,
	}
	for _, stm := range statements {
		if _, err = tx.Exec(stm); err != nil {
			return fmt.Errorf("error executing `%s`: %w", stm, err)
		}
	}
	return tx.Commit()
}
