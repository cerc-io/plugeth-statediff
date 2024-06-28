// VulcanizeDB
// Copyright © 2019 Vulcanize

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

package test_helpers

import (
	"bufio"
	"context"
	"os"
	"testing"

	"github.com/cerc-io/plugeth-statediff/indexer/database/sql"
)

// DedupFile removes duplicates from the given file
func DedupFile(filePath string) error {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}

	stmts := make(map[string]struct{}, 0)
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		s := sc.Text()
		stmts[s] = struct{}{}
	}
	if err != nil {
		return err
	}

	f.Close()

	f, err = os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	for stmt := range stmts {
		f.Write([]byte(stmt + "\n"))
	}

	return nil
}

// TearDownDB is used to tear down the watcher dbs after tests
func TearDownDB(t *testing.T, db sql.Database) {
	ctx := context.Background()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
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
		if _, err = tx.Exec(ctx, stm); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
