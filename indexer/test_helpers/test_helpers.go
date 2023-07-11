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

	"github.com/ethereum/go-ethereum/statediff/indexer/database/sql"
)

// ListContainsString used to check if a list of strings contains a particular string
func ListContainsString(sss []string, s string) bool {
	for _, str := range sss {
		if s == str {
			return true
		}
	}
	return false
}

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

	_, err = tx.Exec(ctx, `DELETE FROM eth.header_cids`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM eth.uncle_cids`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM eth.transaction_cids`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM eth.receipt_cids`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM eth.state_cids`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM eth.storage_cids`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM eth.log_cids`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM ipld.blocks`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM nodes`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DELETE FROM eth_meta.watched_addresses`)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(ctx)
	if err != nil {
		t.Fatal(err)
	}
}
