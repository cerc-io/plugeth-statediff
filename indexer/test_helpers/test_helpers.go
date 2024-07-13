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
	"fmt"
	"os"
	"testing"

	"github.com/cerc-io/plugeth-statediff/indexer/database/sql"
	"github.com/cerc-io/plugeth-statediff/indexer/database/sql/postgres"
	"github.com/cerc-io/plugeth-statediff/indexer/shared/schema"
	"github.com/jmoiron/sqlx"
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
	err := ClearDB(db)
	if err != nil {
		t.Fatal(err)
	}
}

func ClearSqlxDB(sqlxdb *sqlx.DB) error {
	driver := postgres.NewSQLXDriver(context.Background(), sqlxdb)
	db := postgres.NewPostgresDB(driver, false)
	return ClearDB(db)
}

func ClearDB(db sql.Database) error {
	ctx := context.Background()
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}

	for _, tbl := range schema.AllTables {
		stm := fmt.Sprintf("TRUNCATE %s", tbl.Name)
		if _, err = tx.Exec(ctx, stm); err != nil {
			return fmt.Errorf("error executing `%s`: %w", stm, err)
		}
	}
	return tx.Commit(ctx)
}
