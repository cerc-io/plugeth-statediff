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

package indexer

import (
	"context"
	"fmt"

	"github.com/cerc-io/plugeth-statediff/utils/log"
	"github.com/ethereum/go-ethereum/params"

	"github.com/cerc-io/plugeth-statediff/indexer/database/dump"
	"github.com/cerc-io/plugeth-statediff/indexer/database/file"
	"github.com/cerc-io/plugeth-statediff/indexer/database/sql"
	"github.com/cerc-io/plugeth-statediff/indexer/database/sql/postgres"
	"github.com/cerc-io/plugeth-statediff/indexer/interfaces"
	"github.com/cerc-io/plugeth-statediff/indexer/node"
	"github.com/cerc-io/plugeth-statediff/indexer/shared"
)

// NewStateDiffIndexer creates and returns an implementation of the StateDiffIndexer interface.
// The returned indexer is used to process state diffs and write them to a database.
// The returned SQL database, if non-nil, is the indexer's backing database.
// `ctx` is used to cancel an underlying DB connection.
// `chainConfig` is used when processing chain state.
// `nodeInfo` contains metadata on the Ethereum node, which is inserted with the indexed state.
// `config` contains configuration specific to the indexer.
// `isDiff` means to mark state nodes as belonging to an incremental diff, as opposed to a full snapshot.
func NewStateDiffIndexer(
	ctx context.Context,
	chainConfig *params.ChainConfig,
	nodeInfo node.Info,
	config interfaces.Config,
	isDiff bool,
) (
	sql.Database,
	interfaces.StateDiffIndexer,
	error,
) {
	switch config.Type() {
	case shared.FILE:
		log.Info("Starting statediff service in SQL file writing mode")
		fc, ok := config.(file.Config)
		if !ok {
			return nil, nil, fmt.Errorf("file config is not the correct type: got %T, expected %T", config, file.Config{})
		}
		ind, err := file.NewStateDiffIndexer(chainConfig, fc, nodeInfo, isDiff)
		return nil, ind, err
	case shared.POSTGRES:
		log.Info("Starting statediff service in Postgres writing mode")
		pgc, ok := config.(postgres.Config)
		if !ok {
			return nil, nil, fmt.Errorf("postgres config is not the correct type: got %T, expected %T", config, postgres.Config{})
		}
		var err error
		var driver sql.Driver
		switch pgc.Driver {
		case postgres.PGX:
			driver, err = postgres.ConnectPGXDriver(ctx, pgc, nodeInfo)
			if err != nil {
				return nil, nil, err
			}
		case postgres.SQLX:
			driver, err = postgres.ConnectSQLXDriver(ctx, pgc, nodeInfo)
			if err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("unrecognized Postgres driver type: %s", pgc.Driver)
		}
		db := postgres.NewPostgresDB(driver, pgc.Upsert)
		ind, err := sql.NewStateDiffIndexer(ctx, chainConfig, db, isDiff)
		return db, ind, err
	case shared.DUMP:
		log.Info("Starting statediff service in data dump mode")
		dumpc, ok := config.(dump.Config)
		if !ok {
			return nil, nil, fmt.Errorf("dump config is not the correct type: got %T, expected %T", config, dump.Config{})
		}
		return nil, dump.NewStateDiffIndexer(chainConfig, dumpc), nil
	default:
		return nil, nil, fmt.Errorf("unrecognized database type: %s", config.Type())
	}
}
