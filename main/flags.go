package main

import (
	"context"
	"flag"
	"os"

	"github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/indexer/database/dump"
	"github.com/cerc-io/plugeth-statediff/indexer/database/file"
	"github.com/cerc-io/plugeth-statediff/indexer/database/sql/postgres"
	"github.com/cerc-io/plugeth-statediff/indexer/interfaces"
	"github.com/cerc-io/plugeth-statediff/indexer/shared"
	"github.com/cerc-io/plugeth-statediff/utils"
)

var (
	Flags = *flag.NewFlagSet("statediff", flag.PanicOnError)

	enableStatediff bool
	config          = statediff.Config{
		Context: context.Background(),
	}
	dbType     = shared.POSTGRES
	dbDumpDst  = dump.STDOUT
	dbConfig   = postgres.Config{Driver: postgres.PGX}
	fileConfig = file.Config{Mode: file.CSV}
)

func init() {
	Flags.BoolVar(&enableStatediff,
		"statediff", false,
		"Enables the processing of state diffs between each block",
	)
	Flags.BoolVar(&config.EnableWriteLoop,
		"statediff.writing", false,
		"Activates progressive writing of state diffs to database as new blocks are synced",
	)
	Flags.StringVar(&config.ID,
		"statediff.db.nodeid", "",
		"Node ID to use when writing state diffs to database",
	)
	Flags.StringVar(&config.ClientName,
		"statediff.db.clientname", "go-ethereum",
		"Client name to use when writing state diffs to database",
	)
	Flags.UintVar(&config.NumWorkers,
		"statediff.workers", 1,
		"Number of concurrent workers to use during statediff processing (default 1)",
	)
	Flags.BoolVar(&config.WaitForSync,
		"statediff.waitforsync", false,
		"Should the statediff service wait for geth to catch up to the head of the chain?",
	)

	Flags.Var(&dbType,
		"statediff.db.type",
		"Statediff database type (current options: postgres, file, dump)",
	)
	Flags.StringVar(&dbDumpDst,
		"statediff.dump.dst", "stdout",
		"Statediff database dump destination (default is stdout)",
	)

	Flags.Var(&dbConfig.Driver,
		"statediff.db.driver",
		"Statediff database driver type",
	)
	Flags.StringVar(&dbConfig.Hostname,
		"statediff.db.host", "localhost",
		"Statediff database hostname/ip",
	)
	Flags.IntVar(&dbConfig.Port,
		"statediff.db.port", 5432,
		"Statediff database port",
	)
	Flags.StringVar(&dbConfig.DatabaseName,
		"statediff.db.name", "",
		"Statediff database name",
	)
	Flags.StringVar(&dbConfig.Password,
		"statediff.db.password", "",
		"Statediff database password",
	)
	Flags.StringVar(&dbConfig.Username,
		"statediff.db.user", "postgres",
		"Statediff database username",
	)
	Flags.DurationVar(&dbConfig.MaxConnLifetime,
		"statediff.db.maxconnlifetime", 0,
		"Statediff database maximum connection lifetime (in seconds)",
	)
	Flags.DurationVar(&dbConfig.MaxConnIdleTime,
		"statediff.db.maxconnidletime", 0,
		"Statediff database maximum connection idle time (in seconds)",
	)
	Flags.IntVar(&dbConfig.MaxConns,
		"statediff.db.maxconns", 0,
		"Statediff database maximum connections",
	)
	Flags.IntVar(&dbConfig.MinConns,
		"statediff.db.minconns", 0,
		"Statediff database minimum connections",
	)
	Flags.IntVar(&dbConfig.MaxIdle,
		"statediff.db.maxidleconns", 0,
		"Statediff database maximum idle connections",
	)
	Flags.DurationVar(&dbConfig.ConnTimeout,
		"statediff.db.conntimeout", 0,
		"Statediff database connection timeout (in seconds)",
	)
	Flags.BoolVar(&dbConfig.Upsert,
		"statediff.db.upsert", false,
		"Should the statediff service overwrite data existing in the database?",
	)
	Flags.BoolVar(&dbConfig.CopyFrom,
		"statediff.db.copyfrom", false,
		"Should the statediff service use COPY FROM for multiple inserts? (Note: pgx only)",
	)
	Flags.BoolVar(&dbConfig.LogStatements,
		"statediff.db.logstatements", false,
		"Should the statediff service log all database statements? (Note: pgx only)",
	)

	Flags.Var(&fileConfig.Mode,
		"statediff.file.mode",
		"Statediff file writing mode (current options: csv, sql)",
	)
	Flags.StringVar(&fileConfig.OutputDir,
		"statediff.file.csvdir", "",
		"Full path of output directory to write statediff data out to when operating in csv file mode",
	)
	Flags.StringVar(&fileConfig.FilePath,
		"statediff.file.path", "",
		"Full path (including filename) to write statediff data out to when operating in sql file mode",
	)
	Flags.StringVar(&fileConfig.WatchedAddressesFilePath,
		"statediff.file.wapath", "",
		"Full path (including filename) to write statediff watched addresses out to when operating in file mode",
	)
}

func GetConfig() statediff.Config {
	initConfig()
	return config
}

func initConfig() {
	if !enableStatediff {
		config = statediff.Config{}
		return
	}

	if config.ID == "" {
		utils.Fatalf("Must specify node ID for statediff DB output")
	}

	var indexerConfig interfaces.Config
	switch dbType {
	case shared.FILE:
		indexerConfig = fileConfig
	case shared.POSTGRES:
		dbConfig.ID = config.ID
		dbConfig.ClientName = config.ClientName
		indexerConfig = dbConfig
	case shared.DUMP:
		switch dbDumpDst {
		case dump.STDERR:
			indexerConfig = dump.Config{Dump: os.Stdout}
		case dump.STDOUT:
			indexerConfig = dump.Config{Dump: os.Stderr}
		case dump.DISCARD:
			indexerConfig = dump.Config{Dump: dump.Discard}
		default:
			utils.Fatalf("unrecognized dump destination: %s", dbDumpDst)
		}
	default:
		utils.Fatalf("unrecognized database type: %s", dbType)
	}
	config.IndexerConfig = indexerConfig
}
