// VulcanizeDB
// Copyright © 2022 Vulcanize

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

package file_test

import (
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerc-io/plugeth-statediff/indexer/database/file"
	"github.com/cerc-io/plugeth-statediff/indexer/database/sql/postgres"
	"github.com/cerc-io/plugeth-statediff/indexer/mocks"
	"github.com/cerc-io/plugeth-statediff/indexer/test"
)

// docker bind mount is slow to sync files
var delayForDockerSync = 1 * time.Second

func setupCSVIndexer(t *testing.T) {
	if _, err := os.Stat(file.CSVTestConfig.OutputDir); !errors.Is(err, os.ErrNotExist) {
		err := os.RemoveAll(file.CSVTestConfig.OutputDir)
		require.NoError(t, err)
	}

	if _, err := os.Stat(file.CSVTestConfig.WatchedAddressesFilePath); !errors.Is(err, os.ErrNotExist) {
		err := os.Remove(file.CSVTestConfig.WatchedAddressesFilePath)
		require.NoError(t, err)
	}

	ind, err = file.NewStateDiffIndexer(mocks.TestChainConfig, file.CSVTestConfig, test.LegacyNodeInfo, true)
	require.NoError(t, err)

	db, err = postgres.SetupSQLXDB()
	if err != nil {
		t.Fatal(err)
	}
}

func setupCSV(t *testing.T) {
	setupCSVIndexer(t)
	test.SetupTestData(t, ind)
	t.Cleanup(func() { tearDownCSV(t) })
	time.Sleep(delayForDockerSync)
}

func setupCSVNonCanonical(t *testing.T) {
	setupCSVIndexer(t)
	test.SetupTestDataNonCanonical(t, ind)
	t.Cleanup(func() { tearDownCSV(t) })
	time.Sleep(delayForDockerSync)
}

func TestCSVFileIndexer(t *testing.T) {
	t.Run("Publish and index header IPLDs in a single tx", func(t *testing.T) {
		setupCSV(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexHeaderIPLDs(t, db)
	})

	t.Run("Publish and index transaction IPLDs in a single tx", func(t *testing.T) {
		setupCSV(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexTransactionIPLDs(t, db)
	})

	t.Run("Publish and index log IPLDs for multiple receipt of a specific block", func(t *testing.T) {
		setupCSV(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexLogIPLDs(t, db)
	})

	t.Run("Publish and index receipt IPLDs in a single tx", func(t *testing.T) {
		setupCSV(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexReceiptIPLDs(t, db)
	})

	t.Run("Publish and index withdrawal IPLDs in a single tx", func(t *testing.T) {
		setupCSV(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexWithdrawalIPLDs(t, db)
	})

	t.Run("Publish and index state IPLDs in a single tx", func(t *testing.T) {
		setupCSV(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexStateIPLDs(t, db)
	})

	t.Run("Publish and index storage IPLDs in a single tx", func(t *testing.T) {
		setupCSV(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexStorageIPLDs(t, db)
	})
}

func TestCSVFileIndexerNonCanonical(t *testing.T) {
	t.Run("Publish and index header", func(t *testing.T) {
		setupCSVNonCanonical(t)
		dumpCSVFileData(t)

		test.TestPublishAndIndexHeaderNonCanonical(t, db)
	})

	t.Run("Publish and index transactions", func(t *testing.T) {
		setupCSVNonCanonical(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexTransactionsNonCanonical(t, db)
	})

	t.Run("Publish and index receipts", func(t *testing.T) {
		setupCSVNonCanonical(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexReceiptsNonCanonical(t, db)
	})

	t.Run("Publish and index logs", func(t *testing.T) {
		setupCSVNonCanonical(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexLogsNonCanonical(t, db)
	})

	t.Run("Publish and index state nodes", func(t *testing.T) {
		setupCSVNonCanonical(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexStateNonCanonical(t, db)
	})

	t.Run("Publish and index storage nodes", func(t *testing.T) {
		setupCSVNonCanonical(t)
		dumpCSVFileData(t)

		test.DoTestPublishAndIndexStorageNonCanonical(t, db)
	})
}

func TestCSVFileWatchAddressMethods(t *testing.T) {
	setupCSVIndexer(t)
	defer tearDownCSV(t)

	t.Run("Load watched addresses (empty table)", func(t *testing.T) {
		test.TestLoadEmptyWatchedAddresses(t, ind)
	})

	t.Run("Insert watched addresses", func(t *testing.T) {
		args := mocks.GetInsertWatchedAddressesArgs()
		err = ind.InsertWatchedAddresses(args, big.NewInt(int64(mocks.WatchedAt1)))
		require.NoError(t, err)

		resetAndDumpWatchedAddressesCSVFileData(t)

		test.TestInsertWatchedAddresses(t, db)
	})

	t.Run("Insert watched addresses (some already watched)", func(t *testing.T) {
		args := mocks.GetInsertAlreadyWatchedAddressesArgs()
		err = ind.InsertWatchedAddresses(args, big.NewInt(int64(mocks.WatchedAt2)))
		require.NoError(t, err)

		resetAndDumpWatchedAddressesCSVFileData(t)

		test.TestInsertAlreadyWatchedAddresses(t, db)
	})

	t.Run("Remove watched addresses", func(t *testing.T) {
		args := mocks.GetRemoveWatchedAddressesArgs()
		err = ind.RemoveWatchedAddresses(args)
		require.NoError(t, err)

		resetAndDumpWatchedAddressesCSVFileData(t)

		test.TestRemoveWatchedAddresses(t, db)
	})

	t.Run("Remove watched addresses (some non-watched)", func(t *testing.T) {
		args := mocks.GetRemoveNonWatchedAddressesArgs()
		err = ind.RemoveWatchedAddresses(args)
		require.NoError(t, err)

		resetAndDumpWatchedAddressesCSVFileData(t)

		test.TestRemoveNonWatchedAddresses(t, db)
	})

	t.Run("Set watched addresses", func(t *testing.T) {
		args := mocks.GetSetWatchedAddressesArgs()
		err = ind.SetWatchedAddresses(args, big.NewInt(int64(mocks.WatchedAt2)))
		require.NoError(t, err)

		resetAndDumpWatchedAddressesCSVFileData(t)

		test.TestSetWatchedAddresses(t, db)
	})

	t.Run("Set watched addresses (some already watched)", func(t *testing.T) {
		args := mocks.GetSetAlreadyWatchedAddressesArgs()
		err = ind.SetWatchedAddresses(args, big.NewInt(int64(mocks.WatchedAt3)))
		require.NoError(t, err)

		resetAndDumpWatchedAddressesCSVFileData(t)

		test.TestSetAlreadyWatchedAddresses(t, db)
	})

	t.Run("Load watched addresses", func(t *testing.T) {
		test.TestLoadWatchedAddresses(t, ind)
	})

	t.Run("Clear watched addresses", func(t *testing.T) {
		err = ind.ClearWatchedAddresses()
		require.NoError(t, err)

		resetAndDumpWatchedAddressesCSVFileData(t)

		test.TestClearWatchedAddresses(t, db)
	})

	t.Run("Clear watched addresses (empty table)", func(t *testing.T) {
		err = ind.ClearWatchedAddresses()
		require.NoError(t, err)

		resetAndDumpWatchedAddressesCSVFileData(t)

		test.TestClearEmptyWatchedAddresses(t, db)
	})
}
