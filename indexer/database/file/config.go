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

package file

import (
	"fmt"
	"strings"

	"github.com/cerc-io/plugeth-statediff/indexer/shared"
)

// Config holds params for writing out CSV or SQL files
type Config struct {
	Mode                     FileMode
	OutputDir                string
	FilePath                 string
	WatchedAddressesFilePath string
}

// FileMode to explicitly type the mode of file writer we are using
type FileMode string

const (
	CSV     FileMode = "CSV"
	SQL     FileMode = "SQL"
	Invalid FileMode = "Invalid"
)

// ResolveFileMode resolves a FileMode from a provided string
func ResolveFileMode(str string) (FileMode, error) {
	switch strings.ToLower(str) {
	case "csv":
		return CSV, nil
	case "sql":
		return SQL, nil
	default:
		return Invalid, fmt.Errorf("unrecognized file type string: %s", str)
	}
}

// Set satisfies flag.Value
func (f *FileMode) Set(v string) (err error) {
	*f, err = ResolveFileMode(v)
	return
}

// Set satisfies flag.Value
func (f *FileMode) String() string {
	return strings.ToLower(string(*f))
}

// Type satisfies interfaces.Config
func (c Config) Type() shared.DBType {
	return shared.FILE
}

// CSVTestConfig config for unit tests
var CSVTestConfig = Config{
	Mode:                     CSV,
	OutputDir:                "./statediffing_test",
	WatchedAddressesFilePath: "./statediffing_watched_addresses_test_file.csv",
}

// SQLTestConfig config for unit tests
var SQLTestConfig = Config{
	Mode:                     SQL,
	FilePath:                 "./statediffing_test_file.sql",
	WatchedAddressesFilePath: "./statediffing_watched_addresses_test_file.sql",
}
