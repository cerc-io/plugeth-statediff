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

package dump

import (
	"fmt"
	"io"
	"strings"

	"github.com/cerc-io/plugeth-statediff/indexer/shared"
)

// Config for data dump
type Config struct {
	Dump io.WriteCloser
}

// DumpType to explicitly type the dump destination
type DumpType string

const (
	STDOUT  = "Stdout"
	STDERR  = "Stderr"
	DISCARD = "Discard"
	INVALID = "Invalid"
)

// Type satisfies interfaces.Config
func (c Config) Type() shared.DBType {
	return shared.DUMP
}

// ResolveDumpType resolves the dump type for the provided string
func ResolveDumpType(str string) (DumpType, error) {
	switch strings.ToLower(str) {
	case "stdout", "out", "std out":
		return STDOUT, nil
	case "stderr", "err", "std err":
		return STDERR, nil
	case "discard", "void", "devnull", "dev null":
		return DISCARD, nil
	default:
		return INVALID, fmt.Errorf("unrecognized dump type: %s", str)
	}
}

// Set satisfies flag.Value
func (d *DumpType) Set(v string) (err error) {
	*d, err = ResolveDumpType(v)
	return
}

// String satisfies flag.Value
func (d *DumpType) String() string {
	return strings.ToLower(string(*d))
}

// discardWrapper wraps io.Discard with io.Closer
type discardWrapper struct{ io.Writer }

var Discard = discardWrapper{io.Discard}

// Close satisfies io.Closer
func (discardWrapper) Close() error {
	return nil
}
