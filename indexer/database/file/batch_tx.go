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

import "github.com/cerc-io/plugeth-statediff/utils/log"

// BatchTx wraps a void with the state necessary for building the tx concurrently during trie difference iteration
type BatchTx struct {
	blockNum   string
	fileWriter FileWriter
}

// Submit satisfies indexer.AtomicTx
func (tx *BatchTx) Submit() error {
	tx.fileWriter.Flush()
	return nil
}

func (tx *BatchTx) BlockNumber() string {
	return tx.blockNum
}

func (tx *BatchTx) RollbackOnFailure(err error) {
	if p := recover(); p != nil {
		log.Info("panic detected before tx submission, but rollback not supported", "panic", p)
		panic(p)
	} else if err != nil {
		log.Info("error detected before tx submission, but rollback not supported", "error", err)
	}
}
