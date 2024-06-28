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

package shared

import (
	"github.com/ethereum/go-ethereum/common"
)

// HandleZeroAddrPointer will return an empty string for a nil address pointer
func HandleZeroAddrPointer(to *common.Address) string {
	if to == nil {
		return ""
	}
	return to.String()
}

// HandleZeroAddr will return an empty string for a 0 value address
func HandleZeroAddr(to common.Address) string {
	if to == (common.Address{}) {
		return ""
	}
	return to.String()
}

// MaybeStringHash calls String on its argument and returns a pointer to the result.
// When passed nil, it returns nil.
func MaybeStringHash(hash *common.Hash) string {
	if hash == nil {
		return ""
	}
	return hash.String()
}
