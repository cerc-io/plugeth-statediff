// VulcanizeDB
// Copyright © 2024 Vulcanize

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

package ipld

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	mh "github.com/multiformats/go-multihash"
)

// EncodeHeader converts a *types.Header into an IPLD node
func EncodeHeader(header *types.Header) (IPLD, error) {
	headerRLP, err := rlp.EncodeToBytes(header)
	if err != nil {
		return nil, err
	}
	c, err := RawdataToCid(MEthHeader, headerRLP, mh.KECCAK_256)
	if err != nil {
		return nil, err
	}
	return &node{
		cid:     c,
		rawdata: headerRLP,
	}, nil
}

// EncodeTx converts a *types.Transaction to an IPLD node
func EncodeTx(tx *types.Transaction) (IPLD, error) {
	txRaw, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	c, err := RawdataToCid(MEthTx, txRaw, mh.KECCAK_256)
	if err != nil {
		return nil, err
	}
	return &node{
		cid:     c,
		rawdata: txRaw,
	}, nil
}

// EncodeReceipt converts a types.Receipt to an IPLD node
func EncodeReceipt(receipt *types.Receipt) (IPLD, error) {
	rctRaw, err := receipt.MarshalBinary()
	if err != nil {
		return nil, err
	}
	c, err := RawdataToCid(MEthTxReceipt, rctRaw, mh.KECCAK_256)
	if err != nil {
		return nil, err
	}
	return &node{
		cid:     c,
		rawdata: rctRaw,
	}, nil
}

// EncodeLog converts a Log to an IPLD node
func EncodeLog(log *types.Log) (IPLD, error) {
	logRaw, err := rlp.EncodeToBytes(log)
	if err != nil {
		return nil, err
	}
	c, err := RawdataToCid(MEthLog, logRaw, mh.KECCAK_256)
	if err != nil {
		return nil, err
	}
	return &node{
		cid:     c,
		rawdata: logRaw,
	}, nil
}

func EncodeWithdrawal(w *types.Withdrawal) (IPLD, error) {
	wRaw, err := rlp.EncodeToBytes(w)
	if err != nil {
		return nil, err
	}
	c, err := RawdataToCid(MEthWithdrawal, wRaw, mh.KECCAK_256)
	if err != nil {
		return nil, err
	}
	return &node{
		cid:     c,
		rawdata: wRaw,
	}, nil
}
