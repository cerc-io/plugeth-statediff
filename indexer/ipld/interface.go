package ipld

import "github.com/ipfs/go-cid"

// Check that node satisfies the IPLD Node interface.
var _ IPLD = (*node)(nil)

type node struct {
	cid     cid.Cid
	rawdata []byte
}

type IPLD interface {
	Cid() cid.Cid
	RawData() []byte
}

// RawData returns the RLP encoded bytes of the node.
func (b node) RawData() []byte {
	return b.rawdata
}

// Cid returns the CID of the node.
func (b node) Cid() cid.Cid {
	return b.cid
}
