package utils

import (
	"github.com/openrelayxyz/plugeth-utils/core"
	plugeth_types "github.com/openrelayxyz/plugeth-utils/restricted/types"

	"github.com/ethereum/go-ethereum/core/types"
)

type adaptTrieHasher struct {
	types.TrieHasher
}

func AdaptTrieHasher(th types.TrieHasher) plugeth_types.TrieHasher {
	return &adaptTrieHasher{th}
}

// TrieHasher is the tool used to calculate the hash of derivable list.
// This is internal, do not use.
type TrieHasher interface {
	Reset()
	Update([]byte, []byte) error
	Hash() core.Hash
}

func (ath *adaptTrieHasher) Hash() core.Hash {
	return core.Hash(ath.TrieHasher.Hash())
}
