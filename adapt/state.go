package adapt

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/trie"

	plugeth "github.com/openrelayxyz/plugeth-utils/core"
)

// StateView exposes a minimal interface for state access for diff building
type StateView interface {
	OpenTrie(root common.Hash) (StateTrie, error)
	ContractCode(codeHash common.Hash) ([]byte, error)
}

// StateTrie is an interface exposing only the necessary methods from state.Trie
type StateTrie interface {
	GetKey([]byte) []byte
	NodeIterator([]byte) (trie.NodeIterator, error)
}

// adapts a state.Database to StateView - used in tests
type stateDatabaseView struct {
	db state.Database
}

var _ StateView = stateDatabaseView{}

func GethStateView(db state.Database) StateView {
	return stateDatabaseView{db}
}

func (a stateDatabaseView) OpenTrie(root common.Hash) (StateTrie, error) {
	return a.db.OpenTrie(common.Hash(root))
}

func (a stateDatabaseView) ContractCode(hash common.Hash) ([]byte, error) {
	return a.db.ContractCode(common.Address{}, hash)
}

// adapts geth Trie to plugeth
type adaptTrie struct {
	plugeth.Trie
}

func NewStateTrie(t plugeth.Trie) StateTrie { return adaptTrie{t} }

func (a adaptTrie) NodeIterator(start []byte) (trie.NodeIterator, error) {
	return NodeIterator(a.Trie.NodeIterator(start)), nil
}

func NodeIterator(it plugeth.NodeIterator) trie.NodeIterator {
	return adaptIter{it}
}

type adaptIter struct {
	plugeth.NodeIterator
}

func (it adaptIter) Hash() common.Hash {
	return common.Hash(it.NodeIterator.Hash())
}

func (it adaptIter) Parent() common.Hash {
	return common.Hash(it.NodeIterator.Parent())
}

func (it adaptIter) AddResolver(resolver trie.NodeResolver) {
	r := func(owner plugeth.Hash, path []byte, hash plugeth.Hash) []byte {
		return resolver(common.Hash(owner), path, common.Hash(hash))
	}
	it.NodeIterator.AddResolver(r)
}
