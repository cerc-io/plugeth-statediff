package utils

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/trie"
)

type symmDiffIterator struct {
	a, b        iterState // Nodes returned are those in b - a and a - b (keys only)
	yieldFromA  bool      // Whether next node comes from a
	count       int       // Number of nodes scanned on either trie
	eqPathIndex int       // Count index of last pair of equal paths, to detect an updated key
}

// NewSymmetricDifferenceIterator constructs a trie.NodeIterator that iterates over the symmetric difference
// of elements in a and b, i.e., the elements in a that are not in b, and vice versa.
// Returns the iterator, and a pointer to an integer recording the number of nodes seen.
func NewSymmetricDifferenceIterator(a, b trie.NodeIterator) (*symmDiffIterator, *int) {
	it := &symmDiffIterator{
		a: iterState{a, true},
		b: iterState{b, true},
		// common paths are detected by a distance <=1 from this index, so put it out of reach
		eqPathIndex: -2,
	}
	return it, &it.count
}

// pairs an iterator with a cache of its valid status
type iterState struct {
	trie.NodeIterator
	valid bool
}

func (st *iterState) Next(descend bool) bool {
	st.valid = st.NodeIterator.Next(descend)
	return st.valid
}

func (it *symmDiffIterator) curr() *iterState {
	if it.yieldFromA {
		return &it.a
	}
	return &it.b
}

// FromA returns true if the current node is sourced from A.
func (it *symmDiffIterator) FromA() bool {
	return it.yieldFromA
}

// CommonPath returns true if a node with the current path exists in each sub-iterator - i.e. it
// represents an updated node.
func (it *symmDiffIterator) CommonPath() bool {
	return it.count-it.eqPathIndex <= 1
}

func (it *symmDiffIterator) Hash() common.Hash {
	return it.curr().Hash()
}

func (it *symmDiffIterator) Parent() common.Hash {
	return it.curr().Parent()
}

func (it *symmDiffIterator) Leaf() bool {
	return it.curr().Leaf()
}

func (it *symmDiffIterator) LeafKey() []byte {
	return it.curr().LeafKey()
}

func (it *symmDiffIterator) LeafBlob() []byte {
	return it.curr().LeafBlob()
}

func (it *symmDiffIterator) LeafProof() [][]byte {
	return it.curr().LeafProof()
}

func (it *symmDiffIterator) Path() []byte {
	return it.curr().Path()
}

func (it *symmDiffIterator) NodeBlob() []byte {
	return it.curr().NodeBlob()
}

func (it *symmDiffIterator) AddResolver(resolver trie.NodeResolver) {
	panic("not implemented")
}

func (it *symmDiffIterator) Next(bool) bool {
	// NodeIterators start in a "pre-valid" state, so the first Next advances to a valid node.
	if it.count == 0 {
		if it.a.Next(true) {
			it.count++
		}
		if it.b.Next(true) {
			it.count++
		}
	} else {
		if it.curr().Next(true) {
			it.count++
		}
	}
	it.seek()
	return it.a.valid || it.b.valid
}

func (it *symmDiffIterator) seek() {
	// Invariants:
	// - At the end of the function, the sub-iterator with the lexically lesser path
	// points to the next element
	// - Said sub-iterator never points to an element present in the other
	for {
		if !it.b.valid {
			it.yieldFromA = true
			return
		}
		if !it.a.valid {
			it.yieldFromA = false
			return
		}

		cmp := bytes.Compare(it.a.Path(), it.b.Path())
		if cmp == 0 {
			it.eqPathIndex = it.count
			cmp = compareNodes(&it.a, &it.b)
		}
		switch cmp {
		case -1:
			it.yieldFromA = true
			return
		case 1:
			it.yieldFromA = false
			return
		case 0:
			// if A and B have the same path and non-zero hash, they are identical and we can skip
			// the whole subtree
			noHash := it.a.Hash() == common.Hash{}
			if it.a.Next(noHash) {
				it.count++
			}
			if it.b.Next(noHash) {
				it.count++
			}
		}
	}
}

func (it *symmDiffIterator) Error() error {
	if err := it.a.Error(); err != nil {
		return err
	}
	return it.b.Error()
}

func compareNodes(a, b trie.NodeIterator) int {
	if a.Leaf() && !b.Leaf() {
		return -1
	} else if b.Leaf() && !a.Leaf() {
		return 1
	}
	if cmp := bytes.Compare(a.Hash().Bytes(), b.Hash().Bytes()); cmp != 0 {
		return cmp
	}
	if a.Leaf() && b.Leaf() {
		return bytes.Compare(a.LeafBlob(), b.LeafBlob())
	}
	return 0
}
