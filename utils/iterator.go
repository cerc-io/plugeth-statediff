package utils

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/trie"
)

type SymmDiffIterator struct {
	a, b iterState // Nodes returned are those in b - a and a - b (keys only)
	SymmDiffState
}

// pairs an iterator with a cache of its valid status
type iterState struct {
	trie.NodeIterator
	valid bool
}

// SymmDiffState exposes state specific to symmetric difference iteration, which is not accessible
// from the NodeIterator interface. This includes the number of nodes seen, whether the current key
// is common to both A and B, and whether the current node is sourced from A or B.
type SymmDiffState struct {
	yieldFromA  bool // Whether next node comes from a
	count       int  // Number of nodes scanned on either trie
	eqPathIndex int  // Count index of last pair of equal paths, to detect an updated key
}

// NewSymmetricDifferenceIterator constructs a trie.NodeIterator that iterates over the symmetric difference
// of elements in a and b, i.e., the elements in a that are not in b, and vice versa.
// Returns the iterator, and a pointer to an auxiliary object for accessing the state not exposed by the NodeIterator interface recording the number of nodes seen.
func NewSymmetricDifferenceIterator(a, b trie.NodeIterator) *SymmDiffIterator {
	it := &SymmDiffIterator{
		a: iterState{a, true},
		b: iterState{b, true},
		// common paths are detected by a distance <=1 between count and this index, so we start at -2
		SymmDiffState: SymmDiffState{eqPathIndex: -2},
	}
	return it
}

func (st *iterState) Next(descend bool) bool {
	st.valid = st.NodeIterator.Next(descend)
	return st.valid
}

// FromA returns true if the current node is sourced from A.
func (it *SymmDiffState) FromA() bool {
	return it.yieldFromA
}

// CommonPath returns true if a node with the current path exists in each sub-iterator - i.e. it
// represents an updated node.
func (it *SymmDiffState) CommonPath() bool {
	return it.count-it.eqPathIndex <= 1
}

// Count returns the number of nodes seen.
func (it *SymmDiffState) Count() int {
	return it.count
}

func (it *SymmDiffIterator) curr() *iterState {
	if it.yieldFromA {
		return &it.a
	}
	return &it.b
}

func (it *SymmDiffIterator) Hash() common.Hash {
	return it.curr().Hash()
}

func (it *SymmDiffIterator) Parent() common.Hash {
	return it.curr().Parent()
}

func (it *SymmDiffIterator) Leaf() bool {
	return it.curr().Leaf()
}

func (it *SymmDiffIterator) LeafKey() []byte {
	return it.curr().LeafKey()
}

func (it *SymmDiffIterator) LeafBlob() []byte {
	return it.curr().LeafBlob()
}

func (it *SymmDiffIterator) LeafProof() [][]byte {
	return it.curr().LeafProof()
}

func (it *SymmDiffIterator) Path() []byte {
	return it.curr().Path()
}

func (it *SymmDiffIterator) NodeBlob() []byte {
	return it.curr().NodeBlob()
}

func (it *SymmDiffIterator) AddResolver(resolver trie.NodeResolver) {
	panic("not implemented")
}

func (it *SymmDiffIterator) Next(bool) bool {
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

func (it *SymmDiffIterator) seek() {
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

func (it *SymmDiffIterator) Error() error {
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

// AlwaysBState returns a dummy SymmDiffState that indicates all elements are from B, and have no
// common paths with A. This is equivalent to a diff against an empty A.
func AlwaysBState() SymmDiffState {
	return SymmDiffState{yieldFromA: false, eqPathIndex: -2}
}
