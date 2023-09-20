package utils_test

import (
	"testing"

	"github.com/cerc-io/eth-testing/chaindata/mainnet"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerc-io/plugeth-statediff/test_helpers"
	"github.com/cerc-io/plugeth-statediff/utils"
)

type kvs struct{ k, v string }

var (
	testdata1 = []kvs{
		{"barb", "ba"},
		{"bard", "bc"},
		{"bars", "bb"},
		{"bar", "b"},
		{"fab", "z"},
		{"food", "ab"},
		{"foo", "a"},
	}

	testdata2 = []kvs{
		{"aardvark", "c"},
		{"bar", "b"},
		{"barb", "bd"},
		{"bars", "be"},
		{"fab", "z"},
		{"foo", "a"},
		{"foos", "aa"},
		{"jars", "d"},
	}
)

func TestSymmetricDifferenceIterator(t *testing.T) {
	t.Run("with no difference", func(t *testing.T) {
		db := trie.NewDatabase(rawdb.NewMemoryDatabase())
		triea := trie.NewEmpty(db)
		di, count := utils.NewSymmetricDifferenceIterator(triea.NodeIterator(nil), triea.NodeIterator(nil))
		for di.Next(true) {
			t.Errorf("iterator should not yield any elements")
		}
		assert.Equal(t, 0, *count)

		triea.MustUpdate([]byte("foo"), []byte("bar"))
		di, count = utils.NewSymmetricDifferenceIterator(triea.NodeIterator(nil), triea.NodeIterator(nil))
		for di.Next(true) {
			t.Errorf("iterator should not yield any elements")
		}
		assert.Equal(t, 2, *count)

		trieb := trie.NewEmpty(db)
		di, count = utils.NewSymmetricDifferenceIterator(
			triea.NodeIterator([]byte("jars")),
			trieb.NodeIterator(nil))
		for di.Next(true) {
			t.Errorf("iterator should not yield any elements, but got key %s", di.Path())
		}
		assert.Equal(t, 0, *count)

		// // TODO will fail until merged: https://github.com/ethereum/go-ethereum/pull/27838
		// di, count = utils.NewSymmetricDifferenceIterator(
		// 	triea.NodeIterator([]byte("food")),
		// 	trieb.NodeIterator(nil))
		// for di.Next(true) {
		// 	t.Errorf("iterator should not yield any elements, but got key %s", di.Path())
		// }
		// assert.Equal(t, 0, *count)
	})

	t.Run("small difference", func(t *testing.T) {
		dba := trie.NewDatabase(rawdb.NewMemoryDatabase())
		triea := trie.NewEmpty(dba)

		dbb := trie.NewDatabase(rawdb.NewMemoryDatabase())
		trieb := trie.NewEmpty(dbb)
		trieb.MustUpdate([]byte("foo"), []byte("bar"))

		di, count := utils.NewSymmetricDifferenceIterator(triea.NodeIterator(nil), trieb.NodeIterator(nil))
		leaves := 0
		for di.Next(true) {
			if di.Leaf() {
				assert.False(t, di.CommonPath())
				assert.Equal(t, "foo", string(di.LeafKey()))
				assert.Equal(t, "bar", string(di.LeafBlob()))
				leaves++
			}
		}
		assert.Equal(t, 1, leaves)
		assert.Equal(t, 2, *count)

		trieb.MustUpdate([]byte("quux"), []byte("bars"))
		di, count = utils.NewSymmetricDifferenceIterator(triea.NodeIterator(nil), trieb.NodeIterator([]byte("quux")))
		leaves = 0
		for di.Next(true) {
			if di.Leaf() {
				assert.False(t, di.CommonPath())
				assert.Equal(t, "quux", string(di.LeafKey()))
				assert.Equal(t, "bars", string(di.LeafBlob()))
				leaves++
			}
		}
		assert.Equal(t, 1, leaves)
		assert.Equal(t, 1, *count)
	})

	dba := trie.NewDatabase(rawdb.NewMemoryDatabase())
	triea := trie.NewEmpty(dba)
	for _, val := range testdata1 {
		triea.MustUpdate([]byte(val.k), []byte(val.v))
	}
	dbb := trie.NewDatabase(rawdb.NewMemoryDatabase())
	trieb := trie.NewEmpty(dbb)
	for _, val := range testdata2 {
		trieb.MustUpdate([]byte(val.k), []byte(val.v))
	}

	onlyA := make(map[string]string)
	onlyB := make(map[string]string)
	var deletions, creations []string
	it, _ := utils.NewSymmetricDifferenceIterator(triea.NodeIterator(nil), trieb.NodeIterator(nil))
	for it.Next(true) {
		if !it.Leaf() {
			continue
		}
		key, value := string(it.LeafKey()), string(it.LeafBlob())
		if it.FromA() {
			onlyA[key] = value
			if !it.CommonPath() {
				deletions = append(deletions, key)
			}
		} else {
			onlyB[key] = value
			if !it.CommonPath() {
				creations = append(creations, key)
			}
		}
	}

	expectedOnlyA := map[string]string{
		"barb": "ba",
		"bard": "bc",
		"bars": "bb",
		"food": "ab",
	}
	expectedOnlyB := map[string]string{
		"aardvark": "c",
		"barb":     "bd",
		"bars":     "be",
		"foos":     "aa",
		"jars":     "d",
	}
	expectedDeletions := []string{
		"bard",
		"food",
	}
	expectedCreations := []string{
		"aardvark",
		"foos",
		"jars",
	}
	assert.Equal(t, expectedOnlyA, onlyA)
	assert.Equal(t, expectedOnlyB, onlyB)
	assert.Equal(t, expectedDeletions, deletions)
	assert.Equal(t, expectedCreations, creations)
}

// compare the paths traversed by the geth difference iterator and symmetric difference iterator
// within a sample of mainnet data.
func TestCompareDifferenceIterators(t *testing.T) {
	test_helpers.QuietLogs()

	db := rawdb.NewMemoryDatabase()
	core.DefaultGenesisBlock().MustCommit(db)
	blocks := mainnet.GetBlocks()
	chain, _ := core.NewBlockChain(db, nil, nil, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	_, err := chain.InsertChain(blocks[1:])
	if err != nil {
		t.Fatal(err)
	}
	treeA, err := chain.StateCache().OpenTrie(blocks[1].Root())
	if err != nil {
		t.Fatal(err)
	}
	treeB, err := chain.StateCache().OpenTrie(blocks[2].Root())
	if err != nil {
		t.Fatal(err)
	}

	// collect the paths of nodes exclusive to A and B separately, then make sure the symmetric
	// iterator produces the same sets
	var pathsA, pathsB [][]byte
	itBonly, _ := trie.NewDifferenceIterator(treeA.NodeIterator(nil), treeB.NodeIterator(nil))
	for itBonly.Next(true) {
		pathsB = append(pathsB, itBonly.Path())
	}
	itAonly, _ := trie.NewDifferenceIterator(treeB.NodeIterator(nil), treeA.NodeIterator(nil))
	for itAonly.Next(true) {
		pathsA = append(pathsA, itAonly.Path())
	}

	itSym, _ := utils.NewSymmetricDifferenceIterator(treeA.NodeIterator(nil), treeB.NodeIterator(nil))
	var idxA, idxB int
	for itSym.Next(true) {
		if itSym.FromA() {
			require.Equal(t, pathsA[idxA], itSym.Path())
			idxA++
		} else {
			require.Equal(t, pathsB[idxB], itSym.Path())
			idxB++
		}
	}
	require.Equal(t, len(pathsA), idxA)
	require.Equal(t, len(pathsB), idxB)
}
