package utils_test

import (
	"testing"

	"github.com/cerc-io/eth-testing/chains/mainnet"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/triedb"
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
		db := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
		triea := trie.NewEmpty(db)

		ita, err := triea.NodeIterator(nil)
		assert.NoError(t, err)
		itb, err := triea.NodeIterator(nil)
		assert.NoError(t, err)
		di := utils.NewSymmetricDifferenceIterator(ita, itb)
		for di.Next(true) {
			t.Errorf("iterator should not yield any elements")
		}
		assert.Equal(t, 0, di.Count())

		triea.MustUpdate([]byte("foo"), []byte("bar"))
		ita, err = triea.NodeIterator(nil)
		assert.NoError(t, err)
		itb, err = triea.NodeIterator(nil)
		assert.NoError(t, err)

		di = utils.NewSymmetricDifferenceIterator(ita, itb)
		for di.Next(true) {
			t.Errorf("iterator should not yield any elements")
		}
		// two nodes visited: the leaf (value) and its parent
		assert.Equal(t, 2, di.Count())

		trieb := trie.NewEmpty(db)
		ita, err = triea.NodeIterator([]byte("jars"))
		assert.NoError(t, err)
		itb, err = trieb.NodeIterator(nil)
		assert.NoError(t, err)
		di = utils.NewSymmetricDifferenceIterator(ita, itb)
		for di.Next(true) {
			t.Errorf("iterator should not yield any elements")
		}
		assert.Equal(t, 0, di.Count())

		// TODO will fail until merged: https://github.com/ethereum/go-ethereum/pull/27838
		// di, aux = utils.NewSymmetricDifferenceIterator(triea.NodeIterator([]byte("food")), trieb.NodeIterator(nil))
		// for di.Next(true) {
		// 	t.Errorf("iterator should not yield any elements")
		// }
		// assert.Equal(t, 0, di.Count())
	})

	t.Run("small difference", func(t *testing.T) {
		dba := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
		triea := trie.NewEmpty(dba)

		dbb := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
		trieb := trie.NewEmpty(dbb)
		trieb.MustUpdate([]byte("foo"), []byte("bar"))

		ita, err := triea.NodeIterator(nil)
		assert.NoError(t, err)
		itb, err := trieb.NodeIterator(nil)
		assert.NoError(t, err)
		di := utils.NewSymmetricDifferenceIterator(ita, itb)
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
		assert.Equal(t, 2, di.Count())

		trieb.MustUpdate([]byte("quux"), []byte("bars"))
		ita, err = triea.NodeIterator(nil)
		assert.NoError(t, err)
		itb, err = trieb.NodeIterator([]byte("quux"))
		assert.NoError(t, err)
		di = utils.NewSymmetricDifferenceIterator(ita, itb)
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
		assert.Equal(t, 1, di.Count())
	})

	dba := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
	triea := trie.NewEmpty(dba)
	for _, val := range testdata1 {
		triea.MustUpdate([]byte(val.k), []byte(val.v))
	}
	dbb := triedb.NewDatabase(rawdb.NewMemoryDatabase(), nil)
	trieb := trie.NewEmpty(dbb)
	for _, val := range testdata2 {
		trieb.MustUpdate([]byte(val.k), []byte(val.v))
	}

	onlyA := make(map[string]string)
	onlyB := make(map[string]string)
	var deletions, creations []string
	ita, err := triea.NodeIterator(nil)
	assert.NoError(t, err)
	itb, err := trieb.NodeIterator(nil)
	assert.NoError(t, err)
	it := utils.NewSymmetricDifferenceIterator(ita, itb)
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
	core.DefaultGenesisBlock().MustCommit(db, triedb.NewDatabase(db, nil))
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
	ita, err := treeA.NodeIterator(nil)
	assert.NoError(t, err)
	itb, err := treeB.NodeIterator(nil)
	assert.NoError(t, err)
	itBonly, _ := trie.NewDifferenceIterator(ita, itb)
	for itBonly.Next(true) {
		pathsB = append(pathsB, itBonly.Path())
	}
	ita, err = treeA.NodeIterator(nil)
	assert.NoError(t, err)
	itb, err = treeB.NodeIterator(nil)
	assert.NoError(t, err)
	itAonly, _ := trie.NewDifferenceIterator(itb, ita)
	for itAonly.Next(true) {
		pathsA = append(pathsA, itAonly.Path())
	}

	ita, err = treeA.NodeIterator(nil)
	assert.NoError(t, err)
	itb, err = treeB.NodeIterator(nil)
	assert.NoError(t, err)
	itSym := utils.NewSymmetricDifferenceIterator(ita, itb)
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
