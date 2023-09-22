package test_helpers

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"
	"testing"

	statediff "github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/adapt"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

type TestCase struct {
	Name     string
	Args     statediff.Args
	Expected *sdtypes.StateObject
}

type CheckedRoots map[*types.Block][]byte

// Replicates the statediff object, but indexes nodes by CID
type normalizedStateDiff struct {
	BlockNumber *big.Int
	BlockHash   common.Hash
	Nodes       map[string]sdtypes.StateLeafNode
	IPLDs       map[string]sdtypes.IPLD
}

func RunBuilderTests(
	t *testing.T,
	sdb state.Database,
	tests []TestCase,
	params statediff.Params,
	subtrieCounts []uint,
) {
	builder := statediff.NewBuilder(adapt.GethStateView(sdb))
	for _, test := range tests {
		for _, subtries := range subtrieCounts {
			t.Run(fmt.Sprintf("%s with %d subtries", test.Name, subtries), func(t *testing.T) {
				builder.SetSubtrieWorkers(subtries)
				diff, err := builder.BuildStateDiffObject(test.Args, params)
				if err != nil {
					t.Error(err)
				}
				require.Equal(t,
					normalize(test.Expected),
					normalize(&diff),
				)
			})
		}
	}
}

func (roots CheckedRoots) Check(t *testing.T) {
	// Let's also confirm that our root state nodes form the state root hash in the headers
	for block, node := range roots {
		require.Equal(t, block.Root(), crypto.Keccak256Hash(node),
			"expected root does not match actual root", block.Number())
	}
}

func normalize(diff *sdtypes.StateObject) normalizedStateDiff {
	norm := normalizedStateDiff{
		BlockNumber: diff.BlockNumber,
		BlockHash:   diff.BlockHash,
		Nodes:       make(map[string]sdtypes.StateLeafNode),
		IPLDs:       make(map[string]sdtypes.IPLD),
	}
	for _, node := range diff.Nodes {
		sort.Slice(node.StorageDiff, func(i, j int) bool {
			return bytes.Compare(
				node.StorageDiff[i].LeafKey,
				node.StorageDiff[j].LeafKey,
			) < 0
		})
		norm.Nodes[node.AccountWrapper.CID] = node
	}
	for _, ipld := range diff.IPLDs {
		norm.IPLDs[ipld.CID] = ipld
	}
	return norm
}
