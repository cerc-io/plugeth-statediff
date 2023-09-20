package test_helpers

import (
	"bytes"
	"sort"
	"testing"

	statediff "github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/adapt"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
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

type CheckedRoots = map[*types.Block][]byte

func RunBuilderTests(
	t *testing.T,
	sdb state.Database,
	tests []TestCase,
	params statediff.Params,
	roots CheckedRoots,
) {
	builder := statediff.NewBuilder(adapt.GethStateView(sdb))
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			diff, err := builder.BuildStateDiffObject(test.Args, params)
			if err != nil {
				t.Error(err)
			}

			normalize(test.Expected)
			normalize(&diff)
			require.Equal(t, *test.Expected, diff)
		})
	}
	// Let's also confirm that our root state nodes form the state root hash in the headers
	for block, node := range roots {
		require.Equal(t, block.Root(), crypto.Keccak256Hash(node),
			"expected root does not match actual root", block.Number())
	}
}

// Sorts contained state nodes, storage nodes, and IPLDs
func normalize(diff *sdtypes.StateObject) {
	sort.Slice(diff.IPLDs, func(i, j int) bool {
		return diff.IPLDs[i].CID < diff.IPLDs[j].CID
	})
	sort.Slice(diff.Nodes, func(i, j int) bool {
		return bytes.Compare(
			diff.Nodes[i].AccountWrapper.LeafKey,
			diff.Nodes[j].AccountWrapper.LeafKey,
		) < 0
	})
	for _, node := range diff.Nodes {
		sort.Slice(node.StorageDiff, func(i, j int) bool {
			return bytes.Compare(
				node.StorageDiff[i].LeafKey,
				node.StorageDiff[j].LeafKey,
			) < 0
		})
	}
}
