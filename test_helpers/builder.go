package test_helpers

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/cerc-io/eth-iterator-utils/tracker"
	statediff "github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/adapt"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

var subtrieCounts = []uint{1, 8, 32}

type DiffTestCase struct {
	Name     string
	Args     statediff.Args
	Expected *sdtypes.StateObject
}

type SnapshotTestCase struct {
	Name      string
	StateRoot common.Hash
	Expected  *sdtypes.StateObject
}

type CheckedRoots map[*types.Block][]byte

// Replicates the statediff object, but indexes nodes by CID
type normalizedStateDiff struct {
	BlockNumber *big.Int
	BlockHash   common.Hash
	Nodes       map[string]sdtypes.StateLeafNode
	IPLDs       map[string]sdtypes.IPLD
}

func RunBuildStateDiff(
	t *testing.T,
	sdb state.Database,
	tests []DiffTestCase,
	params statediff.Params,
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

func RunStateSnapshot(
	t *testing.T,
	sdb state.Database,
	test SnapshotTestCase,
	params statediff.Params,
) {
	builder := statediff.NewBuilder(adapt.GethStateView(sdb))

	for _, subtries := range subtrieCounts {
		// Skip the recovery test for empty diffs
		doRecovery := len(test.Expected.Nodes) != 0

		t.Run(fmt.Sprintf("%s with %d subtries", test.Name, subtries), func(t *testing.T) {
			builder.SetSubtrieWorkers(subtries)
			var stateNodes []sdtypes.StateLeafNode
			var iplds []sdtypes.IPLD
			interrupt := randomInterrupt(len(test.Expected.IPLDs))
			stateAppender := failingSyncedAppender(&stateNodes, -1)
			ipldAppender := failingSyncedAppender(&iplds, interrupt)
			recoveryFile := filepath.Join(t.TempDir(), "recovery.txt")
			build := func() error {
				tr := tracker.New(recoveryFile, subtries)
				defer tr.CloseAndSave()
				return builder.WriteStateSnapshot(
					test.StateRoot, params, stateAppender, ipldAppender, tr,
				)
			}
			if doRecovery {
				// First attempt fails, second succeeds
				if build() == nil {
					t.Fatal("expected an error")
				}
				require.FileExists(t, recoveryFile)
			}
			ipldAppender = failingSyncedAppender(&iplds, -1)
			if err := build(); err != nil {
				t.Fatal(err)
			}
			diff := sdtypes.StateObject{
				Nodes: stateNodes,
				IPLDs: iplds,
			}
			require.Equal(t,
				normalize(test.Expected),
				normalize(&diff),
			)
		})
	}

}

// an appender which fails on a configured trigger
func failingSyncedAppender[T any](to *[]T, failAt int) func(T) error {
	var mtx sync.Mutex
	return func(item T) error {
		mtx.Lock()
		defer mtx.Unlock()
		if len(*to) == failAt {
			return fmt.Errorf("failing at %d items", failAt)
		}
		*to = append(*to, item)
		return nil
	}
}

// function to pick random int between N/4 and 3N/4
func randomInterrupt(N int) int {
	if N < 2 {
		return 0
	}
	return rand.Intn(N/2) + N/4
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
