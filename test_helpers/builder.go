package test_helpers

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"

	"github.com/cerc-io/plugeth-statediff"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
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
	builder statediff.Builder,
	tests []TestCase,
	params statediff.Params,
	roots CheckedRoots,
) {
	for _, test := range tests {
		diff, err := builder.BuildStateDiffObject(test.Args, params)
		if err != nil {
			t.Error(err)
		}
		receivedStateDiffRlp, err := rlp.EncodeToBytes(&diff)
		if err != nil {
			t.Error(err)
		}
		expectedStateDiffRlp, err := rlp.EncodeToBytes(test.Expected)
		if err != nil {
			t.Error(err)
		}
		sort.Slice(receivedStateDiffRlp, func(i, j int) bool {
			return receivedStateDiffRlp[i] < receivedStateDiffRlp[j]
		})
		sort.Slice(expectedStateDiffRlp, func(i, j int) bool {
			return expectedStateDiffRlp[i] < expectedStateDiffRlp[j]
		})
		if !bytes.Equal(receivedStateDiffRlp, expectedStateDiffRlp) {
			actualb, err := json.Marshal(diff)
			require.NoError(t, err)
			expectedb, err := json.Marshal(test.Expected)
			require.NoError(t, err)

			var expected, actual interface{}
			err = json.Unmarshal(expectedb, &expected)
			require.NoError(t, err)
			err = json.Unmarshal(actualb, &actual)
			require.NoError(t, err)

			require.Equal(t, expected, actual, test.Name)
		}
	}
	// Let's also confirm that our root state nodes form the state root hash in the headers
	for block, node := range roots {
		require.Equal(t, block.Root(), crypto.Keccak256Hash(node),
			"expected root does not match actual root", block.Number())
	}
}
