package mocks_test

import (
	"testing"

	"github.com/cerc-io/plugeth-statediff/test_helpers/mocks"
	"github.com/ethereum/go-ethereum"
)

func TestBackend(t *testing.T) {
	startingblock := uint64(42)
	b := mocks.NewBackend(t, ethereum.SyncProgress{StartingBlock: startingblock})
	block := b.Downloader().Progress().StartingBlock()
	if startingblock != block {
		t.Fatalf("wrong StartingBlock; expected %d, got %d", startingblock, block)
	}
}
