package mocks

import (
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/golang/mock/gomock"

	plugeth "github.com/openrelayxyz/plugeth-utils/core"
)

type Backend struct {
	*MockBackend
	downloader Downloader
}

type Downloader struct {
	ethereum.SyncProgress
}

var _ plugeth.Backend = &Backend{}
var _ plugeth.Downloader = &Downloader{}

func NewBackend(t *testing.T, progress ethereum.SyncProgress) *Backend {
	ctl := gomock.NewController(t)
	dler := Downloader{progress}
	ret := &Backend{
		MockBackend: NewMockBackend(ctl),
		downloader:  dler,
	}
	ret.EXPECT().Downloader().Return(&ret.downloader).AnyTimes()
	return ret
}

func (b *Backend) SetCurrentBlock(block uint64) {
	b.downloader.SyncProgress.CurrentBlock = block
}

func (d Downloader) Progress() plugeth.Progress {
	return d
}

func (d Downloader) StartingBlock() uint64       { return d.SyncProgress.StartingBlock }
func (d Downloader) CurrentBlock() uint64        { return d.SyncProgress.CurrentBlock }
func (d Downloader) HighestBlock() uint64        { return d.SyncProgress.HighestBlock }
func (d Downloader) PulledStates() uint64        { return d.SyncProgress.PulledStates }
func (d Downloader) KnownStates() uint64         { return d.SyncProgress.KnownStates }
func (d Downloader) SyncedAccounts() uint64      { return d.SyncProgress.SyncedAccounts }
func (d Downloader) SyncedAccountBytes() uint64  { return d.SyncProgress.SyncedAccountBytes }
func (d Downloader) SyncedBytecodes() uint64     { return d.SyncProgress.SyncedBytecodes }
func (d Downloader) SyncedBytecodeBytes() uint64 { return d.SyncProgress.SyncedBytecodeBytes }
func (d Downloader) SyncedStorage() uint64       { return d.SyncProgress.SyncedStorage }
func (d Downloader) SyncedStorageBytes() uint64  { return d.SyncProgress.SyncedStorageBytes }
func (d Downloader) HealedTrienodes() uint64     { return d.SyncProgress.HealedTrienodes }
func (d Downloader) HealedTrienodeBytes() uint64 { return d.SyncProgress.HealedTrienodeBytes }
func (d Downloader) HealedBytecodes() uint64     { return d.SyncProgress.HealedBytecodes }
func (d Downloader) HealedBytecodeBytes() uint64 { return d.SyncProgress.HealedBytecodeBytes }
func (d Downloader) HealingTrienodes() uint64    { return d.SyncProgress.HealingTrienodes }
func (d Downloader) HealingBytecode() uint64     { return d.SyncProgress.HealingBytecode }

func TestBackend(t *testing.T) {
	b := NewBackend(t, ethereum.SyncProgress{StartingBlock: 42})

	block := b.Downloader().Progress().StartingBlock()
	if 42 != block {
		t.Fatalf("wrong StartingBlock; expected %d, got %d", 42, block)
	}

	b.SetCurrentBlock(420)
	block = b.Downloader().Progress().CurrentBlock()
	if 420 != block {
		t.Fatalf("wrong CurrentBlock; expected %d, got %d", 420, block)
	}
}
