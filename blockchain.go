package statediff

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"

	plugeth "github.com/openrelayxyz/plugeth-utils/core"
	"github.com/openrelayxyz/plugeth-utils/restricted"

	"github.com/cerc-io/plugeth-statediff/adapt"
	"github.com/cerc-io/plugeth-statediff/utils"
)

type BlockChain interface {
	SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription
	CurrentBlock() *types.Header
	GetBlockByHash(hash common.Hash) *types.Block
	GetBlockByNumber(number uint64) *types.Block
	GetReceiptsByHash(hash common.Hash) types.Receipts
	GetTd(hash common.Hash, number uint64) *big.Int
	StateCache() adapt.StateView
}

// pluginBlockChain adapts the plugeth Backend to the blockChain interface
type pluginBlockChain struct {
	restricted.Backend
	ctx context.Context
}

func NewPluginBlockChain(backend restricted.Backend) BlockChain {
	return &pluginBlockChain{
		Backend: backend,
		ctx:     context.Background(),
	}
}

func (b *pluginBlockChain) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	bufferChan := make(chan plugeth.ChainEvent, chainEventChanSize)
	sub := b.Backend.SubscribeChainEvent(bufferChan)
	go func() {
		for event := range bufferChan {
			block := utils.MustDecode[types.Block](event.Block)
			// Note: logs are processed with receipts while building the payload
			ch <- core.ChainEvent{
				Block: block,
				Hash:  common.Hash(event.Hash),
			}
		}
	}()
	return sub
}

func (b *pluginBlockChain) CurrentBlock() *types.Header {
	buf := b.Backend.CurrentBlock()
	return utils.MustDecode[types.Header](buf)
}

func (b *pluginBlockChain) GetBlockByHash(hash common.Hash) *types.Block {
	buf, err := b.Backend.BlockByHash(b.ctx, plugeth.Hash(hash))
	if err != nil {
		panic(err)
	}
	return utils.MustDecode[types.Block](buf)
}

func (b *pluginBlockChain) GetBlockByNumber(number uint64) *types.Block {
	buf, err := b.Backend.BlockByNumber(b.ctx, int64(number))
	if err != nil {
		panic(err)
	}
	return utils.MustDecode[types.Block](buf)
}

func (b *pluginBlockChain) GetReceiptsByHash(hash common.Hash) types.Receipts {
	buf, err := b.Backend.GetReceipts(b.ctx, plugeth.Hash(hash))
	if err != nil {
		panic(err)
	}
	var receipts types.Receipts
	err = json.Unmarshal(buf, &receipts)
	if err != nil {
		panic(err)
	}
	return receipts
}

func (b *pluginBlockChain) GetTd(hash common.Hash, number uint64) *big.Int {
	return b.Backend.GetTd(b.ctx, plugeth.Hash(hash))
}

func (b *pluginBlockChain) StateCache() adapt.StateView {
	return &pluginStateView{backend: b}
}

func (b *pluginBlockChain) ChainConfig() *params.ChainConfig {
	return adapt.ChainConfig(b.Backend.ChainConfig())
}

// exposes a StateView from a combination of plugeth's core Backend and cached contract code
type pluginStateView struct {
	backend *pluginBlockChain
}

func (p *pluginStateView) OpenTrie(root common.Hash) (adapt.StateTrie, error) {
	t, err := p.backend.GetTrie(plugeth.Hash(root))
	if err != nil {
		return nil, err
	}
	return adapt.NewStateTrie(t), nil
}

func (p *pluginStateView) ContractCode(hash common.Hash) ([]byte, error) {
	return p.backend.GetContractCode(plugeth.Hash(hash))
}
