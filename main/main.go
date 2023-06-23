package main

import (
	"strconv"

	geth_flags "github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/openrelayxyz/plugeth-utils/core"
	"github.com/openrelayxyz/plugeth-utils/restricted"

	statediff "github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/adapt"
	ind "github.com/cerc-io/plugeth-statediff/indexer"
	"github.com/cerc-io/plugeth-statediff/indexer/interfaces"
	"github.com/cerc-io/plugeth-statediff/indexer/node"
	"github.com/cerc-io/plugeth-statediff/utils/log"
)

var (
	pluginLoader core.PluginLoader
	gethContext  core.Context
	service      *statediff.Service
	blockchain   statediff.BlockChain
)

func Initialize(ctx core.Context, pl core.PluginLoader, logger core.Logger) {
	log.SetDefaultLogger(logger)

	// lvl, err := strconv.ParseInt(ctx.String("verbosity"), 10, 8)
	// if err != nil {
	// 	log.Error("cannot parse verbosity", "error", err)
	// }
	// log.TestLogger.SetLevel(int(lvl))
	// log.SetDefaultLogger(log.TestLogger)

	pluginLoader = pl
	gethContext = ctx

	log.Debug("Initialized statediff plugin")
}

func InitializeNode(stack core.Node, b core.Backend) {
	backend := b.(restricted.Backend)

	networkid, err := strconv.ParseUint(gethContext.String(geth_flags.NetworkIdFlag.Name), 10, 64)
	if err != nil {
		log.Error("cannot parse network ID", "error", err)
		return
	}
	serviceConfig := GetConfig()
	blockchain = statediff.NewPluginBlockChain(backend)

	var indexer interfaces.StateDiffIndexer
	if serviceConfig.IndexerConfig != nil {
		info := node.Info{
			GenesisBlock: blockchain.GetBlockByNumber(0).Hash().String(),
			NetworkID:    strconv.FormatUint(networkid, 10),
			ChainID:      backend.ChainConfig().ChainID.Uint64(),
			ID:           serviceConfig.ID,
			ClientName:   serviceConfig.ClientName,
		}
		var err error
		_, indexer, err = ind.NewStateDiffIndexer(serviceConfig.Context,
			adapt.ChainConfig(backend.ChainConfig()), info, serviceConfig.IndexerConfig)
		if err != nil {
			log.Error("failed to construct indexer", "error", err)
		}
	}
	service, err := statediff.NewService(serviceConfig, blockchain, backend, indexer)
	if err != nil {
		log.Error("failed to construct service", "error", err)
	}
	if err = service.Start(); err != nil {
		log.Error("failed to start service", "error", err)
		return
	}
}

func GetAPIs(stack core.Node, backend core.Backend) []core.API {
	return []core.API{
		{
			Namespace: statediff.APIName,
			Version:   statediff.APIVersion,
			Service:   statediff.NewPublicAPI(service),
			Public:    true,
		},
	}
}

// StateUpdate gives us updates about state changes made in each block.
// We extract contract code here, since it's not exposed by plugeth's state interfaces.
func StateUpdate(
	blockRoot core.Hash,
	parentRoot core.Hash,
	destructs map[core.Hash]struct{},
	accounts map[core.Hash][]byte,
	storage map[core.Hash]map[core.Hash][]byte,
	codeUpdates map[core.Hash][]byte) {
	if blockchain == nil {
		log.Warn("StateUpdate called before InitializeNode", "root", blockRoot)
		return
	}

	// for hash, code := range codeUpdates {
	// 	log.Debug("UPDATING CODE", "hash", hash)
	// 	codeStore.Set(hash, code)
	// }
}
