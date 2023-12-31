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
	gethContext core.Context
	service     *statediff.Service
	blockchain  statediff.BlockChain
)

func Initialize(ctx core.Context, pl core.PluginLoader, logger core.Logger) {
	log.SetDefaultLogger(logger)
	gethContext = ctx
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
		_, indexer, err = ind.NewStateDiffIndexer(
			serviceConfig.Context,
			adapt.ChainConfig(backend.ChainConfig()),
			info,
			serviceConfig.IndexerConfig,
			true,
		)
		if err != nil {
			log.Error("failed to construct indexer", "error", err)
		}
	}
	service, err = statediff.NewService(serviceConfig, blockchain, backend, indexer)
	if err != nil {
		log.Error("failed to construct service", "error", err)
	}
	if err = service.Start(); err != nil {
		log.Error("failed to start service", "error", err)
		return
	}

	log.Debug("Initialized statediff plugin")
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
