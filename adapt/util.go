package adapt

import (
	"github.com/ethereum/go-ethereum/params"

	plugeth_params "github.com/openrelayxyz/plugeth-utils/restricted/params"
)

func ChainConfig(cc *plugeth_params.ChainConfig) *params.ChainConfig {
	ret := &params.ChainConfig{
		ChainID: cc.ChainID,

		HomesteadBlock: cc.HomesteadBlock,
		DAOForkBlock:   cc.DAOForkBlock,
		DAOForkSupport: cc.DAOForkSupport,
		EIP150Block:    cc.EIP150Block,
		EIP155Block:    cc.EIP155Block,
		EIP158Block:    cc.EIP158Block,

		ByzantiumBlock:      cc.ByzantiumBlock,
		ConstantinopleBlock: cc.ConstantinopleBlock,
		PetersburgBlock:     cc.PetersburgBlock,
		IstanbulBlock:       cc.IstanbulBlock,
		MuirGlacierBlock:    cc.MuirGlacierBlock,
		BerlinBlock:         cc.BerlinBlock,
		LondonBlock:         cc.LondonBlock,

		ArrowGlacierBlock:  cc.ArrowGlacierBlock,
		GrayGlacierBlock:   cc.GrayGlacierBlock,
		MergeNetsplitBlock: cc.MergeNetsplitBlock,

		ShanghaiTime: cc.ShanghaiTime,
		CancunTime:   cc.CancunTime,
		PragueTime:   cc.PragueTime,

		TerminalTotalDifficulty:       cc.TerminalTotalDifficulty,
		TerminalTotalDifficultyPassed: cc.TerminalTotalDifficultyPassed,
	}
	if cc.Ethash != nil {
		ret.Ethash = &params.EthashConfig{}
	}
	if cc.Clique != nil {
		ret.Clique = &params.CliqueConfig{cc.Clique.Period, cc.Clique.Epoch}
	}
	return ret
}
