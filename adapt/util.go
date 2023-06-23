package adapt

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"

	plugeth "github.com/openrelayxyz/plugeth-utils/core"
	plugeth_params "github.com/openrelayxyz/plugeth-utils/restricted/params"
)

func StateAccount(a *plugeth.StateAccount) *types.StateAccount {
	return &types.StateAccount{
		Nonce:    a.Nonce,
		Balance:  a.Balance,
		Root:     common.Hash(a.Root),
		CodeHash: a.CodeHash,
	}
}

func ChainConfig(cc *plugeth_params.ChainConfig) *params.ChainConfig {
	return &params.ChainConfig{
		ChainID:             cc.ChainID,
		HomesteadBlock:      cc.HomesteadBlock,
		DAOForkBlock:        cc.DAOForkBlock,
		DAOForkSupport:      cc.DAOForkSupport,
		EIP150Block:         cc.EIP150Block,
		EIP155Block:         cc.EIP155Block,
		EIP158Block:         cc.EIP158Block,
		ByzantiumBlock:      cc.ByzantiumBlock,
		ConstantinopleBlock: cc.ConstantinopleBlock,
		PetersburgBlock:     cc.PetersburgBlock,
		IstanbulBlock:       cc.IstanbulBlock,
		MuirGlacierBlock:    cc.MuirGlacierBlock,
		BerlinBlock:         cc.BerlinBlock,
		LondonBlock:         cc.LondonBlock,
	}
}
