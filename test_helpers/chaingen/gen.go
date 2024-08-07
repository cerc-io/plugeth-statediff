package chaingen

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

const secondsPerBlock = 12

type GenContext struct {
	ChainConfig *params.ChainConfig
	GenFuncs    []func(int, *core.BlockGen)
	DB          ethdb.Database

	Keys      map[common.Address]*ecdsa.PrivateKey
	Contracts map[string]*ContractSpec
	Genesis   *types.Block

	block    *core.BlockGen            // cache the current block for my methods' use
	deployed map[common.Address]string // names of deployed contracts keyed by deployer
	time     uint64                    // time at current block, in seconds
}

func NewGenContext(chainConfig *params.ChainConfig, db ethdb.Database) *GenContext {
	return &GenContext{
		ChainConfig: chainConfig,
		DB:          db,
		Keys:        make(map[common.Address]*ecdsa.PrivateKey),
		Contracts:   make(map[string]*ContractSpec),

		deployed: make(map[common.Address]string),
	}
}

func (gen *GenContext) AddFunction(fn func(int, *core.BlockGen)) {
	gen.GenFuncs = append(gen.GenFuncs, fn)
}

func (gen *GenContext) AddOwnedAccount(key *ecdsa.PrivateKey) common.Address {
	addr := crypto.PubkeyToAddress(key.PublicKey)
	gen.Keys[addr] = key
	return addr
}

func (gen *GenContext) AddContract(name string, spec *ContractSpec) {
	gen.Contracts[name] = spec
}

func (gen *GenContext) generate(i int, block *core.BlockGen) {
	gen.block = block
	for _, fn := range gen.GenFuncs {
		fn(i, block)
	}
	gen.time += secondsPerBlock
}

// MakeChain creates a chain of n blocks starting at and including the genesis block.
// the returned hash chain is ordered head->parent.
func (gen *GenContext) MakeChain(n int) ([]*types.Block, []types.Receipts, *core.BlockChain) {
	blocks, receipts := core.GenerateChain(
		gen.ChainConfig, gen.Genesis, ethash.NewFaker(), gen.DB, n, gen.generate,
	)
	chain, err := core.NewBlockChain(gen.DB, nil, nil, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		panic(err)
	}
	return append([]*types.Block{gen.Genesis}, blocks...), receipts, chain
}

func (gen *GenContext) CreateSendTx(from common.Address, to common.Address, amount *big.Int) (*types.Transaction, error) {
	return gen.createTx(from, &to, amount, params.TxGas, nil)
}

func (gen *GenContext) CreateContractTx(from common.Address, contractName string) (*types.Transaction, error) {
	contract := gen.Contracts[contractName]
	if contract == nil {
		return nil, errors.New("No contract with name " + contractName)
	}
	return gen.createTx(from, nil, big.NewInt(0), 1000000, contract.DeploymentCode)
}

func (gen *GenContext) CreateCallTx(from common.Address, to common.Address, methodName string, args ...interface{}) (*types.Transaction, error) {
	contractName, ok := gen.deployed[to]
	if !ok {
		return nil, errors.New("No contract deployed at address " + to.String())
	}
	contract := gen.Contracts[contractName]
	if contract == nil {
		return nil, errors.New("No contract with name " + contractName)
	}

	packed, err := contract.ABI.Pack(methodName, args...)
	if err != nil {
		panic(err)
	}
	return gen.createTx(from, &to, big.NewInt(0), 100000, packed)
}

func (gen *GenContext) DeployContract(from common.Address, contractName string) (common.Address, error) {
	tx, err := gen.CreateContractTx(from, contractName)
	if err != nil {
		return common.Address{}, err
	}
	addr := crypto.CreateAddress(from, gen.block.TxNonce(from))
	gen.deployed[addr] = contractName
	gen.block.AddTx(tx)
	return addr, nil
}

func (gen *GenContext) createTx(from common.Address, to *common.Address, amount *big.Int, gasLimit uint64, data []byte) (*types.Transaction, error) {
	signer := types.MakeSigner(gen.ChainConfig, gen.block.Number(), gen.time)
	nonce := gen.block.TxNonce(from)
	priv, ok := gen.Keys[from]
	if !ok {
		return nil, errors.New("No private key for sender address" + from.String())
	}

	var tx *types.Transaction
	if gen.ChainConfig.IsLondon(gen.block.Number()) {
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   gen.ChainConfig.ChainID,
			Nonce:     nonce,
			To:        to,
			Gas:       gasLimit,
			GasTipCap: big.NewInt(50),
			GasFeeCap: big.NewInt(1000000000),
			Value:     amount,
			Data:      data,
		})
	} else {
		tx = types.NewTx(&types.LegacyTx{
			Nonce: nonce,
			To:    to,
			Value: amount,
			Gas:   gasLimit,
			Data:  data,
		})
	}
	return types.SignTx(tx, signer, priv)
}

func (gen *GenContext) createBlobTx(
	from common.Address,
	to common.Address,
	amount *uint256.Int,
	gasLimit uint64,
	blobData []byte,
) (*types.Transaction, error) {
	signer := types.MakeSigner(gen.ChainConfig, gen.block.Number(), gen.time)
	nonce := gen.block.TxNonce(from)
	priv, ok := gen.Keys[from]
	if !ok {
		return nil, errors.New("No private key for sender address" + from.String())
	}

	if !gen.ChainConfig.IsCancun(gen.block.Number(), gen.time) {
		return nil, errors.New("blob tx is only supported from Cancun fork")
	}

	sidecar := MakeSidecar([][]byte{blobData})
	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.MustFromBig(gen.ChainConfig.ChainID),
		Nonce:      nonce,
		To:         to,
		Gas:        gasLimit,
		GasTipCap:  uint256.NewInt(50),
		GasFeeCap:  uint256.NewInt(1000000000),
		Value:      amount,
		BlobFeeCap: uint256.NewInt(1000000),
		BlobHashes: sidecar.BlobHashes(),
		Sidecar:    sidecar,
	})
	return types.SignTx(tx, signer, priv)
}

// From go-ethereum/cmd/devp2p/internal/ethtest/chain.go
func MakeSidecar(data [][]byte) *types.BlobTxSidecar {
	var (
		blobs       = make([]kzg4844.Blob, len(data))
		commitments []kzg4844.Commitment
		proofs      []kzg4844.Proof
	)
	for i := range blobs {
		copy(blobs[i][:], data[i])
		c, _ := kzg4844.BlobToCommitment(blobs[i])
		p, _ := kzg4844.ComputeBlobProof(blobs[i], c)
		commitments = append(commitments, c)
		proofs = append(proofs, p)
	}
	return &types.BlobTxSidecar{
		Blobs:       blobs,
		Commitments: commitments,
		Proofs:      proofs,
	}
}
