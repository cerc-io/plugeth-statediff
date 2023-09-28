package statediff_test

import (
	"testing"

	statediff "github.com/cerc-io/plugeth-statediff"
	"github.com/cerc-io/plugeth-statediff/indexer/ipld"
	"github.com/cerc-io/plugeth-statediff/test_helpers"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestBuilderSnapshot(t *testing.T) {
	blocks, chain := test_helpers.MakeChain(3, test_helpers.Genesis, test_helpers.TestChainGen)
	contractLeafKey = test_helpers.AddressToLeafKey(test_helpers.ContractAddr)
	defer chain.Stop()
	block0 = test_helpers.Genesis
	block1 = blocks[0]
	block2 = blocks[1]
	block3 = blocks[2]
	params := statediff.Params{}

	tests := []test_helpers.SnapshotTestCase{
		{
			"testEmptyDiff",
			common.Hash{},
			&sdtypes.StateObject{
				Nodes: emptyDiffs,
			},
		},
		{
			"testBlock0",
			//10000 transferred from testBankAddress to account1Addr
			block0.Root(),
			&sdtypes.StateObject{
				Nodes: []sdtypes.StateLeafNode{
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: bankAccountAtBlock0,
							LeafKey: test_helpers.BankLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(bankAccountAtBlock0LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
				},
				IPLDs: []sdtypes.IPLD{
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(bankAccountAtBlock0LeafNode)).String(),
						Content: bankAccountAtBlock0LeafNode,
					},
				},
			},
		},
		{
			"testBlock1",
			//10000 transferred from testBankAddress to account1Addr
			block1.Root(),
			&sdtypes.StateObject{
				Nodes: []sdtypes.StateLeafNode{
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: bankAccountAtBlock1,
							LeafKey: test_helpers.BankLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(bankAccountAtBlock1LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: minerAccountAtBlock1,
							LeafKey: minerLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(minerAccountAtBlock1LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: account1AtBlock1,
							LeafKey: test_helpers.Account1LeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock1LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
				},
				IPLDs: []sdtypes.IPLD{
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(block1BranchRootNode)).String(),
						Content: block1BranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(bankAccountAtBlock1LeafNode)).String(),
						Content: bankAccountAtBlock1LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(minerAccountAtBlock1LeafNode)).String(),
						Content: minerAccountAtBlock1LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock1LeafNode)).String(),
						Content: account1AtBlock1LeafNode,
					},
				},
			},
		},
		{
			"testBlock2",
			//1000 transferred from testBankAddress to account1Addr
			//1000 transferred from account1Addr to account2Addr
			block2.Root(),
			&sdtypes.StateObject{
				Nodes: []sdtypes.StateLeafNode{
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: bankAccountAtBlock2,
							LeafKey: test_helpers.BankLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(bankAccountAtBlock2LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: minerAccountAtBlock2,
							LeafKey: minerLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(minerAccountAtBlock2LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: account1AtBlock2,
							LeafKey: test_helpers.Account1LeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock2LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: contractAccountAtBlock2,
							LeafKey: contractLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(contractAccountAtBlock2LeafNode)).String()},
						StorageDiff: []sdtypes.StorageLeafNode{
							{
								Removed: false,
								Value:   slot0StorageValue,
								LeafKey: slot0StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot0StorageLeafNode)).String(),
							},
							{
								Removed: false,
								Value:   slot1StorageValue,
								LeafKey: slot1StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot1StorageLeafNode)).String(),
							},
						},
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: account2AtBlock2,
							LeafKey: test_helpers.Account2LeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account2AtBlock2LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
				},
				IPLDs: []sdtypes.IPLD{
					{
						CID:     ipld.Keccak256ToCid(ipld.RawBinary, test_helpers.CodeHash.Bytes()).String(),
						Content: test_helpers.ByteCodeAfterDeployment,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(block2BranchRootNode)).String(),
						Content: block2BranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(bankAccountAtBlock2LeafNode)).String(),
						Content: bankAccountAtBlock2LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(minerAccountAtBlock2LeafNode)).String(),
						Content: minerAccountAtBlock2LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock2LeafNode)).String(),
						Content: account1AtBlock2LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(contractAccountAtBlock2LeafNode)).String(),
						Content: contractAccountAtBlock2LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(block2StorageBranchRootNode)).String(),
						Content: block2StorageBranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot0StorageLeafNode)).String(),
						Content: slot0StorageLeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot1StorageLeafNode)).String(),
						Content: slot1StorageLeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account2AtBlock2LeafNode)).String(),
						Content: account2AtBlock2LeafNode,
					},
				},
			},
		},
		{
			"testBlock3",
			//the contract's storage is changed
			//and the block is mined by account 2
			block3.Root(),
			&sdtypes.StateObject{
				Nodes: []sdtypes.StateLeafNode{
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: minerAccountAtBlock2,
							LeafKey: minerLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(minerAccountAtBlock2LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: account1AtBlock2,
							LeafKey: test_helpers.Account1LeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock2LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: bankAccountAtBlock3,
							LeafKey: test_helpers.BankLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(bankAccountAtBlock3LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: contractAccountAtBlock3,
							LeafKey: contractLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(contractAccountAtBlock3LeafNode)).String()},
						StorageDiff: []sdtypes.StorageLeafNode{

							{
								Removed: false,
								Value:   slot0StorageValue,
								LeafKey: slot0StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot0StorageLeafNode)).String(),
							},
							{
								Removed: false,
								Value:   slot1StorageValue,
								LeafKey: slot1StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot1StorageLeafNode)).String(),
							},

							{
								Removed: false,
								Value:   slot3StorageValue,
								LeafKey: slot3StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot3StorageLeafNode)).String(),
							},
						},
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: account2AtBlock3,
							LeafKey: test_helpers.Account2LeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account2AtBlock3LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
				},
				IPLDs: []sdtypes.IPLD{
					{
						CID:     ipld.Keccak256ToCid(ipld.RawBinary, test_helpers.CodeHash.Bytes()).String(),
						Content: test_helpers.ByteCodeAfterDeployment,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(minerAccountAtBlock2LeafNode)).String(),
						Content: minerAccountAtBlock2LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock2LeafNode)).String(),
						Content: account1AtBlock2LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot0StorageLeafNode)).String(),
						Content: slot0StorageLeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot1StorageLeafNode)).String(),
						Content: slot1StorageLeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(block3BranchRootNode)).String(),
						Content: block3BranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(bankAccountAtBlock3LeafNode)).String(),
						Content: bankAccountAtBlock3LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(contractAccountAtBlock3LeafNode)).String(),
						Content: contractAccountAtBlock3LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(block3StorageBranchRootNode)).String(),
						Content: block3StorageBranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot3StorageLeafNode)).String(),
						Content: slot3StorageLeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account2AtBlock3LeafNode)).String(),
						Content: account2AtBlock3LeafNode,
					},
				},
			},
		},
	}

	for _, test := range tests {
		test_helpers.RunStateSnapshot(t, chain.StateCache(), test, params)
	}
}

func TestBuilderSnapshotWithWatchedAddressList(t *testing.T) {
	blocks, chain := test_helpers.MakeChain(3, test_helpers.Genesis, test_helpers.TestChainGen)
	contractLeafKey = test_helpers.AddressToLeafKey(test_helpers.ContractAddr)
	defer chain.Stop()
	block0 = test_helpers.Genesis
	block1 = blocks[0]
	block2 = blocks[1]
	block3 = blocks[2]
	params := statediff.Params{
		WatchedAddresses: []common.Address{test_helpers.Account1Addr, test_helpers.ContractAddr},
	}
	params.ComputeWatchedAddressesLeafPaths()

	var tests = []test_helpers.SnapshotTestCase{
		{
			"testBlock0",
			//10000 transferred from testBankAddress to account1Addr
			block0.Root(),
			&sdtypes.StateObject{
				Nodes: emptyDiffs,
			},
		},
		{
			"testBlock1",
			//10000 transferred from testBankAddress to account1Addr
			block1.Root(),
			&sdtypes.StateObject{
				Nodes: []sdtypes.StateLeafNode{
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: account1AtBlock1,
							LeafKey: test_helpers.Account1LeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock1LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
				},
				IPLDs: []sdtypes.IPLD{
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(block1BranchRootNode)).String(),
						Content: block1BranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock1LeafNode)).String(),
						Content: account1AtBlock1LeafNode,
					},
				},
			},
		},
		{
			"testBlock2",
			//1000 transferred from testBankAddress to account1Addr
			//1000 transferred from account1Addr to account2Addr
			block2.Root(),
			&sdtypes.StateObject{
				Nodes: []sdtypes.StateLeafNode{
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: contractAccountAtBlock2,
							LeafKey: contractLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(contractAccountAtBlock2LeafNode)).String(),
						},
						StorageDiff: []sdtypes.StorageLeafNode{
							{
								Removed: false,
								Value:   slot0StorageValue,
								LeafKey: slot0StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot0StorageLeafNode)).String(),
							},
							{
								Removed: false,
								Value:   slot1StorageValue,
								LeafKey: slot1StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot1StorageLeafNode)).String(),
							},
						},
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: account1AtBlock2,
							LeafKey: test_helpers.Account1LeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock2LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
				},
				IPLDs: []sdtypes.IPLD{
					{
						CID:     ipld.Keccak256ToCid(ipld.RawBinary, test_helpers.CodeHash.Bytes()).String(),
						Content: test_helpers.ByteCodeAfterDeployment,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(block2BranchRootNode)).String(),
						Content: block2BranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(contractAccountAtBlock2LeafNode)).String(),
						Content: contractAccountAtBlock2LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(block2StorageBranchRootNode)).String(),
						Content: block2StorageBranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot0StorageLeafNode)).String(),
						Content: slot0StorageLeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot1StorageLeafNode)).String(),
						Content: slot1StorageLeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock2LeafNode)).String(),
						Content: account1AtBlock2LeafNode,
					},
				},
			},
		},
		{
			"testBlock3",
			//the contract's storage is changed
			//and the block is mined by account 2
			block3.Root(),
			&sdtypes.StateObject{
				Nodes: []sdtypes.StateLeafNode{
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: account1AtBlock2,
							LeafKey: test_helpers.Account1LeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock2LeafNode)).String()},
						StorageDiff: emptyStorage,
					},
					{
						Removed: false,
						AccountWrapper: sdtypes.AccountWrapper{
							Account: contractAccountAtBlock3,
							LeafKey: contractLeafKey,
							CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(contractAccountAtBlock3LeafNode)).String()},
						StorageDiff: []sdtypes.StorageLeafNode{
							{
								Removed: false,
								Value:   slot0StorageValue,
								LeafKey: slot0StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot0StorageLeafNode)).String(),
							},
							{
								Removed: false,
								Value:   slot1StorageValue,
								LeafKey: slot1StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot1StorageLeafNode)).String(),
							},
							{
								Removed: false,
								Value:   slot3StorageValue,
								LeafKey: slot3StorageKey.Bytes(),
								CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot3StorageLeafNode)).String(),
							},
						},
					},
				},
				IPLDs: []sdtypes.IPLD{
					{
						CID:     ipld.Keccak256ToCid(ipld.RawBinary, test_helpers.CodeHash.Bytes()).String(),
						Content: test_helpers.ByteCodeAfterDeployment,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(account1AtBlock2LeafNode)).String(),
						Content: account1AtBlock2LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot0StorageLeafNode)).String(),
						Content: slot0StorageLeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot1StorageLeafNode)).String(),
						Content: slot1StorageLeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(block3BranchRootNode)).String(),
						Content: block3BranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStateTrie, crypto.Keccak256(contractAccountAtBlock3LeafNode)).String(),
						Content: contractAccountAtBlock3LeafNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(block3StorageBranchRootNode)).String(),
						Content: block3StorageBranchRootNode,
					},
					{
						CID:     ipld.Keccak256ToCid(ipld.MEthStorageTrie, crypto.Keccak256(slot3StorageLeafNode)).String(),
						Content: slot3StorageLeafNode,
					},
				},
			},
		},
	}

	for _, test := range tests {
		test_helpers.RunStateSnapshot(t, chain.StateCache(), test, params)
	}
}
