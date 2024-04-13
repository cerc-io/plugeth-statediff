package utils

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cerc-io/plugeth-statediff/utils/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// Fatalf formats a message to standard error and exits the program.
func Fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

func MustDecode[T any](buf []byte) *T {
	var ret T
	err := rlp.DecodeBytes(buf, &ret)
	if err != nil {
		panic(fmt.Errorf("error decoding RLP %T: %w", ret, err))
	}
	return &ret
}

// LoadConfig loads chain config from json file
func LoadConfig(chainConfigPath string) (*params.ChainConfig, error) {
	file, err := os.Open(chainConfigPath)
	if err != nil {
		log.Error("Failed to read chain config file", "error", err)
		return nil, err
	}
	defer file.Close()

	chainConfig := new(params.ChainConfig)
	if err := json.NewDecoder(file).Decode(chainConfig); err != nil {
		log.Error("invalid chain config file", "error", err)

		return nil, err
	}

	log.Debug("Using chain config", "path", chainConfigPath, "content", chainConfig)

	return chainConfig, nil
}

// ChainConfig returns the appropriate ethereum chain config for the provided chain id
func ChainConfig(chainID uint64) (*params.ChainConfig, error) {
	switch chainID {
	case 1:
		return params.MainnetChainConfig, nil
	case 5:
		return params.GoerliChainConfig, nil
	default:
		return nil, fmt.Errorf("chain config for chainid %d not available", chainID)
	}
}
