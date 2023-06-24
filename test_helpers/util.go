package test_helpers

import (
	geth_log "github.com/ethereum/go-ethereum/log"

	"github.com/cerc-io/plugeth-statediff/utils/log"
)

// The geth sync logs are noisy, it can be useful to silence them
func SilenceLogs() {
	geth_log.Root().SetHandler(geth_log.DiscardHandler())
	log.TestLogger.SetLevel(2)
}
