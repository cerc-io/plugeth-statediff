package test_helpers

import (
	geth_log "github.com/ethereum/go-ethereum/log"

	"github.com/cerc-io/plugeth-statediff/utils/log"
)

// QuietLogs silences the geth logs and sets the plugin test log level to "warning"
// The geth sync logs are noisy, so it can be nice to silence them.
func QuietLogs() {
	geth_log.Root().SetHandler(geth_log.DiscardHandler())
	log.TestLogger.SetLevel(2)
}
