package test_helpers

import (
	geth_log "github.com/ethereum/go-ethereum/log"

	"github.com/cerc-io/plugeth-statediff/utils/log"
)

// QuietLogs discards the geth logs and sets the plugin test log level to "warning"
// The geth sync logs are noisy, so during some tests it helps to silence them.
func QuietLogs() {
	geth_log.SetDefault(geth_log.New(geth_log.DiscardHandler()))
	log.TestLogger.SetLevel(2)
}
