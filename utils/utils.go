package utils

import (
	"fmt"
	"os"

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
