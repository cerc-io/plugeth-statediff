// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package statediff

import (
	"time"

	"github.com/cerc-io/plugeth-statediff/utils/log"
	"github.com/ethereum/go-ethereum/core/types"
)

func countStateDiffBegin(block *types.Block) (time.Time, log.Logger) {
	start := time.Now()
	logger := log.New("hash", block.Hash().String(), "number", block.NumberU64())

	defaultStatediffMetrics.underway.Inc(1)
	logger.Debug("writeStateDiff BEGIN",
		"underway", defaultStatediffMetrics.underway.Count(),
		"succeeded", defaultStatediffMetrics.succeeded.Count(),
		"failed", defaultStatediffMetrics.failed.Count(),
		"total_time", defaultStatediffMetrics.totalProcessingTime.Value(),
	)

	return start, logger
}

func countStateDiffEnd(start time.Time, logger log.Logger, err error) time.Duration {
	duration := time.Since(start)
	defaultStatediffMetrics.underway.Dec(1)
	if nil == err {
		defaultStatediffMetrics.succeeded.Inc(1)
	} else {
		defaultStatediffMetrics.failed.Inc(1)
	}
	defaultStatediffMetrics.totalProcessingTime.Inc(duration.Milliseconds())

	logger.Debug("writeStateDiff END",
		"duration", duration,
		"error", err != nil,
		"underway", defaultStatediffMetrics.underway.Count(),
		"succeeded", defaultStatediffMetrics.succeeded.Count(),
		"failed", defaultStatediffMetrics.failed.Count(),
		"total_time", defaultStatediffMetrics.totalProcessingTime.Value(),
	)

	return duration
}

func countApiRequestBegin(methodName string, blockHashOrNumber interface{}) (time.Time, log.Logger) {
	start := time.Now()
	logger := log.New(methodName, blockHashOrNumber)

	defaultStatediffMetrics.apiRequests.Inc(1)
	defaultStatediffMetrics.apiRequestsUnderway.Inc(1)

	logger.Debug("statediff API BEGIN",
		"underway", defaultStatediffMetrics.apiRequestsUnderway.Count(),
		"requests", defaultStatediffMetrics.apiRequests.Count(),
	)

	return start, logger
}

func countApiRequestEnd(start time.Time, logger log.Logger, err error) time.Duration {
	duration := time.Since(start)
	defaultStatediffMetrics.apiRequestsUnderway.Dec(1)

	logger.Debug("statediff API END",
		"duration", duration,
		"error", err != nil,
		"underway", defaultStatediffMetrics.apiRequestsUnderway.Count(),
		"requests", defaultStatediffMetrics.apiRequests.Count(),
	)

	return duration
}
