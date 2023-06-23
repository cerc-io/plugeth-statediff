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
	"context"

	"github.com/ethereum/go-ethereum/common"

	"github.com/cerc-io/plugeth-statediff/types"
	"github.com/cerc-io/plugeth-statediff/utils/log"
)

// APIName is the namespace used for the state diffing service API
const APIName = "statediff"

// APIVersion is the version of the state diffing service API
// TODO: match package version?
const APIVersion = "0.0.1"

// PublicStateDiffAPI provides an RPC subscription interface
// that can be used to stream out state diffs as they
// are produced by a full node
type PublicAPI struct {
	sds *Service
}

// NewPublicStateDiffAPI creates an rpc subscription interface for the underlying statediff service
func NewPublicAPI(sds *Service) *PublicAPI {
	return &PublicAPI{
		sds: sds,
	}
}

// Stream subscribes to statediff payloads as they are created.
func (api *PublicAPI) Stream(ctx context.Context, params Params) (<-chan Payload, error) {
	payloadChan := make(chan Payload, chainEventChanSize)
	clientChan := make(chan Payload, chainEventChanSize)
	quitChan := make(chan bool, 1)
	// subscribe to the service's payload broadcasts
	id := api.sds.Subscribe(payloadChan, quitChan, params)

	go func() {
		defer close(clientChan)
		defer close(payloadChan)
		defer func() {
			if err := api.sds.Unsubscribe(id); err != nil {
				log.Error("Failed to unsubscribe from statediff service", "error", err)
			}
		}()

		for {
			select {
			case payload := <-payloadChan:
				clientChan <- payload
			case <-ctx.Done():
				return
			case <-quitChan:
				return
			}
		}
	}()

	return clientChan, nil
}

// StateDiffAt returns a state diff payload at the specific blockheight
func (api *PublicAPI) StateDiffAt(ctx context.Context, blockNumber uint64, params Params) (*Payload, error) {
	return api.sds.StateDiffAt(blockNumber, params)
}

// StateDiffFor returns a state diff payload for the specific blockhash
func (api *PublicAPI) StateDiffFor(ctx context.Context, blockHash common.Hash, params Params) (*Payload, error) {
	return api.sds.StateDiffFor(blockHash, params)
}

// StreamCodeAndCodeHash writes all of the codehash=>code pairs at a given block to a websocket channel.
func (api *PublicAPI) StreamCodeAndCodeHash(ctx context.Context, blockNumber uint64) (<-chan types.CodeAndCodeHash, error) {
	payloadChan := make(chan types.CodeAndCodeHash, chainEventChanSize)
	clientChan := make(chan types.CodeAndCodeHash, chainEventChanSize)
	quitChan := make(chan bool, 1)
	api.sds.StreamCodeAndCodeHash(blockNumber, payloadChan, quitChan)

	go func() {
		defer close(clientChan)
		defer close(payloadChan)

		for {
			select {
			case payload := <-payloadChan:
				clientChan <- payload
			case <-ctx.Done():
				return
			case <-quitChan:
				return
			}
		}
	}()

	return clientChan, nil
}

// WriteStateDiffAt writes a state diff object directly to DB at the specific blockheight
func (api *PublicAPI) WriteStateDiffAt(ctx context.Context, blockNumber uint64, params Params) JobID {
	var err error
	start, logger := countApiRequestBegin("writeStateDiffAt", blockNumber)
	defer countApiRequestEnd(start, logger, err)

	return api.sds.WriteStateDiffAt(blockNumber, params)
}

// WriteStateDiffFor writes a state diff object directly to DB for the specific block hash
func (api *PublicAPI) WriteStateDiffFor(ctx context.Context, blockHash common.Hash, params Params) error {
	var err error
	start, logger := countApiRequestBegin("writeStateDiffFor", blockHash.String())
	defer countApiRequestEnd(start, logger, err)

	err = api.sds.WriteStateDiffFor(blockHash, params)
	return err
}

// WatchAddress changes the list of watched addresses to which the direct indexing is restricted
// for the given operation.
func (api *PublicAPI) WatchAddress(operation types.OperationType, args []types.WatchAddressArg) error {
	return api.sds.WatchAddress(operation, args)
}

// StreamWrites sets up a subscription that streams the status of completed calls to WriteStateDiff*
func (api *PublicAPI) StreamWrites(ctx context.Context) (<-chan JobStatus, error) {
	// subscribe to events from the statediff service
	statusChan := make(chan JobStatus, chainEventChanSize)
	clientChan := make(chan JobStatus, chainEventChanSize)
	id := api.sds.SubscribeWriteStatus(statusChan)

	go func() {
		defer func() {
			close(statusChan)
			close(clientChan)
		}()

		for {
			select {
			case status := <-statusChan:
				clientChan <- status
			case <-ctx.Done():
				api.sds.UnsubscribeWriteStatus(id)
				return
			}
		}
	}()

	return clientChan, nil
}
