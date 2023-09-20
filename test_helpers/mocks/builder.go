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

package mocks

import (
	statediff "github.com/cerc-io/plugeth-statediff"
	sdtypes "github.com/cerc-io/plugeth-statediff/types"
)

var _ statediff.Builder = &Builder{}

// Builder is a mock state diff builder
type Builder struct {
	Args         statediff.Args
	Params       statediff.Params
	stateDiff    sdtypes.StateObject
	builderError error
}

// BuildStateDiffObject mock method
func (builder *Builder) BuildStateDiffObject(args statediff.Args, params statediff.Params) (sdtypes.StateObject, error) {
	builder.Args = args
	builder.Params = params

	return builder.stateDiff, builder.builderError
}

// BuildStateDiffObject mock method
func (builder *Builder) WriteStateDiff(args statediff.Args, params statediff.Params, output sdtypes.StateNodeSink, iplds sdtypes.IPLDSink) error {
	builder.Args = args
	builder.Params = params

	return builder.builderError
}

// SetStateDiffToBuild mock method
func (builder *Builder) SetStateDiffToBuild(stateDiff sdtypes.StateObject) {
	builder.stateDiff = stateDiff
}

// SetBuilderError mock method
func (builder *Builder) SetError(err error) {
	builder.builderError = err
}
