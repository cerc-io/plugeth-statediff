#!/bin/bash

set -ex

# Note: stack path should be absolute, otherwise SO looks for it in packaged stacks
stack_dir=$(readlink -f "${1:-../fixturenet-eth-stacks/stack-orchestrator/stacks/fixturenet-plugeth}")

[[ -d "$stack_dir" ]]

CONFIG_DIR=$(readlink -f "${CONFIG_DIR:-$(mktemp -d)}")
# By default assume we are running in the project root.
export CERC_REPO_BASE_DIR="${CERC_REPO_BASE_DIR:-$(git rev-parse --show-toplevel)/..}"

laconic_so="laconic-so --verbose --stack $stack_dir"

# Don't run geth/plugeth in the debugger, it will swallow error backtraces
echo CERC_REMOTE_DEBUG=false >> $CONFIG_DIR/stack.env


if [[ -z $SKIP_BUILD ]]; then
  $laconic_so setup-repositories \
    --exclude git.vdb.to/cerc-io/plugeth-statediff
  # Assume the tested image has been built separately
  $laconic_so build-containers \
    --exclude cerc/plugeth-statediff
fi

if ! $laconic_so deploy \
  --env-file $CONFIG_DIR/stack.env \
  --cluster test up
then
  $laconic_so deploy --cluster test logs
  exit 1
fi
