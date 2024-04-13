#!/bin/bash
# Builds and deploys a stack with only what we need.
# This script assumes we are running in the project root.

set -e

# Note: stack path should be absolute, otherwise SO looks for it in packaged stacks
laconic_so="${LACONIC_SO:-laconic-so} --stack $(readlink -f test) --verbose"

CONFIG_DIR=$(readlink -f "${CONFIG_DIR:-$(mktemp -d)}")

# Point stack-orchestrator to the multi-project root
export CERC_REPO_BASE_DIR="${CERC_REPO_BASE_DIR:-$(git rev-parse --show-toplevel)/..}"

# v5 migrations only go up to version 18
echo CERC_STATEDIFF_DB_GOOSE_MIN_VER=18 >> $CONFIG_DIR/stack.env
# don't run plugeth in the debugger
echo CERC_REMOTE_DEBUG=false >> $CONFIG_DIR/stack.env

set -x

if [[ -z $SKIP_BUILD ]]; then
  $laconic_so setup-repositories \
    --exclude git.vdb.to/cerc-io/plugeth,git.vdb.to/cerc-io/plugeth-statediff

  $laconic_so build-containers \
    --exclude cerc/plugeth,cerc/plugeth-statediff
fi

$laconic_so deploy \
    --env-file $CONFIG_DIR/stack.env \
    --cluster test up
