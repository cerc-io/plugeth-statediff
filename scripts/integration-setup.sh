#!/bin/bash
# Builds and deploys a stack with only what we need.
# This script assumes we are running in the project root.

set -e

cluster="${1:-test}"
laconic_so="${LACONIC_SO:-laconic-so} --stack fixturenet-plugeth-tx --verbose"

CONFIG_DIR=$(readlink -f "${CONFIG_DIR:-$(mktemp -d)}")

# Point stack-orchestrator to the multi-project root
export CERC_REPO_BASE_DIR="${CERC_REPO_BASE_DIR:-$(git rev-parse --show-toplevel)/..}"

# v5 migrations only go up to version 18
echo CERC_STATEDIFF_DB_GOOSE_MIN_VER=18 >> $CONFIG_DIR/stack.env

set -x

if [[ -z $SKIP_BUILD ]]; then
    $laconic_so setup-repositories \
        --exclude github.com/dboreham/foundry,github.com/cerc-io/tx-spammer,github.com/cerc-io/ipld-eth-server,git.vdb.to/cerc-io/plugeth,git.vdb.to/cerc-io/plugeth-statediff \
        --branches-file ./test/stack-refs.txt

    $laconic_so build-containers \
        --exclude cerc/ipld-eth-server,cerc/keycloak,cerc/tx-spammer,cerc/foundry,cerc/plugeth,cerc/plugeth-statediff
fi

$laconic_so deploy \
    --exclude foundry,keycloak,tx-spammer,ipld-eth-server \
    --env-file $CONFIG_DIR/stack.env \
    --cluster "$cluster" up
