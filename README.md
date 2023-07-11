# plugeth-statediff

`cerc/go-ethereum` statediff functionality packaged as a plugeth plugin.

## Package

This package provides an auxiliary service that asynchronously processes state diff objects from chain events,
either relaying the state objects to RPC subscribers or writing them directly to Postgres as IPLD objects.

It also exposes RPC endpoints for fetching or writing to Postgres the state diff at a specific block height
or for a specific block hash, this operates on historical block and state data and so depends on a complete state archive.

Data is emitted in this differential format in order to make it feasible to IPLD-ize and index the _entire_ Ethereum state
(including intermediate state and storage trie nodes). If this state diff process is ran continuously from genesis,
the entire state at any block can be materialized from the cumulative differentials up to that point.

## Statediff object

A state diff `StateObject` is the collection of all the state and storage trie nodes that have been updated in a given block.
For convenience, we also associate these nodes with the block number and hash, and optionally the set of code hashes and code for any
contracts deployed in this block.

A complete state diff `StateObject` will include all state and storage intermediate nodes, which is necessary for generating proofs and for
traversing the tries.

```go
// StateObject is a collection of state (and linked storage nodes) as well as the associated block number, block hash,
// and a set of code hashes and their code
type StateObject struct {
	BlockNumber       *big.Int                `json:"blockNumber"     gencodec:"required"`
	BlockHash         common.Hash             `json:"blockHash"       gencodec:"required"`
	Nodes             []StateNode             `json:"nodes"           gencodec:"required"`
	CodeAndCodeHashes []CodeAndCodeHash       `json:"codeMapping"`
}

// StateNode holds the data for a single state diff node
type StateNode struct {
	NodeType     NodeType      `json:"nodeType"        gencodec:"required"`
	Path         []byte        `json:"path"            gencodec:"required"`
	NodeValue    []byte        `json:"value"           gencodec:"required"`
	StorageNodes []StorageNode `json:"storage"`
	LeafKey      []byte        `json:"leafKey"`
}

// StorageNode holds the data for a single storage diff node
type StorageNode struct {
	NodeType  NodeType `json:"nodeType"        gencodec:"required"`
	Path      []byte   `json:"path"            gencodec:"required"`
	NodeValue []byte   `json:"value"           gencodec:"required"`
	LeafKey   []byte   `json:"leafKey"`
}

// CodeAndCodeHash struct for holding codehash => code mappings
// we can't use an actual map because they are not rlp serializable
type CodeAndCodeHash struct {
	Hash common.Hash `json:"codeHash"`
	Code []byte      `json:"code"`
}
```

These objects are packed into a `Payload` structure which can additionally associate the `StateObject`
with the block (header, uncles, and transactions), receipts, and total difficulty.
This `Payload` encapsulates all of the differential data at a given block, and allows us to index the entire Ethereum data structure
as hash-linked IPLD objects.

```go
// Payload packages the data to send to state diff subscriptions
type Payload struct {
	BlockRlp        []byte   `json:"blockRlp"`
	TotalDifficulty *big.Int `json:"totalDifficulty"`
	ReceiptsRlp     []byte   `json:"receiptsRlp"`
	StateObjectRlp  []byte   `json:"stateObjectRlp"    gencodec:"required"`

	encoded []byte
	err     error
}
```

## Usage

This state diffing service runs as an auxiliary service concurrent to the regular syncing process of the geth node.

### CLI configuration

This service introduces a CLI flag namespace `statediff`

`--statediff` flag is used to turn on the service

`--statediff.writing` is used to tell the service to write state diff objects it produces from synced ChainEvents directly to a configured Postgres database

`--statediff.workers` is used to set the number of concurrent workers to process state diff objects and write them into the database

`--statediff.db.type` is the type of database we write out to (current options: postgres, dump, file)

`--statediff.dump.dst` is the destination to write to when operating in database dump mode (stdout, stderr, discard)

`--statediff.db.driver` is the specific driver to use for the database (current options for postgres: pgx and sqlx)

`--statediff.db.host` is the hostname/ip to dial to connect to the database

`--statediff.db.port` is the port to dial to connect to the database

`--statediff.db.name` is the name of the database to connect to

`--statediff.db.user` is the user to connect to the database as

`--statediff.db.password` is the password to use to connect to the database

`--statediff.db.conntimeout` is the connection timeout (in seconds)

`--statediff.db.maxconns` is the maximum number of database connections

`--statediff.db.minconns` is the minimum number of database connections

`--statediff.db.maxidleconns` is the maximum number of idle connections

`--statediff.db.maxconnidletime` is the maximum lifetime for an idle connection (in seconds)

`--statediff.db.maxconnlifetime` is the maximum lifetime for a connection (in seconds)

`--statediff.db.nodeid` is the node id to use in the Postgres database

`--statediff.db.clientname` is the client name to use in the Postgres database

`--statediff.db.upsert` whether or not the service, when operating in a direct database writing mode, should overwrite any existing conflicting data

`--statediff.file.path` full path (including filename) to write statediff data out to when operating in file mode

`--statediff.file.wapath` full path (including filename) to write statediff watched addresses out to when operating in file mode

The service can only operate in full sync mode (`--syncmode=full`), but only the historical RPC endpoints require an archive node (`--gcmode=archive`)

e.g.
`./build/bin/geth --syncmode=full --gcmode=archive --statediff --statediff.writing --statediff.db.type=postgres --statediff.db.driver=sqlx --statediff.db.host=localhost --statediff.db.port=5432 --statediff.db.name=cerc_testing --statediff.db.user=postgres --statediff.db.nodeid=nodeid --statediff.db.clientname=clientname`

When operating in `--statediff.db.type=file` mode, the service will write SQL statements out to the file designated by
`--statediff.file.path`. Please note that it writes out SQL statements with all `ON CONFLICT` constraint checks dropped.
This is done so that we can scale out the production of the SQL statements horizontally, merge the separate SQL files produced,
de-duplicate using unix tools (`sort statediff.sql | uniq` or `sort -u statediff.sql`), bulk load using psql
(`psql db_name --set ON_ERROR_STOP=on -f statediff.sql`), and then add our primary and foreign key constraints and indexes
back afterwards.

### RPC endpoints

The state diffing service exposes both a WS subscription endpoint, and a number of HTTP unary endpoints.

Each of these endpoints requires a set of parameters provided by the caller

```go
// Params is used to carry in parameters from subscribing/requesting clients configuration
type Params struct {
	IntermediateStateNodes   bool
	IntermediateStorageNodes bool
	IncludeBlock             bool
	IncludeReceipts          bool
	IncludeTD                bool
	IncludeCode              bool
	WatchedAddresses         []common.Address
}
```

Using these params we can tell the service whether to include state and/or storage intermediate nodes; whether
to include the associated block (header, uncles, and transactions); whether to include the associated receipts;
whether to include the total difficulty for this block; whether to include the set of code hashes and code for
contracts deployed in this block; whether to limit the diffing process to a list of specific addresses.

#### Subscription endpoint

A websocket supporting RPC endpoint is exposed for subscribing to state diff `StateObjects` that come off the head of the chain while the geth node syncs.

```go
// Stream is a subscription endpoint that fires off state diff payloads as they are created
Stream(ctx context.Context, params Params) (*rpc.Subscription, error)
```

To expose this endpoint the node needs to have the websocket server turned on (`--ws`),
and the `statediff` namespace exposed (`--ws.api=statediff`).

Go code subscriptions to this endpoint can be created using the `rpc.Client.Subscribe()` method,
with the "statediff" namespace, a `statediff.Payload` channel, and the name of the statediff api's rpc method: "stream".

e.g.

```go

cli, err := rpc.Dial("ipcPathOrWsURL")
if err != nil {
	// handle error
}
stateDiffPayloadChan := make(chan statediff.Payload, 20000)
methodName := "stream"
params := statediff.Params{
    IncludeBlock:             true,
    IncludeTD:                true,
    IncludeReceipts:          true,
    IntermediateStorageNodes: true,
    IntermediateStateNodes:   true,
}
rpcSub, err := cli.Subscribe(context.Background(), statediff.APIName, stateDiffPayloadChan, methodName, params)
if err != nil {
	// handle error
}
for {
	select {
	case stateDiffPayload := <- stateDiffPayloadChan:
            // process the payload
        case err := <- rpcSub.Err():
    	    // handle rpc subscription error
        }
}
```

#### Unary endpoints

The service also exposes unary RPC endpoints for retrieving the state diff `StateObject` for a specific block height/hash.

```go
// StateDiffAt returns a state diff payload at the specific blockheight
StateDiffAt(ctx context.Context, blockNumber uint64, params Params) (*Payload, error)

// StateDiffFor returns a state diff payload for the specific blockhash
StateDiffFor(ctx context.Context, blockHash common.Hash, params Params) (*Payload, error)
```

To expose this endpoint the node needs to have the HTTP server turned on (`--http`),
and the `statediff` namespace exposed (`--http.api=statediff`).

### Direct indexing into Postgres

If `--statediff.writing` is set, the service will convert the state diff `StateObject` data into IPLD objects, persist them directly to Postgres,
and generate secondary indexes around the IPLD data.

The schema and migrations for this Postgres database are provided in `statediff/db/`.

#### Postgres setup

We use [pressly/goose](https://github.com/pressly/goose) as our Postgres migration manager.
You can also load the Postgres schema directly into a database using

`psql database_name < schema.sql`

This will only work on a version 12.4 Postgres database.

#### Schema overview

Our Postgres schemas are built around a single IPFS backing Postgres IPLD blockstore table (`ipld.blocks`) that conforms with [go-ds-sql](https://github.com/ipfs/go-ds-sql/blob/master/postgres/postgres.go).
All IPLD objects are stored in this table, where `key` is the blockstore-prefixed multihash key for the IPLD object and `data` contains
the bytes for the IPLD block (in the case of all Ethereum IPLDs, this is the RLP byte encoding of the Ethereum object).

The IPLD objects in this table can be traversed using an IPLD DAG interface, but since this table only maps multihash to raw IPLD object
it is not particularly useful for searching through the data by looking up Ethereum objects by their constituent fields
(e.g. by block number, tx source/recipient, state/storage trie node path). To improve the accessibility of these objects
we create an Ethereum [advanced data layout](https://github.com/ipld/specs#schemas-and-advanced-data-layouts) (ADL) by generating secondary
indexes on top of the raw IPLDs in other Postgres tables.

These secondary index tables fall under the `eth` schema and follow an `{objectType}_cids` naming convention.
These tables provide a view into individual fields of the underlying Ethereum IPLD objects, allowing lookups on these fields, and reference the raw IPLD objects stored in `ipld.blocks`
by foreign keys to their multihash keys.
Additionally, these tables maintain the hash-linked nature of Ethereum objects to one another. E.g. a storage trie node entry in the `storage_cids`
table contains a `state_id` foreign key which references the `id` for the `state_cids` entry that contains the state leaf node for the contract that storage node belongs to,
and in turn that `state_cids` entry contains a `header_id` foreign key which references the `id` of the `header_cids` entry that contains the header for the block these state and storage nodes were updated (diffed).

### Optimization

On mainnet this process is extremely IO intensive and requires significant resources to allow it to keep up with the head of the chain.
The state diff processing time for a specific block is dependent on the number and complexity of the state changes that occur in a block and
the number of updated state nodes that are available in the in-memory cache vs must be retrieved from disc.

If memory permits, one means of improving the efficiency of this process is to increase the in-memory trie cache allocation.
This can be done by increasing the overall `--cache` allocation and/or by increasing the % of the cache allocated to trie
usage with `--cache.trie`.

## Versioning, Branches, Rebasing, and Releasing

Internal tagged releases are maintained for building the latest version of statediffing geth or using it as a go mod dependency.
When a new core go-ethereum version is released, statediffing geth is rebased onto and adjusted to work with the new tag.

We want to maintain a complete record of our git history, but in order to make frequent and timely rebases feasible we also
need to be able to squash our work before performing a rebase. To this end we retain multiple branches with partial incremental history that culminate in
the full incremental history.

### Versioning

Example: `v1.10.16-statediff-3.0.2`

- The first section, `v1.10.16`, corresponds to the release of the root branch this version is rebased onto (e.g., [](https://github.com/ethereum/go-ethereum/releases/tag/v1.10.16)[https://github.com/ethereum/go-ethereum/releases/tag/v1.10.16](https://github.com/ethereum/go-ethereum/releases/tag/v1.10.16))
- The second section, `3.0.2`, corresponds to the version of our statediffing code. The major version here (3) should always correspond with the major version of the `ipld-eth-db` schema version it works with (e.g., [](https://github.com/cerc-io/ipld-eth-db/releases/tag/v3.0.6)[https://github.com/vulcanize/ipld-eth-db/releases/tag/v3.0.6](https://github.com/vulcanize/ipld-eth-db/releases/tag/v3.0.6)); it is only bumped when we bump the major version of the schema.
  - The major version of the schema is only bumped when a breaking change is made to the schema.
  - The minor version is bumped when a new feature is added, or a fix is performed that breaks or updates the statediffing API or CLI in some way.
  - The patch version is bumped whenever minor fixes/patches/features are done that don’t change/break API/CLI compatibility.
- We are very strict about the first section and the major version of the statediffing code, but some discretion is required when deciding to bump minor versus patch version of the statediffing code.

The statediff version is included in the `VersionMeta` in params/version.go

### Branches

We maintain two official kinds of branches:

Major Branch: `{Root Version}-statediff`
Major branches retain the cumulative state of all changes made before the latest root version rebase and track the full incremental history of changes made between the latest root version rebase and the next.
Aside from creating the branch by performing the rebase described in the section below, these branches are never worked off of or committed to directly.

Feature Branch: `{Root Version}-statediff-{Statediff Version}`
Feature branches are checked out from a major branch in order to work on a new feature or fix for the statediffing code.
The statediff version of a feature branch is the new version it affects on the major branch when merged. Internal tagged releases
are cut against these branches after they are merged back to the major branch.

If a developer is unsure what version their patch should affect, they should remain working on an unofficial branch. From there
they can open a PR against the targeted root branch and be directed to the appropriate feature version and branch.

### Rebasing

When a new root tagged release comes out we rebase our statediffing code on top of the new tag using the following process:

1. Checkout a new major branch for the tag from the current major branch
2. On the new major branch, squash all our commits since the last major rebase
3. On the new major branch, perform the rebase against the new tag
4. Push the new major branch to the remote
5. From the new major branch, checkout a new feature branch based on the new major version and the last statediff version
6. On this new feature branch, add the new major branch to the .github/workflows/on-master.yml list of "on push" branches
7. On this new feature branch, make any fixes/adjustments required for all statediffing geth tests to pass
8. PR this feature branch into the new major branch, this PR will trigger CI tests and builds.
9. After merging PR, rebase feature branch onto major branch
10. Cut a new release targeting the feature branch, this release should have the new root version but the same statediff version as the last release
