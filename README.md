# plugeth-statediff

`cerc/go-ethereum` statediff functionality packaged as a plugeth plugin.

## Package

This package provides a [PluGeth](https://github.com/openrelayxyz/plugeth) plugin implementing an
auxiliary service that asynchronously computes changes in the `go-ethereum` state trie. The service
continuously listens for chain updates and builds state diffs, then relays the data to RPC
subscribers or writes them directly to Postgres as IPLD objects.

It also exposes RPC endpoints for fetching or writing to Postgres the state diff at a specific block
height or for a specific block hash. This operates on historical block and state data, and so
depends on a complete state archive.

Data is emitted in this differential format in order to make it feasible to the _entire_ Ethereum
state and publish it to IPLD (including intermediate state and storage trie nodes). If this service
is run continuously from genesis, the entire state at any block can be materialized from the
cumulative differentials up to that point.

## Interface types

The primary interface type is `Payload`, which serves as the main interface for accessing data in a
service. It packages various data components such as block RLP, total difficulty, receipts RLP, and
state object RLP. This encapsulates all of the differential data at a given block, and allows us to
index the entire Ethereum data structure as hash-linked IPLD objects.

The `StateObject` type represents the final diff output structure, including an array of state leaf
nodes and IPLD objects. For convenience, we also associate this object with the block number and
hash.

State leaf nodes contain information about account changes, including whether they are removed, an
account wrapper with account details and identifiers, and an array of storage leaf nodes
representing storage changes. The IPLD type encapsulates CID-content pairs, used for code mappings
and trie node (both intermediate and leaf) IPLD objects.

```go
// Payload packages the data to send to state diff subscriptions
type Payload struct {
    BlockRlp        []byte   `json:"blockRlp"`
    TotalDifficulty *big.Int `json:"totalDifficulty"`
    ReceiptsRlp     []byte   `json:"receiptsRlp"`
    StateObjectRlp  []byte   `json:"stateObjectRlp"    gencodec:"required"`

    // ...
}

// in package "types":

// StateObject is the final output structure from the builder
type StateObject struct {
    BlockNumber *big.Int        `json:"blockNumber"     gencodec:"required"`
    BlockHash   common.Hash     `json:"blockHash"       gencodec:"required"`
    Nodes       []StateLeafNode `json:"nodes"           gencodec:"required"`
    IPLDs       []IPLD          `json:"iplds"`
}

// StateLeafNode holds the data for a single state diff leaf node
type StateLeafNode struct {
    Removed        bool
    AccountWrapper AccountWrapper
    StorageDiff    []StorageLeafNode
}

// AccountWrapper is used to temporarily associate the unpacked node with its raw values
type AccountWrapper struct {
    Account *types.StateAccount
    LeafKey []byte
    CID     string
}

// StorageLeafNode holds the data for a single storage diff node leaf node
type StorageLeafNode struct {
    Removed bool
    Value   []byte
    LeafKey []byte
    CID     string
}

// IPLD holds a cid:content pair, e.g. for codehash to code mappings or for intermediate node IPLD objects
type IPLD struct {
    CID     string
    Content []byte
}
```

## Usage

The service is started when the plugin library is loaded by PluGeth and runs as an auxiliary component of the node as it syncs.

### CLI configuration

This service introduces a CLI flag namespace `statediff`. Note that PluGeth plugin arguments must be separated from geth arguments by `--`, e.g. `geth --datadir data -- --statediff`.

* `--statediff` is used to enable the service
* `--statediff.writing` is used to tell the service to write state diff objects it produces from synced `ChainEvent`s directly to a configured Postgres database
* `--statediff.workers` is used to set the number of concurrent workers to process state diff objects and write them into the database
* `--statediff.db.type` is the type of database we write out to (current options: `postgres`, `dump`, `file`)
* `--statediff.dump.dst` is the destination to write to when operating in database dump mode (`stdout`, `stderr`, `discard`)
* `--statediff.db.driver` is the specific driver to use for the database (current options for postgres: `pgx` and `sqlx`)
* `--statediff.db.host` is the hostname address to dial to connect to the database
* `--statediff.db.port` is the port to dial to connect to the database
* `--statediff.db.name` is the name of the database to connect to
* `--statediff.db.user` is the user to connect to the database as
* `--statediff.db.password` is the password to use to connect to the database
* `--statediff.db.conntimeout` is the connection timeout (in seconds)
* `--statediff.db.maxconns` is the maximum number of database connections
* `--statediff.db.minconns` is the minimum number of database connections
* `--statediff.db.maxidleconns` is the maximum number of idle connections
* `--statediff.db.maxconnidletime` is the maximum lifetime for an idle connection (in seconds)
* `--statediff.db.maxconnlifetime` is the maximum lifetime for a connection (in seconds)
* `--statediff.db.nodeid` is the node id to use in the Postgres database
* `--statediff.db.clientname` is the client name to use in the Postgres database
* `--statediff.db.upsert` whether or not the service, when operating in a direct database writing mode, should overwrite any existing conflicting data
* `--statediff.file.path` full path (including filename) to write statediff data out to when operating in file mode
* `--statediff.file.wapath` full path (including filename) to write statediff watched addresses out to when operating in file mode

The service can only operate in full sync mode (`--syncmode=full`), but only the historical RPC endpoints require an archive node (`--gcmode=archive`)

e.g.
`geth --syncmode=full --gcmode=archive -- --statediff --statediff.writing --statediff.db.type=postgres --statediff.db.driver=sqlx --statediff.db.host=localhost --statediff.db.port=5432 --statediff.db.name=cerc_testing --statediff.db.user=postgres --statediff.db.nodeid=nodeid --statediff.db.clientname=clientname`

When operating in `--statediff.db.type=file` mode, the service will save SQL statements to the file
specified by `--statediff.file.path`. It's important to note that these SQL statements are written
without any `ON CONFLICT` constraint checks. This omission allows us to:
  * horizontally expand the production of SQL statements,
  * merge the individual SQL files generated,
  * remove duplicates using Unix tools (`sort statediff.sql | uniq` or `sort -u statediff.sql`),
  * perform bulk loading using psql (`psql db_name --set ON_ERROR_STOP=on -f statediff.sql`),
  * and then reinstate our primary and foreign key constraints and indexes.

### Payload retrieval

The state diffing service exposes both a websocket subscription endpoint, and a number of HTTP unary
endpoints for retrieving data payloads.

Each of these endpoints requires a set of parameters provided by the caller:

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

Using these params we can tell the service:
  * whether to include state and/or storage intermediate nodes
  * whether to include the associated block (header, uncles, and transactions)
  * whether to include the associated receipts
  * whether to include the total difficulty for this block
  * whether to include the set of code hashes and code for contracts deployed in this block, and
  * whether to limit the diffing process to a list of specific addresses.

#### Subscription endpoints

A websocket-supporting RPC endpoint is exposed for subscribing to state diff `StateObjects` that come off the head of the chain while the geth node syncs.

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

If `--statediff.writing` is enabled, the service will convert the `StateObject`s and all associated
data into IPLD objects, persist them directly to Postgres, and generate secondary indexes around the
IPLD data.

The schema and migrations for this Postgres database are defined in <https://github.com/cerc-io/ipld-eth-db>.

#### RPC endpoints

If enabled, direct indexing will be triggered on every `ChainEvent`, writing diffs for all new
blocks as they are received. However, the service also provides methods for clients to trigger and
track this process:

  * The `WriteStateDiffAt` method directly writes a state diff object to the database at a specific
    block height.
  * Likewise, the `WriteStateDiffFor` method directly writes a state diff object to the database for
    a specific block hash
  * The `StreamWrites` method sets up a subscription to stream the status of completed calls to the
    above methods.
  * The `WatchAddress` method enables the modification of the watched addresses list, restricting
    direct indexing for a given operation and arguments.


#### Schema overview

Our Postgres schemas are built around a single IPFS backing Postgres IPLD blockstore table
(`ipld.blocks`) that conforms with
[go-ds-sql](https://github.com/ipfs/go-ds-sql/blob/master/postgres/postgres.go).  All IPLD objects
are stored in this table, where `key` is the CID for the IPLD object and `data` contains the bytes
for the IPLD block (in the case of all Ethereum IPLDs, this is the RLP byte encoding of the Ethereum
object).

The IPLD objects in this table can be traversed using an IPLD DAG interface, but since this table
only maps CID to raw IPLD object it is not very suitable for looking up Ethereum objects by their
constituent fields (e.g. by tx source/recipient, state/storage trie path). To improve the
accessibility of these objects we create an Ethereum [advanced data
layout](https://github.com/ipld/specs#schemas-and-advanced-data-layouts) (ADL) by generating
secondary indexes on top of the raw IPLDs in other Postgres tables.

These secondary index tables fall under the `eth` schema and follow an `{objectType}_cids` naming
convention.  These tables provide a view into individual fields of the underlying Ethereum IPLD
objects, allowing lookups on these fields, and reference the raw IPLD objects stored in
`ipld.blocks` by CID.  Additionally, these tables maintain the hash-linked nature of Ethereum
objects to one another, e.g. a storage trie node entry in the `storage_cids` table contains a
`state_leaf_key` field referencing the `state_cids` entry for the state trie node of its owning
contract, and that `state_cids` entry in turn contains a `header_id` field referencing the
`block_hash` of the `header_cids` entry for the block in which these state and storage nodes were
updated (diffed).

### Optimization

On mainnet this process is extremely IO intensive and requires significant resources to allow it to
keep up with the head of the chain.  The state diff processing time for a specific block is
dependent on the number and complexity of the state changes that occur in a block and the number of
updated state nodes that are available in the in-memory cache vs must be retrieved from disc.

If memory permits, one means of improving the efficiency of this process is to increase the
in-memory trie cache allocation.  This can be done by increasing the overall `--cache` allocation
and/or by increasing the % of the cache allocated to trie usage with `--cache.trie`.

<!-- TO DO -->
<!-- ## Versioning, Branches, Rebasing, and Releasing -->
