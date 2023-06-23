# Statediff database indexing

To process data in real time as Geth syncs updates to the Ethereum execution layer, the statediff
service is able to directly transform and load data into a Postgres database. The `indexer` package
contains abstractions for handling this ingestion.

## Interface

A `StateDiffIndexer` object is responsible for inserting statediff data into a database, as well as managing watched address lists for a given database.
Three implementations are currently maintained: 
  * `sql` for direct insertion to Postgres
  * `file` which writes to CSV for SQL files for insertion in a separate step
  * `dump` which simply dumps to stdout
