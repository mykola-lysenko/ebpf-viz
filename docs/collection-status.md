# Collection status and freshness

Live snapshots now include an optional `collection` object. The same metadata
survives raw capture imports, OS Map exports, and snapshot comparisons. Files
without metadata remain supported and show unknown coverage.

Each entry in `collection.sources` has a stable source key, display label,
state, attempt time, and last successful collection time (Unix milliseconds).
Successful list commands may also report their record count.

| State | Meaning |
|---|---|
| `ok` | The command returned a validated response, or a capability was confirmed. A successful empty array is valid data. |
| `error` | Command execution, output parsing, or validation failed. |
| `unsupported` | The tool/operation is explicitly unavailable; permission errors remain errors. |
| `partial` | Some discovery coverage was omitted, such as namespaces beyond the scan cap. |
| `skipped` | Collection was deferred or not attempted; the reason is included. |
| `unknown` | Coverage or capability evidence is missing, including older tool versions. |

`attemptedAt` is null for a skipped command. `lastSuccessAt` is null until a
successful collection exists; a failed attempt never advances that timestamp.
Last-good raw data is retained per source after errors. Fresh sources can update
alongside stale ones; this is not an atomic host snapshot. The UI exposes each
source's evidence and times. Old successful data can legitimately be empty.

The poller records no new runtime samples and prunes no program histories when
program collection fails. Recovery measures counters over the interval between
successful samples. Changing the collector configuration clears retained data
and histories so data from different modes/tool configurations cannot mix.

Namespace discovery records the discovered count, scan cap, omitted count,
actual scans, deferrals, and discovery time. Discovery is cached for 30 seconds.
Namespaces confirmed uninteresting by successful BPF and device scans may be
deferred for up to 60 seconds; failed scans are retried on the next poll.
Discovery permission errors and unavailable Docker tooling are explicit.
Counts describe the namespaces discoverable through the reported methods,
not proof that every namespace on a host was visible.

The shell capture tool records command status and stderr, applies a 64-namespace
scan cap, and labels its lack of Docker-VM discovery. It requires no extra JSON
runtime: it rejects obvious non-array output and leaves full JSON/schema
validation to import. Malformed JSON that passes the shell's basic check causes
an explicit import error. Map-entry dump completeness is separate from inventory
collection; see [map-dump comparison semantics](snapshot-diff.md) for A.2.

Collection metadata travels in lightweight SSE metric updates so freshness and
errors update without forcing full topology transmission. A live SSE connection
indicates transport health, not successful host collection. Snapshot diffs show
coverage warnings; equality is unverified when collection is incomplete or
unknown. A.2 builds on these warnings with shared object matching and explicit
map-entry comparison uncertainty.
