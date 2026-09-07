# Snapshot comparison semantics

A.2 uses one object correspondence for inventory relationships and map contents.
The diff compares selected inventory fields and separately reports map-entry
changes; it does not claim that entire captures or kernel object lifetimes are
identical.

## Object matching

- Programs correspond by name, raw program type, and bytecode tag. A changed
  known tag produces an added/removed program. Missing tags leave correspondence
  unverified rather than proving a reload or equality.
- Maps correspond by name and raw map type. Size, flags, capacity, frozen state,
  and pin paths remain compared fields rather than matching keys.
- Within a duplicate identity, only unique, identical, nonempty pin-path sets
  establish a pair. Remaining clones are ambiguous; the UI lists their IDs on
  each side and their instance counts. It does not pair by ascending ID or infer
  the identity of leftover objects by elimination.
- These are logical comparison correspondences. Names and pins can be reused;
  they do not prove physical continuity, especially across hosts or reloads.
  Kernel IDs locate references within each capture only.

Program-to-map relationships and map-to-program users are compared as sets of
these matched identities. ID renumbering alone is not a change; replacing one
relationship with another is a change even if counts stay equal. Missing or
ambiguous targets make that relationship comparison explicitly unverified.
Pin paths and process owner names are compared as sets, ignoring order and
repeated entries. Changed pin paths are listed in the result.

Map contents reuse exactly the map pairs from inventory comparison. Ambiguous
map groups do not receive an arbitrary entry comparison. Load the companion
dump from each respective capture: local map IDs alone cannot verify that an
independently supplied dump file belongs to that capture.

## Dump completeness

The capture script writes map-dump format version 2. Each numeric map ID maps
to a record such as:

```json
{
  "entries": [{ "key": ["0x01"], "value": ["0x02"] }],
  "complete": false,
  "totalEntries": 30,
  "truncated": true,
  "error": "capture timeout",
  "unsupported": false
}
```

`entries` and `complete` are required; the other fields are optional. Without
`totalEntries`, the supplied entry count is used. Import preserves errors,
unsupported flags, acquisition completeness, and truncation. The server still
returns at most 1000 entries and marks its own truncation. A supplied total
cannot be smaller than the supplied entry count.

The shell records successful empty arrays, nonzero command exits (including
valid partial stdout), unsupported collection policy, and omissions after
`--max-maps`. That budget limits attempted supported dumps, including failures.
The script's existing map-type exclusions remain in place. Its 10 MB retained
dump limit discards oversized entries with a recorded reason. Full JSON/schema
validation happens on import, so malformed arrays cause an explicit import
error. Live command errors and malformed output also remain unavailable data.

Legacy array-only dump files still import. Their acquisition completeness is
unknown, so they can support readable shared-value comparisons but cannot prove
absence or complete equality. Older normalized in-memory results continue to
use their existing error/truncation/unsupported fields.

| Observation | Result |
|---|---|
| Readable key on both sides, comparable values differ | Confirmed value change, even if another part of a dump is incomplete |
| Key only in B, A complete | Added entry |
| Key only in A, B complete | Removed entry |
| Key only on one side, other side missing/incomplete | Observed only on that side; addition/removal unverified |
| Read error, duplicate/missing keys, or incomparable representations | Warning; affected comparison unverified |
| Both dumps complete, all keys and readable values agree | No map-entry differences in complete dumps |

BTF-decoded keys remain distinct when their hex fields are empty. Decoded
objects are compared with canonical property ordering; decoded value changes
are detected. Per-CPU ordering and its redundant primary display value do not
create differences. Raw hex and decoded BTF encodings are not assumed
equivalent without conversion evidence. Read errors, including per-CPU errors,
are not treated as values.

Collection coverage warnings from A.1 still apply to inventory differences.
Neither inventory commands nor map enumeration are atomic host snapshots;
results describe observations during collection, not transactional state.

## Reproduce the browser workflow

Load `server/fixtures/snapshot-diff/a.json` and `b.json` in the Diff view, then
attach their respective `a-mapdumps.json` and `b-mapdumps.json` files. These
synthetic captures demonstrate:

- ID changes across hosts with same-count map relationship and pin changes.
- An unresolved `clone` group whose contents are not arbitrarily paired.
- A partial `config` dump: a shared value changes, while a missing entry is an
  unverified removal with the original timeout and truncation evidence.
- Distinct BTF keys in `decoded`, with one changed decoded value.
- Successful empty `routes` dumps compared as equal contents.

Regression tests cover matching, relationships, decoded values, failure and
truncation semantics, import validation, actual shell capture fixtures, and UI
warnings. Chromium exercises these same capture files through the real import
API and also verifies missing and legacy dump behavior.
