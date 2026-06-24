# Follow-ups

Last updated: 2026-06-19

## Active

- `P2` Clean up snapshot dump docs/scripts. `capture-snapshot.sh` still says map dumps are capped at `200`, while server-side truncation is `1000`.
- `P2` Split oversized UI files. `MapEntriesModal.tsx`, `OsMapNodes.tsx`, and `OsMapView.tsx` are large enough to justify focused extraction.
