# Follow-ups

Last updated: 2026-06-19

## Active

- `P1` Move upload validation/Zod out of the initial client bundle. Snapshot/map-dump validation increased the main client chunk; lazy-load validation only when files are uploaded.
- `P1` Fix CSS `@import` ordering warning in `client/src/index.css`. The Google Fonts import currently appears after Tailwind imports and Vite warns during builds.
- `P2` Clean up snapshot dump docs/scripts. `capture-snapshot.sh` still says map dumps are capped at `200`, while server-side truncation is `1000`.
- `P2` Split oversized UI files. `MapEntriesModal.tsx`, `OsMapNodes.tsx`, and `OsMapView.tsx` are large enough to justify focused extraction.
