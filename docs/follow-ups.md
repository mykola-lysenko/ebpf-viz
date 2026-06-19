# Follow-ups

Last updated: 2026-06-19

## Active

- `P0` Fix standalone Node 16 packaging for `undici`. The standalone tarball can currently be built without `node_modules/undici`; Node 16 then tries to install it at startup and can fail or time out without registry access.
- `P1` Move upload validation/Zod out of the initial client bundle. Snapshot/map-dump validation increased the main client chunk; lazy-load validation only when files are uploaded.
- `P1` Fix CSS `@import` ordering warning in `client/src/index.css`. The Google Fonts import currently appears after Tailwind imports and Vite warns during builds.
- `P2` Clean up snapshot dump docs/scripts. `capture-snapshot.sh` still says map dumps are capped at `200`, while server-side truncation is `1000`.
- `P2` Split oversized UI files. `MapEntriesModal.tsx`, `OsMapNodes.tsx`, and `OsMapView.tsx` are large enough to justify focused extraction.

## Proposed UI Follow-ups

- `P2` Add full-name popup for truncated program names in the Programs table. Detect truncation or use a tooltip/hover card so names like `armr_file_lineage_ls...` reveal the full value without opening the detail panel.
- `P2` Add column resizing to the Programs table. Use per-column widths with drag handles in headers, preserve sorting clicks, keep existing responsive hidden columns, and optionally persist widths in local storage.
