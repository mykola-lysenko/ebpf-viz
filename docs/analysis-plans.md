# Analysis Plans

Last updated: 2026-06-29

## Large Control Flow View

Problem: the Control Flow tab renders full Graphviz DOT in the browser. Very large BPF programs can produce huge SVG layouts that freeze the UI.

Plan:

- Add size gates before rendering CFG automatically. If instruction count, DOT byte size, or estimated node count is above a threshold, show a large-program state instead of rendering immediately.
- Provide a simplified fallback view based on basic blocks: block id, instruction range, source snippets, branch targets, and calls. Render it with virtualization instead of SVG layout.
- Add explicit actions for large graphs: render anyway, render simplified CFG, download DOT, and jump to bytecode.
- Move Graphviz rendering to a Web Worker if full graph rendering remains available.
- Add search and navigation for instruction number, source location, helper calls, and branch targets.
- Cache server-computed CFG summaries per program dump so large program navigation does not recompute on every tab switch.

Status: the first implementation is done. The UI now gates automatic Graphviz rendering for large CFGs, renders full Graphviz layouts in a background Web Worker, and shows a searchable, virtualized basic-block fallback with DOT export and explicit "render anyway" controls. CFG summaries are computed on the server and cached by program dump fingerprint, with a client cache fallback for older dump payloads.

Tuning note: local snapshot metadata showed a long tail of large programs, with a top-end around 11k approximate BPF instructions. Synthetic Graphviz checks rendered 1.4k-block graphs comfortably in the worker, while 2.2k+ blocks produced multi-megabyte SVGs that still require main-thread parse/insert work. The automatic render gate now allows moderate graphs after the worker migration but keeps very large graphs on the virtualized fallback.

Remaining work: validate thresholds against more full large-program captures that include xlated dumps and Graphviz DOT.

## Packet Chain Awareness

Problem: the Network tab shows ordered program chains, but it does not explain what a packet may experience while moving through a hook chain.

Plan:

- Detect packet hook context for each chain: hook family, attachment point, ingress/egress direction, and return-value semantics.
- Add static bytecode/source analysis for packet verdicts. Start with return constants for XDP, TC, cgroup_skb, and netfilter.
- Surface per-program capability summaries such as may pass, may drop, may redirect, may reclassify, or unknown dynamic return.
- Use confidence levels. Example: high confidence when all observed exits return constants; unknown when return values depend on maps, helpers, tail calls, or subprograms.
- Visualize chain-level packet flow in the Network tab: direction, ordered programs, possible outcomes, and where a program can short-circuit later programs.
- Use source annotations as supporting evidence when available, but treat bytecode return semantics as the source of truth.

Important constraint: the first version should answer "can this program drop?" or "all observed exits pass" rather than "this specific packet will be dropped." Packet fate is data-dependent.

Status: packet-chain prediction is implemented for TC, cgroup_skb, and cgroup socket-address allow/deny hooks. `pnpm audit:packet-verdicts -- <capture.tar.gz|dir>` now audits dumped xlated programs and groups remaining unknown/not-modeled verdict cases by hook family, program type, and issue reason.

Next data requirement: collect a network/cgroup/all capture with xlated dumps included; inventory-only captures do not contain enough bytecode to audit verdict gaps.
