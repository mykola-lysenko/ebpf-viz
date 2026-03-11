# eBPF Visualizer — TODO

## Backend
- [x] bpftool polling service (prog list, net show, cgroup tree) with configurable interval
- [x] Data parser: transform bpftool JSON → structured VisualizationModel (kernel, network, cgroup)
- [x] Mock data generator for demo/dev mode when bpftool is unavailable
- [x] tRPC procedures: getSnapshot, getProgDetail, setPollingInterval, toggleDemoMode
- [x] Server-sent events or polling endpoint for real-time updates

## Frontend — Layout & Design
- [x] Dark theme design system (index.css) with eBPF color palette
- [x] DashboardLayout with sidebar: Kernel, Network, Cgroups, Programs, Settings
- [x] Global search/filter bar (by name, type, attachment point)
- [x] Auto-refresh toggle with interval selector

## Frontend — Kernel Diagram
- [x] Interactive Linux kernel SVG diagram
- [x] Attachment point zones: XDP, TC ingress/egress, tracepoint, kprobe/kretprobe, cgroup hooks, perf_event, sk_filter
- [x] BPF program badges on each attachment point
- [x] Color-coding by program type

## Frontend — Network Interface View
- [x] Interface list with status indicators
- [x] OSI layer stack (L2/L3/L4/L7) per interface
- [x] BPF programs mapped to correct OSI layer (XDP→L2, TC→L3/L4, sk_filter→L4, sockops→L7)
- [x] Expand/collapse per interface

## Frontend — Cgroup Tree
- [x] Hierarchical tree visualization of cgroup v2 structure
- [x] BPF program badges on each cgroup node
- [x] Attach flags display (multi, override)
- [x] Expand/collapse nodes

## Frontend — Program Detail Panel
- [x] Slide-in panel on program click
- [x] Fields: ID, type, name, tag, loaded_at, map_ids, BTF id, run_time_ns, run_cnt
- [x] Visual state indicators (active, multi-attach, override)
- [x] Copy-to-clipboard for tag/id

## Frontend — Programs Table
- [x] Full list of all loaded BPF programs
- [x] Columns: ID, type, name, tag, loaded_at, maps, attachment
- [x] Sort, filter, search

## Misc
- [x] Demo mode banner
- [x] Settings page: polling interval, demo mode toggle, bpftool path
- [x] Vitest tests for parser and tRPC procedures

## Runtime Statistics (run_cnt / run_time_ns)
- [x] Auto-enable kernel.bpf_stats_enabled=1 in poller startup
- [x] Delta ring buffer (last 60 samples) in poller with per-program rate computation
- [x] ProgSample and ProgHistory types in shared/ebpf-types.ts
- [x] trpc.ebpf.allHistory and trpc.ebpf.activity procedures
- [x] Sparkline component (recharts AreaChart, reusable across all views)
- [x] ProgBadge inline activity bar (width = relative run_cnt, color = avg latency)
- [x] Programs Table: Calls/s, Avg Latency, CPU% columns (sortable)
- [x] Program Detail Panel: time-series AreaChart + stat cards for derived metrics
- [x] Kernel zone cards: heatmap glow intensity based on total CPU time consumed
- [x] Dashboard: Runtime Activity leaderboard with sparklines
- [x] Tests for ring buffer delta computation (41 tests total, all passing)

## OS Map View (React Flow)
- [x] Install @xyflow/react and add /map route + sidebar entry
- [x] useOsMapLayout hook: convert snapshot → React Flow nodes + edges
- [x] Custom node: KernelBoundary, UserspaceBoundary, NetworkBoundary
- [x] Custom node: ZoneNode (kernel hook zones)
- [x] Custom node: CgroupNode (cgroup tree nodes)
- [x] Custom node: InterfaceNode (network interfaces with OSI mini-stack)
- [x] Custom node: ProgramNode (BPF program badge with sparkline)
- [x] Custom node: ProcessNode (owning process pill)
- [x] LOD switching via useViewport zoom thresholds
- [x] Minimap + toolbar (fit, zoom in/out, label toggle)
- [x] Search highlighting (dim non-matching, ring around matches)
- [x] Click program → open existing ProgramDetailPanel
- [x] Click zone/cgroup/interface → zoom-fit that region (double-click)

## Code Inspector
- [x] Install @viz-js/viz for Graphviz CFG rendering
- [x] Backend: tRPC ebpf.progDump procedure (xlated, jited, linum, visual/dot)
- [x] Backend: auto-set kptr_restrict=0 when fetching jited dump
- [x] Shared type: ProgDump with xlated[], jited[], dot, linumLines[], available flags
- [x] Frontend: CodeInspector full-screen modal component
- [x] Tab 1 — BPF Bytecode: line numbers, opcode/register/immediate coloring, jump-target highlighting
- [x] Tab 2 — CFG: @viz-js/viz DOT renderer with pan/zoom
- [x] Tab 3 — JIT Assembly: disassembly with register coloring, unavailable state
- [x] Tab 4 — C Source: interleaved BTF linum view, unavailable state
- [x] Wire "View Code" button into ProgramDetailPanel
- [x] Tests for dump parser

## Standalone Mode (no DB, no OAuth)
- [ ] Remove DB dependency from server startup and routers
- [ ] Replace OAuth middleware with no-op passthrough
- [ ] Remove login/logout UI from frontend
- [ ] Remove useAuth hook usage from layout and pages
- [ ] Write .env.example for standalone install
- [ ] Write Dockerfile for containerized deployment
- [ ] Write INSTALL.md with step-by-step instructions
- [ ] Update tests to reflect no-auth context

## Map Entries Inspector
- [x] bpftool map dump output parsing (hash, array, lpm_trie, per-cpu variants)
- [x] mapDump tRPC procedure with error handling for unsupported map types
- [x] MapEntriesModal component: paginated table, hex/decimal/BTF view modes, copy-to-clipboard
- [x] Per-CPU value expansion (percpu_hash, percpu_array)
- [x] "Dump entries" button on map cards and detail panel in MapsView
- [x] Tests for map dump parser (36 tests, all passing)

## Live Updates via SSE
- [x] Add EventEmitter to ebpf-poller so it fires 'snapshot' events after each poll cycle
- [x] Add GET /api/sse endpoint (Express) that streams snapshot, maps, history, activity events
- [x] useEbpfStream hook: connects to SSE, deserialises superjson, replaces tRPC polling
- [x] EbpfContext updated to consume SSE stream for snapshot/history/activity/maps
- [x] Graceful reconnect with exponential back-off (1s → 30s) on SSE disconnect
- [x] Connection status indicator in sidebar and top bar (Live / Connecting / Reconnecting / Offline)
- [x] Removed refetchInterval polling from MapsView, OsMapView, and EbpfContext
- [x] SettingsView updated to show SSE stream status and explain live-push model
- [x] 10 new SSE endpoint tests (138 total, all passing)

## OS Map Deduplication Fix
- [x] Remove XDP/TC/sk_filter/sockops/netfilter/flow_dissector programs from Kernel Hook Zone nodes (keep only on NIC nodes)
- [x] Empty kernel-only zones are now hidden from the OS map
- [x] 'Kernel Hook Zones' section label hidden when no kernel zones have programs
- [x] Process→NIC-type program edges now point to the NIC interface node
- [x] Map→NIC-type program edges now originate from the NIC interface node
- [x] Updated osmap-layout tests (19 tests, all passing; 145 total)

## NIC Packet Path Stack Diagram
- [x] Packet path stack: L7→L4→L3→L2→NIC HW layers rendered top-to-bottom in InterfaceNode
- [x] Dynamic height: node expands based on number of programs per layer
- [x] Hover tooltip on each program badge (name, rawType, id, attachment detail, JIT/GPL/orphaned badges)
- [x] SVG flow arrows between layers (active/inactive state based on adjacent layer occupancy)
- [x] NIC hardware base node at bottom of stack with custom SVG icon
- [x] Layer descriptions shown in full LOD for inactive layers
- [x] 23 new tests for packet path logic (168 total, all passing)

## Bug Fixes
- [x] L7 layer phantom arrow: empty layers now hidden in compact LOD; FlowArrow only renders when adjacent layer is visible
- [x] netfilter programs were never pushed to iface.layers.L3 in buildNetworkInterfaces (now fixed)
- [x] flow_dissector was incorrectly assigned to L4 (now correctly in L3 alongside netfilter)
- [x] netkit programs now assigned to L2 in buildNetworkInterfaces

## Sockmap Demo Interface
- [x] Added sockmap field to RawNetSnapshot type (shared/ebpf-types.ts)
- [x] Added synthetic sockmap0 interface to MOCK_NET with sock_ops/sk_skb/sk_msg/sk_lookup programs
- [x] Extended buildNetworkInterfaces: sk_skb/sk_lookup → L4, sk_msg/sock_ops → L7
- [x] 5 new tests for sockmap/netfilter/flow_dissector layer assignment (173 total, all passing)

## TC Direction Badges
- [x] Added direction field to BpfAttachment type (shared/ebpf-types.ts)
- [x] Parser sets direction from TC/TCx kind string (clsact/ingress → ingress, clsact/egress → egress)
- [x] ProgBadge reads first TC/TCx attachment direction and renders → (blue) or ← (amber) badge
- [x] Badge has title tooltip: "Ingress (incoming packets)" / "Egress (outgoing packets)"
- [x] 5 new direction tests (177 total, all passing)
