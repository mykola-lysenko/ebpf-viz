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

## Bug Fixes (continued)
- [x] BPF Maps band overlaps Network Layer band: network band height now computed dynamically from estimateInterfaceNodeHeight() instead of hardcoded IFACE_H=200; 3 new layout tests assert no overlap (180 total, all passing)

## Zoom-Adaptive Network Band Height
- [x] Exported zoomToLod() helper derives LOD tier from raw zoom value (mirrors OsMapNodes thresholds)
- [x] buildOsMapLayout accepts optional lod param; estimateInterfaceNodeHeight called with correct LOD
- [x] useOsMapLayout accepts zoom param, derives lod, adds lod to useMemo deps (recomputes only on tier change)
- [x] OsMapCanvas passes zoom state into useOsMapLayout; zoom declared before the hook call
- [x] 5 new tests: zoomToLod thresholds, full>compact>minimal band heights, no-overlap at full LOD (186 total, all passing)

## Richer Demo Cgroup Hierarchy
- [x] Expanded MOCK_CGROUPS to 4-level tree: root → system/user/machine.slice → services (kubelet, docker, ssh, nginx, containerd) → pods/sessions
- [x] Root cgroup has global ingress/egress policy; system.slice has device policy; kubelet has all 5 program types
- [x] Docker container scopes (docker-abc123.scope, docker-fedcba.scope) at depth 3 under docker.service
- [x] Kubernetes pod scopes (pod-nginx, pod-redis, pod-logger) at depth 4 under kubepods QoS slices
- [x] User sessions (session-1, session-2) and user@1000.service at depth 3 under user-1000.slice
- [x] Fixed buildCgroupTree to correctly handle root /sys/fs/cgroup node and proper parent-child wiring
- [x] 5 new cgroup tree tests covering 4-level wiring, structural nodes, alphabetical sort, session depth, node count (191 total, all passing)

## NIC/Sockmap Layer Filtering
- [x] Added kind: "nic" | "sockmap" field to NetworkInterface type and InterfaceNodeData
- [x] Parser sets kind="nic" for all device-level entries (XDP/TC/netfilter/netkit) and kind="sockmap" for sockmap entries
- [x] InterfaceNode uses visibleLayers filtered by kind: NIC shows only L2+L3, sockmap shows only L4+L7
- [x] NicHardwareBase and L2→NIC FlowArrow hidden on sockmap nodes
- [x] Sockmap node uses purple (#8b5cf6) accent colour and map icon (🗺) instead of green plug (🔌)
- [x] 4 kind-field assertions added to existing buildNetworkInterfaces tests (191 total, all passing)

## Bug: Mock Data Leaking into Live Mode
- [x] RESOLVED: Not a bug. test_map/test_array/test_perf were real pinned BPF maps created during development to test bpftool map dump JSON format. Removed with sudo rm /sys/fs/bpf/test_hash /sys/fs/bpf/test_array /sys/fs/bpf/test_perf. Live data path confirmed correct, no mock data leaks.

## Shared-Bytecode Highlighting (Options A + C)
- [x] Option A: tagCount computed client-side from full program list; "×N clones" badge in Programs table Tag column
- [x] Option A: clicking badge sets tagFilter state; table filters to show only programs with that tag
- [x] Option A: active filter shown as dismissible amber chip below the search bar
- [x] Option A: hint text shows count of shared tags when no filter is active
- [x] Option C: SharedTagDot component renders coloured glowing dot next to each program chip in Cgroups tree
- [x] Option C: legend panel at top of Cgroups tree (only shown when shared tags exist)
- [x] Option C: hover tooltip shows tag prefix, sibling count, and scrollable list of id + cgroup path
- [x] Option C: colours assigned deterministically (sorted tag → palette index) for stable rendering
- [x] 14 new tests: buildTagCount, collectTagSiblings, buildSharedTagMap, buildTagColorMap (205 total, all passing)

## Standalone Deployment Package
- [x] Standalone build script: bundles all server deps into a single index.js, copies dist/public, produces ebpf-viz-standalone.tar.gz
- [x] .env.example for standalone install (no Manus OAuth, no DB required)
- [x] DEPLOY.md with step-by-step instructions for Mac build + devserver deploy
- [x] Standalone mode: disable OAuth middleware, skip DB init when DATABASE_URL is absent

## HOST Binding (IPv6 Support)
- [x] Read HOST env var in server/_core/index.ts and pass to server.listen(port, host)
- [x] Update .env.example with HOST documentation
- [x] Update build-standalone.sh start.sh template with HOST documentation
- [x] Rebuild standalone package

## Node 16 Web API Polyfill
- [x] Add undici as a dependency for Headers/Request/Response/fetch polyfill
- [x] Create server/polyfill.ts that installs globals when missing
- [x] Import polyfill as first import in server/_core/index.ts
- [x] Rebuild standalone package and verify tRPC calls work

## Node 16 Crash Fixes
- [x] Fix ERR_STREAM_WRITE_AFTER_END: wrap tRPC middleware to make res.end() idempotent and swallow write-after-end errors
- [x] Add error listener on ServerResponse to prevent process crash
- [x] Suppress OAuth ERROR log when OAUTH_SERVER_URL is not set (standalone mode has no OAuth)
- [x] Rebuild standalone package and verify tRPC calls work without crashing

## Network Tab: NIC vs Sockmap Split
- [x] Split NetworkView into two sections: "Network Interfaces" (kind=nic) and "Sockmap Interfaces" (kind=sockmap)
- [x] Add section headers with interface count and description
- [x] Hide sockmap section when no sockmap interfaces exist (live mode)
- [x] Update tests if needed

## Node 16: Truncated tRPC Response Body
- [x] Diagnose: on Node 16, 'close' fires synchronously inside res.end(), triggering abort mid-stream via tRPC's incomingMessageToRequest signal
- [x] Fix: defer res.once('close', cb) by one setImmediate tick so pipeTo() resolves before abort fires
- [x] Rebuild standalone and verify full JSON responses are delivered

## Maps View: No Maps Shown (200+ BPF programs)
- [x] Diagnose: maps were delivered via SSE stream but EbpfContext never exposed them; MapsView used a stale tRPC query with staleTime:Infinity
- [x] Fix: expose maps from SSE stream through EbpfContext; MapsView now reads from context
- [x] Fix: increase maxBuffer from 1MB to 32MB in runBpftool to prevent silent truncation on large systems
- [x] Rebuild standalone and verify

## Suppress [Auth] Missing session cookie log in standalone mode
- [x] Found in sdk.ts verifySession() — fires on every tRPC call when no cookie is present
- [x] Guard with ENV.oAuthServerUrl check: only log when OAuth is configured
- [x] Rebuilt standalone and verified guard is present in bundle

## Code Dump: Persistent Truncated JSON on Node 16
- [x] Root cause: req.once('aborted', onAbort) also triggers the AbortController, bypassing the setImmediate res.once('close') patch
- [x] Fix: patch ReadableStream.prototype.pipeTo in polyfill.ts to strip the signal option on Node 16, preventing any abort from truncating the body
- [x] Also install ReadableStream/WritableStream/TransformStream globals from stream/web for correct instanceof checks
- [x] Rebuilt and verified: 22KB response delivered as valid JSON, server stays alive

## Code Dump: Deep Debug (still failing after pipeTo fix)
- [ ] Trace full request/response path for progDump on a real BPF program
- [ ] Identify exact truncation point
- [ ] Fix and verify

## Code Dump: Definitive Fix (response buffering)
- [x] Root cause confirmed: tRPC uses chunked transfer encoding; any abort mid-stream truncates body on Node 16
- [x] Fix: intercept res.write() in tRPC middleware wrapper to buffer all chunks in memory, then send as single res.end(buffer) with Content-Length header — no chunked encoding, no abort risk
- [x] Verified: Content-Length: 25195 set correctly, full 25KB JSON delivered, server stays alive

## Remaining Action Items
- [x] Add Node.js version check to start.sh (fail if < 16)
- [x] Add /healthz endpoint for monitoring
- [x] Add ./start.sh --demo flag for DEMO_MODE=1
- [x] Add --no-warnings flag to suppress Node 16 ESM warnings
- [x] Rebuild standalone package with all fixes and deliver to user

## Bug: progDump still truncated on Node 16 (regression)
- [x] Root cause: DEMO_MODE env var was never read by startPoller() — poller ran in live mode even when DEMO_MODE=1 was set
- [x] In live mode, mock program IDs (1-25) don't exist in the kernel → progDump returned null → frontend got 35-byte null response
- [x] Fix 1: resolveDefaultConfig() reads DEMO_MODE env var at module load time
- [x] Fix 2: startPoller() skips bpftool check when already in demo mode
- [x] Fix 3: progDump procedure returns buildMockProgDump() for demo mode programs
- [x] Verified: 7/7 tests pass, all mock programs return valid xlated + CFG DOT

## Bug: Maps view empty in demo and live modes (regression)
- [x] Root cause: same DEMO_MODE env var not read — poller ran in live mode, real programs have no map_ids
- [x] Fix: resolveDefaultConfig() reads DEMO_MODE env var at module load time
- [x] In live mode: bpftool map list returns 0 maps on this kernel (cgroup programs have no maps) — correct behavior
- [x] In demo mode: buildMockMaps() now called correctly, returns 11 maps
- [x] Verified: maps count = 11 in demo mode, SSE stream emits non-empty maps events

## Bug: 500 Internal Server Error with Content-Length: 0 on live devserver
- [x] Root cause: tRPC's writeResponse() `finally { res.end() }` fires with no body BEFORE internal_exceptionHandler calls res.end(errorJson). Old `ended=true` guard blocked the error JSON, producing 500 with Content-Length: 0.
- [x] Fix: deferred empty end() calls via setImmediate. A subsequent non-empty end(body) call cancels the deferred empty end and flushes the real body.
- [x] Added writeHead interception to log all 5xx responses with method + path to stdout.
- [x] Verified: 400 invalid input returns Content-Length=1672 with full error JSON; 200 responses unchanged.
- [x] 205 unit tests pass, standalone package rebuilt.

## Feature: Map value interpreter dropdown (Raw / IPv4 / IPv6)
- [x] Add parseHexBytes/bytesToIPv4/bytesToIPv6/interpretHex helpers in MapEntriesModal
- [x] Add "Interpret as" row (Raw, IPv4, IPv6) to the toolbar, separate from the display mode toggle
- [x] Key and value interpretations are independent (separate InterpretToggle controls)
- [x] Interpretation errors shown in amber italic (e.g. "(need 4B, got 8B)")
- [x] Per-CPU value expansion respects the selected value interpretation
- [x] Interpret row hidden in BTF/decimal mode (bytes already decoded)
- [x] Column headers show active interpretation label (e.g. "Key (ipv4)")
- [x] 13 new unit tests in server/ip-interpret.test.ts — all 218 tests pass

## Feature: MAC address interpretation in map viewer
- [x] Add bytesToMAC() helper (6 bytes → aa:bb:cc:dd:ee:ff, lowercase, zero-padded)
- [x] Extend InterpretMode to include "mac"
- [x] Add MAC option to INTERPRET_OPTIONS in MapEntriesModal
- [x] 6 new unit tests for bytesToMAC — all 224 tests pass

## Feature: Port interpretation in map viewer
- [x] Add bytesToPort() helper (2 bytes big-endian → decimal, annotates well-known ports with service name)
- [x] Extend InterpretMode to include "port"
- [x] Add Port option to INTERPRET_OPTIONS in MapEntriesModal
- [x] 5 new unit tests for bytesToPort — all 229 tests pass

## Feature: Extended map value interpretations (Index, U64 LE, U32 BE, Cgroup ID, Protocol)
- [x] Add bytesToU32LE() — 4 bytes LE → decimal (array index, CPU ID)
- [x] Add bytesToU64LE() — 8 bytes LE → decimal (counters, timestamps, cgroup inode IDs); uses DataView split to avoid float precision loss
- [x] Add bytesToU32BE() — 4 bytes BE → decimal
- [x] Add bytesToCgroupId() — 8-byte inode-only or 12-byte inode+attach_type; 21 attach type names
- [x] Add bytesToProtocol() — 1 byte → "N (name)" for 23 well-known IP protocols
- [x] Extend InterpretMode (9 options total) and INTERPRET_OPTIONS with all five
- [x] Auto-detect best default: array/percpu_array → key=U32 LE; cgroup_storage/percpu_cgroup_storage/cgrp_storage → key=Cgroup
- [x] 13 new unit tests — all 242 tests pass

## Feature: Remember last-used interpretation per map type (localStorage)
- [x] Add loadInterpretPrefs(mapType) / saveInterpretPrefs(mapType, key, val) helpers with validation against VALID_MODES set
- [x] Initialize keyInterpret and valInterpret from saved prefs, falling back to auto-detect defaults
- [x] Save prefs on every change via handleKeyInterpretChange / handleValInterpretChange wrappers
- [x] Storage key format: "ebpf-viz:interp:<mapType>" → {key, val}
- [x] Silently ignores localStorage errors (private browsing, quota exceeded)
- [x] 242 tests pass, TS clean

## Feature: Populate demo mode maps with realistic mock entries
- [x] Add buildMockMapDump(mapId, mapType, mapName) in server/ebpf-mock-map-dump.ts
- [x] xdp_blocked_ips (hash): 8 blocked IPv4 addresses with U64 LE drop counters
- [x] xdp_stats (percpu_array): 8 XDP action buckets with per-CPU U64 LE counters
- [x] lb_backends (lpm_trie): 5 prefix+IPv4 entries with backend IP+port
- [x] tc_flow_table (hash): 6 TCP/UDP/ICMP flow tuples with byte counters
- [x] pid_filter (hash): 8 PID entries with U32 LE flag values
- [x] syscall_filter (hash): 8 syscall numbers with U32 LE flag values
- [x] rtt_histogram (array): 100 buckets with realistic RTT distribution
- [x] conn_track (lru_hash): 8 TCP/UDP connection tuples with timestamps
- [x] config_map (array): 16 config flags/values
- [x] exec_events (perf_event_array) and sock_redirect (sockmap) marked unsupported
- [x] Wire via isDemoMode() export from ebpf-poller.ts
- [x] 242 tests pass, standalone bundle verified: 10 maps with entries, 2 unsupported

## Feature: Replace InterpretToggle pill buttons with Select dropdowns
- [x] Replace InterpretToggle component with shadcn Select in MapEntriesModal
- [x] Key as and Value as each get a compact labeled Select dropdown (h-7, min-w-[110px])
- [x] All 10 options, auto-detect defaults, and localStorage persistence fully preserved
- [x] Row uses flex-wrap so both dropdowns stack gracefully on narrow modals
- [x] 242 tests pass, TS clean

## Bug: Select dropdowns in MapEntriesModal fail to open in preview
- [x] Root cause: Radix UI SelectContent uses Portal to render into document.body; in preview iframe the portal content was intercepted by the preview overlay before pointer events reached the dropdown
- [x] Fix: added container prop to shadcn SelectContent (forwarded to SelectPrimitive.Portal); modal passes containerRef.current so dropdown renders inside the modal DOM node instead of document.body
- [x] Verified in browser: dropdown opens correctly showing all 10 options in both dev server and preview mode

## Feature: Filter interpretation dropdown by byte length compatibility
- [x] Added requiredBytes: number | number[] | null to each INTERPRET_OPTIONS entry
- [x] Added compatibleOptions(byteLen) helper — returns only options whose requiredBytes matches, always includes raw
- [x] Added keyBytes/valueBytes props to MapEntriesModalProps; MapsView passes dumpMap.bytesKey/bytesValue
- [x] InterpretToggle accepts byteLen prop and renders only compatible options
- [x] State initialization falls back to raw if saved/default preference is incompatible with actual size
- [x] effectiveValue guard in InterpretToggle resets to raw if current value becomes incompatible
- [x] 242 tests pass, TS clean

## Bug: "Dump Entries" / "Inspect Map Entries" button invisible in Maps view
- [x] Root cause: button used text-[var(--accent)]/80 which resolved to near-black on the dark card background
- [x] Fix: replaced with explicit cyan-300/cyan-500 palette (bg-cyan-500/15 border-cyan-500/40 text-cyan-300) on both the card button and the detail panel CTA
- [x] Verified in browser: button clearly visible with cyan text and border on all map cards

## Feature: Simplify U32 LE/BE to U32 + BE toggle; U64 LE to U64
- [x] Merged u32le + u32be → u32 (LE default); merged u64le → u64 (LE default)
- [x] Added keyBE / valBE boolean state per column
- [x] Added small "BE" toggle button next to each dropdown (amber when active, dim when inactive)
- [x] BE toggle only shown for byte-order-sensitive modes (u32, u64, ipv4, port, mac)
- [x] interpretHex reverses byte array when bigEndian=true before passing to helper
- [x] EntryRow and per-CPU expansion both receive and respect keyBE/valBE
- [x] 242 tests pass, TS clean, standalone rebuilt

## Feature: Timestamp interpretation for 8-byte U64 nanosecond values
- [x] Add bytesToTimestamp() helper: reads 8-byte LE U64 nanoseconds, formats as elapsed time (e.g. "3d 14h 22m 5s 123ms")
- [x] Zero value shown as "0 (never)" to distinguish unset entries from zero-elapsed
- [x] Very large values (> 365 days) shown with year component
- [x] Add "ts" to InterpretMode union type
- [x] Add "Timestamp" option to INTERPRET_OPTIONS with requiredBytes: 8 and beToggleable: false
- [x] Wire into interpretHex() dispatch
- [x] Add unit tests for bytesToTimestamp (zero, sub-ms, ms, seconds, minutes, hours, days, years, 100y) — 12 tests
- [x] Update VALID_MODES set to include "ts"
- [x] Added ktime_map (map 24) to demo data: 8 PID → timestamp entries showcasing all time ranges
- [x] Added fentry__tcp_close (prog 26) to MOCK_PROGS referencing ktime_map
- [x] 254 tests pass, TS clean, standalone rebuilt

## Feature: Map entry search/filter bar
- [x] Add search text input in the modal toolbar (row 3, below interpret toggles)
- [x] Filter applies to both interpreted key text AND interpreted value text (post-interpretation)
- [x] Case-insensitive substring match; also supports raw hex search
- [x] Match count badge: "N / total matches" shown next to the input
- [x] Clear button (×) inside the input when non-empty
- [x] Filtered results reset pagination to page 0
- [x] Empty state message when no entries match the filter
- [x] Search bar visible in all modes (hex, decimal, BTF) for consistency
- [x] Keyboard shortcut: Escape clears the filter
- [x] 254 tests pass, TS clean

## Bug: bpftool not found at /usr/local/bin/bpftool
- [x] Add resolveBpftoolPath() helper: checks BPFTOOL_PATH env, then `which bpftool`, then common paths
- [x] Use resolveBpftoolPath() in ebpf-poller.ts resolveDefaultConfig()
- [x] Use resolveBpftoolPath() in ebpf-dump.ts BPFTOOL constant
- [x] Improve error message in ebpf-map-dump.ts to suggest setting BPFTOOL_PATH env var
- [x] 254 tests pass, TS clean

## Feature: Relative-time display for loaded_at
- [x] Add formatRelativeTime(unixSec) helper: "just now", "5m ago", "2h 15m ago", "3d 7h ago", absolute date for >=7d
- [x] Add formatFullTimestamp(unixSec) helper for tooltip display
- [x] Add useNow(intervalMs) hook that ticks every 30s to keep relative times fresh
- [x] Show relative time in Programs table "Loaded" column with full timestamp as tooltip
- [x] Show relative time in Program detail panel "Loaded at" row with full timestamp as tooltip
- [x] Show relative time in Dashboard "Recently Loaded" sidebar list with full timestamp as tooltip
- [x] Auto-refresh every 30s so the relative time stays current without a page reload
- [x] 11 unit tests for formatRelativeTime (zero, future, <60s, minutes, exact hours, hours+minutes, exact days, days+hours, >=7d, very old)
- [x] 265 tests pass, TS clean

## Feature: Map entry export (JSON / CSV)
- [x] Add Export button (Download icon) in the map entries modal header toolbar
- [x] Dropdown with two options: "Export as JSON" and "Export as CSV"
- [x] Export uses the currently filtered entries (respects search filter)
- [x] JSON export: array of { index, keyHex, key, valueHex, value } objects using interpreted text
- [x] CSV export: header row "Index,Key,Value" + one row per entry with proper CSV escaping
- [x] File is named <mapName>-entries.json / <mapName>-entries.csv
- [x] Toast notification on successful export
- [x] Export button hidden when no entries are loaded
- [x] 265 tests pass, TS clean

## Feature: Live entry count badge on Maps list
- [x] Add mapEntryCounts tRPC query: returns { mapId, count, unsupported }[] for all maps in one batch call
- [x] Server: reuses dumpMapEntries / buildMockMapDump and returns totalEntries per map
- [x] Maps view: Entries stat cell shows live count with a subtle "live" label in cyan
- [x] Badge styled subtly (muted, small font) — doesn't compete with map type badge
- [x] Counts fetched in background (staleTime 30s, refetchInterval 30s) — no loading spinner on the map row
- [x] Unsupported map types show "—" instead of a count
- [x] While counts are loading, falls back to static maxEntries in muted white
- [x] 265 tests pass, TS clean

## Feature: OS Map topology JSON download
- [x] Add "Download Topology JSON" button in OsMapView toolbar (Download icon, next to Labels toggle)
- [x] Download includes full snapshot + computed layout (nodes/edges positions) as JSON
- [x] File named ebpf-topology-<hostname>-<timestamp>.json
- [x] Optimization analysis written: docs/osmap-performance-analysis.md
- [x] 265 tests pass, TS clean

## Optimization: OS Map immediate performance fixes
- [x] Enable onlyRenderVisibleElements={true} on ReactFlow in OsMapCanvas
- [x] Wrap all 9 node components in React.memo with data+selected comparator
- [x] Lift LOD out of per-node useViewport() — derive lod once in OsMapCanvas from zoom state
- [x] Inject lod into each node's data object via displayNodes useMemo (no layout hook changes needed)
- [x] Remove useLod() / useViewport() from OsMapNodes.tsx entirely
- [x] 265 tests pass, TS clean

## Feature: Auto-rebuild standalone tarball on every commit
- [x] Install .git/hooks/pre-commit that runs build-standalone.sh before every commit
- [x] Hook stages the updated ebpf-viz-standalone.tar.gz automatically
- [x] Verified: build succeeds, produces 2.1 MB tarball (2526 modules, 6s build)

## Feature: BPF Snapshot workflow (capture / upload / render)
- [x] capture-snapshot.sh: self-contained bash script, bpftool only (no jq/node/python)
- [x] Script auto-discovers bpftool (BPFTOOL_PATH env, which, common paths)
- [x] Script outputs ebpf-snapshot-<hostname>-<timestamp>.json with _ebpfVizSnapshot:true marker
- [x] Script prints scp instructions after capture
- [x] Extend topology download (OS Map) to export full EbpfSnapshot with _ebpfVizSnapshot:true marker
- [x] Renamed download file to ebpf-snapshot-<host>-<ts>.json (directly re-uploadable)
- [x] Add "Load Snapshot" button in the app header (FolderOpen icon, accepts .json)
- [x] Add AppMode type ("live" | "demo" | "snapshot") to EbpfContext
- [x] Add loadSnapshot(file) and clearSnapshot() to EbpfContext
- [x] Add snapshotMeta (filename, capturedAt, hostname, kernelVersion) to EbpfContext
- [x] Loaded snapshot takes priority over live SSE stream
- [x] Mode indicator in sidebar: Camera icon + filename + XCircle clear button in snapshot mode
- [x] Mode indicator in TopBar: SNAPSHOT badge with filename + X clear button
- [x] Capture time shown in TopBar instead of live time in snapshot mode
- [x] Refresh button disabled in snapshot mode
- [x] Snapshot is ephemeral (in-memory only, lost on refresh)
- [x] All existing views work transparently in snapshot mode (snapshot replaces live data)
- [x] 265 tests pass, TS clean

## Bug/UX: Orphaned program banner shows count only
- [x] Show each orphaned program's name and ID in the banner
- [x] Show last-known owning process comm + PID (from pids field) or "owning process PID unknown" if pids is empty
- [x] Add "View in Programs →" link to the Programs table
- [x] 265 tests pass, TS clean

## Bug: Snapshot upload fails for raw bpftool format (capture-snapshot.sh output)
- [x] Add trpc.ebpf.parseSnapshot mutation: accepts raw bpftool JSON, returns EbpfSnapshot
- [x] Update loadSnapshot in EbpfContext: detect raw format, call parseSnapshot.mutateAsync
- [x] Show loading toast while server parses the snapshot
- [x] Test with real snapshot from devvm — SUCCESS (215 progs, 12 cgroup roots, 1 iface, 256KB response)

## Feature: Orphaned-only filter chip in Programs table
- [x] Add orphanFilter boolean state to ProgramsView
- [x] visiblePrograms useMemo now chains tagFilter + orphanFilter
- [x] "Orphaned only (N)" toggle chip appears in the type-filter bar when orphaned programs exist
- [x] Chip is right-aligned (ml-auto) so it doesn't crowd the type chips
- [x] Active chip uses red-400 palette to match the orphaned badge colour
- [x] Subtitle line shows "· orphaned only" when filter is active
- [x] 265 tests pass, TS clean

## Feature: Cgroup subtree collapse with depth slider in OS Map toolbar
- [x] Add collapsedChildren?: number to CgroupNodeData interface
- [x] Add countDescendants() helper in useOsMapLayout
- [x] layoutCgroupTree() accepts optional maxDepth parameter; prunes nodes deeper than maxDepth
- [x] buildOsMapLayout() accepts optional maxCgroupDepth parameter; passes to layoutCgroupTree
- [x] Nodes at the depth limit get collapsedChildren = total hidden descendants
- [x] useOsMapLayout() accepts optional maxCgroupDepth parameter; passes to buildOsMapLayout
- [x] OsMapCanvas: maxCgroupDepth state + maxTreeDepth computed from snapshot
- [x] MapToolbar: depth slider (range input) appears when maxTreeDepth > 0
- [x] Slider range: 0 to maxTreeDepth; value = maxCgroupDepth ?? maxTreeDepth
- [x] Slider at max position resets to undefined (show all)
- [x] Blue X button clears the depth limit when active
- [x] CgroupNode component: shows "+ N hidden" dashed badge when collapsedChildren > 0
- [x] 265 tests pass, TS clean

## Bug: Maps tab empty in Snapshot mode
- [x] Diagnose why MapsView shows no maps when a snapshot is loaded
- [x] Fix parseSnapshot mutation to return { snapshot, maps } instead of just snapshot
- [x] Add snapshotMaps state to EbpfContext; maps field now uses snapshotMaps in snapshot mode
- [x] Fix OsMapCanvas to use context maps in snapshot mode (disable live tRPC query)
- [x] Disable mapEntryCounts query in snapshot mode (map IDs don't exist on local kernel)
- [x] Disable Dump Entries button in snapshot mode with clear tooltip
- [x] Fix Download Topology JSON to include maps for round-trip re-upload support
- [x] Verified: parseSnapshot returns { snapshot: { programs: 1 }, maps: 3 } with correct cross-refs
