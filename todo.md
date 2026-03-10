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
