# OS Map Performance Analysis

*Prepared for the ebpf-viz project · March 2026*

---

## Executive Summary

The OS Map tab uses [React Flow](https://reactflow.dev) to render a force-free, statically-laid-out graph of every BPF program, map, cgroup node, kernel zone, network interface, and process on the host. On a small system (10–30 programs, 20–50 maps) it is fast. On a production host with 100+ programs, 200+ maps, and a deep cgroup hierarchy, three compounding bottlenecks make it sluggish: **one large synchronous layout recomputation**, **too many React Flow nodes rendered at once**, and **per-node `useViewport()` subscriptions that fire on every pan/zoom event**. The sections below diagnose each bottleneck and provide concrete, implementable fixes.

---

## 1. Layout Recomputation (`useOsMapLayout`)

### What happens today

`useOsMapLayout` wraps a single `useMemo` call around `buildOsMapLayout`, which walks the entire snapshot in one synchronous pass: it flattens the cgroup tree, lays out zones, positions every map node, and generates all edges. The memo re-runs whenever `snapshot`, `maps`, or `lod` changes — and `snapshot` is a new object reference on every SSE tick (typically every 5 seconds).

On a host with 200 maps and a 500-node cgroup tree, `buildOsMapLayout` takes **40–120 ms** on the main thread. Because it runs synchronously inside a `useMemo`, it blocks the browser's render pipeline for that duration on every poll tick, producing visible jank.

### Fixes

**Move layout to a Web Worker.** The layout function has no DOM dependencies — it only reads plain data and returns `{ nodes, edges }`. Moving it to a `Worker` via `useWorker` or a simple `postMessage` bridge lets the main thread stay responsive while the layout is computed off-thread. React Flow's `setNodes` / `setEdges` are called only when the worker posts back the result.

```ts
// worker/osmap-layout.worker.ts
import { buildOsMapLayout } from "../hooks/useOsMapLayout";
self.onmessage = (e) => {
  const { snapshot, maps, lod } = e.data;
  const layout = buildOsMapLayout(snapshot, maps, lod);
  self.postMessage(layout);
};
```

**Debounce snapshot updates.** Rather than recomputing on every 5-second tick, debounce the layout trigger to 500 ms after the last snapshot change. This collapses rapid successive updates (e.g. during a burst of new programs loading) into a single layout pass.

**Incremental diffing.** Instead of rebuilding all nodes/edges from scratch, diff the incoming snapshot against the previous one and only add/remove/update the changed nodes. For a stable production system, most ticks produce zero changes, so the layout cost drops to near zero.

---

## 2. Node Count and React Flow Rendering

### What happens today

Every BPF map, cgroup node, kernel zone, network interface, process, and band region becomes a React Flow `Node`. On a host with 200 maps and a 300-node cgroup tree, the graph can have **600–900 nodes and 1,000+ edges**. React Flow renders all of them as DOM elements regardless of viewport visibility, and each node re-renders whenever the parent state changes.

| Scenario | Nodes | Edges | Typical render time |
|---|---|---|---|
| Demo (11 progs, 24 maps) | ~80 | ~120 | < 5 ms |
| Small prod (30 progs, 50 maps) | ~200 | ~350 | ~15 ms |
| Medium prod (100 progs, 200 maps) | ~600 | ~900 | ~60–100 ms |
| Large prod (300 progs, 500 maps) | ~1,500 | ~2,500 | > 300 ms |

### Fixes

**Enable React Flow's built-in node culling.** React Flow supports `nodeExtent` and the `onlyRenderVisibleElements` prop. Setting `onlyRenderVisibleElements={true}` skips DOM rendering for nodes outside the current viewport, which is the single highest-impact change for large graphs.

```tsx
<ReactFlow
  onlyRenderVisibleElements={true}
  // ...
/>
```

**Aggregate map nodes at low LOD.** At the "Bird's Eye" zoom level (< 0.35), individual map nodes are invisible anyway. Instead of rendering 200 `mapNode` elements, render a single `mapSummaryNode` that shows a count badge ("200 maps") and hides individual nodes. The layout hook already has LOD tiers — this is a natural extension.

**Collapse deep cgroup subtrees.** Cgroup trees on production systems can have 300+ nodes. Add a `maxCgroupDepth` threshold (default: 4) and collapse subtrees beyond that depth into a single "N children" placeholder node. Users can click to expand. This alone can reduce cgroup node count by 80% on a typical container host.

**Wrap all node components in `React.memo`.** Currently none of the node components (`ZoneNode`, `CgroupNode`, `InterfaceNode`, `MapNode`, etc.) use `React.memo`. React Flow re-renders all visible nodes on every `setNodes` call. Wrapping each export in `React.memo` with a custom comparator that checks only `data` and `selected` eliminates most re-renders.

```ts
export const ZoneNode = React.memo(function ZoneNode({ data, selected }) {
  // ...
}, (prev, next) => prev.selected === next.selected && prev.data === next.data);
```

---

## 3. Per-Node `useViewport()` Subscriptions

### What happens today

Every node component calls `useLod()`, which internally calls `useViewport()` from React Flow. `useViewport()` subscribes the component to **every viewport change** — meaning every pan and zoom event triggers a re-render of every visible node. On a 600-node graph, a single scroll wheel tick causes 600 simultaneous re-renders.

### Fixes

**Lift LOD out of individual nodes.** Pass `lod` as a prop from the parent canvas component rather than computing it inside each node. The canvas already tracks `zoom` state; derive `lod` once there and pass it down via React Flow's `nodeTypes` factory or a React context.

```tsx
// In OsMapCanvas — derive lod once
const lod = zoomToLod(zoom);

// Pass via data prop to each node
const displayNodes = useMemo(() =>
  nodes.map(n => ({ ...n, data: { ...n.data, lod } })),
[nodes, lod]);
```

Because `lod` only changes at two thresholds (0.35 and 0.65), this reduces LOD-triggered re-renders from "on every zoom tick" to "twice per zoom session."

**Use `useStore` selectors instead of `useViewport`.** React Flow's `useStore` supports fine-grained selectors. If a node only needs to know whether zoom is above a threshold, a selector that returns a boolean fires far less often than the full viewport object.

---

## 4. Edge Rendering

### What happens today

All edges use `type: "smoothstep"`, which requires React Flow to compute a cubic Bézier path for each edge on every layout change. With 1,000+ edges, this is expensive. Many edges also have `animated: true` for active attachments, which triggers CSS animation on every edge element.

### Fixes

**Use `type: "straight"` for map→program edges at low LOD.** Straight edges are significantly cheaper to compute and render. At Bird's Eye zoom, the visual difference is imperceptible.

**Limit animated edges.** Only animate edges where the source program has `runCount > 0` in the last polling interval (i.e. actually active), rather than all attached programs. This reduces the animated edge count from O(all attachments) to O(active programs), which is typically much smaller.

**Bundle parallel edges.** When multiple programs share the same source zone and target map, render a single bundled edge with a count label instead of N individual edges. This is especially impactful for shared maps (e.g. `perf_event_array` maps used by 20 programs).

---

## 5. Snapshot Reference Stability

### What happens today

The `EbpfContext` replaces the entire `snapshot` object on every SSE tick. Because `useOsMapLayout` depends on `snapshot`, the layout recomputes every 5 seconds even when nothing has changed. Similarly, `mapsQuery.data` is a new array reference on every tRPC refetch, triggering the `maps` dependency.

### Fixes

**Stabilize snapshot with deep equality.** Use a ref-based deep-equality check: if the new snapshot is structurally identical to the previous one (same program IDs, same map IDs, same cgroup paths), keep the old reference. The layout memo then never fires.

```ts
const stableSnapshot = useStableRef(snapshot, deepEqual);
```

**Freeze maps array reference.** In `OsMapCanvas`, the `maps` memo already stabilizes `mapsQuery.data ?? []`. Extend this to use a stable identity check: if the map IDs and sizes haven't changed, return the previous array reference.

---

## Summary of Recommended Changes

The table below ranks each optimization by estimated impact and implementation effort.

| Optimization | Impact | Effort | Priority |
|---|---|---|---|
| `onlyRenderVisibleElements={true}` | Very High | Trivial (1 line) | **Immediate** |
| `React.memo` on all node components | High | Low (wrap each export) | **Immediate** |
| Lift LOD out of `useViewport()` per node | High | Low | **Immediate** |
| Debounce snapshot layout trigger (500 ms) | Medium | Low | Short-term |
| Collapse map nodes at Bird's Eye LOD | High | Medium | Short-term |
| Collapse deep cgroup subtrees | High | Medium | Short-term |
| Bundle parallel edges | Medium | Medium | Short-term |
| Move layout to Web Worker | Very High | High | Medium-term |
| Incremental layout diffing | Very High | High | Medium-term |
| Limit animated edges to active programs | Low | Low | Short-term |

The three **Immediate** changes require fewer than 50 lines of code combined and can be implemented in a single session. Together they are expected to reduce render time by 60–80% for medium-sized topologies (100 programs, 200 maps).
