import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  useReactFlow,
  ReactFlowProvider,
  useNodesState,
  useEdgesState,
  Panel,
  type Node,
  type Edge,
  type NodeMouseHandler,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useEbpf } from "@/contexts/EbpfContext";
import { useOsMapLayout, zoomToLod } from "@/hooks/useOsMapLayout";
import {
  OS_MAP_NODE_TYPES,
  type MapNodeData,
} from "@/components/osmap/OsMapNodes";
import {
  MapLegend,
  MapPlaceholder,
  MapToolbar,
  OS_MAP_FLOW_STYLES,
} from "@/components/osmap/OsMapChrome";
import { MapEntriesModal } from "@/components/MapEntriesModal";
import { MAP_TYPE_META } from "../../../shared/ebpf-types";
import type {
  ZoneNodeData,
  CgroupNodeData,
  InterfaceNodeData,
  ProcessNodeData,
} from "@/hooks/useOsMapLayout";
import { cn } from "@/lib/utils";
import { trpc } from "@/lib/trpc";

const STRUCTURAL_NODES = [
  "band-userspace",
  "band-kernel",
  "band-network",
  "label-zones",
  "label-cgroups",
  "label-maps",
];

// ─── Inner canvas (needs ReactFlowProvider context) ───────────────────────────

function OsMapCanvas() {
  const {
    snapshot,
    searchQuery,
    setSelectedProgram,
    maps: contextMaps,
    appMode,
    historyMap,
    snapshotMapDumps,
  } = useEbpf();
  const [dumpMapId, setDumpMapId] = useState<number | null>(null);
  // In snapshot mode, maps come from EbpfContext (parsed from the snapshot file).
  // In live/demo mode, maps arrive via the SSE stream (also in EbpfContext).
  // We also keep a live tRPC query as a fallback for live mode in case the SSE
  // stream hasn't delivered maps yet.
  const mapsQuery = trpc.ebpf.maps.useQuery(undefined, {
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    enabled: appMode !== "snapshot",
  });
  // Stabilize the maps array reference — a new [] on every render would cause
  // useOsMapLayout's useMemo to recompute every render, creating an infinite loop.
  const maps = useMemo(() => {
    if (appMode === "snapshot") return contextMaps;
    return contextMaps.length > 0 ? contextMaps : (mapsQuery.data ?? []);
  }, [appMode, contextMaps, mapsQuery.data]);
  // zoom must be declared before useOsMapLayout so the LOD can be derived from it
  const [zoom, setZoom] = useState(0.35);
  // maxCgroupDepth: undefined = show all; 0 = root only; N = show up to depth N
  const [maxCgroupDepth, setMaxCgroupDepth] = useState<number | undefined>(
    undefined
  );
  const [focusedProcessId, setFocusedProcessId] = useState<number | null>(null);

  // pid → program IDs (precomputed, stable across focus changes)
  const pidToProgIds = useMemo(() => {
    if (!snapshot) return new Map<number, number[]>();
    const m = new Map<number, number[]>();
    snapshot.programs.forEach(p => {
      if (p.pids) {
        for (const { pid } of p.pids) {
          let arr = m.get(pid);
          if (!arr) {
            arr = [];
            m.set(pid, arr);
          }
          arr.push(p.id);
        }
      }
    });
    return m;
  }, [snapshot]);

  const focusedProgIds = useMemo(() => {
    return focusedProcessId ? pidToProgIds.get(focusedProcessId) : undefined;
  }, [focusedProcessId, pidToProgIds]);

  const layout = useOsMapLayout(
    snapshot,
    maps,
    zoom,
    maxCgroupDepth,
    focusedProgIds
  );
  const { fitView, getViewport, setViewport } = useReactFlow();
  // Keep stable refs so they never appear in useEffect deps
  const fitViewRef = useRef(fitView);
  useEffect(() => {
    fitViewRef.current = fitView;
  });
  const setViewportRef = useRef(setViewport);
  useEffect(() => {
    setViewportRef.current = setViewport;
  });
  const [nodes, setNodes, onNodesChangeRaw] = useNodesState(layout.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layout.edges);

  // Persist user-moved node positions
  const onNodesChange = useCallback(
    (changes: Parameters<typeof onNodesChangeRaw>[0]) => {
      const filtered = changes.filter(c => c.type !== "select");

      // If a node was explicitly moved by the user, save its new position to localStorage
      filtered.forEach(change => {
        if (change.type === "position" && change.dragging && change.position) {
          try {
            const key = `osmap-pos-${snapshot?.hostname}-${change.id}`;
            localStorage.setItem(key, JSON.stringify(change.position));
          } catch {
            /* ignore */
          }
        }
      });

      if (filtered.length > 0) onNodesChangeRaw(filtered);
    },
    [onNodesChangeRaw, snapshot]
  );
  const [showLabels, setShowLabels] = useState(true);
  const didFit = useRef(false);
  const fitAttempts = useRef(0);

  // Sync layout → nodes/edges when snapshot or maps change.
  // fitView is accessed via ref so it never appears in deps (it is not stable
  // across renders in React Flow and would cause an infinite loop).
  const getViewportRef = useRef(getViewport);
  useEffect(() => {
    getViewportRef.current = getViewport;
  });

  // Track layout structure so we can skip no-op node replacements.
  // Replacing 1600+ nodes with identical-but-new objects causes React Flow
  // to re-render every node component, producing a visible blink.
  const prevLayoutFingerprint = useRef("");
  useEffect(() => {
    // Build a lightweight fingerprint: node IDs in order.
    // If the fingerprint is unchanged, the layout is structurally identical
    // (same nodes, same positions) — skip the expensive setNodes call.
    const fingerprint = layout.nodes.map(n => n.id).join("\0");
    const structureChanged = fingerprint !== prevLayoutFingerprint.current;

    if (!structureChanged && didFit.current) {
      return; // identical layout — nothing to update
    }
    prevLayoutFingerprint.current = fingerprint;

    // Capture viewport BEFORE replacing nodes so we can restore it after
    // LOD-driven relayouts (which would otherwise let React Flow reset
    // the viewport when all node objects are replaced).
    const savedViewport = didFit.current ? getViewportRef.current() : null;

    // Apply saved coordinates from localStorage before setting nodes into the React Flow instance
    const restoredNodes = layout.nodes.map(n => {
      try {
        const saved = localStorage.getItem(
          `osmap-pos-${snapshot?.hostname}-${n.id}`
        );
        if (saved) {
          const parsed = JSON.parse(saved);
          if (
            parsed &&
            typeof parsed.x === "number" &&
            typeof parsed.y === "number"
          ) {
            return { ...n, position: { x: parsed.x, y: parsed.y } };
          }
        }
      } catch {
        /* ignore parsing errors */
      }
      return n;
    });

    setNodes(restoredNodes);
    setEdges(layout.edges);
    // Only auto-fit on initial load (not on LOD-driven relayouts, which would
    // fight with focus mode or manual panning).
    if (!didFit.current && layout.nodes.length > 0) {
      const tryFit = (delay: number) => {
        setTimeout(() => {
          isAnimating.current = true;
          const contentNodes = layout.nodes.filter(
            n =>
              n.type === "zoneNode" ||
              n.type === "cgroupNode" ||
              n.type === "interfaceNode" ||
              n.type === "processNode" ||
              n.type === "mapNode" ||
              n.type === "mapSummaryNode"
          );
          fitViewRef.current({
            nodes: contentNodes.length > 0 ? contentNodes : undefined,
            duration: 600,
            padding: 0.15,
          });
          fitAttempts.current += 1;
          if (fitAttempts.current < 2) tryFit(800);
          else didFit.current = true;
        }, delay);
      };
      tryFit(300);
    } else if (savedViewport && !isAnimating.current) {
      // Restore viewport synchronously to prevent blink between setNodes
      // and the next paint. Skip during fitView animations so they aren't
      // overridden by the restore.
      setViewportRef.current(savedViewport);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout]);

  // Track zoom for LOD.  Only update zoom state when a gesture or animation
  // finishes (onMoveEnd), never mid-gesture (onMove).  Updating on every
  // frame would trigger state → re-render, and if zoom crosses a LOD
  // threshold mid-gesture, layout recomputes and all nodes get replaced,
  // which disrupts the ongoing pan/zoom.
  const isAnimating = useRef(false);

  const onMoveEnd = useCallback(() => {
    isAnimating.current = false;
    const vp = getViewport();
    setZoom(vp.zoom);
  }, [getViewport]);

  // Precompute program→node mapping once when snapshot/maps change.
  // Both search and focus filtering then do cheap Set lookups instead of
  // re-traversing the entire cgroup tree, zones, and interfaces.
  const progNodeIndex = useMemo(() => {
    if (!snapshot) return null;
    // progId → set of node IDs that contain this program
    const index = new Map<number, Set<string>>();
    const addEntry = (progId: number, nodeId: string) => {
      let s = index.get(progId);
      if (!s) {
        s = new Set();
        index.set(progId, s);
      }
      s.add(nodeId);
    };

    snapshot.kernelZones.forEach(z => {
      z.programs.forEach(p => addEntry(p.id, `zone-${z.zone}`));
    });

    (function walkCgroup(nodes: typeof snapshot.cgroupTree) {
      nodes.forEach(n => {
        n.programs.forEach(p => addEntry(p.id, `cgroup-${n.path}`));
        walkCgroup(n.children);
      });
    })(snapshot.cgroupTree);

    // Host interfaces only — the OS map renders only !netns interfaces, and
    // a netns iface named eth0 would otherwise index its programs onto the
    // HOST eth0 node (same `iface-${name}` id).
    snapshot.networkInterfaces.forEach(iface => {
      if (iface.netns) return;
      iface.allPrograms.forEach(p => addEntry(p.id, `iface-${iface.name}`));
    });

    snapshot.programs.forEach(p => {
      if (p.pids) {
        p.pids.forEach(({ pid }) => addEntry(p.id, `proc-${pid}`));
      }
    });

    maps.forEach(map => {
      map.usedByProgIds.forEach(progId => {
        addEntry(progId, `map-${map.id}`);
        // Also index by summary node ID so filtering works in aggregated view
        addEntry(progId, `map-summary-${map.category}`);
      });
    });

    return index;
  }, [snapshot, maps]);

  // Search highlighting: dim non-matching nodes
  const highlightedNodeIds = useMemo(() => {
    if (!searchQuery || !snapshot || !progNodeIndex) return null;
    const q = searchQuery.toLowerCase();
    const matchingProgIds = snapshot.programs
      .filter(
        p =>
          p.name.toLowerCase().includes(q) ||
          p.rawType.toLowerCase().includes(q) ||
          p.tag.toLowerCase().includes(q)
      )
      .map(p => p.id);

    const nodeIds = new Set<string>(STRUCTURAL_NODES);
    matchingProgIds.forEach(id => {
      progNodeIndex.get(id)?.forEach(nid => nodeIds.add(nid));
    });
    return nodeIds;
  }, [searchQuery, snapshot, progNodeIndex]);

  // Focus mode: trace a process's programs to zones, interfaces, cgroups, and maps
  const focusedNodeIds = useMemo(() => {
    if (focusedProcessId === null || !progNodeIndex) return null;
    const progIds = pidToProgIds.get(focusedProcessId);
    if (!progIds || progIds.length === 0) return null;

    const nodeIds = new Set<string>(STRUCTURAL_NODES);
    nodeIds.add(`proc-${focusedProcessId}`);
    progIds.forEach(id => {
      progNodeIndex.get(id)?.forEach(nid => {
        // Skip other processes that share the same program — only the
        // focused process node (added above) should be included.
        if (!nid.startsWith("proc-")) nodeIds.add(nid);
      });
    });
    return nodeIds;
  }, [focusedProcessId, progNodeIndex, pidToProgIds]);

  // Combine search and focus filters — if both active, intersect them
  const activeFilter = useMemo(() => {
    if (highlightedNodeIds && focusedNodeIds) {
      // Intersection: node must match both search and focus
      const combined = new Set<string>();
      highlightedNodeIds.forEach(id => {
        if (focusedNodeIds.has(id)) combined.add(id);
      });
      // Always keep structural nodes
      [
        "band-userspace",
        "band-kernel",
        "band-network",
        "label-zones",
        "label-cgroups",
        "label-maps",
      ].forEach(id => {
        combined.add(id);
      });
      return combined;
    }
    return highlightedNodeIds ?? focusedNodeIds;
  }, [highlightedNodeIds, focusedNodeIds]);

  // Derive LOD tier from current zoom (changes at only 2 thresholds, not on every tick)
  const lod = zoomToLod(zoom);

  // Inject lod into node data so node components don't need to call useViewport()
  // individually (eliminates per-node re-renders on pan/zoom).
  // Opacity is handled via CSS (see focusStyles below) so that focus/search
  // toggling doesn't recreate node objects — which caused React Flow to drop
  // the paint until the next user interaction.
  const displayNodes = useMemo(() => {
    return nodes.map(n => {
      const isFiltered = activeFilter ? activeFilter.has(n.id) : false;
      return {
        ...n,
        className: isFiltered ? "is-filtered" : undefined,
        data: { ...n.data, lod },
      };
    });
  }, [nodes, lod, activeFilter]);

  // Contextual edge animation: animate edges coming from actively running programs
  const activeProgIds = useMemo(() => {
    const s = new Set<number>();
    if (!historyMap) return s;
    historyMap.forEach((history, id) => {
      if ((history.latest?.callsPerSec ?? 0) > 0) {
        s.add(id);
      }
    });
    return s;
  }, [historyMap]);

  const displayEdges = useMemo(() => {
    return edges.map(e => {
      const isFiltered = activeFilter
        ? activeFilter.has(e.source) && activeFilter.has(e.target)
        : false;

      let isAnimated = false;
      if (activeProgIds.size > 0) {
        const match = e.id.match(/-prog-(\d+)/);
        if (match && activeProgIds.has(parseInt(match[1], 10))) {
          isAnimated = true;
        }
      }

      const classes = [];
      if (isFiltered) classes.push("is-filtered");
      if (isAnimated) classes.push("animated");

      return {
        ...e,
        className: classes.length > 0 ? classes.join(" ") : undefined,
      };
    });
  }, [edges, activeFilter, activeProgIds]);

  // Node click handler — extract program from zone/cgroup/interface and open detail panel,
  // or toggle focus mode when clicking a process node.
  const onNodeClick: NodeMouseHandler = useCallback(
    (_evt, node) => {
      if (!snapshot) return;

      const type = node.type;

      if (type === "processNode") {
        const data = node.data as unknown as ProcessNodeData;
        // Toggle focus: click same process again to exit
        setFocusedProcessId(prev => (prev === data.pid ? null : data.pid));
        return;
      }

      if (type === "mapNode") {
        const data = node.data as unknown as MapNodeData;
        setDumpMapId(data.mapId);
        return;
      }

      if (type === "zoneNode") {
        const data = node.data as unknown as ZoneNodeData;
        if (data.programs.length === 1) {
          setSelectedProgram(data.programs[0]);
        }
      } else if (type === "cgroupNode") {
        const data = node.data as unknown as CgroupNodeData;
        if (data.programs.length === 1) {
          setSelectedProgram(data.programs[0]);
        }
      } else if (type === "interfaceNode") {
        const data = node.data as unknown as InterfaceNodeData;
        if (data.allPrograms.length === 1) {
          setSelectedProgram(data.allPrograms[0]);
        }
      }
    },
    [snapshot, setSelectedProgram]
  );

  // Focus mode: no viewport change — just dim non-focused nodes via displayNodes
  // opacity. The user's current pan/zoom is preserved. If a process's programs
  // span many zones/cgroups, fitting them all would zoom to the full overview,
  // which looks like an unwanted viewport reset.

  // Double-click to zoom-fit node
  const onNodeDoubleClick: NodeMouseHandler = useCallback(
    (_evt, node) => {
      isAnimating.current = true;
      fitView({
        nodes: [node],
        duration: 500,
        padding: 0.3,
      });
    },
    [fitView]
  );

  const progCount = snapshot?.stats.total ?? 0;

  // Resolve focused process info for the toolbar badge
  const focusedProcess = useMemo(() => {
    if (focusedProcessId === null || !snapshot) return null;
    for (const p of snapshot.programs) {
      if (p.pids) {
        const match = p.pids.find(({ pid }) => pid === focusedProcessId);
        if (match) return { pid: match.pid, comm: match.comm };
      }
    }
    return null;
  }, [focusedProcessId, snapshot]);

  // Compute the maximum cgroup depth in the current snapshot
  const maxTreeDepth = useMemo(() => {
    if (!snapshot) return 0;
    let max = 0;
    const snap = snapshot;
    function walk(nodes: typeof snap.cgroupTree) {
      nodes.forEach(n => {
        max = Math.max(max, n.depth);
        walk(n.children);
      });
    }
    walk(snap.cgroupTree);
    return max;
  }, [snapshot]);

  // Download the full topology snapshot as JSON for performance testing
  const handleDownload = useCallback(() => {
    if (!snapshot) return;
    // Produce a file that is directly re-uploadable via "Load Snapshot" in the UI.
    // The _ebpfVizSnapshot flag tells the loader this is a pre-parsed snapshot
    // (not a raw capture-snapshot.sh output), so it can be used as-is.
    // maps is included so the Maps tab is populated on re-upload.
    const payload = {
      _ebpfVizSnapshot: true,
      _version: 1,
      capturedAt: new Date().toISOString(),
      timestamp: snapshot.timestamp,
      hostname: snapshot.hostname ?? "unknown",
      kernelVersion: snapshot.kernelVersion ?? "unknown",
      bpftoolVersion: snapshot.bpftoolVersion ?? "unknown",
      demoMode: snapshot.demoMode,
      // Full parsed snapshot — can be rendered directly without server-side processing
      snapshot,
      // Parsed maps — included so the Maps tab is populated on re-upload
      maps,
    };
    const json = JSON.stringify(payload, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    a.href = url;
    a.download = `ebpf-snapshot-${snapshot.hostname ?? "host"}-${ts}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [snapshot]);

  const dumpMap = dumpMapId ? maps.find(m => m.id === dumpMapId) : null;
  const mapMeta = dumpMap
    ? (MAP_TYPE_META[dumpMap.type] ?? MAP_TYPE_META["unknown"]!)
    : null;

  return (
    <div style={{ width: "100%", height: "100%", position: "relative" }}>
      <style>{OS_MAP_FLOW_STYLES}</style>

      <ReactFlow
        className={cn("os-map-flow", activeFilter ? "filtering-active" : "")}
        nodes={displayNodes}
        edges={displayEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onNodeDoubleClick={onNodeDoubleClick}
        onMoveEnd={onMoveEnd}
        nodeTypes={OS_MAP_NODE_TYPES}
        minZoom={0.08}
        maxZoom={3}
        defaultEdgeOptions={{
          type: "smoothstep",
        }}
        proOptions={{ hideAttribution: true }}
        style={{ background: "oklch(0.075 0.012 240)" }}
        fitView={false}
        defaultViewport={{ x: -100, y: -50, zoom: 0.35 }}
        onlyRenderVisibleElements={true}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={24}
          size={1}
          color="oklch(0.25 0.01 240 / 0.5)"
        />

        <MiniMap
          position="bottom-right"
          nodeColor={n => {
            if (n.type === "kernelBand") return "oklch(0.18 0.018 240)";
            if (n.type === "userspaceBand") return "oklch(0.18 0.020 55)";
            if (n.type === "networkBand") return "oklch(0.18 0.020 160)";
            if (n.type === "zoneNode")
              return (
                ((n.data as unknown as ZoneNodeData).color ?? "#6b7280") + "80"
              );
            if (n.type === "cgroupNode") return "#3b82f680";
            if (n.type === "interfaceNode") return "#10b98180";
            if (n.type === "processNode") return "#f59e0b80";
            if (n.type === "mapNode") return "#a78bfa80";
            return "oklch(0.25 0.01 240)";
          }}
          style={{ width: 160, height: 100 }}
          zoomable
          pannable
        />

        <Controls position="bottom-left" showInteractive={false} />

        {/* Top toolbar */}
        <Panel position="top-left">
          <MapToolbar
            zoom={zoom}
            showLabels={showLabels}
            onToggleLabels={() => setShowLabels(l => !l)}
            nodeCount={
              nodes.filter(
                n => !n.type?.includes("Band") && !n.type?.includes("Label")
              ).length
            }
            progCount={progCount}
            onDownload={handleDownload}
            maxTreeDepth={maxTreeDepth}
            maxCgroupDepth={maxCgroupDepth}
            onMaxCgroupDepthChange={setMaxCgroupDepth}
            focusedProcess={focusedProcess}
            onClearFocus={() => setFocusedProcessId(null)}
          />
        </Panel>

        {/* Legend */}
        <Panel position="top-right">
          <MapLegend />
        </Panel>

        {/* Search match count */}
        {searchQuery && highlightedNodeIds && (
          <Panel position="bottom-center">
            <div
              style={{
                padding: "4px 12px",
                background: "oklch(0.12 0.015 240 / 0.95)",
                border: "1px solid #00d4ff40",
                borderRadius: 8,
                fontSize: 10,
                fontFamily: "monospace",
                color: "#00d4ff",
              }}
            >
              {highlightedNodeIds.size - 5} nodes match "{searchQuery}"
            </div>
          </Panel>
        )}
      </ReactFlow>

      {/* Map Entries Modal */}
      {dumpMap && mapMeta && (
        <MapEntriesModal
          mapId={dumpMap.id}
          mapName={dumpMap.name}
          mapType={dumpMap.rawType}
          mapColor={mapMeta.color}
          keyBytes={dumpMap.bytesKey}
          valueBytes={dumpMap.bytesValue}
          onClose={() => setDumpMapId(null)}
          snapshotDump={
            appMode === "snapshot" ? snapshotMapDumps[dumpMap.id] : undefined
          }
        />
      )}
    </div>
  );
}

// ─── Page wrapper ─────────────────────────────────────────────────────────────

export default function OsMapView() {
  const { snapshot, isLoading } = useEbpf();

  if (isLoading && !snapshot) {
    return <MapPlaceholder />;
  }

  if (!snapshot) {
    return (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "oklch(0.075 0.012 240)",
        }}
      >
        <p style={{ color: "oklch(0.55 0.01 240)", fontFamily: "monospace" }}>
          No snapshot data available
        </p>
      </div>
    );
  }

  return (
    <div style={{ width: "100%", height: "100%" }}>
      <ReactFlowProvider>
        <OsMapCanvas />
      </ReactFlowProvider>
    </div>
  );
}
