import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
import { OS_MAP_NODE_TYPES } from "@/components/osmap/OsMapNodes";
import type { ZoneNodeData, CgroupNodeData, InterfaceNodeData, ProcessNodeData } from "@/hooks/useOsMapLayout";
import type { BpfProgram } from "../../../shared/ebpf-types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Maximize2, ZoomIn, ZoomOut, Layers, Map as MapIcon,
  Eye, EyeOff, Info, Cpu, Download, X
} from "lucide-react";
import { cn } from "@/lib/utils";
import { trpc } from "@/lib/trpc";

const STRUCTURAL_NODES = ["band-userspace", "band-kernel", "band-network", "label-zones", "label-cgroups", "label-maps"];

// ─── Styles injected once ─────────────────────────────────────────────────────

const FLOW_STYLES = `
.os-map-flow .react-flow__renderer { background: transparent; }
.os-map-flow .react-flow__edge-path { transition: stroke 0.3s ease, opacity 0.3s ease; }
.os-map-flow .react-flow__node { transition: opacity 0.3s ease; }
.os-map-flow .react-flow__controls { background: oklch(0.12 0.015 240 / 0.9); border: 1px solid oklch(0.22 0.015 240); border-radius: 10px; overflow: hidden; }
.os-map-flow .react-flow__controls-button { background: transparent; border: none; color: oklch(0.65 0.01 240); fill: oklch(0.65 0.01 240); }
.os-map-flow .react-flow__controls-button:hover { background: oklch(0.18 0.015 240); color: oklch(0.9 0.01 240); fill: oklch(0.9 0.01 240); }
.os-map-flow .react-flow__minimap { background: oklch(0.10 0.012 240 / 0.95); border: 1px solid oklch(0.22 0.015 240); border-radius: 10px; overflow: hidden; }
.os-map-flow .react-flow__minimap-mask { fill: oklch(0.06 0.012 240 / 0.7); }
.os-map-flow .react-flow__background { opacity: 0.4; }

/* Fast DOM-based styling for active search/focus filters */
.os-map-flow.filtering-active .react-flow__node {
  opacity: 0.10;
}
.os-map-flow.filtering-active .react-flow__edge {
  opacity: 0;
}
.os-map-flow.filtering-active .react-flow__node[data-is-filtered="true"],
.os-map-flow.filtering-active .react-flow__edge[data-is-filtered="true"],
.os-map-flow.filtering-active .react-flow__node.is-filtered,
.os-map-flow.filtering-active .react-flow__edge.is-filtered {
  opacity: 1;
}
`;

// ─── LOD legend ───────────────────────────────────────────────────────────────

function LodIndicator({ zoom }: { zoom: number }) {
  const level = zoom <= 0.45 ? "Bird's Eye" : zoom < 0.65 ? "Overview" : "Detail";
  const color = zoom <= 0.45 ? "#f59e0b" : zoom < 0.65 ? "#10b981" : "#00d4ff";
  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 6,
      padding: "4px 10px",
      background: "oklch(0.12 0.015 240 / 0.9)",
      border: `1px solid ${color}40`,
      borderRadius: 8,
      fontSize: 10,
      fontFamily: "monospace",
      color,
    }}>
      <Layers size={10} />
      {level} · {(zoom * 100).toFixed(0)}%
    </div>
  );
}

// ─── Toolbar ──────────────────────────────────────────────────────────────────

function MapToolbar({
  zoom,
  showLabels,
  onToggleLabels,
  nodeCount,
  progCount,
  onDownload,
  maxTreeDepth,
  maxCgroupDepth,
  onMaxCgroupDepthChange,
  focusedProcess,
  onClearFocus,
}: {
  zoom: number;
  showLabels: boolean;
  onToggleLabels: () => void;
  nodeCount: number;
  progCount: number;
  onDownload: () => void;
  maxTreeDepth: number;
  maxCgroupDepth: number | undefined;
  onMaxCgroupDepthChange: (v: number | undefined) => void;
  focusedProcess: { pid: number; comm: string } | null;
  onClearFocus: () => void;
}) {
  const { fitView, zoomIn, zoomOut } = useReactFlow();

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "6px 10px",
      background: "oklch(0.11 0.015 240 / 0.95)",
      border: "1px solid oklch(0.22 0.015 240)",
      borderRadius: 12,
      backdropFilter: "blur(8px)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 4, marginRight: 4 }}>
        <MapIcon size={14} style={{ color: "#00d4ff" }} />
        <span style={{ fontSize: 11, fontWeight: 700, color: "#00d4ff", fontFamily: "monospace" }}>
          OS Map
        </span>
      </div>

      <div style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }} />

      <LodIndicator zoom={zoom} />

      <div style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }} />

      <span style={{ fontSize: 10, fontFamily: "monospace", color: "oklch(0.55 0.01 240)" }}>
        {progCount} programs · {nodeCount} nodes
      </span>

      {/* Focus mode indicator */}
      {focusedProcess && (
        <>
          <div style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }} />
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            padding: "3px 8px 3px 10px",
            background: "#f59e0b18",
            border: "1px solid #f59e0b40",
            borderRadius: 6,
          }}>
            <Eye size={10} style={{ color: "#f59e0b" }} />
            <span style={{ fontSize: 10, fontFamily: "monospace", color: "#f59e0b", whiteSpace: "nowrap" }}>
              {focusedProcess.comm}
              <span style={{ color: "#f59e0b80", marginLeft: 4 }}>pid {focusedProcess.pid}</span>
            </span>
            <button
              onClick={onClearFocus}
              title="Exit focus mode"
              style={{
                width: 16, height: 16, borderRadius: 4,
                background: "#f59e0b20",
                border: "1px solid #f59e0b40",
                display: "flex", alignItems: "center", justifyContent: "center",
                cursor: "pointer", color: "#f59e0b", padding: 0,
              }}
            >
              <X size={9} />
            </button>
          </div>
        </>
      )}

      <div style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }} />

      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={() => zoomIn({ duration: 300 })}
            style={{
              width: 28, height: 28, borderRadius: 6,
              background: "oklch(0.16 0.015 240)",
              border: "1px solid oklch(0.25 0.015 240)",
              display: "flex", alignItems: "center", justifyContent: "center",
              cursor: "pointer", color: "oklch(0.7 0.01 240)",
            }}
          >
            <ZoomIn size={13} />
          </button>
        </TooltipTrigger>
        <TooltipContent>Zoom in</TooltipContent>
      </Tooltip>

      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={() => zoomOut({ duration: 300 })}
            style={{
              width: 28, height: 28, borderRadius: 6,
              background: "oklch(0.16 0.015 240)",
              border: "1px solid oklch(0.25 0.015 240)",
              display: "flex", alignItems: "center", justifyContent: "center",
              cursor: "pointer", color: "oklch(0.7 0.01 240)",
            }}
          >
            <ZoomOut size={13} />
          </button>
        </TooltipTrigger>
        <TooltipContent>Zoom out</TooltipContent>
      </Tooltip>

      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={() => fitView({ duration: 600, padding: 0.06 })}
            style={{
              width: 28, height: 28, borderRadius: 6,
              background: "oklch(0.16 0.015 240)",
              border: "1px solid oklch(0.25 0.015 240)",
              display: "flex", alignItems: "center", justifyContent: "center",
              cursor: "pointer", color: "oklch(0.7 0.01 240)",
            }}
          >
            <Maximize2 size={13} />
          </button>
        </TooltipTrigger>
        <TooltipContent>Fit all</TooltipContent>
      </Tooltip>

      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={onToggleLabels}
            style={{
              width: 28, height: 28, borderRadius: 6,
              background: showLabels ? "oklch(0.16 0.015 240 / 0.8)" : "oklch(0.14 0.015 240)",
              border: `1px solid ${showLabels ? "#00d4ff40" : "oklch(0.25 0.015 240)"}`,
              display: "flex", alignItems: "center", justifyContent: "center",
              cursor: "pointer",
              color: showLabels ? "#00d4ff" : "oklch(0.5 0.01 240)",
            }}
          >
            {showLabels ? <Eye size={13} /> : <EyeOff size={13} />}
          </button>
        </TooltipTrigger>
        <TooltipContent>{showLabels ? "Hide labels" : "Show labels"}</TooltipContent>
      </Tooltip>

      {/* Cgroup depth slider — only shown when tree has depth > 0 */}
      {maxTreeDepth > 0 && (
        <>
          <div style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }} />
          <Tooltip>
            <TooltipTrigger asChild>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ fontSize: 10, fontFamily: "monospace", color: "oklch(0.55 0.01 240)", whiteSpace: "nowrap" }}>
                  Cgroup depth:
                </span>
                <input
                  type="range"
                  min={0}
                  max={maxTreeDepth}
                  value={maxCgroupDepth ?? maxTreeDepth}
                  onChange={e => {
                    const v = parseInt(e.target.value, 10);
                    onMaxCgroupDepthChange(v >= maxTreeDepth ? undefined : v);
                  }}
                  style={{
                    width: 72,
                    accentColor: "#3b82f6",
                    cursor: "pointer",
                  }}
                />
                <span style={{
                  fontSize: 10,
                  fontFamily: "monospace",
                  color: maxCgroupDepth !== undefined ? "#3b82f6" : "oklch(0.55 0.01 240)",
                  minWidth: 14,
                  textAlign: "right",
                }}>
                  {maxCgroupDepth ?? maxTreeDepth}
                </span>
                {maxCgroupDepth !== undefined && (
                  <button
                    onClick={() => onMaxCgroupDepthChange(undefined)}
                    title="Show all depths"
                    style={{
                      width: 16, height: 16, borderRadius: 4,
                      background: "#3b82f620",
                      border: "1px solid #3b82f640",
                      display: "flex", alignItems: "center", justifyContent: "center",
                      cursor: "pointer", color: "#3b82f6", padding: 0,
                    }}
                  >
                    <X size={9} />
                  </button>
                )}
              </div>
            </TooltipTrigger>
            <TooltipContent>
              {maxCgroupDepth !== undefined
                ? `Showing cgroup subtrees up to depth ${maxCgroupDepth} — drag to expand`
                : `Showing full cgroup tree (depth ${maxTreeDepth}) — drag to collapse subtrees`}
            </TooltipContent>
          </Tooltip>
        </>
      )}

      <div style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }} />

      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={onDownload}
            style={{
              width: 28, height: 28, borderRadius: 6,
              background: "oklch(0.16 0.015 240)",
              border: "1px solid oklch(0.25 0.015 240)",
              display: "flex", alignItems: "center", justifyContent: "center",
              cursor: "pointer", color: "oklch(0.7 0.01 240)",
            }}
          >
            <Download size={13} />
          </button>
        </TooltipTrigger>
        <TooltipContent>Download topology JSON</TooltipContent>
      </Tooltip>
    </div>
  );
}

// ─── Legend ───────────────────────────────────────────────────────────────────

function MapLegend() {
  const [open, setOpen] = useState(false);

  const items = [
    { color: "#f59e0b", label: "Userspace (processes)" },
    { color: "#00d4ff", label: "Kernel hook zones" },
    { color: "#3b82f6", label: "Cgroup hierarchy" },
    { color: "#10b981", label: "Network interfaces" },
    { color: "#ffffff30", label: "Dashed = ownership edge" },
    { color: "#00d4ff50", label: "Animated = active attachment" },
    { color: "#a78bfa",   label: "BPF maps (data/event/control)" },
    { color: "#a78bfa40", label: "Dashed border = aggregated maps" },
    { color: "#a78bfa40", label: "Dashed line = program \u2192 map edge" },
  ];

  return (
    <div style={{ position: "relative" }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: 28, height: 28, borderRadius: 6,
          background: open ? "oklch(0.16 0.015 240)" : "oklch(0.13 0.015 240)",
          border: `1px solid ${open ? "#00d4ff40" : "oklch(0.22 0.015 240)"}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          cursor: "pointer", color: open ? "#00d4ff" : "oklch(0.55 0.01 240)",
        }}
      >
        <Info size={13} />
      </button>

      {open && (
        <div style={{
          position: "absolute",
          bottom: 36,
          right: 0,
          background: "oklch(0.11 0.015 240 / 0.98)",
          border: "1px solid oklch(0.22 0.015 240)",
          borderRadius: 10,
          padding: "10px 14px",
          minWidth: 220,
          backdropFilter: "blur(12px)",
          zIndex: 100,
        }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: "#00d4ff", fontFamily: "monospace", marginBottom: 8, letterSpacing: "0.1em" }}>
            LEGEND
          </div>
          {items.map(({ color, label }) => (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
              <div style={{
                width: 12, height: 12, borderRadius: 3,
                background: color,
                flexShrink: 0,
              }} />
              <span style={{ fontSize: 10, color: "oklch(0.65 0.01 240)", fontFamily: "monospace" }}>
                {label}
              </span>
            </div>
          ))}
          <div style={{ marginTop: 8, paddingTop: 8, borderTop: "1px solid oklch(0.18 0.01 240)" }}>
            <div style={{ fontSize: 9, color: "oklch(0.45 0.01 240)", fontFamily: "monospace", lineHeight: 1.5 }}>
              Scroll to zoom · Drag to pan<br />
              Double-click node to zoom-fit<br />
              Click program badge to inspect
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Inner canvas (needs ReactFlowProvider context) ───────────────────────────

function OsMapCanvas() {
  const { snapshot, searchQuery, setSelectedProgram, maps: contextMaps, appMode, historyMap } = useEbpf();
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
  const [maxCgroupDepth, setMaxCgroupDepth] = useState<number | undefined>(undefined);
  const [focusedProcessId, setFocusedProcessId] = useState<number | null>(null);

  // pid → program IDs (precomputed, stable across focus changes)
  const pidToProgIds = useMemo(() => {
    if (!snapshot) return new Map<number, number[]>();
    const m = new Map<number, number[]>();
    snapshot.programs.forEach(p => {
      if (p.pids) {
        for (const { pid } of p.pids) {
          let arr = m.get(pid);
          if (!arr) { arr = []; m.set(pid, arr); }
          arr.push(p.id);
        }
      }
    });
    return m;
  }, [snapshot]);

  const focusedProgIds = useMemo(() => {
    return focusedProcessId ? pidToProgIds.get(focusedProcessId) : undefined;
  }, [focusedProcessId, pidToProgIds]);

  const layout = useOsMapLayout(snapshot, maps, zoom, maxCgroupDepth, focusedProgIds);
  const { fitView, getViewport, setViewport } = useReactFlow();
  // Keep stable refs so they never appear in useEffect deps
  const fitViewRef = useRef(fitView);
  useEffect(() => { fitViewRef.current = fitView; });
  const setViewportRef = useRef(setViewport);
  useEffect(() => { setViewportRef.current = setViewport; });
  const [nodes, setNodes, onNodesChangeRaw] = useNodesState(layout.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layout.edges);
  // Filter out React Flow's internal selection changes — we use our own focus
  // mode, and selection changes cause all node objects to churn (triggering a
  // visible blink when React Flow re-renders 1600+ nodes).
  const onNodesChange = useCallback(
    (changes: Parameters<typeof onNodesChangeRaw>[0]) => {
      const filtered = changes.filter(c => c.type !== "select");
      if (filtered.length > 0) onNodesChangeRaw(filtered);
    },
    [onNodesChangeRaw]
  );
  const [showLabels, setShowLabels] = useState(true);
  const didFit = useRef(false);
  const fitAttempts = useRef(0);

  // Sync layout → nodes/edges when snapshot or maps change.
  // fitView is accessed via ref so it never appears in deps (it is not stable
  // across renders in React Flow and would cause an infinite loop).
  const getViewportRef = useRef(getViewport);
  useEffect(() => { getViewportRef.current = getViewport; });

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
    setNodes(layout.nodes);
    setEdges(layout.edges);
    // Only auto-fit on initial load (not on LOD-driven relayouts, which would
    // fight with focus mode or manual panning).
    if (!didFit.current && layout.nodes.length > 0) {
      const tryFit = (delay: number) => {
        setTimeout(() => {
          isAnimating.current = true;
          const contentNodes = layout.nodes.filter(
            n => n.type === "zoneNode" || n.type === "cgroupNode" ||
                 n.type === "interfaceNode" || n.type === "processNode" ||
                 n.type === "mapNode" || n.type === "mapSummaryNode"
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
      if (!s) { s = new Set(); index.set(progId, s); }
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

    snapshot.networkInterfaces.forEach(iface => {
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
      .filter(p =>
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
      ["band-userspace", "band-kernel", "band-network", "label-zones", "label-cgroups", "label-maps"].forEach(id => {
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
      const isFiltered = activeFilter ? (activeFilter.has(e.source) && activeFilter.has(e.target)) : false;
      
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
  const onNodeClick: NodeMouseHandler = useCallback((_evt, node) => {
    if (!snapshot) return;

    const type = node.type;

    if (type === "processNode") {
      const data = node.data as unknown as ProcessNodeData;
      // Toggle focus: click same process again to exit
      setFocusedProcessId(prev => prev === data.pid ? null : data.pid);
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
  }, [snapshot, setSelectedProgram]);

  // Focus mode: no viewport change — just dim non-focused nodes via displayNodes
  // opacity. The user's current pan/zoom is preserved. If a process's programs
  // span many zones/cgroups, fitting them all would zoom to the full overview,
  // which looks like an unwanted viewport reset.

  // Double-click to zoom-fit node
  const onNodeDoubleClick: NodeMouseHandler = useCallback((_evt, node) => {
    isAnimating.current = true;
    fitView({
      nodes: [node],
      duration: 500,
      padding: 0.3,
    });
  }, [fitView]);

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
      nodes.forEach(n => { max = Math.max(max, n.depth); walk(n.children); });
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

  return (
    <div style={{ width: "100%", height: "100%", position: "relative" }}>
      <style>{FLOW_STYLES}</style>

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
          nodeColor={(n) => {
            if (n.type === "kernelBand") return "oklch(0.18 0.018 240)";
            if (n.type === "userspaceBand") return "oklch(0.18 0.020 55)";
            if (n.type === "networkBand") return "oklch(0.18 0.020 160)";
            if (n.type === "zoneNode") return ((n.data as unknown as ZoneNodeData).color ?? "#6b7280") + "80";
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
            nodeCount={nodes.filter(n => !n.type?.includes("Band") && !n.type?.includes("Label")).length}
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
            <div style={{
              padding: "4px 12px",
              background: "oklch(0.12 0.015 240 / 0.95)",
              border: "1px solid #00d4ff40",
              borderRadius: 8,
              fontSize: 10,
              fontFamily: "monospace",
              color: "#00d4ff",
            }}>
              {highlightedNodeIds.size - 5} nodes match "{searchQuery}"
            </div>
          </Panel>
        )}
      </ReactFlow>
    </div>
  );
}

// ─── Loading / empty states ───────────────────────────────────────────────────

function MapPlaceholder() {
  return (
    <div style={{
      width: "100%",
      height: "100%",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      gap: 16,
      background: "oklch(0.075 0.012 240)",
    }}>
      <div style={{
        width: 48, height: 48,
        border: "2px solid #00d4ff",
        borderTopColor: "transparent",
        borderRadius: "50%",
        animation: "spin 1s linear infinite",
      }} />
      <p style={{ fontSize: 13, color: "oklch(0.55 0.01 240)", fontFamily: "monospace" }}>
        Building OS map…
      </p>
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
      <div style={{
        width: "100%", height: "100%",
        display: "flex", alignItems: "center", justifyContent: "center",
        background: "oklch(0.075 0.012 240)",
      }}>
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
