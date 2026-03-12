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
  Eye, EyeOff, Info, Cpu, Download
} from "lucide-react";
import { cn } from "@/lib/utils";
import { trpc } from "@/lib/trpc";

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
`;

// ─── LOD legend ───────────────────────────────────────────────────────────────

function LodIndicator({ zoom }: { zoom: number }) {
  const level = zoom < 0.35 ? "Bird's Eye" : zoom < 0.65 ? "Overview" : "Detail";
  const color = zoom < 0.35 ? "#f59e0b" : zoom < 0.65 ? "#10b981" : "#00d4ff";
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
}: {
  zoom: number;
  showLabels: boolean;
  onToggleLabels: () => void;
  nodeCount: number;
  progCount: number;
  onDownload: () => void;
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
    { color: "#a78bfa40", label: "Dashed = program → map edge" },
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
  const { snapshot, searchQuery, setSelectedProgram } = useEbpf();
  // Maps arrive via SSE push — no polling needed here
  const mapsQuery = trpc.ebpf.maps.useQuery(undefined, { staleTime: Infinity, refetchOnWindowFocus: false });
  // Stabilize the maps array reference — a new [] on every render would cause
  // useOsMapLayout's useMemo to recompute every render, creating an infinite loop.
  const maps = useMemo(() => mapsQuery.data ?? [], [mapsQuery.data]);
  // zoom must be declared before useOsMapLayout so the LOD can be derived from it
  const [zoom, setZoom] = useState(0.35);
  const layout = useOsMapLayout(snapshot, maps, zoom);
  const { fitView, getViewport } = useReactFlow();
  // Keep a stable ref to fitView so it never appears in useEffect deps
  const fitViewRef = useRef(fitView);
  useEffect(() => { fitViewRef.current = fitView; });
  const [nodes, setNodes, onNodesChange] = useNodesState(layout.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layout.edges);
  const [showLabels, setShowLabels] = useState(true);
  const didFit = useRef(false);
  const fitAttempts = useRef(0);

  // Sync layout → nodes/edges when snapshot or maps change.
  // fitView is accessed via ref so it never appears in deps (it is not stable
  // across renders in React Flow and would cause an infinite loop).
  useEffect(() => {
    setNodes(layout.nodes);
    setEdges(layout.edges);
    if (!didFit.current && layout.nodes.length > 0) {
      const tryFit = (delay: number) => {
        setTimeout(() => {
          const contentNodes = layout.nodes.filter(
            n => n.type === "zoneNode" || n.type === "cgroupNode" ||
                 n.type === "interfaceNode" || n.type === "processNode"
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
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout]);

  // Track zoom for LOD
  const onMoveEnd = useCallback(() => {
    const vp = getViewport();
    setZoom(vp.zoom);
  }, [getViewport]);

  const onMove = useCallback(() => {
    const vp = getViewport();
    setZoom(vp.zoom);
  }, [getViewport]);

  // Search highlighting: dim non-matching nodes
  const highlightedNodeIds = useMemo(() => {
    if (!searchQuery || !snapshot) return null;
    const snap = snapshot;
    const q = searchQuery.toLowerCase();
    const matchingProgIds = new Set(
      snap.programs
        .filter(p =>
          p.name.toLowerCase().includes(q) ||
          p.rawType.toLowerCase().includes(q) ||
          p.tag.toLowerCase().includes(q)
        )
        .map(p => p.id)
    );

    const nodeIds = new Set<string>();
    // Always keep band nodes
    nodeIds.add("band-userspace");
    nodeIds.add("band-kernel");
    nodeIds.add("band-network");
    nodeIds.add("label-zones");
    nodeIds.add("label-cgroups");

    // Zones that contain matching programs
    snap.kernelZones.forEach(z => {
      if (z.programs.some(p => matchingProgIds.has(p.id))) {
        nodeIds.add(`zone-${z.zone}`);
      }
    });

    // Cgroup nodes that contain matching programs
    function walkCgroup(nodes: typeof snap.cgroupTree) {
      nodes.forEach(n => {
        if (n.programs.some(p => matchingProgIds.has(p.id))) {
          nodeIds.add(`cgroup-${n.path}`);
        }
        walkCgroup(n.children);
      });
    }
    walkCgroup(snap.cgroupTree);

    // Interfaces that contain matching programs
    snap.networkInterfaces.forEach(iface => {
      if (iface.allPrograms.some(p => matchingProgIds.has(p.id))) {
        nodeIds.add(`iface-${iface.name}`);
      }
    });

    // Process nodes that own matching programs
    snap.programs
      .filter(p => matchingProgIds.has(p.id) && p.pids)
      .forEach(p => p.pids!.forEach(({ pid }) => nodeIds.add(`proc-${pid}`)));

    return nodeIds;
  }, [searchQuery, snapshot]);

  // Derive LOD tier from current zoom (changes at only 2 thresholds, not on every tick)
  const lod = zoomToLod(zoom);

  // Apply highlight opacity to nodes AND inject lod into data so node components
  // don't need to call useViewport() individually (eliminates per-node re-renders on pan/zoom)
  const displayNodes = useMemo(() => {
    return nodes.map(n => ({
      ...n,
      data: { ...n.data, lod },
      ...(highlightedNodeIds ? {
        style: {
          ...n.style,
          opacity: highlightedNodeIds.has(n.id) ? 1 : 0.15,
          transition: "opacity 0.3s ease",
        },
      } : {}),
    }));
  }, [nodes, highlightedNodeIds, lod]);

  // Apply highlight opacity to edges
  const displayEdges = useMemo(() => {
    if (!highlightedNodeIds) return edges;
    return edges.map(e => ({
      ...e,
      style: {
        ...e.style,
        opacity: (highlightedNodeIds.has(e.source) && highlightedNodeIds.has(e.target)) ? 1 : 0.05,
      },
    }));
  }, [edges, highlightedNodeIds]);

  // Node click handler — extract program from zone/cgroup/interface and open detail panel
  const onNodeClick: NodeMouseHandler = useCallback((_evt, node) => {
    if (!snapshot) return;

    // Double-click to zoom-fit is handled by onNodeDoubleClick
    const type = node.type;

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

  // Double-click to zoom-fit node
  const onNodeDoubleClick: NodeMouseHandler = useCallback((_evt, node) => {
    fitView({
      nodes: [node],
      duration: 500,
      padding: 0.3,
    });
  }, [fitView]);

  const progCount = snapshot?.stats.total ?? 0;

  // Download the full topology snapshot as JSON for performance testing
  const handleDownload = useCallback(() => {
    if (!snapshot) return;
    // Produce a file that is directly re-uploadable via "Load Snapshot" in the UI.
    // The _ebpfVizSnapshot flag tells the loader this is a pre-parsed snapshot
    // (not a raw capture-snapshot.sh output), so it can be used as-is.
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
        className="os-map-flow"
        nodes={displayNodes}
        edges={displayEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onNodeDoubleClick={onNodeDoubleClick}
        onMove={onMove}
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
