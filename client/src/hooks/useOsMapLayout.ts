import { useMemo } from "react";
import type { Node, Edge } from "@xyflow/react";
import type { EbpfSnapshot, BpfProgram, BpfMap, CgroupNode, NetworkInterface, KernelAttachmentZone } from "../../../shared/ebpf-types";
import type { MapNodeData } from "../components/osmap/OsMapNodes";

// ─── Layout constants ────────────────────────────────────────────────────────

const CANVAS_W = 1800;

// Band Y positions (top of each band)
const USERSPACE_Y = 0;
const USERSPACE_H = 220;

const KERNEL_Y = USERSPACE_H + 40;
const KERNEL_PADDING = 40;

// Inside kernel: zones section
const ZONES_SECTION_Y = KERNEL_Y + KERNEL_PADDING + 60; // below kernel header
const ZONE_W = 200;
const ZONE_H = 110;
const ZONE_GAP = 24;

// Inside kernel: cgroup section (below zones)
const CGROUP_SECTION_OFFSET_Y = ZONE_H + 80; // relative to ZONES_SECTION_Y
const CGROUP_NODE_W = 220;
const CGROUP_NODE_H = 80;
const CGROUP_H_GAP = 32;
const CGROUP_V_GAP = 24;

const KERNEL_H_DYNAMIC = true; // computed from content

// Network band (below kernel)
const NET_BAND_TOP_MARGIN = 60;
const IFACE_W = 220;
const IFACE_H = 200;
const IFACE_GAP = 32;

// Program node dimensions
const PROG_W = 180;
const PROG_H = 52;
const PROG_GAP = 8;

// ─── Zone layout data ─────────────────────────────────────────────────────────

const ZONE_COLORS: Record<string, string> = {
  xdp:            "#00d4ff",
  tc_ingress:     "#7c3aed",
  tc_egress:      "#6d28d9",
  socket_filter:  "#a78bfa",
  kprobe:         "#f59e0b",
  tracepoint:     "#10b981",
  perf_event:     "#f97316",
  cgroup:         "#3b82f6",
  flow_dissector: "#ec4899",
  netfilter:      "#f43f5e",
  sk_ops:         "#8b5cf6",
  other:          "#6b7280",
};

const ZONE_ICONS: Record<string, string> = {
  xdp: "⚡", tc_ingress: "↓", tc_egress: "↑", socket_filter: "🔌",
  kprobe: "🔍", tracepoint: "📍", perf_event: "📊", cgroup: "📁",
  flow_dissector: "🔀", netfilter: "🛡", sk_ops: "🔧", other: "⚙",
};

// ─── Node type identifiers ────────────────────────────────────────────────────

export type OsMapNodeType =
  | "userspaceBand"
  | "kernelBand"
  | "networkBand"
  | "zoneSectionLabel"
  | "cgroupSectionLabel"
  | "zoneNode"
  | "cgroupNode"
  | "interfaceNode"
  | "programNode"
  | "processNode"
  | "mapNode";

export interface ZoneNodeData {
  zone: string;
  label: string;
  description: string;
  color: string;
  icon: string;
  programCount: number;
  programs: BpfProgram[];
  isPacketPath: boolean;
}

export interface CgroupNodeData {
  path: string;
  name: string;
  depth: number;
  programs: BpfProgram[];
  hasChildren: boolean;
  color: string;
}

export interface InterfaceNodeData {
  name: string;
  ifindex: number;
  layers: NetworkInterface["layers"];
  allPrograms: BpfProgram[];
}

export interface ProgramNodeData {
  program: BpfProgram;
  parentId: string;
  color: string;
}

export interface ProcessNodeData {
  pid: number;
  comm: string;
  programIds: number[];
}

export interface BandNodeData {
  label: string;
  width: number;
  height: number;
  color: string;
}

export interface SectionLabelData {
  label: string;
  color: string;
}

// ─── Layout helpers ───────────────────────────────────────────────────────────

function flattenCgroup(nodes: CgroupNode[]): CgroupNode[] {
  const result: CgroupNode[] = [];
  function walk(n: CgroupNode) {
    result.push(n);
    n.children.forEach(walk);
  }
  nodes.forEach(walk);
  return result;
}

/** Assign x,y positions to cgroup nodes using a simple tree layout */
function layoutCgroupTree(
  roots: CgroupNode[],
  startX: number,
  startY: number
): Map<string, { x: number; y: number; w: number; h: number }> {
  const positions = new Map<string, { x: number; y: number; w: number; h: number }>();

  // Group nodes by depth
  const byDepth: CgroupNode[][] = [];
  function collect(n: CgroupNode, depth: number) {
    if (!byDepth[depth]) byDepth[depth] = [];
    byDepth[depth].push(n);
    n.children.forEach(c => collect(c, depth + 1));
  }
  roots.forEach(r => collect(r, 0));

  // Layout: each depth level is a column
  byDepth.forEach((levelNodes, depth) => {
    levelNodes.forEach((node, idx) => {
      positions.set(node.path, {
        x: startX + depth * (CGROUP_NODE_W + CGROUP_H_GAP),
        y: startY + idx * (CGROUP_NODE_H + CGROUP_V_GAP),
        w: CGROUP_NODE_W,
        h: CGROUP_NODE_H,
      });
    });
  });

  return positions;
}

// ─── Main layout function ─────────────────────────────────────────────────────

export interface OsMapLayout {
  nodes: Node[];
  edges: Edge[];
  totalHeight: number;
  totalWidth: number;
}

// ─── Map category colors ─────────────────────────────────────────────────────

const MAP_CATEGORY_COLORS: Record<string, string> = {
  data:    "#a78bfa",
  event:   "#f97316",
  control: "#10b981",
  socket:  "#06b6d4",
  other:   "#6b7280",
};

export function buildOsMapLayout(snapshot: EbpfSnapshot, maps: BpfMap[] = []): OsMapLayout {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // ── 1. Zones row ────────────────────────────────────────────────────────────
  const PACKET_ZONES = ["xdp", "tc_ingress", "netfilter", "socket_filter", "tc_egress"];
  const SYSTEM_ZONES = ["kprobe", "tracepoint", "perf_event", "cgroup", "flow_dissector", "sk_ops", "other"];
  const allZoneKeys = [...PACKET_ZONES, ...SYSTEM_ZONES];

  const zoneMap = new Map(snapshot.kernelZones.map(z => [z.zone, z]));

  // Two rows of zones
  const packetRowY = ZONES_SECTION_Y;
  const systemRowY = ZONES_SECTION_Y + ZONE_H + 32;

  PACKET_ZONES.forEach((zk, idx) => {
    const zone = zoneMap.get(zk as any);
    if (!zone) return;
    const x = KERNEL_PADDING + idx * (ZONE_W + ZONE_GAP);
    const y = packetRowY;
    nodes.push({
      id: `zone-${zk}`,
      type: "zoneNode",
      position: { x, y },
      data: {
        zone: zk,
        label: zone.label,
        description: zone.description,
        color: ZONE_COLORS[zk] ?? "#6b7280",
        icon: ZONE_ICONS[zk] ?? "⚙",
        programCount: zone.programs.length,
        programs: zone.programs,
        isPacketPath: true,
      } satisfies ZoneNodeData,
      style: { width: ZONE_W, height: ZONE_H },
    });
  });

  SYSTEM_ZONES.forEach((zk, idx) => {
    const zone = zoneMap.get(zk as any);
    if (!zone) return;
    const x = KERNEL_PADDING + idx * (ZONE_W + ZONE_GAP);
    const y = systemRowY;
    nodes.push({
      id: `zone-${zk}`,
      type: "zoneNode",
      position: { x, y },
      data: {
        zone: zk,
        label: zone.label,
        description: zone.description,
        color: ZONE_COLORS[zk] ?? "#6b7280",
        icon: ZONE_ICONS[zk] ?? "⚙",
        programCount: zone.programs.length,
        programs: zone.programs,
        isPacketPath: false,
      } satisfies ZoneNodeData,
      style: { width: ZONE_W, height: ZONE_H },
    });
  });

  // Zone section label
  nodes.push({
    id: "label-zones",
    type: "zoneSectionLabel",
    position: { x: KERNEL_PADDING, y: ZONES_SECTION_Y - 36 },
    data: { label: "Kernel Hook Zones", color: "#00d4ff" } satisfies SectionLabelData,
    selectable: false,
    draggable: false,
  });

  // ── 2. Cgroup tree ──────────────────────────────────────────────────────────
  const cgroupStartX = KERNEL_PADDING;
  const cgroupStartY = systemRowY + ZONE_H + 60;

  const cgroupPositions = layoutCgroupTree(snapshot.cgroupTree, cgroupStartX, cgroupStartY);

  const allCgroups = flattenCgroup(snapshot.cgroupTree);

  // Compute cgroup section total height
  let cgroupMaxY = cgroupStartY;
  cgroupPositions.forEach(pos => {
    cgroupMaxY = Math.max(cgroupMaxY, pos.y + pos.h);
  });

  allCgroups.forEach(cgNode => {
    const pos = cgroupPositions.get(cgNode.path);
    if (!pos) return;

    nodes.push({
      id: `cgroup-${cgNode.path}`,
      type: "cgroupNode",
      position: { x: pos.x, y: pos.y },
      data: {
        path: cgNode.path,
        name: cgNode.name || cgNode.path,
        depth: cgNode.depth,
        programs: cgNode.programs,
        hasChildren: cgNode.children.length > 0,
        color: "#3b82f6",
      } satisfies CgroupNodeData,
      style: { width: CGROUP_NODE_W, height: CGROUP_NODE_H },
    });

    // Edge to parent
    if (cgNode.depth > 0) {
      const parentPath = cgNode.path.split("/").slice(0, -1).join("/") || "/";
      const parentId = `cgroup-${parentPath}`;
      edges.push({
        id: `e-cgroup-${parentPath}-${cgNode.path}`,
        source: parentId,
        target: `cgroup-${cgNode.path}`,
        type: "smoothstep",
        style: { stroke: "#3b82f650", strokeWidth: 1.5 },
        animated: false,
      });
    }
  });

  // Cgroup section label
  nodes.push({
    id: "label-cgroups",
    type: "cgroupSectionLabel",
    position: { x: cgroupStartX, y: cgroupStartY - 36 },
    data: { label: "Cgroup Hierarchy", color: "#3b82f6" } satisfies SectionLabelData,
    selectable: false,
    draggable: false,
  });

  // ── 3. Compute kernel band height ───────────────────────────────────────────
  const kernelContentBottom = cgroupMaxY + KERNEL_PADDING;
  const kernelH = kernelContentBottom - KERNEL_Y;

  // Kernel band background node
  nodes.push({
    id: "band-kernel",
    type: "kernelBand",
    position: { x: 0, y: KERNEL_Y },
    data: {
      label: "Linux Kernel",
      width: CANVAS_W,
      height: kernelH,
      color: "#00d4ff",
    } satisfies BandNodeData,
    selectable: false,
    draggable: false,
    zIndex: -10,
  });

  // ── 4. Network interfaces ───────────────────────────────────────────────────
  const NET_Y = KERNEL_Y + kernelH + NET_BAND_TOP_MARGIN;

  snapshot.networkInterfaces.forEach((iface, idx) => {
    const x = KERNEL_PADDING + idx * (IFACE_W + IFACE_GAP);
    const y = NET_Y + 60;

    nodes.push({
      id: `iface-${iface.name}`,
      type: "interfaceNode",
      position: { x, y },
      data: {
        name: iface.name,
        ifindex: iface.ifindex,
        layers: iface.layers,
        allPrograms: iface.allPrograms,
      } satisfies InterfaceNodeData,
      style: { width: IFACE_W },
    });

    // Edge from XDP zone to interface if it has XDP programs
    if (iface.layers.L2.some(p => p.type === "xdp")) {
      edges.push({
        id: `e-xdp-${iface.name}`,
        source: "zone-xdp",
        target: `iface-${iface.name}`,
        type: "smoothstep",
        style: { stroke: "#00d4ff40", strokeWidth: 1.5, strokeDasharray: "4 3" },
        animated: true,
      });
    }
    // Edge from TC zone to interface if it has TC programs
    if (iface.layers.L2.some(p => p.rawType === "sched_cls" || p.rawType === "sched_act")) {
      edges.push({
        id: `e-tc-${iface.name}`,
        source: "zone-tc_ingress",
        target: `iface-${iface.name}`,
        type: "smoothstep",
        style: { stroke: "#7c3aed40", strokeWidth: 1.5, strokeDasharray: "4 3" },
        animated: true,
      });
    }
  });

  // Network band
  const netIfaceCount = Math.max(snapshot.networkInterfaces.length, 1);
  const netBandH = IFACE_H + 120;
  nodes.push({
    id: "band-network",
    type: "networkBand",
    position: { x: 0, y: NET_Y },
    data: {
      label: "Network Layer",
      width: CANVAS_W,
      height: netBandH,
      color: "#10b981",
    } satisfies BandNodeData,
    selectable: false,
    draggable: false,
    zIndex: -10,
  });

  // ── 5. Userspace processes ──────────────────────────────────────────────────
  // Collect unique processes from program pids
  const processMap = new Map<number, { pid: number; comm: string; programIds: number[] }>();
  snapshot.programs.forEach(p => {
    if (p.pids) {
      p.pids.forEach(({ pid, comm }) => {
        if (!processMap.has(pid)) {
          processMap.set(pid, { pid, comm, programIds: [] });
        }
        processMap.get(pid)!.programIds.push(p.id);
      });
    }
  });

  const processes = Array.from(processMap.values());
  const PROC_W = 140;
  const PROC_H = 52;
  const PROC_GAP = 20;

  processes.forEach((proc, idx) => {
    const x = KERNEL_PADDING + idx * (PROC_W + PROC_GAP);
    const y = USERSPACE_Y + 60;
    nodes.push({
      id: `proc-${proc.pid}`,
      type: "processNode",
      position: { x, y },
      data: proc satisfies ProcessNodeData,
      style: { width: PROC_W, height: PROC_H },
    });

    // Edges from process to owned programs in kernel zones
    proc.programIds.forEach(progId => {
      const prog = snapshot.programs.find(p => p.id === progId);
      if (!prog) return;
      const zoneKey = progTypeToZone(prog.rawType);
      edges.push({
        id: `e-proc-${proc.pid}-prog-${progId}`,
        source: `proc-${proc.pid}`,
        target: `zone-${zoneKey}`,
        type: "smoothstep",
        style: { stroke: "#ffffff15", strokeWidth: 1, strokeDasharray: "3 4" },
        animated: false,
      });
    });
  });

  // Userspace band
  nodes.push({
    id: "band-userspace",
    type: "userspaceBand",
    position: { x: 0, y: USERSPACE_Y },
    data: {
      label: "Userspace",
      width: CANVAS_W,
      height: USERSPACE_H,
      color: "#f59e0b",
    } satisfies BandNodeData,
    selectable: false,
    draggable: false,
    zIndex: -10,
  });

  // ── 6. BPF Maps (below network band) ─────────────────────────────────────────────────────────────────────
  const MAP_SECTION_TOP_MARGIN = 60;
  const MAP_W = 180;
  const MAP_H = 90;
  const MAP_GAP_X = 20;
  const MAP_GAP_Y = 16;
  const MAP_COLS = Math.max(1, Math.floor((CANVAS_W - KERNEL_PADDING * 2 + MAP_GAP_X) / (MAP_W + MAP_GAP_X)));
  const MAPS_Y = NET_Y + netBandH + MAP_SECTION_TOP_MARGIN;

  let mapsMaxY = MAPS_Y;

  if (maps.length > 0) {
    // Section label
    nodes.push({
      id: "label-maps",
      type: "zoneSectionLabel",
      position: { x: KERNEL_PADDING, y: MAPS_Y - 36 },
      data: { label: "BPF Maps", color: "#a78bfa" },
      selectable: false,
      draggable: false,
    });

    maps.forEach((map, idx) => {
      const col = idx % MAP_COLS;
      const row = Math.floor(idx / MAP_COLS);
      const x = KERNEL_PADDING + col * (MAP_W + MAP_GAP_X);
      const y = MAPS_Y + row * (MAP_H + MAP_GAP_Y);
      const nodeId = `map-${map.id}`;
      const color = MAP_CATEGORY_COLORS[map.category] ?? "#6b7280";

      nodes.push({
        id: nodeId,
        type: "mapNode",
        position: { x, y },
        data: {
          mapId: map.id,
          name: map.name,
          rawType: map.rawType,
          category: map.category,
          color,
          bytesKey: map.bytesKey,
          bytesValue: map.bytesValue,
          maxEntries: map.maxEntries,
          bytesMemlock: map.bytesMemlock,
          isShared: map.usedByProgIds.length > 1,
          frozen: map.frozen,
          pinned: map.pinnedPaths.length > 0,
        } satisfies MapNodeData,
        style: { width: MAP_W, height: MAP_H },
      });

      mapsMaxY = Math.max(mapsMaxY, y + MAP_H);

      // Edges from programs to this map
      map.usedByProgIds.forEach(progId => {
        const prog = snapshot.programs.find(p => p.id === progId);
        if (!prog) return;
        const zoneKey = progTypeToZone(prog.rawType);
        edges.push({
          id: `e-prog-${progId}-map-${map.id}`,
          source: `zone-${zoneKey}`,
          target: nodeId,
          type: "smoothstep",
          style: { stroke: `${color}40`, strokeWidth: 1, strokeDasharray: "3 4" },
          animated: false,
          markerEnd: { type: "arrowclosed" as any, color, width: 8, height: 8 },
        });
      });
    });
  }

  const totalHeight = (maps.length > 0 ? mapsMaxY + 60 : NET_Y + netBandH + 60);

  return { nodes, edges, totalHeight, totalWidth: CANVAS_W };
}

function progTypeToZone(rawType: string): string {
  if (rawType === "xdp") return "xdp";
  if (rawType === "sched_cls" || rawType === "sched_act") return "tc_ingress";
  if (rawType === "kprobe" || rawType === "kretprobe") return "kprobe";
  if (rawType === "tracepoint" || rawType === "raw_tracepoint") return "tracepoint";
  if (rawType === "perf_event") return "perf_event";
  if (rawType.startsWith("cgroup")) return "cgroup";
  if (rawType === "flow_dissector") return "flow_dissector";
  if (rawType === "netfilter") return "netfilter";
  if (rawType === "sock_ops" || rawType === "sk_ops") return "sk_ops";
  if (rawType === "socket_filter") return "socket_filter";
  return "other";
}

export function useOsMapLayout(snapshot: EbpfSnapshot | null, maps: BpfMap[] = []): OsMapLayout {
  return useMemo(() => {
    if (!snapshot) return { nodes: [], edges: [], totalHeight: 1200, totalWidth: CANVAS_W };
    return buildOsMapLayout(snapshot, maps);
  }, [snapshot, maps]);
}
