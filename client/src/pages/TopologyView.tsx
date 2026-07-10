import { useMemo } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  Position,
  ReactFlowProvider,
  type Node,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Share2, Box, Server } from "lucide-react";
import { useEbpf } from "@/contexts/EbpfContext";
import type {
  NamespaceTopology,
  NamespaceTopologyNode,
} from "../../../shared/ebpf-types";

// ─── Namespace node ───────────────────────────────────────────────────────────

interface NsNodeData extends Record<string, unknown> {
  label: string;
  inferred: boolean;
  deviceCount: number;
  programCount: number;
  isHost: boolean;
}

function NamespaceNode({ data }: NodeProps<Node<NsNodeData>>) {
  const Icon = data.isHost ? Server : Box;
  return (
    <div
      className="rounded-xl border px-4 py-3 shadow-lg min-w-[190px]"
      style={{
        background: data.inferred ? "oklch(0.30 0.02 250 / 0.4)" : "oklch(0.32 0.05 220 / 0.55)",
        borderColor: data.inferred ? "oklch(0.55 0.03 250 / 0.5)" : "oklch(0.72 0.15 220 / 0.7)",
        borderStyle: data.inferred ? "dashed" : "solid",
      }}
    >
      <Handle type="target" position={Position.Left} className="!bg-transparent !border-0" />
      <Handle type="source" position={Position.Right} className="!bg-transparent !border-0" />
      <div className="flex items-center gap-2">
        <Icon size={15} style={{ color: "oklch(0.80 0.15 220)" }} />
        <span className="font-semibold text-sm text-foreground truncate max-w-[220px]">
          {data.label}
        </span>
      </div>
      <div className="mt-1 text-[11px] text-muted-foreground">
        {data.inferred ? (
          <span>inferred peer · not directly scanned</span>
        ) : (
          <span>
            {data.deviceCount} device{data.deviceCount !== 1 ? "s" : ""} · {data.programCount} prog
            {data.programCount !== 1 ? "s" : ""}
          </span>
        )}
      </div>
    </div>
  );
}

const NODE_TYPES = { namespace: NamespaceNode };

// ─── Layout ───────────────────────────────────────────────────────────────────

const COL_W = 340;
const ROW_H = 130;

/** Simple layered layout: host + scanned namespaces in a left column, each
 *  inferred peer placed to the right of a namespace it connects to. */
function layout(topo: NamespaceTopology): { nodes: Node<NsNodeData>[]; edges: Edge[] } {
  const scanned = topo.nodes.filter(n => !n.inferred);
  const inferred = topo.nodes.filter(n => n.inferred);

  const pos = new Map<string, { x: number; y: number }>();
  scanned.forEach((n, i) => pos.set(n.id, { x: 0, y: i * ROW_H }));

  // Which scanned namespace does each inferred peer hang off of?
  const parentOf = new Map<string, string>();
  for (const e of topo.edges) {
    const aInf = inferred.some(n => n.id === e.a.namespace);
    const bInf = inferred.some(n => n.id === e.b.namespace);
    if (aInf && !bInf) parentOf.set(e.a.namespace, e.b.namespace);
    else if (bInf && !aInf) parentOf.set(e.b.namespace, e.a.namespace);
  }

  const childRow = new Map<string, number>(); // stacking offset per parent
  inferred.forEach(n => {
    const parent = parentOf.get(n.id);
    const base = parent ? pos.get(parent) : undefined;
    const row = childRow.get(parent ?? "") ?? 0;
    childRow.set(parent ?? "", row + 1);
    pos.set(n.id, {
      x: COL_W,
      y: (base?.y ?? 0) + row * (ROW_H * 0.9),
    });
  });

  const isHost = (n: NamespaceTopologyNode) => n.id === "host";

  const nodes: Node<NsNodeData>[] = topo.nodes.map(n => ({
    id: n.id,
    type: "namespace",
    position: pos.get(n.id) ?? { x: 0, y: 0 },
    data: {
      label: n.label,
      inferred: n.inferred,
      deviceCount: n.deviceCount,
      programCount: n.programCount,
      isHost: isHost(n),
    },
  }));

  const edges: Edge[] = topo.edges.map((e, i) => {
    const progNames = Array.from(
      new Set([...e.a.programs, ...e.b.programs].map(p => p.name))
    );
    const label =
      `${e.kind}` +
      (progNames.length ? `  ${progNames.join(", ")}` : "") +
      (e.ambiguous ? "  (?)" : "");
    return {
      id: `edge-${i}`,
      source: e.a.namespace,
      target: e.b.namespace,
      label,
      animated: e.kind === "netkit",
      style: {
        stroke: e.kind === "netkit" ? "oklch(0.72 0.15 220)" : "oklch(0.60 0.02 250)",
        strokeWidth: 2,
        strokeDasharray: e.ambiguous ? "6 4" : undefined,
      },
      labelStyle: { fill: "var(--foreground)", fontSize: 11, fontWeight: 500 },
      labelBgStyle: { fill: "var(--background)", fillOpacity: 0.85 },
      labelBgPadding: [6, 3] as [number, number],
      labelBgBorderRadius: 4,
    };
  });

  return { nodes, edges };
}

// ─── View ─────────────────────────────────────────────────────────────────────

function TopologyCanvas() {
  const { snapshot } = useEbpf();
  const topo = snapshot?.namespaceTopology;

  const { nodes, edges } = useMemo(
    () => (topo && topo.nodes.length > 0 ? layout(topo) : { nodes: [], edges: [] }),
    [topo]
  );

  if (!snapshot) {
    return (
      <div className="flex items-center justify-center h-full">
        <p className="text-muted-foreground">Loading…</p>
      </div>
    );
  }

  const hasData = nodes.length > 0;

  return (
    <div className="h-full flex flex-col">
      <div className="p-6 pb-3 shrink-0">
        <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
          <Share2 size={20} className="text-primary" />
          Namespace Topology
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          How network namespaces are wired together by netkit / veth device pairs.
          Solid boxes were scanned directly; dashed boxes are peers inferred from a
          device pair. Animated edges are netkit; <span className="font-mono">(?)</span>{" "}
          marks program attribution that could not be pinned to one side.
        </p>
      </div>

      {hasData ? (
        <div className="flex-1 min-h-0">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={NODE_TYPES}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            proOptions={{ hideAttribution: true }}
            minZoom={0.2}
          >
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="glass rounded-xl p-8 text-center max-w-lg">
            <Share2 size={32} className="text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">
              No cross-namespace device pairs found.
            </p>
            <p className="text-xs text-muted-foreground/60 mt-2">
              This graph is built from netkit/veth pairs discovered by scanning other
              network namespaces (container/pod datapaths). It populates when the
              dashboard can reach those namespaces — a real Kubernetes node, or a
              Docker host where the containers are visible.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default function TopologyView() {
  return (
    <ReactFlowProvider>
      <TopologyCanvas />
    </ReactFlowProvider>
  );
}
