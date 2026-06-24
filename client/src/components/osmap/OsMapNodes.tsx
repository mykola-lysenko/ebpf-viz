import React from "react";
import { Handle, Position } from "@xyflow/react";
import type {
  ZoneNodeData,
  CgroupNodeData,
  ProcessNodeData,
  BandNodeData,
  SectionLabelData,
} from "../../hooks/useOsMapLayout";
import { InterfaceNode } from "./OsMapInterfaceNode";

export { estimateInterfaceNodeHeight } from "./OsMapInterfaceNode";

// ─── LOD type (injected via data.lod from OsMapCanvas) ──────────────────────
type Lod = "minimal" | "compact" | "full";

// ─── Band nodes (background regions) ─────────────────────────────────────────

function BandNode({
  data,
  label,
  accentColor,
  pattern,
}: {
  data: BandNodeData;
  label: string;
  accentColor: string;
  pattern: "userspace" | "kernel" | "network";
}) {
  const bg =
    pattern === "kernel"
      ? "oklch(0.10 0.018 240 / 0.85)"
      : pattern === "userspace"
        ? "oklch(0.12 0.020 55 / 0.70)"
        : "oklch(0.10 0.020 160 / 0.70)";

  return (
    <div
      style={{
        width: data.width,
        height: data.height,
        background: bg,
        border: `1px solid ${accentColor}20`,
        borderRadius: 20,
        pointerEvents: "none",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Top label strip */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 36,
          background: `${accentColor}12`,
          borderBottom: `1px solid ${accentColor}25`,
          display: "flex",
          alignItems: "center",
          paddingLeft: 20,
          gap: 8,
        }}
      >
        <div
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: accentColor,
            boxShadow: `0 0 6px ${accentColor}`,
          }}
        />
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            color: accentColor,
            fontFamily: "monospace",
          }}
        >
          {label}
        </span>
      </div>
    </div>
  );
}

export function UserspaceBandNode({ data }: { data: BandNodeData }) {
  return (
    <BandNode
      data={data}
      label="Userspace"
      accentColor="#f59e0b"
      pattern="userspace"
    />
  );
}

export function KernelBandNode({ data }: { data: BandNodeData }) {
  return (
    <BandNode
      data={data}
      label="Linux Kernel"
      accentColor="#00d4ff"
      pattern="kernel"
    />
  );
}

export function NetworkBandNode({ data }: { data: BandNodeData }) {
  return (
    <BandNode
      data={data}
      label="Network Layer"
      accentColor="#10b981"
      pattern="network"
    />
  );
}

// ─── Section label nodes ──────────────────────────────────────────────────────

export function ZoneSectionLabelNode({ data }: { data: SectionLabelData }) {
  return (
    <div style={{ pointerEvents: "none" }}>
      <span
        style={{
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          color: data.color,
          fontFamily: "monospace",
          opacity: 0.7,
        }}
      >
        ── {data.label} ──
      </span>
    </div>
  );
}

export function CgroupSectionLabelNode({ data }: { data: SectionLabelData }) {
  return (
    <div style={{ pointerEvents: "none" }}>
      <span
        style={{
          fontSize: 10,
          fontWeight: 700,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          color: data.color,
          fontFamily: "monospace",
          opacity: 0.7,
        }}
      >
        ── {data.label} ──
      </span>
    </div>
  );
}

// ─── Zone node ────────────────────────────────────────────────────────────────

export function ZoneNode({
  data,
  selected,
}: {
  data: ZoneNodeData & { lod?: Lod };
  selected?: boolean;
}) {
  const lod: Lod = data.lod ?? "compact";
  const { color, icon, label, programCount, description, isPacketPath } = data;
  const hasProgs = programCount > 0;

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        background: hasProgs ? `${color}12` : "oklch(0.13 0.015 240 / 0.6)",
        border: `1.5px solid ${selected ? color : hasProgs ? `${color}50` : "oklch(0.22 0.015 240 / 0.5)"}`,
        borderRadius: 12,
        padding: lod === "minimal" ? 8 : 12,
        display: "flex",
        flexDirection: "column",
        gap: 6,
        boxShadow: selected
          ? `0 0 0 2px ${color}60, 0 0 20px ${color}30`
          : hasProgs
            ? `0 0 12px ${color}20`
            : undefined,
        transition: "box-shadow 0.3s ease, border-color 0.3s ease",
        cursor: "default",
        overflow: "hidden",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
        <span style={{ fontSize: lod === "minimal" ? 12 : 14 }}>&#x1f5c4;</span>
        {lod !== "minimal" && (
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              color: hasProgs ? color : "oklch(0.6 0.01 240)",
              lineHeight: 1.2,
              flex: 1,
            }}
          >
            {label}
          </span>
        )}
        {/* Count badge */}
        <div
          style={{
            minWidth: 20,
            height: 20,
            borderRadius: 10,
            background: hasProgs ? `${color}25` : "oklch(0.18 0.01 240)",
            border: `1px solid ${hasProgs ? `${color}50` : "oklch(0.25 0.01 240)"}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "0 5px",
          }}
        >
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              fontFamily: "monospace",
              color: hasProgs ? color : "oklch(0.5 0.01 240)",
            }}
          >
            {programCount}
          </span>
        </div>
      </div>

      {/* Description (full LOD only) */}
      {lod === "full" && (
        <p
          style={{
            fontSize: 9.5,
            color: "oklch(0.55 0.01 240)",
            lineHeight: 1.4,
            margin: 0,
            overflow: "hidden",
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
          }}
        >
          {description}
        </p>
      )}

      {/* Program list (full LOD, has programs) */}
      {lod === "full" && hasProgs && (
        <div
          style={{ display: "flex", flexWrap: "wrap", gap: 3, marginTop: 2 }}
        >
          {data.programs.slice(0, 4).map(p => (
            <div
              key={p.id}
              style={{
                fontSize: 9,
                fontFamily: "monospace",
                background: `${color}18`,
                border: `1px solid ${color}30`,
                borderRadius: 4,
                padding: "1px 5px",
                color: color,
                maxWidth: 80,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {p.name}
            </div>
          ))}
          {data.programs.length > 4 && (
            <div
              style={{
                fontSize: 9,
                fontFamily: "monospace",
                color: "oklch(0.5 0.01 240)",
                padding: "1px 5px",
              }}
            >
              +{data.programs.length - 4}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Cgroup node ──────────────────────────────────────────────────────────────

export function CgroupNode({
  data,
  selected,
}: {
  data: CgroupNodeData & { lod?: Lod };
  selected?: boolean;
}) {
  const lod: Lod = data.lod ?? "compact";
  const { color, name, path, programs, depth, collapsedChildren } = data;
  const hasProgs = programs.length > 0;
  const isCollapsed = collapsedChildren !== undefined && collapsedChildren > 0;

  const displayName = name.length > 28 ? name.slice(0, 26) + "…" : name;

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        background: hasProgs ? `${color}10` : "oklch(0.12 0.015 240 / 0.7)",
        border: `1.5px solid ${selected ? color : hasProgs ? `${color}45` : "oklch(0.20 0.015 240 / 0.5)"}`,
        borderRadius: 10,
        padding: lod === "minimal" ? 6 : 10,
        display: "flex",
        flexDirection: "column",
        gap: 4,
        boxShadow: selected ? `0 0 0 2px ${color}60` : undefined,
        cursor: "default",
        overflow: "hidden",
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />

      {/* Path label */}
      <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
        <span style={{ fontSize: 12 }}>📁</span>
        {lod !== "minimal" && (
          <span
            style={{
              fontSize: 10,
              fontWeight: 600,
              fontFamily: "monospace",
              color: hasProgs ? color : "oklch(0.6 0.01 240)",
              flex: 1,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {displayName}
          </span>
        )}
        {hasProgs && (
          <div
            style={{
              minWidth: 18,
              height: 18,
              borderRadius: 9,
              background: `${color}25`,
              border: `1px solid ${color}50`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              padding: "0 4px",
            }}
          >
            <span
              style={{
                fontSize: 9,
                fontWeight: 700,
                fontFamily: "monospace",
                color,
              }}
            >
              {programs.length}
            </span>
          </div>
        )}
      </div>

      {/* Programs (full LOD) */}
      {lod === "full" && hasProgs && (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {programs.slice(0, 3).map(p => (
            <div
              key={p.id}
              style={{
                fontSize: 9,
                fontFamily: "monospace",
                color: p.color,
                background: `${p.color}12`,
                border: `1px solid ${p.color}25`,
                borderRadius: 3,
                padding: "1px 5px",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {p.name}
            </div>
          ))}
          {programs.length > 3 && (
            <span
              style={{
                fontSize: 9,
                color: "oklch(0.5 0.01 240)",
                fontFamily: "monospace",
              }}
            >
              +{programs.length - 3} more
            </span>
          )}
        </div>
      )}

      {/* Collapsed subtree indicator */}
      {isCollapsed && lod !== "minimal" && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 4,
            marginTop: 2,
            padding: "2px 5px",
            background: `${color}10`,
            border: `1px dashed ${color}40`,
            borderRadius: 4,
          }}
        >
          <span style={{ fontSize: 9 }}>+</span>
          <span
            style={{
              fontSize: 9,
              fontFamily: "monospace",
              color: `${color}cc`,
            }}
          >
            {collapsedChildren} hidden
          </span>
        </div>
      )}
    </div>
  );
}

// ─── Process node ─────────────────────────────────────────────────────────────

export function ProcessNode({
  data,
  selected,
}: {
  data: ProcessNodeData & { lod?: Lod };
  selected?: boolean;
}) {
  const color = "#f59e0b";
  const lod: Lod = data.lod ?? "compact";

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        background: `${color}10`,
        border: `1.5px solid ${selected ? color : `${color}40`}`,
        borderRadius: 8,
        padding: "6px 10px",
        display: "flex",
        flexDirection: "column",
        gap: 2,
        boxShadow: selected ? `0 0 0 2px ${color}60` : undefined,
        cursor: "default",
        overflow: "hidden",
      }}
    >
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
        <span style={{ fontSize: 11 }}>⚙</span>
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            fontFamily: "monospace",
            color,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {data.comm}
        </span>
      </div>
      {lod !== "minimal" && (
        <span
          style={{
            fontSize: 9,
            fontFamily: "monospace",
            color: "oklch(0.5 0.01 240)",
          }}
        >
          pid {data.pid} · {data.programIds.length} prog
          {data.programIds.length !== 1 ? "s" : ""}
        </span>
      )}
    </div>
  );
}

// ─── Map node ───────────────────────────────────────────────────────────────────

export type MapNodeData = {
  mapId: number;
  name: string;
  rawType: string;
  category: string;
  color: string;
  bytesKey: number;
  bytesValue: number;
  maxEntries: number;
  bytesMemlock: number;
  isShared: boolean;
  frozen: boolean;
  pinned: boolean;
};

export type MapSummaryNodeData = {
  category: string;
  color: string;
  count: number;
  mapIds: number[];
};

export function MapSummaryNode({
  data,
  selected,
}: {
  data: MapSummaryNodeData & { lod?: Lod };
  selected?: boolean;
}) {
  const { category, color, count } = data;
  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        background: `${color}15`,
        border: `2px dashed ${selected ? color : `${color}60`}`,
        borderRadius: 12,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 4,
        boxShadow: selected ? `0 0 16px ${color}40` : undefined,
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      <span style={{ fontSize: 20 }}>&#x1f4c2;</span>
      <div
        style={{
          fontSize: 11,
          fontWeight: 800,
          fontFamily: "monospace",
          color,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {count} {category} maps
      </div>
      <div
        style={{
          fontSize: 9,
          color: "oklch(0.55 0.01 240)",
          fontFamily: "monospace",
        }}
      >
        aggregated
      </div>
    </div>
  );
}

export function MapNode({
  data,
  selected,
}: {
  data: MapNodeData & { lod?: Lod };
  selected?: boolean;
}) {
  const lod: Lod = data.lod ?? "compact";
  const {
    color,
    name,
    rawType,
    isShared,
    frozen,
    pinned,
    bytesKey,
    bytesValue,
    maxEntries,
  } = data;

  const formatEntries = (n: number) => {
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
    return String(n);
  };

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        background: `${color}12`,
        border: `1.5px solid ${selected ? color : `${color}45`}`,
        borderRadius: 10,
        padding: lod === "minimal" ? 6 : 10,
        display: "flex",
        flexDirection: "column",
        gap: 4,
        boxShadow: selected
          ? `0 0 0 2px ${color}60, 0 0 16px ${color}30`
          : isShared
            ? `0 0 10px ${color}20`
            : undefined,
        cursor: "default",
        overflow: "hidden",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
        <span style={{ fontSize: lod === "minimal" ? 12 : 14 }}>&#x1f5c4;</span>
        {lod !== "minimal" && (
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              fontFamily: "monospace",
              color,
              flex: 1,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {name}
          </span>
        )}
        {isShared && (
          <div
            style={{
              fontSize: 8,
              fontWeight: 700,
              fontFamily: "monospace",
              color: "#f59e0b",
              background: "#f59e0b18",
              border: "1px solid #f59e0b40",
              borderRadius: 4,
              padding: "1px 4px",
            }}
          >
            shared
          </div>
        )}
      </div>

      {/* Type */}
      {lod !== "minimal" && (
        <span
          style={{
            fontSize: 9,
            fontFamily: "monospace",
            color: "oklch(0.55 0.01 240)",
          }}
        >
          {rawType}
        </span>
      )}

      {/* Schema (full LOD) */}
      {lod === "full" && (
        <div style={{ display: "flex", gap: 4 }}>
          {[
            { label: "key", value: `${bytesKey}B` },
            { label: "val", value: `${bytesValue}B` },
            { label: "max", value: formatEntries(maxEntries) },
          ].map(({ label, value }) => (
            <div
              key={label}
              style={{
                flex: 1,
                background: "oklch(0.10 0.01 240 / 0.8)",
                borderRadius: 4,
                padding: "2px 4px",
                textAlign: "center",
              }}
            >
              <div
                style={{
                  fontSize: 7.5,
                  color: "oklch(0.45 0.01 240)",
                  textTransform: "uppercase",
                }}
              >
                {label}
              </div>
              <div
                style={{
                  fontSize: 9,
                  fontFamily: "monospace",
                  color: "oklch(0.75 0.01 240)",
                }}
              >
                {value}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Flags */}
      {lod === "full" && (frozen || pinned) && (
        <div style={{ display: "flex", gap: 3 }}>
          {frozen && (
            <span
              style={{
                fontSize: 8,
                color: "#60a5fa",
                background: "#60a5fa15",
                border: "1px solid #60a5fa30",
                borderRadius: 3,
                padding: "1px 4px",
              }}
            >
              frozen
            </span>
          )}
          {pinned && (
            <span
              style={{
                fontSize: 8,
                color: "#34d399",
                background: "#34d39915",
                border: "1px solid #34d39930",
                borderRadius: 3,
                padding: "1px 4px",
              }}
            >
              pinned
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Memoized node wrappers ───────────────────────────────────────────────────
// React.memo prevents re-renders when data/selected haven't changed.
// This is critical for large topologies where setNodes() is called frequently.

const dataEq = (a: unknown, b: unknown) => a === b;
const nodeEq = <P extends { data: unknown; selected?: boolean }>(
  prev: P,
  next: P
) => prev.selected === next.selected && dataEq(prev.data, next.data);

const MemoUserspaceBandNode = React.memo(UserspaceBandNode, nodeEq);
const MemoKernelBandNode = React.memo(KernelBandNode, nodeEq);
const MemoNetworkBandNode = React.memo(NetworkBandNode, nodeEq);
const MemoZoneSectionLabelNode = React.memo(ZoneSectionLabelNode, nodeEq);
const MemoCgroupSectionLabelNode = React.memo(CgroupSectionLabelNode, nodeEq);
const MemoZoneNode = React.memo(ZoneNode, nodeEq);
const MemoCgroupNode = React.memo(CgroupNode, nodeEq);
const MemoInterfaceNode = React.memo(InterfaceNode, nodeEq);
const MemoProcessNode = React.memo(ProcessNode, nodeEq);
const MemoMapNode = React.memo(MapNode, nodeEq);
const MemoMapSummaryNode = React.memo(MapSummaryNode, nodeEq);

// ─── Node type map (export for ReactFlow) ─────────────────────────────────────

export const OS_MAP_NODE_TYPES = {
  userspaceBand: MemoUserspaceBandNode,
  kernelBand: MemoKernelBandNode,
  networkBand: MemoNetworkBandNode,
  zoneSectionLabel: MemoZoneSectionLabelNode,
  cgroupSectionLabel: MemoCgroupSectionLabelNode,
  zoneNode: MemoZoneNode,
  cgroupNode: MemoCgroupNode,
  interfaceNode: MemoInterfaceNode,
  processNode: MemoProcessNode,
  mapNode: MemoMapNode,
  mapSummaryNode: MemoMapSummaryNode,
} as const;
