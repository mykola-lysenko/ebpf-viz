import React from "react";
import { Handle, Position, useViewport } from "@xyflow/react";
import type {
  ZoneNodeData,
  CgroupNodeData,
  InterfaceNodeData,
  ProgramNodeData,
  ProcessNodeData,
  BandNodeData,
  SectionLabelData,
} from "../../hooks/useOsMapLayout";
import { cn } from "@/lib/utils";
import type { BpfProgram } from "../../../../shared/ebpf-types";

// ─── LOD thresholds ───────────────────────────────────────────────────────────
// zoom < 0.35 → minimal (count only)
// zoom < 0.65 → compact (icon + label + count)
// zoom >= 0.65 → full (all details)

function useLod() {
  const { zoom } = useViewport();
  if (zoom < 0.35) return "minimal" as const;
  if (zoom < 0.65) return "compact" as const;
  return "full" as const;
}

// ─── Band nodes (background regions) ─────────────────────────────────────────

function BandNode({ data, label, accentColor, pattern }: {
  data: BandNodeData;
  label: string;
  accentColor: string;
  pattern: "userspace" | "kernel" | "network";
}) {
  const bg = pattern === "kernel"
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
  return <BandNode data={data} label="Userspace" accentColor="#f59e0b" pattern="userspace" />;
}

export function KernelBandNode({ data }: { data: BandNodeData }) {
  return <BandNode data={data} label="Linux Kernel" accentColor="#00d4ff" pattern="kernel" />;
}

export function NetworkBandNode({ data }: { data: BandNodeData }) {
  return <BandNode data={data} label="Network Layer" accentColor="#10b981" pattern="network" />;
}

// ─── Section label nodes ──────────────────────────────────────────────────────

export function ZoneSectionLabelNode({ data }: { data: SectionLabelData }) {
  return (
    <div style={{ pointerEvents: "none" }}>
      <span style={{
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: "0.14em",
        textTransform: "uppercase",
        color: data.color,
        fontFamily: "monospace",
        opacity: 0.7,
      }}>
        ── {data.label} ──
      </span>
    </div>
  );
}

export function CgroupSectionLabelNode({ data }: { data: SectionLabelData }) {
  return (
    <div style={{ pointerEvents: "none" }}>
      <span style={{
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: "0.14em",
        textTransform: "uppercase",
        color: data.color,
        fontFamily: "monospace",
        opacity: 0.7,
      }}>
        ── {data.label} ──
      </span>
    </div>
  );
}

// ─── Zone node ────────────────────────────────────────────────────────────────

export function ZoneNode({ data, selected }: { data: ZoneNodeData; selected?: boolean }) {
  const lod = useLod();
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
        boxShadow: selected ? `0 0 0 2px ${color}60, 0 0 20px ${color}30` : hasProgs ? `0 0 12px ${color}20` : undefined,
        transition: "box-shadow 0.3s ease, border-color 0.3s ease",
        cursor: "default",
        overflow: "hidden",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ fontSize: lod === "minimal" ? 14 : 18 }}>{icon}</span>
        {lod !== "minimal" && (
          <span style={{
            fontSize: 11,
            fontWeight: 700,
            color: hasProgs ? color : "oklch(0.6 0.01 240)",
            lineHeight: 1.2,
            flex: 1,
          }}>
            {label}
          </span>
        )}
        {/* Count badge */}
        <div style={{
          minWidth: 20,
          height: 20,
          borderRadius: 10,
          background: hasProgs ? `${color}25` : "oklch(0.18 0.01 240)",
          border: `1px solid ${hasProgs ? `${color}50` : "oklch(0.25 0.01 240)"}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "0 5px",
        }}>
          <span style={{
            fontSize: 10,
            fontWeight: 700,
            fontFamily: "monospace",
            color: hasProgs ? color : "oklch(0.5 0.01 240)",
          }}>
            {programCount}
          </span>
        </div>
      </div>

      {/* Description (full LOD only) */}
      {lod === "full" && (
        <p style={{
          fontSize: 9.5,
          color: "oklch(0.55 0.01 240)",
          lineHeight: 1.4,
          margin: 0,
          overflow: "hidden",
          display: "-webkit-box",
          WebkitLineClamp: 2,
          WebkitBoxOrient: "vertical",
        }}>
          {description}
        </p>
      )}

      {/* Program list (full LOD, has programs) */}
      {lod === "full" && hasProgs && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 3, marginTop: 2 }}>
          {data.programs.slice(0, 4).map(p => (
            <div key={p.id} style={{
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
            }}>
              {p.name}
            </div>
          ))}
          {data.programs.length > 4 && (
            <div style={{
              fontSize: 9,
              fontFamily: "monospace",
              color: "oklch(0.5 0.01 240)",
              padding: "1px 5px",
            }}>
              +{data.programs.length - 4}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Cgroup node ──────────────────────────────────────────────────────────────

export function CgroupNode({ data, selected }: { data: CgroupNodeData; selected?: boolean }) {
  const lod = useLod();
  const { color, name, path, programs, depth } = data;
  const hasProgs = programs.length > 0;

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
          <span style={{
            fontSize: 10,
            fontWeight: 600,
            fontFamily: "monospace",
            color: hasProgs ? color : "oklch(0.6 0.01 240)",
            flex: 1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}>
            {displayName}
          </span>
        )}
        {hasProgs && (
          <div style={{
            minWidth: 18,
            height: 18,
            borderRadius: 9,
            background: `${color}25`,
            border: `1px solid ${color}50`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "0 4px",
          }}>
            <span style={{ fontSize: 9, fontWeight: 700, fontFamily: "monospace", color }}>
              {programs.length}
            </span>
          </div>
        )}
      </div>

      {/* Programs (full LOD) */}
      {lod === "full" && hasProgs && (
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {programs.slice(0, 3).map(p => (
            <div key={p.id} style={{
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
            }}>
              {p.name}
            </div>
          ))}
          {programs.length > 3 && (
            <span style={{ fontSize: 9, color: "oklch(0.5 0.01 240)", fontFamily: "monospace" }}>
              +{programs.length - 3} more
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Interface node ───────────────────────────────────────────────────────────

const OSI_LAYERS = [
  { key: "L7", label: "L7 App", color: "#8b5cf6" },
  { key: "L4", label: "L4 Transport", color: "#10b981" },
  { key: "L3", label: "L3 Network", color: "#3b82f6" },
  { key: "L2", label: "L2 Data Link", color: "#00d4ff" },
] as const;

export function InterfaceNode({ data, selected }: { data: InterfaceNodeData; selected?: boolean }) {
  const lod = useLod();
  const { name, layers, allPrograms } = data;
  const hasProgs = allPrograms.length > 0;
  const color = "#10b981";

  return (
    <div
      style={{
        width: "100%",
        background: "oklch(0.11 0.018 160 / 0.8)",
        border: `1.5px solid ${selected ? color : hasProgs ? `${color}50` : "oklch(0.20 0.015 240 / 0.5)"}`,
        borderRadius: 12,
        overflow: "hidden",
        boxShadow: selected ? `0 0 0 2px ${color}60` : hasProgs ? `0 0 10px ${color}15` : undefined,
        cursor: "default",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      {/* Interface header */}
      <div style={{
        background: `${color}15`,
        borderBottom: `1px solid ${color}30`,
        padding: "6px 10px",
        display: "flex",
        alignItems: "center",
        gap: 6,
      }}>
        <span style={{ fontSize: 12 }}>🔌</span>
        <span style={{
          fontSize: 11,
          fontWeight: 700,
          fontFamily: "monospace",
          color,
        }}>
          {name}
        </span>
        {hasProgs && (
          <span style={{
            marginLeft: "auto",
            fontSize: 9,
            fontFamily: "monospace",
            color: `${color}cc`,
          }}>
            {allPrograms.length} prog{allPrograms.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {/* OSI layers */}
      {lod !== "minimal" && (
        <div style={{ padding: "6px 8px", display: "flex", flexDirection: "column", gap: 3 }}>
          {OSI_LAYERS.map(({ key, label, color: lc }) => {
            const progs = layers[key as keyof typeof layers] ?? [];
            return (
              <div key={key} style={{
                background: progs.length > 0 ? `${lc}12` : "oklch(0.13 0.01 240 / 0.5)",
                border: `1px solid ${progs.length > 0 ? `${lc}35` : "oklch(0.18 0.01 240 / 0.5)"}`,
                borderRadius: 6,
                padding: "3px 7px",
                display: "flex",
                alignItems: "center",
                gap: 5,
              }}>
                <span style={{
                  fontSize: 9,
                  fontWeight: 700,
                  fontFamily: "monospace",
                  color: progs.length > 0 ? lc : "oklch(0.4 0.01 240)",
                  width: 28,
                  flexShrink: 0,
                }}>
                  {key}
                </span>
                {lod === "full" && (
                  <span style={{
                    fontSize: 8.5,
                    color: "oklch(0.45 0.01 240)",
                    flex: 1,
                  }}>
                    {label}
                  </span>
                )}
                {progs.length > 0 && (
                  <div style={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                    {progs.slice(0, 2).map(p => (
                      <div key={p.id} style={{
                        fontSize: 8,
                        fontFamily: "monospace",
                        background: `${lc}20`,
                        border: `1px solid ${lc}35`,
                        borderRadius: 3,
                        padding: "0 4px",
                        color: lc,
                        maxWidth: 60,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}>
                        {p.name}
                      </div>
                    ))}
                    {progs.length > 2 && (
                      <span style={{ fontSize: 8, color: "oklch(0.45 0.01 240)", fontFamily: "monospace" }}>
                        +{progs.length - 2}
                      </span>
                    )}
                  </div>
                )}
                {progs.length === 0 && lod === "full" && (
                  <span style={{ fontSize: 8, color: "oklch(0.35 0.01 240)", fontFamily: "monospace" }}>
                    —
                  </span>
                )}
              </div>
            );
          })}
        </div>
      )}

      {lod === "minimal" && (
        <div style={{ padding: "4px 10px", fontSize: 9, fontFamily: "monospace", color: "oklch(0.5 0.01 240)" }}>
          {allPrograms.length} programs
        </div>
      )}
    </div>
  );
}

// ─── Process node ─────────────────────────────────────────────────────────────

export function ProcessNode({ data, selected }: { data: ProcessNodeData; selected?: boolean }) {
  const color = "#f59e0b";
  const lod = useLod();

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
        <span style={{
          fontSize: 10,
          fontWeight: 700,
          fontFamily: "monospace",
          color,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}>
          {data.comm}
        </span>
      </div>
      {lod !== "minimal" && (
        <span style={{
          fontSize: 9,
          fontFamily: "monospace",
          color: "oklch(0.5 0.01 240)",
        }}>
          pid {data.pid} · {data.programIds.length} prog{data.programIds.length !== 1 ? "s" : ""}
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

export function MapNode({ data, selected }: { data: MapNodeData; selected?: boolean }) {
  const lod = useLod();
  const { color, name, rawType, isShared, frozen, pinned, bytesKey, bytesValue, maxEntries } = data;

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
        <span style={{ fontSize: lod === "minimal" ? 12 : 14 }}>🗄</span>
        {lod !== "minimal" && (
          <span style={{
            fontSize: 10,
            fontWeight: 700,
            fontFamily: "monospace",
            color,
            flex: 1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}>
            {name}
          </span>
        )}
        {isShared && (
          <div style={{
            fontSize: 8,
            fontWeight: 700,
            fontFamily: "monospace",
            color: "#f59e0b",
            background: "#f59e0b18",
            border: "1px solid #f59e0b40",
            borderRadius: 4,
            padding: "1px 4px",
          }}>
            shared
          </div>
        )}
      </div>

      {/* Type */}
      {lod !== "minimal" && (
        <span style={{
          fontSize: 9,
          fontFamily: "monospace",
          color: "oklch(0.55 0.01 240)",
        }}>
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
            <div key={label} style={{
              flex: 1,
              background: "oklch(0.10 0.01 240 / 0.8)",
              borderRadius: 4,
              padding: "2px 4px",
              textAlign: "center",
            }}>
              <div style={{ fontSize: 7.5, color: "oklch(0.45 0.01 240)", textTransform: "uppercase" }}>{label}</div>
              <div style={{ fontSize: 9, fontFamily: "monospace", color: "oklch(0.75 0.01 240)" }}>{value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Flags */}
      {lod === "full" && (frozen || pinned) && (
        <div style={{ display: "flex", gap: 3 }}>
          {frozen && (
            <span style={{ fontSize: 8, color: "#60a5fa", background: "#60a5fa15", border: "1px solid #60a5fa30", borderRadius: 3, padding: "1px 4px" }}>frozen</span>
          )}
          {pinned && (
            <span style={{ fontSize: 8, color: "#34d399", background: "#34d39915", border: "1px solid #34d39930", borderRadius: 3, padding: "1px 4px" }}>pinned</span>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Node type map (export for ReactFlow) ─────────────────────────────────────

export const OS_MAP_NODE_TYPES = {
  userspaceBand: UserspaceBandNode,
  kernelBand: KernelBandNode,
  networkBand: NetworkBandNode,
  zoneSectionLabel: ZoneSectionLabelNode,
  cgroupSectionLabel: CgroupSectionLabelNode,
  zoneNode: ZoneNode,
  cgroupNode: CgroupNode,
  interfaceNode: InterfaceNode,
  processNode: ProcessNode,
  mapNode: MapNode,
} as const;
