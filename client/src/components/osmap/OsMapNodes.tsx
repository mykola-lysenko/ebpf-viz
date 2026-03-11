import React, { useState } from "react";
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

/**
 * Packet path layers displayed top-to-bottom in the NIC stack diagram.
 * Packet flows: NIC HW → L2 (XDP) → L3 (TC / netfilter) → L4 (sk_filter / sk_ops) → L7 (sk_msg)
 * We render them bottom-to-top visually so the NIC is at the bottom and L7 at the top,
 * matching the mental model of a packet travelling up the stack.
 */
const PACKET_PATH_LAYERS = [
  {
    key: "L7" as const,
    label: "L7 — Application",
    shortLabel: "L7",
    description: "sk_msg · sk_skb · sk_lookup",
    color: "#8b5cf6",
    icon: "📦",
  },
  {
    key: "L4" as const,
    label: "L4 — Transport",
    shortLabel: "L4",
    description: "socket_filter · sock_ops",
    color: "#10b981",
    icon: "🔌",
  },
  {
    key: "L3" as const,
    label: "L3 — Network",
    shortLabel: "L3",
    description: "TC ingress/egress · netfilter · flow_dissector",
    color: "#3b82f6",
    icon: "🛡",
  },
  {
    key: "L2" as const,
    label: "L2 — Data Link",
    shortLabel: "L2",
    description: "XDP (driver / offload / generic)",
    color: "#00d4ff",
    icon: "⚡",
  },
];

/** Tooltip shown when hovering a program badge inside the stack */
function ProgramTooltip({ prog, color, onClose }: {
  prog: BpfProgram;
  color: string;
  onClose: () => void;
}) {
  const attachment = prog.attachments[0];
  return (
    <div
      onMouseLeave={onClose}
      style={{
        position: "absolute",
        zIndex: 9999,
        bottom: "calc(100% + 6px)",
        left: "50%",
        transform: "translateX(-50%)",
        background: "oklch(0.10 0.018 240 / 0.97)",
        border: `1px solid ${color}50`,
        borderRadius: 8,
        padding: "8px 10px",
        minWidth: 160,
        maxWidth: 220,
        boxShadow: `0 4px 20px oklch(0 0 0 / 0.6), 0 0 0 1px ${color}20`,
        pointerEvents: "auto",
      }}
    >
      {/* Arrow */}
      <div style={{
        position: "absolute",
        bottom: -5,
        left: "50%",
        transform: "translateX(-50%)",
        width: 8,
        height: 8,
        background: "oklch(0.10 0.018 240)",
        border: `1px solid ${color}50`,
        borderTop: "none",
        borderLeft: "none",
        rotate: "45deg",
      }} />

      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        {/* Program name */}
        <div style={{
          fontSize: 10,
          fontWeight: 700,
          fontFamily: "monospace",
          color,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}>
          {prog.name || `prog#${prog.id}`}
        </div>

        {/* Type row */}
        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          <span style={{
            fontSize: 8,
            fontFamily: "monospace",
            background: `${color}18`,
            border: `1px solid ${color}35`,
            borderRadius: 3,
            padding: "1px 5px",
            color,
          }}>
            {prog.rawType}
          </span>
          <span style={{ fontSize: 8, fontFamily: "monospace", color: "oklch(0.5 0.01 240)" }}>
            id {prog.id}
          </span>
        </div>

        {/* Attachment detail */}
        {attachment && (
          <div style={{
            fontSize: 8.5,
            color: "oklch(0.6 0.01 240)",
            lineHeight: 1.4,
            fontFamily: "monospace",
            borderTop: "1px solid oklch(0.20 0.01 240)",
            paddingTop: 4,
            marginTop: 1,
          }}>
            {attachment.detail}
          </div>
        )}

        {/* JIT / GPL badges */}
        <div style={{ display: "flex", gap: 3 }}>
          {prog.jited && (
            <span style={{ fontSize: 7.5, color: "#10b981", background: "#10b98115", border: "1px solid #10b98130", borderRadius: 3, padding: "1px 4px" }}>JIT</span>
          )}
          {prog.gplCompatible && (
            <span style={{ fontSize: 7.5, color: "#6b7280", background: "oklch(0.15 0.01 240)", border: "1px solid oklch(0.22 0.01 240)", borderRadius: 3, padding: "1px 4px" }}>GPL</span>
          )}
          {prog.orphaned && (
            <span style={{ fontSize: 7.5, color: "#ef4444", background: "#ef444415", border: "1px solid #ef444430", borderRadius: 3, padding: "1px 4px" }}>orphaned</span>
          )}
        </div>
      </div>
    </div>
  );
}

/** A single program badge with hover tooltip */
function ProgBadge({ prog, color }: { prog: BpfProgram; color: string }) {
  const [hovered, setHovered] = useState(false);
  const displayName = prog.name.length > 12 ? prog.name.slice(0, 11) + "…" : prog.name;

  return (
    <div style={{ position: "relative" }}>
      <div
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        style={{
          fontSize: 8,
          fontFamily: "monospace",
          background: hovered ? `${color}30` : `${color}18`,
          border: `1px solid ${hovered ? `${color}70` : `${color}35`}`,
          borderRadius: 4,
          padding: "2px 6px",
          color,
          cursor: "default",
          whiteSpace: "nowrap",
          transition: "background 0.15s, border-color 0.15s",
          userSelect: "none",
        }}
      >
        {displayName}
      </div>
      {hovered && (
        <ProgramTooltip prog={prog} color={color} onClose={() => setHovered(false)} />
      )}
    </div>
  );
}

/** Flow arrow between layers — a small downward chevron */
function FlowArrow({ color, active }: { color: string; active: boolean }) {
  return (
    <div style={{
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      height: 10,
      opacity: active ? 0.7 : 0.2,
    }}>
      <svg width="12" height="10" viewBox="0 0 12 10" fill="none">
        <path d="M6 0 L6 6 M3 4 L6 8 L9 4" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}

/** NIC hardware base — the physical card at the bottom of the stack */
function NicHardwareBase({ name, color }: { name: string; color: string }) {
  return (
    <div style={{
      background: `${color}10`,
      border: `1px solid ${color}30`,
      borderRadius: 6,
      padding: "4px 8px",
      display: "flex",
      alignItems: "center",
      gap: 5,
    }}>
      <svg width="12" height="10" viewBox="0 0 12 10" fill="none">
        <rect x="1" y="2" width="10" height="6" rx="1" stroke={color} strokeWidth="1" />
        <rect x="3" y="4" width="2" height="2" rx="0.5" fill={color} opacity="0.6" />
        <rect x="7" y="4" width="2" height="2" rx="0.5" fill={color} opacity="0.6" />
        <line x1="4" y1="8" x2="4" y2="10" stroke={color} strokeWidth="1" />
        <line x1="8" y1="8" x2="8" y2="10" stroke={color} strokeWidth="1" />
      </svg>
      <span style={{
        fontSize: 9,
        fontWeight: 700,
        fontFamily: "monospace",
        color,
      }}>
        {name}
      </span>
      <span style={{
        marginLeft: "auto",
        fontSize: 8,
        fontFamily: "monospace",
        color: "oklch(0.45 0.01 240)",
      }}>
        NIC
      </span>
    </div>
  );
}

export function InterfaceNode({ data, selected }: { data: InterfaceNodeData; selected?: boolean }) {
  const lod = useLod();
  const { name, layers, allPrograms } = data;
  const hasProgs = allPrograms.length > 0;
  const color = "#10b981";

  // Determine which layers are active (have programs)
  const activeLayers = PACKET_PATH_LAYERS.filter(
    l => (layers[l.key] ?? []).length > 0
  );

  return (
    <div
      style={{
        width: "100%",
        background: "oklch(0.11 0.018 160 / 0.8)",
        border: `1.5px solid ${selected ? color : hasProgs ? `${color}50` : "oklch(0.20 0.015 240 / 0.5)"}`,
        borderRadius: 12,
        overflow: "visible",
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
        borderRadius: "10px 10px 0 0",
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

      {/* ── Packet path stack diagram ── */}
      {lod !== "minimal" && (
        <div style={{ padding: "8px 8px 6px", display: "flex", flexDirection: "column", gap: 0 }}>

          {/* Layers rendered top-to-bottom: L7 → L4 → L3 → L2 → NIC HW
               In compact LOD, empty layers are hidden to reduce visual noise.
               In full LOD, all layers are shown with their descriptions. */}
          {PACKET_PATH_LAYERS.map((layer, idx) => {
            const progs = layers[layer.key] ?? [];
            const active = progs.length > 0;
            const isLast = idx === PACKET_PATH_LAYERS.length - 1;
            const nextProgs = isLast ? [] : (layers[PACKET_PATH_LAYERS[idx + 1].key] ?? []);

            // In compact LOD, skip empty layers entirely to avoid phantom arrows
            if (!active && lod !== "full") {
              return null;
            }

            return (
              <React.Fragment key={layer.key}>
                {/* Layer row */}
                <div style={{
                  background: active ? `${layer.color}14` : "oklch(0.12 0.01 240 / 0.6)",
                  border: `1px solid ${active ? `${layer.color}40` : "oklch(0.18 0.01 240 / 0.5)"}`,
                  borderRadius: 7,
                  padding: "4px 7px",
                  display: "flex",
                  flexDirection: "column",
                  gap: 3,
                  transition: "background 0.2s, border-color 0.2s",
                  boxShadow: active ? `inset 0 0 0 1px ${layer.color}10` : undefined,
                }}>
                  {/* Layer header */}
                  <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                    <span style={{ fontSize: 10 }}>{layer.icon}</span>
                    <span style={{
                      fontSize: 9,
                      fontWeight: 700,
                      fontFamily: "monospace",
                      color: active ? layer.color : "oklch(0.38 0.01 240)",
                      flex: 1,
                    }}>
                      {lod === "full" ? layer.label : layer.shortLabel}
                    </span>
                    {active && (
                      <span style={{
                        fontSize: 8,
                        fontFamily: "monospace",
                        color: `${layer.color}99`,
                        background: `${layer.color}12`,
                        border: `1px solid ${layer.color}25`,
                        borderRadius: 3,
                        padding: "0 4px",
                      }}>
                        {progs.length}
                      </span>
                    )}
                  </div>

                  {/* Description (full LOD, inactive layers) */}
                  {lod === "full" && !active && (
                    <div style={{
                      fontSize: 8,
                      color: "oklch(0.32 0.01 240)",
                      fontFamily: "monospace",
                      lineHeight: 1.3,
                    }}>
                      {layer.description}
                    </div>
                  )}

                  {/* Program badges */}
                  {active && (
                    <div style={{
                      display: "flex",
                      flexWrap: "wrap",
                      gap: 3,
                      paddingTop: 1,
                    }}>
                      {progs.slice(0, lod === "full" ? 6 : 3).map(p => (
                        <ProgBadge key={p.id} prog={p} color={layer.color} />
                      ))}
                      {progs.length > (lod === "full" ? 6 : 3) && (
                        <span style={{
                          fontSize: 8,
                          fontFamily: "monospace",
                          color: "oklch(0.45 0.01 240)",
                          alignSelf: "center",
                        }}>
                          +{progs.length - (lod === "full" ? 6 : 3)}
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {/* Flow arrow between layers — only shown when the next layer is also visible */}
                {!isLast && (active || nextProgs.length > 0 || lod === "full") && (
                  <FlowArrow
                    color={layer.color}
                    active={active || nextProgs.length > 0}
                  />
                )}
              </React.Fragment>
            );
          })}

          {/* Arrow from L2 to NIC HW — always shown since NIC HW base is always rendered */}
          <FlowArrow color="#00d4ff" active={(layers.L2 ?? []).length > 0} />

          {/* NIC hardware base */}
          <NicHardwareBase name={name} color={color} />
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
