import React, { useState } from "react";
import { Handle, Position } from "@xyflow/react";
import type { InterfaceNodeData } from "../../hooks/useOsMapLayout";
import type {
  BpfProgram,
  NetworkInterface,
} from "../../../../shared/ebpf-types";

type Lod = "minimal" | "compact" | "full";

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

export function estimateInterfaceNodeHeight(
  layers: NetworkInterface["layers"],
  lod: Lod = "compact"
): number {
  if (lod === "minimal") return 52;

  const HEADER_H = 32;
  const OUTER_PAD = 14;
  const LAYER_BASE_H = 28;
  const BADGE_ROW_H = 18;
  const BADGES_PER_ROW = lod === "full" ? 6 : 3;
  const ARROW_H = 10;
  const NIC_HW_H = 30;
  const PACKET_PATH_KEYS: Array<keyof NetworkInterface["layers"]> = [
    "L7",
    "L4",
    "L3",
    "L2",
  ];

  let contentH = 0;
  let visibleLayerCount = 0;

  for (const key of PACKET_PATH_KEYS) {
    const progs = layers[key] ?? [];
    const active = progs.length > 0;
    if (!active && lod !== "full") continue;

    visibleLayerCount++;
    let layerH = LAYER_BASE_H;
    if (active) {
      const rows = Math.ceil(
        Math.min(progs.length, lod === "full" ? 6 : 3) / BADGES_PER_ROW
      );
      layerH += rows * BADGE_ROW_H;
    } else if (lod === "full") {
      layerH += 14;
    }
    contentH += layerH;
  }

  const arrowCount = Math.max(0, visibleLayerCount);
  contentH += arrowCount * ARROW_H;
  contentH += NIC_HW_H;

  return HEADER_H + OUTER_PAD + contentH;
}

function ProgramTooltip({
  prog,
  color,
  onClose,
}: {
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
      <div
        style={{
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
        }}
      />

      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        <div
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
          {prog.name || `prog#${prog.id}`}
        </div>

        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          <span
            style={{
              fontSize: 8,
              fontFamily: "monospace",
              background: `${color}18`,
              border: `1px solid ${color}35`,
              borderRadius: 3,
              padding: "1px 5px",
              color,
            }}
          >
            {prog.rawType}
          </span>
          <span
            style={{
              fontSize: 8,
              fontFamily: "monospace",
              color: "oklch(0.5 0.01 240)",
            }}
          >
            id {prog.id}
          </span>
        </div>

        {attachment && (
          <div
            style={{
              fontSize: 8.5,
              color: "oklch(0.6 0.01 240)",
              lineHeight: 1.4,
              fontFamily: "monospace",
              borderTop: "1px solid oklch(0.20 0.01 240)",
              paddingTop: 4,
              marginTop: 1,
            }}
          >
            {attachment.detail}
          </div>
        )}

        <div style={{ display: "flex", gap: 3 }}>
          {prog.jited && (
            <span
              style={{
                fontSize: 7.5,
                color: "#10b981",
                background: "#10b98115",
                border: "1px solid #10b98130",
                borderRadius: 3,
                padding: "1px 4px",
              }}
            >
              JIT
            </span>
          )}
          {prog.gplCompatible && (
            <span
              style={{
                fontSize: 7.5,
                color: "#6b7280",
                background: "oklch(0.15 0.01 240)",
                border: "1px solid oklch(0.22 0.01 240)",
                borderRadius: 3,
                padding: "1px 4px",
              }}
            >
              GPL
            </span>
          )}
          {prog.orphaned && (
            <span
              style={{
                fontSize: 7.5,
                color: "#ef4444",
                background: "#ef444415",
                border: "1px solid #ef444430",
                borderRadius: 3,
                padding: "1px 4px",
              }}
            >
              orphaned
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function getTcDirection(prog: BpfProgram): "ingress" | "egress" | undefined {
  const tcAttachment = prog.attachments.find(
    a => (a.kind === "tc" || a.kind === "tcx") && a.direction != null
  );
  return tcAttachment?.direction;
}

function ProgBadge({ prog, color }: { prog: BpfProgram; color: string }) {
  const [hovered, setHovered] = useState(false);
  const displayName =
    prog.name.length > 12 ? prog.name.slice(0, 11) + "…" : prog.name;
  const direction = getTcDirection(prog);

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
          display: "flex",
          alignItems: "center",
          gap: 3,
        }}
      >
        {displayName}
        {direction && (
          <span
            title={
              direction === "ingress"
                ? "Ingress (incoming packets)"
                : "Egress (outgoing packets)"
            }
            style={{
              fontSize: 7,
              fontWeight: 700,
              fontFamily: "monospace",
              background: direction === "ingress" ? "#3b82f620" : "#f59e0b20",
              border: `1px solid ${
                direction === "ingress" ? "#3b82f650" : "#f59e0b50"
              }`,
              color: direction === "ingress" ? "#60a5fa" : "#fbbf24",
              borderRadius: 3,
              padding: "0 3px",
              lineHeight: "1.6",
              letterSpacing: "0.02em",
            }}
          >
            {direction === "ingress" ? "→" : "←"}
          </span>
        )}
      </div>
      {hovered && (
        <ProgramTooltip
          prog={prog}
          color={color}
          onClose={() => setHovered(false)}
        />
      )}
    </div>
  );
}

function FlowArrow({ color, active }: { color: string; active: boolean }) {
  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        height: 10,
        opacity: active ? 0.7 : 0.2,
      }}
    >
      <svg width="12" height="10" viewBox="0 0 12 10" fill="none">
        <path
          d="M6 0 L6 6 M3 4 L6 8 L9 4"
          stroke={color}
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}

function NicHardwareBase({ name, color }: { name: string; color: string }) {
  return (
    <div
      style={{
        background: `${color}10`,
        border: `1px solid ${color}30`,
        borderRadius: 6,
        padding: "4px 8px",
        display: "flex",
        alignItems: "center",
        gap: 5,
      }}
    >
      <svg width="12" height="10" viewBox="0 0 12 10" fill="none">
        <rect
          x="1"
          y="2"
          width="10"
          height="6"
          rx="1"
          stroke={color}
          strokeWidth="1"
        />
        <rect
          x="3"
          y="4"
          width="2"
          height="2"
          rx="0.5"
          fill={color}
          opacity="0.6"
        />
        <rect
          x="7"
          y="4"
          width="2"
          height="2"
          rx="0.5"
          fill={color}
          opacity="0.6"
        />
        <line x1="4" y1="8" x2="4" y2="10" stroke={color} strokeWidth="1" />
        <line x1="8" y1="8" x2="8" y2="10" stroke={color} strokeWidth="1" />
      </svg>
      <span
        style={{
          fontSize: 9,
          fontWeight: 700,
          fontFamily: "monospace",
          color,
        }}
      >
        {name}
      </span>
      <span
        style={{
          marginLeft: "auto",
          fontSize: 8,
          fontFamily: "monospace",
          color: "oklch(0.45 0.01 240)",
        }}
      >
        NIC
      </span>
    </div>
  );
}

export function InterfaceNode({
  data,
  selected,
}: {
  data: InterfaceNodeData & { lod?: Lod };
  selected?: boolean;
}) {
  const lod: Lod = data.lod ?? "compact";
  const { name, kind, layers, allPrograms } = data;
  const hasProgs = allPrograms.length > 0;
  const isSockmap = kind === "sockmap";
  const color = isSockmap ? "#8b5cf6" : "#10b981";

  const NIC_LAYER_KEYS = new Set(["L2", "L3"]);
  const SOCKMAP_LAYER_KEYS = new Set(["L4", "L7"]);
  const allowedKeys = isSockmap ? SOCKMAP_LAYER_KEYS : NIC_LAYER_KEYS;
  const visibleLayers = PACKET_PATH_LAYERS.filter(l => allowedKeys.has(l.key));

  return (
    <div
      style={{
        width: "100%",
        background: "oklch(0.11 0.018 160 / 0.8)",
        border: `1.5px solid ${
          selected
            ? color
            : hasProgs
              ? `${color}50`
              : "oklch(0.20 0.015 240 / 0.5)"
        }`,
        borderRadius: 12,
        overflow: "visible",
        boxShadow: selected
          ? `0 0 0 2px ${color}60`
          : hasProgs
            ? `0 0 10px ${color}15`
            : undefined,
        cursor: "default",
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />

      <div
        style={{
          background: `${color}15`,
          borderBottom: `1px solid ${color}30`,
          padding: "6px 10px",
          display: "flex",
          alignItems: "center",
          gap: 6,
          borderRadius: "10px 10px 0 0",
        }}
      >
        <span style={{ fontSize: 12 }}>{isSockmap ? "🗺" : "🔌"}</span>
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            fontFamily: "monospace",
            color,
          }}
        >
          {name}
        </span>
        {hasProgs && (
          <span
            style={{
              marginLeft: "auto",
              fontSize: 9,
              fontFamily: "monospace",
              color: `${color}cc`,
            }}
          >
            {allPrograms.length} prog{allPrograms.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {lod !== "minimal" && (
        <div
          style={{
            padding: "8px 8px 6px",
            display: "flex",
            flexDirection: "column",
            gap: 0,
          }}
        >
          {visibleLayers.map((layer, idx) => {
            const progs = layers[layer.key] ?? [];
            const active = progs.length > 0;
            const isLast = idx === visibleLayers.length - 1;
            const nextProgs = isLast
              ? []
              : (layers[visibleLayers[idx + 1].key] ?? []);

            if (!active && lod !== "full") {
              return null;
            }

            return (
              <React.Fragment key={layer.key}>
                <div
                  style={{
                    background: active
                      ? `${layer.color}14`
                      : "oklch(0.12 0.01 240 / 0.6)",
                    border: `1px solid ${
                      active ? `${layer.color}40` : "oklch(0.18 0.01 240 / 0.5)"
                    }`,
                    borderRadius: 7,
                    padding: "4px 7px",
                    display: "flex",
                    flexDirection: "column",
                    gap: 3,
                    transition: "background 0.2s, border-color 0.2s",
                    boxShadow: active
                      ? `inset 0 0 0 1px ${layer.color}10`
                      : undefined,
                  }}
                >
                  <div
                    style={{ display: "flex", alignItems: "center", gap: 5 }}
                  >
                    <span style={{ fontSize: 10 }}>{layer.icon}</span>
                    <span
                      style={{
                        fontSize: 9,
                        fontWeight: 700,
                        fontFamily: "monospace",
                        color: active ? layer.color : "oklch(0.38 0.01 240)",
                        flex: 1,
                      }}
                    >
                      {lod === "full" ? layer.label : layer.shortLabel}
                    </span>
                    {active && (
                      <span
                        style={{
                          fontSize: 8,
                          fontFamily: "monospace",
                          color: `${layer.color}99`,
                          background: `${layer.color}12`,
                          border: `1px solid ${layer.color}25`,
                          borderRadius: 3,
                          padding: "0 4px",
                        }}
                      >
                        {progs.length}
                      </span>
                    )}
                  </div>

                  {lod === "full" && !active && (
                    <div
                      style={{
                        fontSize: 8,
                        color: "oklch(0.32 0.01 240)",
                        fontFamily: "monospace",
                        lineHeight: 1.3,
                      }}
                    >
                      {layer.description}
                    </div>
                  )}

                  {active && (
                    <div
                      style={{
                        display: "flex",
                        flexWrap: "wrap",
                        gap: 3,
                        paddingTop: 1,
                      }}
                    >
                      {progs.slice(0, lod === "full" ? 6 : 3).map(p => (
                        <ProgBadge key={p.id} prog={p} color={layer.color} />
                      ))}
                      {progs.length > (lod === "full" ? 6 : 3) && (
                        <span
                          style={{
                            fontSize: 8,
                            fontFamily: "monospace",
                            color: "oklch(0.45 0.01 240)",
                            alignSelf: "center",
                          }}
                        >
                          +{progs.length - (lod === "full" ? 6 : 3)}
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {!isLast &&
                  (active || nextProgs.length > 0 || lod === "full") && (
                    <FlowArrow
                      color={layer.color}
                      active={active || nextProgs.length > 0}
                    />
                  )}
              </React.Fragment>
            );
          })}

          {!isSockmap && (
            <FlowArrow color="#00d4ff" active={(layers.L2 ?? []).length > 0} />
          )}
          {!isSockmap && <NicHardwareBase name={name} color={color} />}
        </div>
      )}

      {lod === "minimal" && (
        <div
          style={{
            padding: "4px 10px",
            fontSize: 9,
            fontFamily: "monospace",
            color: "oklch(0.5 0.01 240)",
          }}
        >
          {allPrograms.length} programs
        </div>
      )}
    </div>
  );
}
