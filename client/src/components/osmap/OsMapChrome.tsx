import { useState } from "react";
import { useReactFlow } from "@xyflow/react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Download,
  Eye,
  EyeOff,
  Info,
  Layers,
  Map as MapIcon,
  Maximize2,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react";

export const OS_MAP_FLOW_STYLES = `
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

function LodIndicator({ zoom }: { zoom: number }) {
  const level =
    zoom <= 0.45 ? "Bird's Eye" : zoom < 0.65 ? "Overview" : "Detail";
  const color = zoom <= 0.45 ? "#f59e0b" : zoom < 0.65 ? "#10b981" : "#00d4ff";
  return (
    <div
      style={{
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
      }}
    >
      <Layers size={10} />
      {level} · {(zoom * 100).toFixed(0)}%
    </div>
  );
}

export function MapToolbar({
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
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "6px 10px",
        background: "oklch(0.11 0.015 240 / 0.95)",
        border: "1px solid oklch(0.22 0.015 240)",
        borderRadius: 12,
        backdropFilter: "blur(8px)",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 4,
          marginRight: 4,
        }}
      >
        <MapIcon size={14} style={{ color: "#00d4ff" }} />
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            color: "#00d4ff",
            fontFamily: "monospace",
          }}
        >
          OS Map
        </span>
      </div>

      <div
        style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }}
      />

      <LodIndicator zoom={zoom} />

      <div
        style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }}
      />

      <span
        style={{
          fontSize: 10,
          fontFamily: "monospace",
          color: "oklch(0.55 0.01 240)",
        }}
      >
        {progCount} programs · {nodeCount} nodes
      </span>

      {focusedProcess && (
        <>
          <div
            style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }}
          />
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "3px 8px 3px 10px",
              background: "#f59e0b18",
              border: "1px solid #f59e0b40",
              borderRadius: 6,
            }}
          >
            <Eye size={10} style={{ color: "#f59e0b" }} />
            <span
              style={{
                fontSize: 10,
                fontFamily: "monospace",
                color: "#f59e0b",
                whiteSpace: "nowrap",
              }}
            >
              {focusedProcess.comm}
              <span style={{ color: "#f59e0b80", marginLeft: 4 }}>
                pid {focusedProcess.pid}
              </span>
            </span>
            <button
              onClick={onClearFocus}
              title="Exit focus mode"
              style={{
                width: 16,
                height: 16,
                borderRadius: 4,
                background: "#f59e0b20",
                border: "1px solid #f59e0b40",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                cursor: "pointer",
                color: "#f59e0b",
                padding: 0,
              }}
            >
              <X size={9} />
            </button>
          </div>
        </>
      )}

      <div
        style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }}
      />

      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={() => zoomIn({ duration: 300 })}
            style={{
              width: 28,
              height: 28,
              borderRadius: 6,
              background: "oklch(0.16 0.015 240)",
              border: "1px solid oklch(0.25 0.015 240)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              color: "oklch(0.7 0.01 240)",
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
              width: 28,
              height: 28,
              borderRadius: 6,
              background: "oklch(0.16 0.015 240)",
              border: "1px solid oklch(0.25 0.015 240)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              color: "oklch(0.7 0.01 240)",
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
              width: 28,
              height: 28,
              borderRadius: 6,
              background: "oklch(0.16 0.015 240)",
              border: "1px solid oklch(0.25 0.015 240)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              color: "oklch(0.7 0.01 240)",
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
              width: 28,
              height: 28,
              borderRadius: 6,
              background: showLabels
                ? "oklch(0.16 0.015 240 / 0.8)"
                : "oklch(0.14 0.015 240)",
              border: `1px solid ${showLabels ? "#00d4ff40" : "oklch(0.25 0.015 240)"}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              color: showLabels ? "#00d4ff" : "oklch(0.5 0.01 240)",
            }}
          >
            {showLabels ? <Eye size={13} /> : <EyeOff size={13} />}
          </button>
        </TooltipTrigger>
        <TooltipContent>
          {showLabels ? "Hide labels" : "Show labels"}
        </TooltipContent>
      </Tooltip>

      {maxTreeDepth > 0 && (
        <>
          <div
            style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }}
          />
          <Tooltip>
            <TooltipTrigger asChild>
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span
                  style={{
                    fontSize: 10,
                    fontFamily: "monospace",
                    color: "oklch(0.55 0.01 240)",
                    whiteSpace: "nowrap",
                  }}
                >
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
                <span
                  style={{
                    fontSize: 10,
                    fontFamily: "monospace",
                    color:
                      maxCgroupDepth !== undefined
                        ? "#3b82f6"
                        : "oklch(0.55 0.01 240)",
                    minWidth: 14,
                    textAlign: "right",
                  }}
                >
                  {maxCgroupDepth ?? maxTreeDepth}
                </span>
                {maxCgroupDepth !== undefined && (
                  <button
                    onClick={() => onMaxCgroupDepthChange(undefined)}
                    title="Show all depths"
                    style={{
                      width: 16,
                      height: 16,
                      borderRadius: 4,
                      background: "#3b82f620",
                      border: "1px solid #3b82f640",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      cursor: "pointer",
                      color: "#3b82f6",
                      padding: 0,
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

      <div
        style={{ width: 1, height: 16, background: "oklch(0.25 0.01 240)" }}
      />

      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={onDownload}
            style={{
              width: 28,
              height: 28,
              borderRadius: 6,
              background: "oklch(0.16 0.015 240)",
              border: "1px solid oklch(0.25 0.015 240)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              color: "oklch(0.7 0.01 240)",
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

export function MapLegend() {
  const [open, setOpen] = useState(false);
  const items = [
    { color: "#f59e0b", label: "Userspace (processes)" },
    { color: "#00d4ff", label: "Kernel hook zones" },
    { color: "#3b82f6", label: "Cgroup hierarchy" },
    { color: "#10b981", label: "Network interfaces" },
    { color: "#ffffff30", label: "Dashed = ownership edge" },
    { color: "#00d4ff50", label: "Animated = active attachment" },
    { color: "#a78bfa", label: "BPF maps (data/event/control)" },
    { color: "#a78bfa40", label: "Dashed border = aggregated maps" },
    { color: "#a78bfa40", label: "Dashed line = program → map edge" },
  ];

  return (
    <div style={{ position: "relative" }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: 28,
          height: 28,
          borderRadius: 6,
          background: open ? "oklch(0.16 0.015 240)" : "oklch(0.13 0.015 240)",
          border: `1px solid ${open ? "#00d4ff40" : "oklch(0.22 0.015 240)"}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          cursor: "pointer",
          color: open ? "#00d4ff" : "oklch(0.55 0.01 240)",
        }}
      >
        <Info size={13} />
      </button>

      {open && (
        <div
          style={{
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
          }}
        >
          <div
            style={{
              fontSize: 10,
              fontWeight: 700,
              color: "#00d4ff",
              fontFamily: "monospace",
              marginBottom: 8,
              letterSpacing: "0.1em",
            }}
          >
            LEGEND
          </div>
          {items.map(({ color, label }) => (
            <div
              key={label}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                marginBottom: 5,
              }}
            >
              <div
                style={{
                  width: 12,
                  height: 12,
                  borderRadius: 3,
                  background: color,
                  flexShrink: 0,
                }}
              />
              <span
                style={{
                  fontSize: 10,
                  color: "oklch(0.65 0.01 240)",
                  fontFamily: "monospace",
                }}
              >
                {label}
              </span>
            </div>
          ))}
          <div
            style={{
              marginTop: 8,
              paddingTop: 8,
              borderTop: "1px solid oklch(0.18 0.01 240)",
            }}
          >
            <div
              style={{
                fontSize: 9,
                color: "oklch(0.45 0.01 240)",
                fontFamily: "monospace",
                lineHeight: 1.5,
              }}
            >
              Scroll to zoom · Drag to pan
              <br />
              Double-click node to zoom-fit
              <br />
              Click program badge to inspect
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function MapPlaceholder() {
  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 16,
        background: "oklch(0.075 0.012 240)",
      }}
    >
      <div
        style={{
          width: 48,
          height: 48,
          border: "2px solid #00d4ff",
          borderTopColor: "transparent",
          borderRadius: "50%",
          animation: "spin 1s linear infinite",
        }}
      />
      <p
        style={{
          fontSize: 13,
          color: "oklch(0.55 0.01 240)",
          fontFamily: "monospace",
        }}
      >
        Building OS map…
      </p>
    </div>
  );
}
