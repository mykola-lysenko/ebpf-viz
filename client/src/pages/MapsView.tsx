import { useEffect, useMemo, useState } from "react";
import { trpc } from "@/lib/trpc";
import { useEbpf } from "@/contexts/EbpfContext";
import { MAP_TYPE_META } from "../../../shared/ebpf-types";
import type { BpfMap } from "../../../shared/ebpf-types";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { MapEntriesModal } from "@/components/MapEntriesModal";
import { cn } from "@/lib/utils";
import {
  Database,
  Zap,
  GitBranch,
  Network,
  HelpCircle,
  Search,
  Pin,
  Lock,
  Copy,
  X,
  Share2,
  List,
  ArrowDownWideNarrow,
} from "lucide-react";

// ─── Helpers ───────────────────────────────────────────────────────────────

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  data: <Database className="w-4 h-4" />,
  event: <Zap className="w-4 h-4" />,
  control: <GitBranch className="w-4 h-4" />,
  socket: <Network className="w-4 h-4" />,
  other: <HelpCircle className="w-4 h-4" />,
};

const CATEGORY_LABELS: Record<string, string> = {
  data: "Data",
  event: "Event",
  control: "Control",
  socket: "Socket",
  other: "Other",
};

// Map types that cannot be dumped (kernel-internal or write-only)
const UNSUPPORTED_DUMP_TYPES = new Set([
  "perf_event_array",
  "ringbuf",
  "user_ringbuf",
  "cgroup_array",
  "devmap",
  "devmap_hash",
  "cpumap",
  "xskmap",
  "sockmap",
  "sockhash",
  "reuseport_sockarray",
]);

const MAP_COUNT_PREFETCH_LIMIT = 24;
const MAP_COUNT_CACHE_TTL_MS = 5 * 60_000;
type EntryCountCacheValue = { count: number | null; updatedAt: number };
type MapSortMode = "default" | "most-shared";
type MapProgramInfo = {
  id: number;
  name: string;
  color: string;
  rawType: string;
  type: string;
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatEntries(n: number): string {
  if (n === 0) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return String(n);
}

function sharedUserCount(map: BpfMap): number {
  return map.usedByProgIds.length;
}

function isSharedMap(map: BpfMap): boolean {
  return sharedUserCount(map) > 1;
}

function programTypeSummary(programs: MapProgramInfo[]): string {
  const types = Array.from(new Set(programs.map(program => program.rawType)))
    .sort()
    .slice(0, 3);
  if (types.length === 0) return "program type unavailable";
  const extra =
    new Set(programs.map(program => program.rawType)).size - types.length;
  return extra > 0 ? `${types.join(", ")} +${extra}` : types.join(", ");
}

function SharedMapBadge({
  map,
  programs,
}: {
  map: BpfMap;
  programs: MapProgramInfo[];
}) {
  const visiblePrograms = programs.slice(0, 8);
  const unknownCount = Math.max(0, map.usedByProgIds.length - programs.length);

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={event => event.stopPropagation()}
          className="inline-flex items-center gap-1 rounded-full border border-amber-500/45 bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-amber-300 shadow-sm shadow-amber-500/10 transition-colors hover:bg-amber-500/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300/50"
        >
          <Share2 className="h-2.5 w-2.5" />
          shared by {sharedUserCount(map)}
        </button>
      </TooltipTrigger>
      <TooltipContent side="left" className="max-w-80 text-left">
        <div className="space-y-2">
          <div>
            <div className="font-semibold">Shared map hotspot</div>
            <div className="text-[11px] opacity-80">
              Referenced by {sharedUserCount(map)} BPF programs. Shared maps
              often carry policy, state, counters, or tail-call routing between
              programs.
            </div>
          </div>
          <div className="space-y-1">
            {visiblePrograms.map(program => (
              <div
                key={program.id}
                className="flex min-w-0 items-center gap-2 rounded bg-background/20 px-1.5 py-1"
              >
                <span
                  className="h-2 w-2 shrink-0 rounded-full"
                  style={{ backgroundColor: program.color }}
                />
                <span className="min-w-0 flex-1 truncate font-mono text-[11px]">
                  {program.name}
                </span>
                <span className="shrink-0 text-[10px] opacity-70">
                  {program.rawType} #{program.id}
                </span>
              </div>
            ))}
            {programs.length > visiblePrograms.length && (
              <div className="text-[11px] opacity-70">
                +{programs.length - visiblePrograms.length} more program
                {programs.length - visiblePrograms.length === 1 ? "" : "s"}
              </div>
            )}
            {unknownCount > 0 && (
              <div className="text-[11px] opacity-70">
                +{unknownCount} referenced program
                {unknownCount === 1 ? "" : "s"} not present in this snapshot
              </div>
            )}
          </div>
        </div>
      </TooltipContent>
    </Tooltip>
  );
}

// ─── Map Card ──────────────────────────────────────────────────────────────

function MapCard({
  map,
  programs,
  selected,
  onClick,
  onDumpEntries,
  entryCount,
  isSnapshotMode,
  hasDumpData,
}: {
  map: BpfMap;
  programs: MapProgramInfo[];
  selected: boolean;
  onClick: () => void;
  onDumpEntries: (e: React.MouseEvent) => void;
  entryCount: number | null | undefined; // null = unsupported, undefined = loading
  isSnapshotMode?: boolean;
  hasDumpData?: boolean;
}) {
  const meta = MAP_TYPE_META[map.type] ?? MAP_TYPE_META["unknown"]!;
  const isShared = isSharedMap(map);
  const canDump =
    !UNSUPPORTED_DUMP_TYPES.has(map.rawType) &&
    (!isSnapshotMode || hasDumpData);

  return (
    <div
      onClick={onClick}
      className={`
        relative rounded-xl border cursor-pointer transition-all duration-200 p-4
        ${
          selected
            ? "border-[var(--accent)] bg-[var(--accent)]/10 shadow-lg shadow-[var(--accent)]/20"
            : isShared
              ? "border-amber-500/25 bg-amber-500/[0.06] shadow-sm shadow-amber-500/10 hover:bg-amber-500/[0.09] hover:border-amber-400/40"
              : "border-white/10 bg-white/5 hover:bg-white/8 hover:border-white/20"
        }
      `}
    >
      {/* Shared badge */}
      {isShared && (
        <div className="absolute top-3 right-3">
          <SharedMapBadge map={map} programs={programs} />
        </div>
      )}

      {/* Header */}
      <div className="flex items-start gap-3 mb-3">
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{
            backgroundColor: `${meta.color}22`,
            border: `1px solid ${meta.color}55`,
          }}
        >
          <div style={{ color: meta.color }}>
            {CATEGORY_ICONS[map.category]}
          </div>
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-mono text-sm font-semibold text-white truncate pr-24">
            {map.name}
          </div>
          <div className="text-xs mt-0.5" style={{ color: meta.color }}>
            {map.rawType}
          </div>
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-2 mb-3">
        <div className="bg-black/30 rounded-lg p-2 text-center">
          <div className="text-[10px] text-white/40 uppercase tracking-wide mb-0.5">
            Key
          </div>
          <div className="text-xs font-mono text-white/80">{map.bytesKey}B</div>
        </div>
        <div className="bg-black/30 rounded-lg p-2 text-center">
          <div className="text-[10px] text-white/40 uppercase tracking-wide mb-0.5">
            Value
          </div>
          <div className="text-xs font-mono text-white/80">
            {map.bytesValue}B
          </div>
        </div>
        <div className="bg-black/30 rounded-lg p-2 text-center">
          <div className="text-[10px] text-white/40 uppercase tracking-wide mb-0.5">
            Entries
          </div>
          {entryCount !== undefined ? (
            <div className="flex flex-col items-center gap-0.5">
              <div className="text-xs font-mono text-white/80">
                {entryCount === null ? "—" : formatEntries(entryCount)}
              </div>
              {entryCount !== null && (
                <div className="text-[9px] text-cyan-400/60 font-mono">
                  live
                </div>
              )}
            </div>
          ) : (
            <div className="text-xs font-mono text-white/30">
              {formatEntries(map.maxEntries)}
            </div>
          )}
        </div>
      </div>

      {/* Flags row */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <span className="text-[10px] text-white/30 font-mono">
          {formatBytes(map.bytesMemlock)} locked
        </span>
        {map.frozen && (
          <div className="flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-blue-500/20 border border-blue-500/30">
            <Lock className="w-2.5 h-2.5 text-blue-400" />
            <span className="text-[10px] text-blue-400">frozen</span>
          </div>
        )}
        {map.pinnedPaths.length > 0 && (
          <div className="flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-green-500/20 border border-green-500/30">
            <Pin className="w-2.5 h-2.5 text-green-400" />
            <span className="text-[10px] text-green-400">pinned</span>
          </div>
        )}
        {map.btfId !== undefined && (
          <div className="px-1.5 py-0.5 rounded-full bg-purple-500/20 border border-purple-500/30">
            <span className="text-[10px] text-purple-400">BTF</span>
          </div>
        )}
      </div>

      {/* Programs using this map */}
      {programs.length > 0 ? (
        <div className="flex flex-wrap gap-1 mb-3">
          {programs.slice(0, 3).map(p => (
            <div
              key={p.id}
              className="flex items-center gap-1 px-1.5 py-0.5 rounded-md text-[10px] font-mono"
              style={{
                backgroundColor: `${p.color}22`,
                border: `1px solid ${p.color}44`,
                color: p.color,
              }}
            >
              {p.name}
            </div>
          ))}
          {programs.length > 3 && (
            <div className="px-1.5 py-0.5 rounded-md text-[10px] text-white/40 bg-white/5 border border-white/10">
              +{programs.length - 3} more
            </div>
          )}
        </div>
      ) : (
        <div className="text-[10px] text-white/20 italic mb-3">
          No programs attached
        </div>
      )}

      {/* Dump Entries button */}
      {canDump && (
        <button
          onClick={onDumpEntries}
          className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-medium transition-all
            bg-cyan-500/15 border border-cyan-500/40 text-cyan-300
            hover:bg-cyan-500/25 hover:border-cyan-400/60 hover:text-cyan-200"
        >
          <List className="w-3 h-3" />
          Dump Entries
        </button>
      )}
      {!canDump && (
        <div
          className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs
          bg-white/3 border border-white/5 text-white/20 cursor-default"
          title={
            isSnapshotMode && !hasDumpData
              ? "Load a map dump file to inspect entries in snapshot mode"
              : `${map.rawType} maps cannot be enumerated`
          }
        >
          <List className="w-3 h-3" />
          {isSnapshotMode && !hasDumpData ? "Load map dumps" : "Not dumpable"}
        </div>
      )}

      {/* Map ID */}
      <div className="absolute bottom-3 right-3 text-[10px] font-mono text-white/20">
        #{map.id}
      </div>
    </div>
  );
}

// ─── Map Detail Panel ──────────────────────────────────────────────────────

function MapDetailPanel({
  map,
  programs,
  onClose,
  onDumpEntries,
  isSnapshotMode,
  hasDumpData,
}: {
  map: BpfMap;
  programs: MapProgramInfo[];
  onClose: () => void;
  onDumpEntries: () => void;
  isSnapshotMode?: boolean;
  hasDumpData?: boolean;
}) {
  const meta = MAP_TYPE_META[map.type] ?? MAP_TYPE_META["unknown"]!;
  const [copied, setCopied] = useState<string | null>(null);
  const canDump =
    !UNSUPPORTED_DUMP_TYPES.has(map.rawType) &&
    (!isSnapshotMode || hasDumpData);
  const isShared = isSharedMap(map);

  const copy = (text: string, key: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    });
  };

  return (
    <div className="fixed right-0 top-0 h-full w-96 bg-[#0d1117] border-l border-white/10 z-50 flex flex-col shadow-2xl">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{
              backgroundColor: `${meta.color}22`,
              border: `1px solid ${meta.color}55`,
            }}
          >
            <div style={{ color: meta.color }}>
              {CATEGORY_ICONS[map.category]}
            </div>
          </div>
          <div>
            <div className="font-mono text-sm font-semibold text-white">
              {map.name}
            </div>
            <div className="text-xs" style={{ color: meta.color }}>
              {map.rawType}
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg hover:bg-white/10 text-white/40 hover:text-white transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Description */}
        <div className="bg-white/5 rounded-xl p-3 border border-white/10">
          <div className="text-xs text-white/50 mb-1">Description</div>
          <div className="text-sm text-white/80">{meta.description}</div>
        </div>

        {/* Shared hotspot */}
        {isShared && (
          <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 p-3">
            <div className="mb-1 flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-amber-300">
              <Share2 className="h-3.5 w-3.5" />
              Shared Map Hotspot
            </div>
            <div className="text-sm text-white/80">
              Shared by {sharedUserCount(map)} programs
              {programs.length > 0 && ` across ${programTypeSummary(programs)}`}
              .
            </div>
            <div className="mt-1 text-xs text-white/45">
              This map is likely coordinating state, policy, counters, or
              tail-call control flow between multiple BPF programs.
            </div>
          </div>
        )}

        {/* Dump Entries CTA */}
        <button
          onClick={onDumpEntries}
          disabled={!canDump}
          className={`
            w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-medium transition-all
            ${
              canDump
                ? "bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/25 hover:border-cyan-400/60 hover:text-cyan-200"
                : "bg-white/5 border border-white/10 text-white/25 cursor-not-allowed"
            }
          `}
          title={
            !canDump
              ? isSnapshotMode && !hasDumpData
                ? "Load a map dump file to inspect entries"
                : `${map.rawType} maps cannot be enumerated`
              : undefined
          }
        >
          <List className="w-4 h-4" />
          {canDump
            ? "Inspect Map Entries"
            : isSnapshotMode && !hasDumpData
              ? "Load map dumps to inspect"
              : "Entries not available"}
        </button>

        {/* Identity */}
        <div className="space-y-2">
          <div className="text-xs text-white/30 uppercase tracking-wider">
            Identity
          </div>
          {[
            { label: "Map ID", value: String(map.id) },
            { label: "Type", value: map.rawType },
            {
              label: "Category",
              value: CATEGORY_LABELS[map.category] ?? map.category,
            },
            {
              label: "Flags",
              value: `0x${map.flags.toString(16).padStart(4, "0")}`,
            },
            ...(map.btfId !== undefined
              ? [{ label: "BTF ID", value: String(map.btfId) }]
              : []),
          ].map(({ label, value }) => (
            <div
              key={label}
              className="flex items-center justify-between py-1.5 border-b border-white/5"
            >
              <span className="text-xs text-white/40">{label}</span>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-white/80">{value}</span>
                <button
                  onClick={() => copy(value, label)}
                  className="p-0.5 rounded hover:bg-white/10 text-white/20 hover:text-white/60 transition-colors"
                >
                  {copied === label ? (
                    <span className="text-[10px] text-green-400">✓</span>
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Schema */}
        <div className="space-y-2">
          <div className="text-xs text-white/30 uppercase tracking-wider">
            Schema
          </div>
          <div className="grid grid-cols-3 gap-2">
            {[
              { label: "Key Size", value: `${map.bytesKey} bytes` },
              { label: "Value Size", value: `${map.bytesValue} bytes` },
              { label: "Max Entries", value: formatEntries(map.maxEntries) },
            ].map(({ label, value }) => (
              <div
                key={label}
                className="bg-black/30 rounded-lg p-2.5 text-center border border-white/5"
              >
                <div className="text-[10px] text-white/30 mb-1">{label}</div>
                <div className="text-sm font-mono text-white/80">{value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Memory */}
        <div className="space-y-2">
          <div className="text-xs text-white/30 uppercase tracking-wider">
            Memory
          </div>
          <div className="bg-black/30 rounded-xl p-3 border border-white/5">
            <div className="flex items-center justify-between">
              <span className="text-xs text-white/40">Locked memory</span>
              <span className="text-xs font-mono text-white/80">
                {formatBytes(map.bytesMemlock)}
              </span>
            </div>
            {map.frozen && (
              <div className="flex items-center gap-2 mt-2 pt-2 border-t border-white/5">
                <Lock className="w-3 h-3 text-blue-400" />
                <span className="text-xs text-blue-400">
                  Map is frozen (read-only)
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Pinned paths */}
        {map.pinnedPaths.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs text-white/30 uppercase tracking-wider">
              Pinned Paths
            </div>
            {map.pinnedPaths.map(path => (
              <div
                key={path}
                className="flex items-center gap-2 bg-green-500/10 rounded-lg p-2.5 border border-green-500/20"
              >
                <Pin className="w-3 h-3 text-green-400 flex-shrink-0" />
                <span className="text-xs font-mono text-green-300 truncate">
                  {path}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* Programs using this map */}
        <div className="space-y-2">
          <div className="text-xs text-white/30 uppercase tracking-wider">
            Used by {programs.length} program{programs.length !== 1 ? "s" : ""}
          </div>
          {programs.length === 0 ? (
            <div className="text-xs text-white/20 italic bg-white/3 rounded-lg p-3 border border-white/5">
              No programs reference this map
            </div>
          ) : (
            <div className="space-y-1.5">
              {programs.map(p => (
                <div
                  key={p.id}
                  className="flex items-center gap-2.5 rounded-lg p-2.5 border"
                  style={{
                    backgroundColor: `${p.color}11`,
                    borderColor: `${p.color}33`,
                  }}
                >
                  <div
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ backgroundColor: p.color }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-mono text-white/80 truncate">
                      {p.name}
                    </div>
                    <div className="text-[10px]" style={{ color: p.color }}>
                      {p.rawType}
                    </div>
                  </div>
                  <div className="text-[10px] font-mono text-white/30">
                    #{p.id}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────

export default function MapsView() {
  const { snapshot, maps, appMode, snapshotMapDumps } = useEbpf();
  // Maps are delivered live via the SSE stream (EbpfContext.maps).
  // In snapshot mode, maps come from the loaded snapshot file.

  const [search, setSearch] = useState("");
  const [category, setCategory] = useState<string>("all");
  const [sharedOnly, setSharedOnly] = useState(false);
  const [sortMode, setSortMode] = useState<MapSortMode>("default");
  const [selectedMap, setSelectedMap] = useState<BpfMap | null>(null);
  const [dumpMap, setDumpMap] = useState<BpfMap | null>(null);
  const [entryCountCache, setEntryCountCache] = useState<
    Map<number, EntryCountCacheValue>
  >(() => new Map());

  // Build a quick lookup of program info by id
  const progById = useMemo(() => {
    const m = new Map<number, MapProgramInfo>();
    if (snapshot) {
      for (const p of snapshot.programs) {
        m.set(p.id, {
          id: p.id,
          name: p.name,
          color: p.color,
          rawType: p.rawType,
          type: p.type,
        });
      }
    }
    return m;
  }, [snapshot]);

  // Category counts
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: maps.length };
    for (const m of maps) {
      counts[m.category] = (counts[m.category] ?? 0) + 1;
    }
    return counts;
  }, [maps]);

  // Filtered maps
  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    const matches = maps.filter(m => {
      if (category !== "all" && m.category !== category) return false;
      if (sharedOnly && !isSharedMap(m)) return false;
      if (
        q &&
        !m.name.toLowerCase().includes(q) &&
        !m.rawType.toLowerCase().includes(q)
      )
        return false;
      return true;
    });

    if (sortMode === "most-shared") {
      return matches.slice().sort((a, b) => {
        const sharedDelta = sharedUserCount(b) - sharedUserCount(a);
        if (sharedDelta !== 0) return sharedDelta;
        return a.name.localeCompare(b.name);
      });
    }

    return matches;
  }, [maps, search, category, sharedOnly, sortMode]);

  const countRequestIds = useMemo(() => {
    if (appMode === "snapshot") return [];

    const ids = new Set<number>();
    const now = Date.now();
    const isFresh = (mapId: number) => {
      const cached = entryCountCache.get(mapId);
      return (
        cached !== undefined && now - cached.updatedAt < MAP_COUNT_CACHE_TTL_MS
      );
    };

    for (const map of filtered) {
      if (ids.size >= MAP_COUNT_PREFETCH_LIMIT) break;
      if (UNSUPPORTED_DUMP_TYPES.has(map.rawType)) continue;
      if (!isFresh(map.id)) ids.add(map.id);
    }

    if (
      selectedMap &&
      !UNSUPPORTED_DUMP_TYPES.has(selectedMap.rawType) &&
      !isFresh(selectedMap.id)
    ) {
      ids.add(selectedMap.id);
    }

    return Array.from(ids);
  }, [appMode, entryCountCache, filtered, selectedMap]);

  const { data: entryCounts } = trpc.ebpf.mapEntryCounts.useQuery(
    { ids: countRequestIds },
    {
      enabled: countRequestIds.length > 0,
      staleTime: 5 * 60_000,
      refetchOnWindowFocus: false,
    }
  );

  useEffect(() => {
    if (!entryCounts?.length) return;
    setEntryCountCache(prev => {
      const next = new Map(prev);
      const updatedAt = Date.now();
      for (const { mapId, count } of entryCounts)
        next.set(mapId, { count, updatedAt });
      return next;
    });
  }, [entryCounts]);

  useEffect(() => {
    const liveMapIds = new Set(maps.map(map => map.id));
    setEntryCountCache(prev => {
      let changed = false;
      const next = new Map<number, EntryCountCacheValue>();
      for (const [mapId, value] of Array.from(prev.entries())) {
        if (liveMapIds.has(mapId)) next.set(mapId, value);
        else changed = true;
      }
      return changed ? next : prev;
    });
  }, [maps]);

  // Stats
  const totalMemlock = useMemo(
    () => maps.reduce((s, m) => s + m.bytesMemlock, 0),
    [maps]
  );
  const sharedCount = useMemo(
    () => maps.filter(m => m.usedByProgIds.length > 1).length,
    [maps]
  );
  const pinnedCount = useMemo(
    () => maps.filter(m => m.pinnedPaths.length > 0).length,
    [maps]
  );

  const selectedPrograms = useMemo(() => {
    if (!selectedMap) return [];
    return selectedMap.usedByProgIds
      .map(id => progById.get(id))
      .filter((p): p is NonNullable<typeof p> => p !== undefined);
  }, [selectedMap, progById]);

  const meta = dumpMap
    ? (MAP_TYPE_META[dumpMap.type] ?? MAP_TYPE_META["unknown"]!)
    : null;

  return (
    <div className="flex h-full">
      {/* Main content */}
      <div
        className={`flex-1 flex flex-col overflow-hidden transition-all duration-300 ${selectedMap ? "mr-96" : ""}`}
      >
        {/* Header */}
        <div className="px-6 pt-6 pb-4 border-b border-white/10 flex-shrink-0">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-xl font-semibold text-white flex items-center gap-2">
                <Database className="w-5 h-5 text-[var(--accent)]" />
                BPF Maps
              </h1>
              <p className="text-sm text-white/40 mt-0.5">
                {maps.length} maps · {formatBytes(totalMemlock)} locked ·{" "}
                {sharedCount} shared · {pinnedCount} pinned
              </p>
            </div>
          </div>

          {/* Summary stat cards */}
          <div className="grid grid-cols-5 gap-3 mb-4">
            {[
              { label: "Total Maps", value: maps.length, color: "#00d4ff" },
              {
                label: "Shared",
                value: sharedCount,
                color: "#f59e0b",
                desc: "used by 2+ progs",
              },
              {
                label: "Pinned",
                value: pinnedCount,
                color: "#10b981",
                desc: "on bpffs",
              },
              {
                label: "With BTF",
                value: maps.filter(m => m.btfId !== undefined).length,
                color: "#8b5cf6",
              },
              {
                label: "Locked Mem",
                value: formatBytes(totalMemlock),
                color: "#ec4899",
              },
            ].map(({ label, value, color }) => (
              <div
                key={label}
                className="bg-white/5 rounded-xl p-3 border border-white/10"
              >
                <div className="text-[10px] text-white/40 uppercase tracking-wider mb-1">
                  {label}
                </div>
                <div className="text-lg font-bold font-mono" style={{ color }}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* Search + category filter */}
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
              <Input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search maps..."
                className="pl-9 h-8 text-sm bg-white/5 border-white/10 text-white placeholder:text-white/30 focus:border-[var(--accent)]/50"
              />
            </div>
            <Tabs value={category} onValueChange={setCategory}>
              <TabsList className="bg-white/5 border border-white/10 h-8">
                <TabsTrigger
                  value="all"
                  className="text-xs h-6 px-2.5 data-[state=active]:bg-[var(--accent)]/20 data-[state=active]:text-[var(--accent)]"
                >
                  All ({categoryCounts.all ?? 0})
                </TabsTrigger>
                {["data", "event", "control", "socket", "other"].map(cat =>
                  categoryCounts[cat] ? (
                    <TabsTrigger
                      key={cat}
                      value={cat}
                      className="text-xs h-6 px-2.5 data-[state=active]:bg-[var(--accent)]/20 data-[state=active]:text-[var(--accent)]"
                    >
                      {CATEGORY_LABELS[cat]} ({categoryCounts[cat]})
                    </TabsTrigger>
                  ) : null
                )}
              </TabsList>
            </Tabs>
            <button
              type="button"
              onClick={() => setSharedOnly(value => !value)}
              className={cn(
                "inline-flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-xs transition-colors",
                sharedOnly
                  ? "border-amber-500/45 bg-amber-500/15 text-amber-300"
                  : "border-white/10 bg-white/5 text-white/45 hover:border-amber-500/35 hover:text-amber-300"
              )}
              title="Show only maps referenced by more than one BPF program."
            >
              <Share2 className="h-3.5 w-3.5" />
              Shared only ({sharedCount})
            </button>
            <button
              type="button"
              onClick={() =>
                setSortMode(mode =>
                  mode === "most-shared" ? "default" : "most-shared"
                )
              }
              className={cn(
                "inline-flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-xs transition-colors",
                sortMode === "most-shared"
                  ? "border-cyan-500/45 bg-cyan-500/15 text-cyan-300"
                  : "border-white/10 bg-white/5 text-white/45 hover:border-cyan-500/35 hover:text-cyan-300"
              )}
              title="Sort maps by how many programs reference them."
            >
              <ArrowDownWideNarrow className="h-3.5 w-3.5" />
              Most shared
            </button>
          </div>
        </div>

        {/* Map grid */}
        <div className="flex-1 overflow-y-auto p-6">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-white/30">
              <Database className="w-12 h-12 mb-3 opacity-30" />
              <div className="text-sm">
                {maps.length === 0
                  ? "No BPF maps detected — programs on this system may not use maps"
                  : "No maps match the current filter"}
              </div>
              {maps.length === 0 && (
                <div className="text-xs mt-2 text-white/20">
                  Switch to Demo Mode in Settings to see example maps
                </div>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
              {filtered.map(map => (
                <MapCard
                  key={map.id}
                  map={map}
                  programs={map.usedByProgIds
                    .map(id => progById.get(id))
                    .filter((p): p is NonNullable<typeof p> => p !== undefined)}
                  selected={selectedMap?.id === map.id}
                  onClick={() =>
                    setSelectedMap(prev => (prev?.id === map.id ? null : map))
                  }
                  onDumpEntries={e => {
                    e.stopPropagation();
                    setDumpMap(map);
                  }}
                  entryCount={entryCountCache.get(map.id)?.count}
                  isSnapshotMode={appMode === "snapshot"}
                  hasDumpData={
                    appMode === "snapshot" && !!snapshotMapDumps[map.id]
                  }
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Detail panel */}
      {selectedMap && (
        <MapDetailPanel
          map={selectedMap}
          programs={selectedPrograms}
          onClose={() => setSelectedMap(null)}
          onDumpEntries={() => setDumpMap(selectedMap)}
          isSnapshotMode={appMode === "snapshot"}
          hasDumpData={
            appMode === "snapshot" && !!snapshotMapDumps[selectedMap.id]
          }
        />
      )}

      {/* Map Entries Modal */}
      {dumpMap && meta && (
        <MapEntriesModal
          mapId={dumpMap.id}
          mapName={dumpMap.name}
          mapType={dumpMap.rawType}
          mapColor={meta.color}
          keyBytes={dumpMap.bytesKey}
          valueBytes={dumpMap.bytesValue}
          onClose={() => setDumpMap(null)}
          snapshotDump={
            appMode === "snapshot" ? snapshotMapDumps[dumpMap.id] : undefined
          }
        />
      )}
    </div>
  );
}
