import { useCallback, useMemo, useRef, useState } from "react";
import { GitCompare, Upload, X, ArrowRight, Plus, Minus, Pencil } from "lucide-react";
import { useEbpf } from "@/contexts/EbpfContext";
import type { EbpfSnapshot, BpfMap } from "../../../shared/ebpf-types";
import { diffSnapshots, type DiffEntry, type SnapshotDiffSection } from "../../../shared/snapshot-diff";
import { cn } from "@/lib/utils";

interface LoadedSide {
  filename: string;
  hostname: string;
  capturedAt: string;
  snapshot: EbpfSnapshot;
  maps: BpfMap[];
}

function DropSlot({
  label,
  side,
  onLoad,
  onClear,
}: {
  label: string;
  side: LoadedSide | null;
  onLoad: (file: File) => void;
  onClear: () => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);

  return (
    <div
      onDragOver={e => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={e => {
        e.preventDefault();
        setDragOver(false);
        const file = e.dataTransfer.files?.[0];
        if (file) onLoad(file);
      }}
      className={cn(
        "rounded-xl border p-4 transition-colors",
        dragOver ? "border-primary bg-primary/5" : "border-border bg-card/40"
      )}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          {label}
        </span>
        {side && (
          <button
            type="button"
            onClick={onClear}
            className="text-muted-foreground hover:text-foreground"
            title="Clear"
          >
            <X size={14} />
          </button>
        )}
      </div>
      {side ? (
        <div className="text-sm">
          <div className="font-mono text-foreground truncate">{side.filename}</div>
          <div className="text-xs text-muted-foreground mt-1">
            {side.hostname} · {side.snapshot.stats.total} programs · {side.maps.length} maps
          </div>
          <div className="text-[11px] text-muted-foreground/70 mt-0.5">{side.capturedAt}</div>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          className="flex w-full flex-col items-center gap-2 py-6 text-muted-foreground hover:text-foreground"
        >
          <Upload size={20} />
          <span className="text-xs">Drop a snapshot JSON here, or click to browse</span>
        </button>
      )}
      <input
        ref={inputRef}
        type="file"
        accept=".json,application/json"
        className="hidden"
        onChange={e => {
          const file = e.target.files?.[0];
          if (file) onLoad(file);
          if (inputRef.current) inputRef.current.value = "";
        }}
      />
    </div>
  );
}

function StatTile({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-lg border border-border bg-card/40 px-3 py-2 text-center">
      <div className={cn("text-lg font-bold tabular-nums", value > 0 ? tone : "text-muted-foreground/50")}>
        {value > 0 ? value : "0"}
      </div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
    </div>
  );
}

function DiffRow({ entry, kind }: { entry: DiffEntry; kind: "added" | "removed" | "changed" }) {
  const icon =
    kind === "added" ? <Plus size={12} /> : kind === "removed" ? <Minus size={12} /> : <Pencil size={12} />;
  const tone =
    kind === "added"
      ? "text-emerald-400 border-emerald-500/25 bg-emerald-500/5"
      : kind === "removed"
        ? "text-rose-400 border-rose-500/25 bg-rose-500/5"
        : "text-amber-300 border-amber-500/25 bg-amber-500/5";
  return (
    <div className={cn("flex flex-wrap items-center gap-2 rounded-lg border px-2.5 py-1.5", tone)}>
      <span className="shrink-0">{icon}</span>
      <span className="font-mono text-xs text-foreground truncate">{entry.name}</span>
      <span className="rounded border border-border/50 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
        {entry.type}
      </span>
      {entry.changes && entry.changes.length > 0 && (
        <span className="text-[11px] text-muted-foreground">{entry.changes.join(" · ")}</span>
      )}
    </div>
  );
}

function DiffSectionBlock({ title, section }: { title: string; section: SnapshotDiffSection }) {
  const total = section.added.length + section.removed.length + section.changed.length;
  if (total === 0) {
    return (
      <div className="glass rounded-xl p-4">
        <h3 className="text-sm font-semibold text-foreground mb-1">{title}</h3>
        <p className="text-xs text-muted-foreground">No differences.</p>
      </div>
    );
  }
  return (
    <div className="glass rounded-xl p-4 space-y-3">
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      {section.added.length > 0 && (
        <div className="space-y-1.5">
          {section.added.map(e => (
            <DiffRow key={`a-${e.key}-${e.id}`} entry={e} kind="added" />
          ))}
        </div>
      )}
      {section.changed.length > 0 && (
        <div className="space-y-1.5">
          {section.changed.map(e => (
            <DiffRow key={`c-${e.key}-${e.id}`} entry={e} kind="changed" />
          ))}
        </div>
      )}
      {section.removed.length > 0 && (
        <div className="space-y-1.5">
          {section.removed.map(e => (
            <DiffRow key={`r-${e.key}-${e.id}`} entry={e} kind="removed" />
          ))}
        </div>
      )}
    </div>
  );
}

export default function DiffView() {
  const { parseSnapshotFile } = useEbpf();
  const [a, setA] = useState<LoadedSide | null>(null);
  const [b, setB] = useState<LoadedSide | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (file: File, set: (s: LoadedSide) => void) => {
      setError(null);
      try {
        const { snapshot, maps, meta } = await parseSnapshotFile(file);
        set({
          filename: meta.filename,
          hostname: meta.hostname,
          capturedAt: meta.capturedAt,
          snapshot,
          maps,
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load snapshot");
      }
    },
    [parseSnapshotFile]
  );

  const diff = useMemo(
    () => (a && b ? diffSnapshots(a.snapshot, b.snapshot, a.maps, b.maps) : null),
    [a, b]
  );

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
          <GitCompare size={20} className="text-primary" />
          Snapshot Diff
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Compare two captured snapshots (from <span className="font-mono">capture-snapshot.sh</span> or
          Download Topology). Programs are matched by name + bytecode; maps by name + type.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_1fr] items-center gap-4">
        <DropSlot label="Baseline (A)" side={a} onLoad={f => load(f, setA)} onClear={() => setA(null)} />
        <ArrowRight className="hidden md:block text-muted-foreground mx-auto" size={20} />
        <DropSlot label="Compare (B)" side={b} onLoad={f => load(f, setB)} onClear={() => setB(null)} />
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive/80">
          {error}
        </div>
      )}

      {!diff && !error && (
        <div className="glass rounded-xl p-8 text-center">
          <GitCompare size={28} className="text-muted-foreground mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">Load two snapshots to see what changed.</p>
        </div>
      )}

      {diff && (
        <>
          {diff.summary.identical ? (
            <div className="glass rounded-xl p-4 text-sm text-emerald-400">
              The two snapshots are identical (no program or map differences).
            </div>
          ) : (
            <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
              <StatTile label="Progs +" value={diff.summary.programsAdded} tone="text-emerald-400" />
              <StatTile label="Progs −" value={diff.summary.programsRemoved} tone="text-rose-400" />
              <StatTile label="Progs ~" value={diff.summary.programsChanged} tone="text-amber-300" />
              <StatTile label="Maps +" value={diff.summary.mapsAdded} tone="text-emerald-400" />
              <StatTile label="Maps −" value={diff.summary.mapsRemoved} tone="text-rose-400" />
              <StatTile label="Maps ~" value={diff.summary.mapsChanged} tone="text-amber-300" />
            </div>
          )}
          <DiffSectionBlock title="Programs" section={diff.programs} />
          {(a!.maps.length > 0 || b!.maps.length > 0) && (
            <DiffSectionBlock title="Maps" section={diff.maps} />
          )}
        </>
      )}
    </div>
  );
}
