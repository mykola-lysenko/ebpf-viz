import { lazy, Suspense, useState, useRef, useCallback } from "react";
import { Link, useLocation } from "wouter";
import {
  Cpu, Network, FolderTree, List, Settings,
  LayoutDashboard, RefreshCw, Wifi, WifiOff,
  ChevronLeft, ChevronRight, Search, X, Map, Database,
  Radio, Upload, FolderOpen, Camera, XCircle, Share2, GitCompare
} from "lucide-react";
import { EbpfProvider, useEbpf } from "@/contexts/EbpfContext";
import type { StreamStatus } from "@/hooks/useEbpfStream";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

const ProgramDetailPanel = lazy(() =>
  import("./ProgramDetailPanel").then(module => ({
    default: module.ProgramDetailPanel,
  }))
);

const NAV_ITEMS = [
  { path: "/",         icon: LayoutDashboard, label: "Dashboard",  },
  { path: "/kernel",   icon: Cpu,             label: "Kernel",     },
  { path: "/network",  icon: Network,         label: "Network",    },
  { path: "/topology", icon: Share2,          label: "Topology",   },
  { path: "/cgroups",  icon: FolderTree,      label: "Cgroups",    },
  { path: "/programs", icon: List,            label: "Programs",   },
  { path: "/maps",     icon: Database,        label: "Maps",       },
  { path: "/diff",     icon: GitCompare,      label: "Diff",       },
  { path: "/map",      icon: Map,             label: "OS Map",     },
  { path: "/settings", icon: Settings,        label: "Settings",   },
];

function StreamStatusDot({ status }: { status: StreamStatus }) {
  const dotClass = {
    live:         "bg-emerald-400 animate-pulse",
    connecting:   "bg-amber-400 animate-pulse",
    reconnecting: "bg-amber-400 animate-pulse",
    offline:      "bg-red-500",
  }[status];

  const label = {
    live:         "Live",
    connecting:   "Connecting…",
    reconnecting: "Reconnecting…",
    offline:      "Offline",
  }[status];

  return (
    <div className="flex items-center gap-2">
      <div className={cn("w-2 h-2 rounded-full shrink-0", dotClass)} />
      <span className="text-xs text-muted-foreground">{label}</span>
    </div>
  );
}

function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const [location] = useLocation();
  const { snapshot, streamStatus, refresh, isLoading, demoMode, appMode, snapshotMeta, clearSnapshot } = useEbpf();

  return (
    <aside
      className={cn(
        "flex flex-col h-screen border-r border-border transition-all duration-300 shrink-0",
        "bg-[oklch(0.10_0.012_240)]",
        collapsed ? "w-16" : "w-56"
      )}
    >
      {/* Logo */}
      <div className={cn(
        "flex items-center gap-3 px-4 py-4 border-b border-border",
        collapsed && "justify-center px-0"
      )}>
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/20 border border-primary/30 shrink-0">
          <span className="text-primary font-bold text-sm font-mono">eBPF</span>
        </div>
        {!collapsed && (
          <div>
            <div className="text-sm font-semibold text-foreground">eBPF Viz</div>
            <div className="text-xs text-muted-foreground font-mono">
              {snapshot?.hostname ?? "—"}
            </div>
          </div>
        )}
      </div>

      {/* Status bar */}
      {!collapsed && (
        <div className="px-3 py-2 border-b border-border">
          {appMode === "snapshot" ? (
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Camera size={12} className="text-violet-400 shrink-0" />
                  <span className="text-xs text-violet-400">Snapshot</span>
                </div>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button
                      onClick={clearSnapshot}
                      className="text-muted-foreground hover:text-foreground transition-colors"
                    >
                      <XCircle size={13} />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent side="right">Clear snapshot — return to live mode</TooltipContent>
                </Tooltip>
              </div>
              {snapshotMeta && (
                <div className="text-[10px] text-muted-foreground mt-1 font-mono truncate" title={snapshotMeta.filename}>
                  {snapshotMeta.filename}
                </div>
              )}
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <StreamStatusDot status={streamStatus} />
              {demoMode && (
                <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-amber-500/50 text-amber-400">
                  DEMO
                </Badge>
              )}
            </div>
          )}
          {snapshot && (
            <div className="text-xs text-muted-foreground mt-1 font-mono">
              {snapshot.stats.total} programs · {snapshot.kernelVersion}
            </div>
          )}
        </div>
      )}

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-1">
        {NAV_ITEMS.map(({ path, icon: Icon, label }) => {
          const isActive = location === path;
          return collapsed ? (
            <Tooltip key={path}>
              <TooltipTrigger asChild>
                <Link href={path}>
                  <div className={cn(
                    "flex items-center justify-center w-10 h-10 rounded-lg mx-auto transition-all duration-150 cursor-pointer",
                    isActive
                      ? "bg-accent text-foreground shadow-[inset_2px_0_0_var(--primary)]"
                      : "text-muted-foreground hover:text-foreground hover:bg-accent"
                  )}>
                    <Icon size={18} />
                  </div>
                </Link>
              </TooltipTrigger>
              <TooltipContent side="right">{label}</TooltipContent>
            </Tooltip>
          ) : (
            <Link key={path} href={path}>
              <div className={cn(
                "sidebar-item",
                isActive && "active"
              )}>
                <Icon size={16} className="shrink-0" />
                <span>{label}</span>
              </div>
            </Link>
          );
        })}
      </nav>

      {/* Bottom controls */}
      <div className={cn(
        "border-t border-border p-2 flex",
        collapsed ? "flex-col items-center gap-2" : "items-center justify-between gap-2"
      )}>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="w-8 h-8 text-muted-foreground hover:text-foreground"
              onClick={refresh}
              disabled={isLoading || appMode === "snapshot"}
            >
              <RefreshCw size={14} className={cn(isLoading && "animate-spin")} />
            </Button>
          </TooltipTrigger>
          <TooltipContent side={collapsed ? "right" : "top"}>
            {appMode === "snapshot" ? "Refresh disabled in snapshot mode" : "Force refresh"}
          </TooltipContent>
        </Tooltip>

        <Button
          variant="ghost"
          size="icon"
          className="w-8 h-8 text-muted-foreground hover:text-foreground ml-auto"
          onClick={onToggle}
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </Button>
      </div>
    </aside>
  );
}

function TopBar() {
  const { searchQuery, setSearchQuery, snapshot, demoMode, streamStatus, appMode, snapshotMeta, loadSnapshot, loadMapDumps, clearSnapshot, snapshotMapDumps } = useEbpf();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const mapDumpsInputRef = useRef<HTMLInputElement>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isDumpsLoading, setIsDumpsLoading] = useState(false);

  const handleFileChange = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setIsLoading(true);
    try {
      await loadSnapshot(file);
      toast.success(`Snapshot loaded: ${file.name}`, {
        description: `${snapshot?.stats.total ?? "?"} programs captured`,
      });
    } catch (err) {
      toast.error("Failed to load snapshot", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setIsLoading(false);
      // Reset so the same file can be re-selected
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }, [loadSnapshot, snapshot]);

  const handleMapDumpsChange = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setIsDumpsLoading(true);
    try {
      const { loaded } = await loadMapDumps(file);
      toast.success(`Map dumps loaded: ${file.name}`, {
        description: `${loaded} map${loaded === 1 ? "" : "s"} with entry data`,
      });
    } catch (err) {
      toast.error("Failed to load map dumps", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setIsDumpsLoading(false);
      if (mapDumpsInputRef.current) mapDumpsInputRef.current.value = "";
    }
  }, [loadMapDumps]);

  const statusIcon = {
    live:         <Wifi size={14} />,
    connecting:   <Radio size={14} className="animate-pulse" />,
    reconnecting: <Radio size={14} className="animate-pulse" />,
    offline:      <WifiOff size={14} />,
  }[streamStatus];

  const statusColor = {
    live:         "text-emerald-400",
    connecting:   "text-amber-400",
    reconnecting: "text-amber-400",
    offline:      "text-red-400",
  }[streamStatus];

  const statusLabel = {
    live:         "Live stream",
    connecting:   "Connecting…",
    reconnecting: "Reconnecting…",
    offline:      "Stream offline",
  }[streamStatus];

  return (
    <header className="h-12 border-b border-border flex items-center gap-3 px-4 shrink-0 bg-[oklch(0.095_0.012_240)]">
      {/* Search */}
      <div className="relative flex-1 max-w-md">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
        <Input
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="Search programs, types, attachment points…"
          className="pl-8 h-8 text-sm bg-muted/50 border-border/50 focus:border-primary/50"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery("")}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
          >
            <X size={12} />
          </button>
        )}
      </div>

      <div className="flex items-center gap-3 ml-auto">
        {/* Mode badges */}
        {appMode === "snapshot" && (
          <div className="flex items-center gap-1.5">
            <Badge variant="outline" className="border-violet-500/50 text-violet-400 text-xs gap-1">
              <Camera size={10} />
              SNAPSHOT
            </Badge>
            {snapshotMeta && (
              <span className="text-[10px] text-muted-foreground font-mono hidden md:block max-w-[160px] truncate" title={snapshotMeta.filename}>
                {snapshotMeta.filename}
              </span>
            )}
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={clearSnapshot}
                  className="text-muted-foreground hover:text-foreground transition-colors"
                >
                  <X size={13} />
                </button>
              </TooltipTrigger>
              <TooltipContent>Clear snapshot — return to live mode</TooltipContent>
            </Tooltip>
          </div>
        )}
        {appMode === "demo" && (
          <Badge variant="outline" className="border-amber-500/50 text-amber-400 text-xs">
            DEMO MODE
          </Badge>
        )}

        {/* Snapshot timestamp or live time */}
        {snapshot && (
          <span className="text-xs text-muted-foreground font-mono hidden sm:block">
            {appMode === "snapshot" && snapshotMeta
              ? new Date(snapshotMeta.capturedAt).toLocaleString()
              : new Date(snapshot.timestamp).toLocaleTimeString()}
          </span>
        )}

        {/* Load Map Dumps button — only shown in snapshot mode */}
        {appMode === "snapshot" && (
          <>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  className={cn(
                    "h-8 gap-1.5 text-xs",
                    Object.keys(snapshotMapDumps).length > 0
                      ? "text-cyan-400 hover:text-cyan-300"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                  onClick={() => mapDumpsInputRef.current?.click()}
                  disabled={isDumpsLoading}
                >
                  {isDumpsLoading ? (
                    <RefreshCw size={13} className="animate-spin" />
                  ) : (
                    <Database size={13} />
                  )}
                  <span className="hidden sm:inline">
                    {Object.keys(snapshotMapDumps).length > 0
                      ? `Map Dumps (${Object.keys(snapshotMapDumps).length})`
                      : "Load Map Dumps"}
                  </span>
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {Object.keys(snapshotMapDumps).length > 0
                  ? `${Object.keys(snapshotMapDumps).length} maps with entry data loaded — click to reload`
                  : "Load a map dump file (from capture-snapshot.sh --dump-maps) to inspect map entries"}
              </TooltipContent>
            </Tooltip>
            <input
              ref={mapDumpsInputRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              data-testid="map-dumps-input"
              onChange={handleMapDumpsChange}
            />
          </>
        )}

        {/* Load Snapshot button */}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="sm"
              className={cn(
                "h-8 gap-1.5 text-xs",
                appMode === "snapshot"
                  ? "text-violet-400 hover:text-violet-300"
                  : "text-muted-foreground hover:text-foreground"
              )}
              onClick={() => fileInputRef.current?.click()}
              disabled={isLoading}
            >
              {isLoading ? (
                <RefreshCw size={13} className="animate-spin" />
              ) : (
                <FolderOpen size={13} />
              )}
              <span className="hidden sm:inline">Load Snapshot</span>
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            Load a snapshot JSON file (from OS Map download or capture-snapshot.sh)
          </TooltipContent>
        </Tooltip>
        <input
          ref={fileInputRef}
          type="file"
          accept=".json,application/json"
          className="hidden"
          data-testid="snapshot-input"
          onChange={handleFileChange}
        />

        {/* Stream status (hidden in snapshot mode) */}
        {appMode !== "snapshot" && (
          <Tooltip>
            <TooltipTrigger asChild>
              <div className={cn("flex items-center gap-1.5 px-2 py-1 rounded text-xs", statusColor)}>
                {statusIcon}
                <span className="hidden sm:inline">{statusLabel}</span>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              {streamStatus === "live"
                ? "Receiving live updates via SSE"
                : streamStatus === "offline"
                ? "Connection lost — check server"
                : "Establishing SSE connection…"}
            </TooltipContent>
          </Tooltip>
        )}
      </div>
    </header>
  );
}

function LayoutInner({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const { selectedProgram, setSelectedProgram, historyMap } = useEbpf();

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(c => !c)} />
      <div className="flex flex-col flex-1 min-w-0">
        <TopBar />
        <main className="flex-1 overflow-auto">
          {children}
        </main>
      </div>
      {selectedProgram && (
        <Suspense
          fallback={
            <div className="fixed right-0 top-0 z-50 flex h-screen w-full max-w-2xl items-center justify-center border-l border-border bg-card/95 text-sm text-muted-foreground shadow-2xl">
              Loading program details...
            </div>
          }
        >
          <ProgramDetailPanel
            program={selectedProgram}
            history={historyMap.get(selectedProgram.id) ?? null}
            onClose={() => setSelectedProgram(null)}
          />
        </Suspense>
      )}
    </div>
  );
}

export default function EbpfLayout({ children }: { children: React.ReactNode }) {
  return (
    <EbpfProvider>
      <LayoutInner>{children}</LayoutInner>
    </EbpfProvider>
  );
}
