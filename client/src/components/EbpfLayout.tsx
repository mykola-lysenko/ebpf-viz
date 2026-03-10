import React, { useState } from "react";
import { Link, useLocation } from "wouter";
import {
  Cpu, Network, FolderTree, List, Settings,
  LayoutDashboard, RefreshCw, Wifi, WifiOff,
  ChevronLeft, ChevronRight, Search, X, Map
} from "lucide-react";
import { EbpfProvider, useEbpf } from "@/contexts/EbpfContext";
import { ProgramDetailPanel } from "./ProgramDetailPanel";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { path: "/",         icon: LayoutDashboard, label: "Dashboard",  },
  { path: "/kernel",   icon: Cpu,             label: "Kernel",     },
  { path: "/network",  icon: Network,         label: "Network",    },
  { path: "/cgroups",  icon: FolderTree,      label: "Cgroups",    },
  { path: "/programs", icon: List,            label: "Programs",   },
  { path: "/map",      icon: Map,             label: "OS Map",     },
  { path: "/settings", icon: Settings,        label: "Settings",   },
];

function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const [location] = useLocation();
  const { snapshot, autoRefresh, refresh, isLoading, demoMode } = useEbpf();

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
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className={cn(
                "live-dot w-2 h-2 rounded-full",
                autoRefresh ? "bg-emerald-400 text-emerald-400" : "bg-muted-foreground text-muted-foreground"
              )} />
              <span className="text-xs text-muted-foreground">
                {autoRefresh ? "Live" : "Paused"}
              </span>
            </div>
            {demoMode && (
              <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-amber-500/50 text-amber-400">
                DEMO
              </Badge>
            )}
          </div>
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
              disabled={isLoading}
            >
              <RefreshCw size={14} className={cn(isLoading && "animate-spin")} />
            </Button>
          </TooltipTrigger>
          <TooltipContent side={collapsed ? "right" : "top"}>Refresh now</TooltipContent>
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
  const { searchQuery, setSearchQuery, snapshot, demoMode, autoRefresh, setAutoRefresh } = useEbpf();

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
        {demoMode && (
          <Badge variant="outline" className="border-amber-500/50 text-amber-400 text-xs">
            DEMO MODE
          </Badge>
        )}

        {snapshot && (
          <span className="text-xs text-muted-foreground font-mono hidden sm:block">
            {new Date(snapshot.timestamp).toLocaleTimeString()}
          </span>
        )}

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className={cn(
                "w-8 h-8",
                autoRefresh ? "text-emerald-400" : "text-muted-foreground"
              )}
              onClick={() => setAutoRefresh(!autoRefresh)}
            >
              {autoRefresh ? <Wifi size={14} /> : <WifiOff size={14} />}
            </Button>
          </TooltipTrigger>
          <TooltipContent>{autoRefresh ? "Pause auto-refresh" : "Resume auto-refresh"}</TooltipContent>
        </Tooltip>
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
        <ProgramDetailPanel
          program={selectedProgram}
          history={historyMap.get(selectedProgram.id) ?? null}
          onClose={() => setSelectedProgram(null)}
        />
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
