import { useState } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { trpc } from "@/lib/trpc";
import { Settings, RefreshCw, Terminal, Cpu, Info, CheckCircle, Radio, Wifi } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

const INTERVAL_OPTIONS = [
  { label: "1 second",  value: 1000 },
  { label: "3 seconds", value: 3000 },
  { label: "5 seconds", value: 5000 },
  { label: "10 seconds",value: 10000 },
  { label: "30 seconds",value: 30000 },
  { label: "1 minute",  value: 60000 },
];

export default function SettingsView() {
  const { snapshot, streamStatus, refreshInterval, setRefreshInterval, demoMode } = useEbpf();
  const [saving, setSaving] = useState(false);

  const updateConfig = trpc.ebpf.updateConfig.useMutation({
    onSuccess: () => {
      toast.success("Configuration updated");
      setSaving(false);
    },
    onError: (err) => {
      toast.error(`Failed to update: ${err.message}`);
      setSaving(false);
    },
  });

  const { data: status } = trpc.ebpf.status.useQuery(undefined, {
    refetchInterval: 10_000,
  });

  const handleIntervalChange = (ms: number) => {
    setRefreshInterval(ms);
    setSaving(true);
    updateConfig.mutate({ intervalMs: ms });
  };

  const handleToggleDemo = () => {
    setSaving(true);
    updateConfig.mutate({ demoMode: !demoMode });
  };

  const streamStatusLabel = {
    live:         "Live",
    connecting:   "Connecting…",
    reconnecting: "Reconnecting…",
    offline:      "Offline",
  }[streamStatus];

  const streamStatusColor = {
    live:         "border-emerald-500/40 text-emerald-400",
    connecting:   "border-amber-500/40 text-amber-400",
    reconnecting: "border-amber-500/40 text-amber-400",
    offline:      "border-destructive/40 text-destructive",
  }[streamStatus];

  return (
    <div className="p-6 space-y-6 max-w-2xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
          <Settings size={20} className="text-primary" />
          Settings
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">Configure polling interval, data source, and display options</p>
      </div>

      {/* System info */}
      <div className="glass rounded-xl p-5 space-y-3">
        <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Info size={14} className="text-primary" />
          System Information
        </h2>
        <div className="divide-y divide-border/50">
          {[
            { label: "Hostname", value: snapshot?.hostname ?? "—" },
            { label: "Kernel", value: snapshot?.kernelVersion ?? "—" },
            { label: "bpftool", value: snapshot?.bpftoolVersion ?? "—" },
            { label: "Total programs", value: snapshot?.stats.total?.toString() ?? "—" },
            { label: "Mode", value: demoMode ? "Demo (mock data)" : "Live (bpftool)" },
          ].map(({ label, value }) => (
            <div key={label} className="flex items-center justify-between py-2">
              <span className="text-xs text-muted-foreground">{label}</span>
              <span className="text-xs font-mono text-foreground">{value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Live stream status */}
      <div className="glass rounded-xl p-5 space-y-4">
        <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Wifi size={14} className="text-primary" />
          Live Stream (SSE)
        </h2>
        <p className="text-xs text-muted-foreground">
          The dashboard receives live updates via Server-Sent Events (SSE). No polling is required — the server pushes a new snapshot automatically after each bpftool cycle.
        </p>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className={cn("text-xs", streamStatusColor)}>
            {streamStatusLabel}
          </Badge>
          {streamStatus === "live" && (
            <span className="text-xs text-muted-foreground">
              Connected · updates push every {status?.config.intervalMs ? `${status.config.intervalMs / 1000}s` : "…"}
            </span>
          )}
          {(streamStatus === "reconnecting" || streamStatus === "connecting") && (
            <Radio size={12} className="text-amber-400 animate-pulse" />
          )}
        </div>
      </div>

      {/* Polling config */}
      <div className="glass rounded-xl p-5 space-y-4">
        <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <RefreshCw size={14} className="text-primary" />
          Polling Interval
        </h2>
        <p className="text-xs text-muted-foreground">
          Controls how often the server runs bpftool to collect new data. Shorter intervals give faster updates at the cost of more CPU overhead.
        </p>

        <div>
          <div className="grid grid-cols-3 gap-2">
            {INTERVAL_OPTIONS.map(opt => (
              <button
                key={opt.value}
                onClick={() => handleIntervalChange(opt.value)}
                className={cn(
                  "px-3 py-2 rounded-lg text-xs font-mono border transition-all",
                  refreshInterval === opt.value
                    ? "border-primary/60 bg-primary/15 text-primary"
                    : "border-border/60 text-muted-foreground hover:border-border hover:text-foreground"
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Demo mode */}
      <div className="glass rounded-xl p-5 space-y-4">
        <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Terminal size={14} className="text-primary" />
          Data Source
        </h2>

        <div className="flex items-start gap-4">
          <button
            onClick={() => !demoMode || handleToggleDemo()}
            className={cn(
              "flex-1 p-4 rounded-xl border transition-all text-left",
              !demoMode
                ? "border-primary/60 bg-primary/10"
                : "border-border/60 hover:border-border"
            )}
          >
            <div className="flex items-center gap-2 mb-1">
              <Cpu size={14} className={!demoMode ? "text-primary" : "text-muted-foreground"} />
              <span className={cn("text-sm font-medium", !demoMode ? "text-foreground" : "text-muted-foreground")}>
                Live (bpftool)
              </span>
              {!demoMode && <CheckCircle size={13} className="text-primary ml-auto" />}
            </div>
            <p className="text-xs text-muted-foreground">
              Polls real eBPF programs from the running kernel using bpftool.
            </p>
          </button>

          <button
            onClick={() => demoMode || handleToggleDemo()}
            className={cn(
              "flex-1 p-4 rounded-xl border transition-all text-left",
              demoMode
                ? "border-amber-500/60 bg-amber-500/10"
                : "border-border/60 hover:border-border"
            )}
          >
            <div className="flex items-center gap-2 mb-1">
              <Terminal size={14} className={demoMode ? "text-amber-400" : "text-muted-foreground"} />
              <span className={cn("text-sm font-medium", demoMode ? "text-amber-300" : "text-muted-foreground")}>
                Demo Mode
              </span>
              {demoMode && <CheckCircle size={13} className="text-amber-400 ml-auto" />}
            </div>
            <p className="text-xs text-muted-foreground">
              Uses rich mock data to demonstrate all visualization features.
            </p>
          </button>
        </div>

        {status?.lastError && (
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-xs text-destructive/80 font-mono">
            Last error: {status.lastError}
          </div>
        )}
      </div>

      {/* Poller status */}
      {status && (
        <div className="glass rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-foreground">Poller Status</h2>
          <div className="divide-y divide-border/50">
            <div className="flex items-center justify-between py-2">
              <span className="text-xs text-muted-foreground">Running</span>
              <Badge variant="outline" className={cn(
                "text-[10px]",
                status.running ? "border-emerald-500/40 text-emerald-400" : "border-destructive/40 text-destructive"
              )}>
                {status.running ? "yes" : "no"}
              </Badge>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-xs text-muted-foreground">Last poll</span>
              <span className="text-xs font-mono text-foreground">
                {status.lastPollTime ? new Date(status.lastPollTime).toLocaleTimeString() : "—"}
              </span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-xs text-muted-foreground">Interval</span>
              <span className="text-xs font-mono text-foreground">{status.config.intervalMs}ms</span>
            </div>
            <div className="flex items-center justify-between py-2">
              <span className="text-xs text-muted-foreground">SSE stream</span>
              <Badge variant="outline" className={cn("text-[10px]", streamStatusColor)}>
                {streamStatusLabel}
              </Badge>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
