import React, { useState } from "react";
import { useEbpf } from "@/contexts/EbpfContext";
import { ProgBadge } from "@/components/ProgBadge";
import { FolderTree, Folder, FolderOpen, ChevronDown, ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { CgroupNode } from "../../../shared/ebpf-types";

const ATTACH_TYPE_COLORS: Record<string, string> = {
  cgroup_inet_ingress:  "#3b82f6",
  cgroup_inet_egress:   "#6d28d9",
  cgroup_device:        "#1d4ed8",
  cgroup_sock_create:   "#2563eb",
  cgroup_sockops:       "#8b5cf6",
  cgroup_sock_release:  "#a78bfa",
  cgroup_bind4:         "#0ea5e9",
  cgroup_bind6:         "#0284c7",
  cgroup_connect4:      "#0369a1",
  cgroup_connect6:      "#075985",
  cgroup_sendmsg4:      "#7c3aed",
  cgroup_sendmsg6:      "#6d28d9",
  cgroup_recvmsg4:      "#5b21b6",
  cgroup_recvmsg6:      "#4c1d95",
  cgroup_sysctl:        "#f59e0b",
  cgroup_getsockopt:    "#d97706",
  cgroup_setsockopt:    "#b45309",
};

function AttachTypeTag({ attachType, attachFlags }: { attachType: string; attachFlags?: string }) {
  const color = ATTACH_TYPE_COLORS[attachType] ?? "#6b7280";
  return (
    <span
      className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border"
      style={{ color, borderColor: `${color}40`, background: `${color}10` }}
    >
      {attachType.replace("cgroup_", "")}
      {attachFlags && <span className="opacity-60">[{attachFlags}]</span>}
    </span>
  );
}

function CgroupNodeRow({
  node,
  depth,
  searchQuery,
  filteredIds,
}: {
  node: CgroupNode;
  depth: number;
  searchQuery: string;
  filteredIds: Set<number>;
}) {
  const hasMatchingProgs = node.programs.some(p => filteredIds.has(p.id));
  const hasMatchingChildren = (n: CgroupNode): boolean =>
    n.programs.some(p => filteredIds.has(p.id)) ||
    n.children.some(hasMatchingChildren);

  const isVisible = !searchQuery || hasMatchingProgs || hasMatchingChildren(node);
  const [expanded, setExpanded] = useState(depth < 2 || hasMatchingProgs);

  if (!isVisible) return null;

  const visibleProgs = searchQuery
    ? node.programs.filter(p => filteredIds.has(p.id))
    : node.programs;

  const hasChildren = node.children.length > 0;
  const indent = depth * 20;

  return (
    <div className="cgroup-node">
      {/* Node row */}
      <div
        className={cn(
          "flex items-start gap-2 py-2 px-3 rounded-lg hover:bg-accent/20 transition-colors group",
          visibleProgs.length > 0 && "bg-blue-500/5"
        )}
        style={{ paddingLeft: `${indent + 12}px` }}
      >
        {/* Expand toggle */}
        <button
          className="shrink-0 mt-0.5 text-muted-foreground hover:text-foreground transition-colors"
          onClick={() => setExpanded(e => !e)}
          disabled={!hasChildren}
        >
          {hasChildren ? (
            expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />
          ) : (
            <span className="w-3 inline-block" />
          )}
        </button>

        {/* Folder icon */}
        <div className="shrink-0 mt-0.5">
          {expanded && hasChildren
            ? <FolderOpen size={14} className="text-amber-400/70" />
            : <Folder size={14} className={cn(
                "transition-colors",
                visibleProgs.length > 0 ? "text-blue-400/70" : "text-muted-foreground/50"
              )} />
          }
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-foreground font-medium">{node.name}</span>
            {visibleProgs.length > 0 && (
              <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-blue-500/40 text-blue-400">
                {visibleProgs.length} prog{visibleProgs.length !== 1 ? "s" : ""}
              </Badge>
            )}
          </div>

          {/* Programs */}
          {visibleProgs.length > 0 && (
            <div className="mt-2 space-y-1.5">
              {visibleProgs.map(p => {
                const cgroupAtt = p.attachments.find(a => a.cgroupPath === node.path);
                return (
                  <div key={p.id} className="flex items-center gap-2 flex-wrap">
                    <ProgBadge program={p} />
                    {cgroupAtt && (
                      <AttachTypeTag
                        attachType={cgroupAtt.detail.split(" ")[0]}
                        attachFlags={cgroupAtt.attachFlags}
                      />
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Children */}
      {expanded && node.children.length > 0 && (
        <div className="relative">
          <div
            className="absolute top-0 bottom-0 border-l border-dashed border-border/30"
            style={{ left: `${indent + 20}px` }}
          />
          {node.children.map(child => (
            <CgroupNodeRow
              key={child.path}
              node={child}
              depth={depth + 1}
              searchQuery={searchQuery}
              filteredIds={filteredIds}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function CgroupView() {
  const { snapshot, filteredPrograms, searchQuery } = useEbpf();

  if (!snapshot) {
    return <div className="flex items-center justify-center h-full"><p className="text-muted-foreground">Loading…</p></div>;
  }

  const filteredIds = new Set(filteredPrograms.map(p => p.id));
  const cgroupProgs = snapshot.programs.filter(p =>
    p.type.startsWith("cgroup") || p.type === "sock_ops"
  );

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-xl font-bold text-foreground flex items-center gap-2">
          <FolderTree size={20} className="text-primary" />
          Cgroup Hierarchy
        </h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {snapshot.cgroupTree.length} top-level cgroup{snapshot.cgroupTree.length !== 1 ? "s" : ""} · {cgroupProgs.length} BPF programs
        </p>
      </div>

      {/* Attach type legend */}
      <div className="glass rounded-xl p-4">
        <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Attach Types</div>
        <div className="flex flex-wrap gap-2">
          {Object.entries(ATTACH_TYPE_COLORS).slice(0, 10).map(([type, color]) => (
            <span
              key={type}
              className="text-[10px] font-mono px-2 py-0.5 rounded border"
              style={{ color, borderColor: `${color}40`, background: `${color}10` }}
            >
              {type.replace("cgroup_", "")}
            </span>
          ))}
          <span className="text-[10px] text-muted-foreground px-2 py-0.5">+ more</span>
        </div>
      </div>

      {/* Tree */}
      <div className="glass rounded-xl p-4">
        <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 font-mono">
          /sys/fs/cgroup
        </div>
        {snapshot.cgroupTree.length > 0 ? (
          <div className="space-y-0.5">
            {snapshot.cgroupTree.map(node => (
              <CgroupNodeRow
                key={node.path}
                node={node}
                depth={0}
                searchQuery={searchQuery}
                filteredIds={filteredIds}
              />
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <FolderTree size={32} className="text-muted-foreground mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No cgroup BPF programs found.</p>
            <p className="text-xs text-muted-foreground/60 mt-1">
              cgroup_skb, cgroup_sock, and sock_ops programs will appear here.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
