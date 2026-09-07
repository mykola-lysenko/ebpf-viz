import { z } from "zod";
import { SourceCollector } from "./collection";
import { collectionError, type CollectionStatus } from "../shared/collection-status";
import { rawBpfProgSchema, rawBpfMapSchema, rawBpfLinkSchema, rawCgroupEntrySchema, rawNetnsLinkSchema } from "../shared/snapshot-validation";
import { exec, execFile, execSync } from "child_process";
import { existsSync } from "fs";
import { promisify } from "util";
import { hostname } from "os";
import type {
  BpfMap,
  EbpfSnapshot,
  PollingConfig,
  RawBpfLink,
  RawBpfMap,
  RawBpfProg,
  RawCgroupEntry,
  RawNetSnapshot,
  RawNetnsSnapshot,
  RawNetnsLink,
  RawTcFilterEntry,
} from "../shared/ebpf-types";
import { buildSnapshot, netnsLinkKind, PAIRED_LINK_KINDS } from "./ebpf-parser";
import { buildMockMaps, parseMaps } from "./ebpf-map-parser";
import { discoverNetNamespaces, clearNetnsDiscoveryCache, MAX_NETNS, type NetnsReach } from "./ebpf-netns";
import { MOCK_CGROUPS, MOCK_LINKS, MOCK_NET, MOCK_NETNS, MOCK_PROGS, MOCK_SYSTEM } from "./ebpf-mock";
import {
  ingestSnapshot,
  pruneStale,
  buildActivitySummary,
  getAllHistories,
  getHistory,
  clearAll,
} from "./ebpf-stats-ring";

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

// ─── Config ──────────────────────────────────────────────────────────────────

/**
 * Discover the bpftool binary path at startup.
 * Priority: BPFTOOL_PATH env var → `which bpftool` → common install locations.
 * Returns the first path that exists, or the last fallback (so the error
 * message still shows a useful path rather than "undefined").
 */
export function resolveBpftoolPath(): string {
  if (process.env.BPFTOOL_PATH) return process.env.BPFTOOL_PATH;
  // Try `which bpftool` (works on any distro with bpftool in PATH)
  try {
    const found = execSync("which bpftool 2>/dev/null", { encoding: "utf8" }).trim();
    if (found) return found;
  } catch { /* not in PATH */ }
  // Common install locations across distros
  const candidates = [
    "/usr/sbin/bpftool",
    "/usr/bin/bpftool",
    "/usr/local/sbin/bpftool",
    "/usr/local/bin/bpftool",
    "/sbin/bpftool",
  ];
  for (const p of candidates) {
    if (existsSync(p)) return p;
  }
  // Return the most common path as a fallback so the error message is helpful
  return "/usr/sbin/bpftool";
}

// ─── Env-var defaults ──────────────────────────────────────────────────────────────────
// Read environment variables at module load time so they are available
// before startPoller() is called. These are the same variables documented
// in .env.example and start.sh.
function resolveDefaultConfig(): PollingConfig {
  const demoMode = process.env.DEMO_MODE === "1" || process.env.DEMO_MODE === "true";
  const bpftoolPath = resolveBpftoolPath();
  const intervalMs = process.env.POLL_INTERVAL_MS
    ? parseInt(process.env.POLL_INTERVAL_MS, 10)
    : 5000;
  return { intervalMs, demoMode, bpftoolPath, sudo: true };
}

const DEFAULT_CONFIG: PollingConfig = resolveDefaultConfig();

// ─── State ─────────────────────────────────────────────────────────────────

let config: PollingConfig = { ...DEFAULT_CONFIG };
let latestSnapshot: EbpfSnapshot | null = null;
let latestMaps: BpfMap[] = [];
const collector = new SourceCollector();
let collection: CollectionStatus | undefined;
let pollingTimer: ReturnType<typeof setInterval> | null = null;
let lastError: string | null = null;
let bpftoolVersion = "unknown";
let bpftoolHasSkeletons: boolean | null = null;
let bpftoolCheckedAt: number | null = null;
let kernelVersion = "unknown";
let isPolling = false;
let pendingConfig: Partial<PollingConfig> | null = null;
let statsEnabled = false;
/** True when *we* flipped kernel.bpf_stats_enabled from 0 to 1, so we can
 *  restore it on shutdown instead of leaving per-invocation overhead on
 *  every BPF program in the system forever. */
let statsEnabledByUs = false;

const listeners = new Set<(snap: EbpfSnapshot) => void>();

// ─── bpf_stats_enabled ─────────────────────────────────────────────────────

async function ensureBpfStatsEnabled(): Promise<void> {
  try {
    const { stdout } = await execAsync("cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null");
    const current = parseInt(stdout.trim(), 10);
    if (current === 1) {
      statsEnabled = true;
      console.log("[ebpf-poller] bpf_stats_enabled is already 1 — run_time_ns will be collected");
      return;
    }
    // BPF_STATS_ENABLED=0 opts out of flipping the sysctl (stats add
    // per-invocation overhead to every BPF program on the system).
    const optOut = process.env.BPF_STATS_ENABLED;
    if (optOut === "0" || optOut?.toLowerCase() === "false") {
      statsEnabled = false;
      console.log("[ebpf-poller] BPF_STATS_ENABLED=0 — leaving kernel.bpf_stats_enabled off; run_time_ns will be 0");
      return;
    }
    // Try to enable it
    await execAsync("sudo sysctl -w kernel.bpf_stats_enabled=1 2>/dev/null");
    statsEnabled = true;
    statsEnabledByUs = true;
    console.log("[ebpf-poller] Enabled kernel.bpf_stats_enabled=1 — runtime stats will accumulate (restored on shutdown)");
  } catch {
    statsEnabled = false;
    console.warn("[ebpf-poller] Could not enable bpf_stats_enabled — run_time_ns will be 0");
  }
}

// ─── System info ───────────────────────────────────────────────────────────

/**
 * Parse `bpftool version` output. `hasSkeletons` is null when the build is
 * too old to print a features line at all (pre-v5.19), so we can't tell.
 * A build without the "skeletons" feature silently omits the `pids` field
 * from all prog/map listings — every program then looks ownerless/orphaned.
 */
export function parseBpftoolVersion(stdout: string): {
  version: string;
  hasSkeletons: boolean | null;
} {
  const lines = stdout.trim().split("\n");
  const featuresLine = lines.find(line => line.trim().startsWith("features:"));
  return {
    version: lines[0] ?? "unknown",
    hasSkeletons: featuresLine ? /\bskeletons\b/.test(featuresLine) : null,
  };
}

async function getSystemInfo(): Promise<void> {
  try {
    const { stdout: kv } = await execAsync("uname -r");
    kernelVersion = kv.trim();
  } catch { kernelVersion = "unknown"; }

  try {
    const { stdout } = await execFileAsync(config.bpftoolPath, ["version"], { timeout: 5000 });
    bpftoolCheckedAt = Date.now();
    const parsed = parseBpftoolVersion(stdout);
    bpftoolVersion = parsed.version;
    bpftoolHasSkeletons = parsed.hasSkeletons;
    if (bpftoolHasSkeletons === false) {
      console.warn(
        `[ebpf-poller] ${config.bpftoolPath} was built without skeleton support ` +
        "(no \"skeletons\" entry in `bpftool version` features) — it cannot report " +
        "process ownership, so the pids field is silently omitted and every program " +
        "will appear orphaned. Ubuntu's linux-tools bpftool is a common culprit; " +
        "build from https://github.com/libbpf/bpftool and point BPFTOOL_PATH at it."
      );
    }
  } catch { bpftoolVersion = "built from source"; }
}

// ─── Run bpftool commands ──────────────────────────────────────────────────

async function runBpftool(args: string): Promise<string> {
  // -f/--bpffs: include bpffs pin paths ("pinned" arrays) in prog/map/link
  // listings — without it bpftool omits the field entirely. Harmless for the
  // other subcommands.
  const argv = ["-j", "-f", ...args.split(/\s+/)];
  const cmd = config.sudo ? "sudo" : config.bpftoolPath;
  const fullArgv = config.sudo ? [config.bpftoolPath, ...argv] : argv;
  // Raise maxBuffer from the Node default (1 MB) to 32 MB.
  // On systems with 200+ BPF programs, bpftool map list / prog list JSON output
  // can easily exceed 1 MB, causing exec() to throw ERR_CHILD_PROCESS_STDIO_MAXBUFFER
  // and silently returning an empty result.
  const { stdout } = await execFileAsync(cmd, fullArgv, { timeout: 10000, maxBuffer: 32 * 1024 * 1024 });
  return stdout.trim();
}

/** Build the command prefix that runs argv inside a discovered namespace. */
function reachCommand(reach: NetnsReach, argv: string[]): { cmd: string; args: string[] } {
  if (reach.via === "docker") {
    // docker talks to its own daemon; no sudo needed with docker-group access.
    return { cmd: "docker", args: ["exec", reach.container, ...argv] };
  }
  const nsenterArgv = [`--net=${reach.nsPath}`, "--", ...argv];
  return config.sudo
    ? { cmd: "sudo", args: ["nsenter", ...nsenterArgv] }
    : { cmd: "nsenter", args: nsenterArgv };
}

/** Run `bpftool net show` inside a namespace. For docker reach, uses whatever
 *  bpftool the container provides (kind nodes often lack a working one — the
 *  caller tolerates an empty result and falls back to ip-link topology). */
async function runBpftoolNetInNetns(reach: NetnsReach): Promise<string> {
  const bpftool = reach.via === "docker" ? "bpftool" : config.bpftoolPath;
  const { cmd, args } = reachCommand(reach, [bpftool, "-j", "net", "show"]);
  const { stdout } = await execFileAsync(cmd, args, {
    timeout: 10000,
    maxBuffer: 32 * 1024 * 1024,
  });
  return stdout.trim();
}

/** Run `ip -d -j link show` inside a namespace for device-pair topology. */
async function runIpLinkInNetns(reach: NetnsReach): Promise<string> {
  const { cmd, args } = reachCommand(reach, ["ip", "-d", "-j", "link", "show"]);
  const { stdout } = await execFileAsync(cmd, args, {
    timeout: 10000,
    maxBuffer: 32 * 1024 * 1024,
  });
  return stdout.trim();
}

/** Normalize `ip -d -j link show` JSON into RawNetnsLink[]. */
function parseIpLinks(stdout: string): RawNetnsLink[] {
  const raw = parseArray<Record<string, unknown>>(stdout, rawNetnsLinkSchema);
  return raw
    .filter((l): l is Record<string, unknown> => !!l && typeof l === "object")
    .map(l => ({
      ifindex: Number(l.ifindex),
      ifname: String(l.ifname ?? ""),
      link_index: typeof l.link_index === "number" ? l.link_index : undefined,
      link_netnsid:
        typeof l.link_netnsid === "number" ? l.link_netnsid : undefined,
      kind: (l.linkinfo as { info_kind?: string } | undefined)?.info_kind,
      operstate: typeof l.operstate === "string" ? l.operstate : undefined,
    }))
    .filter(l => Number.isFinite(l.ifindex) && l.ifname);
}

/** Does this namespace hold anything worth showing — a netdev BPF attachment,
 *  or a device pair (netkit/veth) that connects it to another namespace? */
function isInterestingNetns(ns: RawNetnsSnapshot): boolean {
  const snapshot = ns.net[0];
  const hasProg =
    !!snapshot &&
    [
      snapshot.xdp,
      snapshot.tc,
      snapshot.tcx,
      snapshot.netkit,
      snapshot.flow_dissector,
      snapshot.netfilter,
    ].some(section => (section?.length ?? 0) > 0);
  const hasPair = (ns.links ?? []).some(
    l => PAIRED_LINK_KINDS.has(netnsLinkKind(l) ?? "") && typeof l.link_index === "number"
  );
  return hasProg || hasPair;
}

/** Namespaces that recently had nothing to show are skipped for a while —
 *  most pods never carry netdev BPF programs, and each scan costs two execs. */
const UNINTERESTING_NETNS_TTL_MS = 60_000;
const uninterestingNetns = new Map<string, number>();

/** Scan all reachable non-root network namespaces for BPF net attachments and
 *  device-pair topology. Per-namespace failures (vanished mid-poll, nsenter
 *  denied, no bpftool in container, non-JSON bpftool output) degrade
 *  gracefully — a namespace with only ip-link topology and no bpftool net
 *  still contributes to the graph. */
async function fetchNetnsData(): Promise<RawNetnsSnapshot[]> {
  const discovery = await collector.read("namespaceDiscovery", "Namespace discovery",
    discoverNetNamespaces, { refs: [], at: 0, discovered: 0, omitted: 0, issues: [] }, result => result.at);
  const discoveryStatus = collector.sources.namespaceDiscovery;
  if (discoveryStatus.state === "ok") {
    discoveryStatus.lastSuccessAt = discovery.at;
    if (discovery.omitted) {
      discoveryStatus.state = "partial";
      discoveryStatus.detail = `${discovery.omitted} namespaces omitted by the ${MAX_NETNS} namespace limit`;
    }
  }
  for (const [index, issue] of Array.from(discovery.issues.entries())) {
    collector.sources[`namespaceDiscovery:${index}`] = {
      ...issue, attemptedAt: discovery.at, lastSuccessAt: null,
    };
  }
  const now = Date.now();
  let skipped = 0;
  const snapshots = await Promise.all(discovery.refs.map(async ref => {
    const netKey = `netns:${ref.id}:net`;
    const linksKey = `netns:${ref.id}:links`;
    const netLabel = `${ref.label}: BPF attachments`;
    const linksLabel = `${ref.label}: device topology`;
    const boringSince = uninterestingNetns.get(ref.id);
    if (boringSince !== undefined && now - boringSince < UNINTERESTING_NETNS_TTL_MS) {
      skipped++;
      const detail = "Previously empty namespace; rescan deferred for up to 60 seconds";
      return { id: ref.id, label: ref.label,
        net: collector.skip<RawNetSnapshot[]>(netKey, netLabel, detail, []),
        links: collector.skip<RawNetnsLink[]>(linksKey, linksLabel, detail, []) };
    }
    const [net, links] = await Promise.all([
      collector.read(netKey, netLabel, async () => parseNet(await runBpftoolNetInNetns(ref.reach)), []),
      collector.read(linksKey, linksLabel, async () => parseIpLinks(await runIpLinkInNetns(ref.reach)), []),
    ]);
    const ns = { id: ref.id, label: ref.label, net, links };
    // Failed scans are retried next poll, never cached as empty namespaces.
    if (collector.sources[netKey].state === "ok" && collector.sources[linksKey].state === "ok" && !isInterestingNetns(ns)) {
      uninterestingNetns.set(ref.id, now);
    } else uninterestingNetns.delete(ref.id);
    return ns;
  }));
  for (const [id, at] of Array.from(uninterestingNetns)) {
    if (now - at > UNINTERESTING_NETNS_TTL_MS * 5) uninterestingNetns.delete(id);
  }
  collection!.namespaces = { limit: MAX_NETNS, discovered: discovery.discovered,
    scanned: discovery.refs.length - skipped, skipped, omitted: discovery.omitted,
    discoveryAt: discovery.at };
  return snapshots.filter(isInterestingNetns);
}

async function runTcFilterShow(
  devname: string,
  direction: RawTcFilterEntry["direction"]
): Promise<RawTcFilterEntry[]> {
  const tcArgs = [
    "-s",
    "-d",
    "-j",
    "filter",
    "show",
    "dev",
    devname,
    direction,
  ];
  const cmd = config.sudo ? "sudo" : "tc";
  const fullArgv = config.sudo ? ["tc", ...tcArgs] : tcArgs;
  const { stdout } = await execFileAsync(cmd, fullArgv, {
    timeout: 5000,
    maxBuffer: 16 * 1024 * 1024,
  });
  const parsed = parseArray<Record<string, unknown>>(stdout, z.record(z.string(), z.unknown()));

  return parsed
    .filter(item => item && typeof item === "object")
    .map((item, order) => ({
      ...(item as Record<string, unknown>),
      devname,
      direction,
      order,
    })) as RawTcFilterEntry[];
}

/** Validate before caching: malformed JSON or an error object is not an empty inventory. */
function parseArray<T>(raw: string, item: z.ZodType): T[] {
  return z.array(item).parse(JSON.parse(stripNonJson(raw))) as T[];
}

const netEntrySchema = z.object({
  devname: z.string().optional(), ifindex: z.number().optional(),
  id: z.number().optional(), prog_id: z.number().optional(),
}).catchall(z.unknown());
const netSchema = z.object(Object.fromEntries(
  ["xdp", "tc", "tcx", "netkit", "flow_dissector", "netfilter", "sockmap"]
    .map(key => [key, z.array(netEntrySchema).optional()])
)).catchall(z.unknown());
function parseNet(raw: string): RawNetSnapshot[] { return parseArray(raw, netSchema); }

// Strip libbpf warning lines that pollute JSON output
function stripNonJson(raw: string): string {
  return raw
    .split("\n")
    .filter(line => !line.startsWith("libbpf:"))
    .join("\n")
    .trim();
}

async function fetchLiveData() {
  collector.begin();
  collection = { sources: collector.sources };
  const [progs, net, cgroups, cgroupsEffective, rawMaps, links, netns] = await Promise.all([
    collector.read("progs", "Programs", async () => parseArray<RawBpfProg>(await runBpftool("prog list"), rawBpfProgSchema), []),
    collector.read("net", "Host network attachments", async () => parseNet(await runBpftool("net")), []),
    collector.read("cgroups", "Cgroup attachments", async () => parseArray<RawCgroupEntry>(await runBpftool("cgroup tree"), rawCgroupEntrySchema), []),
    collector.read("cgroupsEffective", "Effective cgroup attachments", async () => parseArray<RawCgroupEntry>(await runBpftool("cgroup tree /sys/fs/cgroup effective"), rawCgroupEntrySchema), []),
    collector.read("maps", "Maps", async () => parseArray<RawBpfMap>(await runBpftool("map list"), rawBpfMapSchema), []),
    collector.read("links", "BPF links", async () => parseArray<RawBpfLink>(await runBpftool("link list"), rawBpfLinkSchema), []),
    fetchNetnsData(),
  ]);
  collector.sources.processOwnership = {
    label: "Process ownership", state: bpftoolHasSkeletons === true ? "ok" : bpftoolHasSkeletons === false ? "unsupported" : "unknown",
    attemptedAt: bpftoolCheckedAt, lastSuccessAt: bpftoolHasSkeletons === true ? bpftoolCheckedAt : null,
    detail: bpftoolHasSkeletons === true ? "bpftool reports skeleton support" : "bpftool process-ownership support is unavailable or unverified",
  };
  const tcDevices = new Map<string, number>();
  for (const entry of net[0]?.tc ?? []) tcDevices.set(entry.devname, entry.ifindex);
  const tcFilters = (await Promise.all(Array.from(tcDevices.entries()).flatMap(([devname, ifindex]) =>
    (["ingress", "egress"] as const).map(async direction => {
      const key = `tc:${devname}:${direction}`;
      const label = `${devname}: TC ${direction} ordering`;
      const filters = collector.sources.net.state === "ok"
        ? await collector.read(key, label, () => runTcFilterShow(devname, direction), [])
        : collector.skip<RawTcFilterEntry[]>(key, label, "Host network inventory is stale or unavailable", []);
      return filters.map(filter => ({ ...filter, ifindex }));
    })
  ))).flat();
  if (net[0]) net[0] = { ...net[0], tcFilters };
  collector.prune();
  return { progs, net, cgroups, cgroupsEffective, rawMaps, links, netns };
}

// ─── Poll ──────────────────────────────────────────────────────────────────

async function poll(): Promise<void> {
  if (isPolling) return;
  isPolling = true;

  const pollStart = Date.now();
  try {
    let progs: RawBpfProg[];
    let net: RawNetSnapshot[];
    let cgroups: RawCgroupEntry[];
    let cgroupsEffective: RawCgroupEntry[] = [];

    let rawMaps: RawBpfMap[] = [];
    let links: RawBpfLink[] = [];
    let netns: RawNetnsSnapshot[] = [];

    if (config.demoMode) {
      collection = undefined;
      // Simulate incrementing stats in demo mode so sparklines are always active
      const now = Date.now();
      progs = MOCK_PROGS.map(p => ({
        ...p,
        run_cnt: (p.run_cnt ?? 0) + Math.floor(Math.random() * 200 + 10),
        run_time_ns: (p.run_time_ns ?? 0) + Math.floor(Math.random() * 5_000_000 + 50_000),
      }));
      net = MOCK_NET;
      cgroups = MOCK_CGROUPS;
      cgroupsEffective = [];
      links = MOCK_LINKS;
      netns = MOCK_NETNS;
      void now; // used implicitly via Date.now() in ingestSnapshot
    } else {
      const data = await fetchLiveData();
      progs = data.progs;
      net = data.net;
      cgroups = data.cgroups;
      cgroupsEffective = data.cgroupsEffective;
      rawMaps = data.rawMaps;
      links = data.links;
      netns = data.netns;
    }

    const snap = buildSnapshot(
      progs,
      net,
      cgroups,
      {
        hostname: config.demoMode ? MOCK_SYSTEM.hostname : hostname(),
        kernelVersion,
        bpftoolVersion,
        demoMode: config.demoMode,
        // Demo data always carries pids; live data only when the bpftool
        // build can report them (skeleton support).
        pidsReliable: config.demoMode || bpftoolHasSkeletons === true,
      },
      cgroupsEffective,
      links,
      netns
    );

    snap.collection = collection;

    // ── Parse maps ─────────────────────────────────────────────────────────
    if (config.demoMode) {
      latestMaps = buildMockMaps(snap.programs);
    } else {
      latestMaps = parseMaps(rawMaps, snap.programs);
    }

    // ── Feed the stats ring buffer ──────────────────────────────────────────
    if (!collection || collection.sources.progs?.state === "ok") {
      ingestSnapshot(snap.programs, collection?.sources.progs.lastSuccessAt ?? snap.timestamp);
      pruneStale(new Set(snap.programs.map(p => p.id)));
    }

    latestSnapshot = snap;
    lastError = collection ? collectionError(collection) : null;

    const elapsed = Date.now() - pollStart;
    if (elapsed > 2000 || !latestSnapshot) {
      console.log(`[ebpf-poller] poll completed in ${elapsed}ms — ${snap.stats.total} programs, ${latestMaps.length} maps`);
    }

    for (const cb of Array.from(listeners)) {
      try { cb(snap); } catch { /* ignore listener errors */ }
    }
  } catch (err) {
    lastError = err instanceof Error ? err.message : String(err);
    console.error("[ebpf-poller] poll error:", lastError);
    if (collection) {
      collection.sources.snapshot = { label: "Snapshot assembly", state: "error", attemptedAt: Date.now(),
        lastSuccessAt: latestSnapshot?.timestamp ?? null, error: lastError.slice(0, 2048) };
      if (latestSnapshot && !latestSnapshot.demoMode) {
        // The published model is still the previous one; do not claim freshly
        // collected sections were incorporated into it.
        const sources = Object.fromEntries(Object.entries(collection.sources).map(([key, status]) => [key, {
          ...status, state: status.state === "ok" ? "skipped" as const : status.state,
          lastSuccessAt: latestSnapshot?.collection?.sources[key]?.lastSuccessAt ?? null,
          detail: "Previous snapshot retained after assembly failure",
        }]));
        latestSnapshot = { ...latestSnapshot, collection: { ...collection, sources } };
        for (const cb of Array.from(listeners)) { try { cb(latestSnapshot); } catch { /* isolate listeners */ } }
      }
    }
    // Keep serving the last good snapshot and surface the error via poller
    // status. Swapping in mock data here (as this used to do) presented
    // synthetic programs as live while config.demoMode stayed false, routed
    // prog/map drill-downs at nonexistent kernel IDs, and mixed mock samples
    // into the real stats rings. Demo mode is only entered explicitly, via
    // DEMO_MODE or the startup bpftool availability check.
  } finally {
    isPolling = false;
    if (pendingConfig) {
      const updates = pendingConfig;
      pendingConfig = null;
      updateConfig(updates);
    }
  }
}

// ─── Public API ────────────────────────────────────────────────────────────

export async function startPoller(): Promise<void> {
  // Run system info discovery and bpftool checks in background so the
  // HTTP server can start accepting connections immediately.  SSE clients
  // receive a "ping" until the first snapshot is ready, then get the full
  // data bundle automatically via the subscriber callback.

  // Log if demo mode was requested via env var
  if (config.demoMode) {
    console.log("[ebpf-poller] Demo mode enabled via DEMO_MODE env var — using synthetic data");
    statsEnabled = true;
    kernelVersion = MOCK_SYSTEM.kernelVersion;
    bpftoolVersion = MOCK_SYSTEM.bpftoolVersion;
  } else {
    // Check if bpftool is actually available (runs in background)
    try {
      await getSystemInfo();
      await runBpftool("version");
      // Only try to enable stats when we have a real bpftool
      await ensureBpfStatsEnabled();
    } catch {
      console.warn("[ebpf-poller] bpftool not accessible, enabling demo mode");
      config.demoMode = true;
      statsEnabled = true; // demo mode always has stats
      kernelVersion = MOCK_SYSTEM.kernelVersion;
      bpftoolVersion = MOCK_SYSTEM.bpftoolVersion;
    }
  }

  // First poll runs in background — don't block server startup
  poll().catch(err => {
    console.error("[ebpf-poller] first poll failed:", err);
  });

  if (pollingTimer) clearInterval(pollingTimer);
  pollingTimer = setInterval(poll, config.intervalMs);
}

export function stopPoller(): void {
  if (pollingTimer) {
    clearInterval(pollingTimer);
    pollingTimer = null;
  }
}

/**
 * Undo kernel settings this process changed. Currently: disable
 * kernel.bpf_stats_enabled if we were the ones who enabled it (it adds
 * measurable per-invocation overhead to every BPF program on the host).
 */
export async function restoreKernelSettings(): Promise<void> {
  if (!statsEnabledByUs) return;
  statsEnabledByUs = false;
  try {
    await execAsync("sudo sysctl -w kernel.bpf_stats_enabled=0 2>/dev/null");
    console.log("[ebpf-poller] Restored kernel.bpf_stats_enabled=0");
  } catch {
    console.error("[ebpf-poller] Failed to restore kernel.bpf_stats_enabled — check it manually");
  }
}

export function getLatestSnapshot(): EbpfSnapshot | null {
  return latestSnapshot;
}

export function getLatestMaps(): BpfMap[] {
  return latestMaps;
}

export function isStatsEnabled(): boolean {
  return statsEnabled;
}

export function getPollerStatus(): {
  running: boolean;
  config: PollingConfig;
  lastError: string | null;
  lastPollTime: number | null;
  statsEnabled: boolean;
  /** false = bpftool build cannot report pids (all programs look orphaned);
   *  null = unknown (demo mode, or bpftool too old to list features). */
  bpftoolHasSkeletons: boolean | null;
  collection?: CollectionStatus;
} {
  return {
    running: pollingTimer !== null,
    config,
    lastError,
    lastPollTime: latestSnapshot?.timestamp ?? null,
    statsEnabled,
    bpftoolHasSkeletons,
    collection: latestSnapshot?.collection ?? collection,
  };
}

export function updateConfig(updates: Partial<PollingConfig>): void {
  if (isPolling) {
    pendingConfig = { ...pendingConfig, ...updates };
    return;
  }
  if ((updates.demoMode !== undefined && updates.demoMode !== config.demoMode) ||
      (updates.bpftoolPath !== undefined && updates.bpftoolPath !== config.bpftoolPath) ||
      (updates.sudo !== undefined && updates.sudo !== config.sudo)) {
    collector.clear();
    clearNetnsDiscoveryCache();
    uninterestingNetns.clear();
    clearAll();
    collection = undefined;
    latestSnapshot = null;
    latestMaps = [];
    bpftoolHasSkeletons = null;
    bpftoolCheckedAt = null;
  }
  config = { ...config, ...updates };

  // Restart interval if changed
  if (updates.intervalMs !== undefined && pollingTimer) {
    clearInterval(pollingTimer);
    pollingTimer = setInterval(poll, config.intervalMs);
  }

  // Immediate poll on config change
  poll();
}

export function subscribe(
  cb: (snap: EbpfSnapshot) => void,
  options: { immediate?: boolean } = {}
): () => void {
  listeners.add(cb);
  // Immediately deliver latest if available
  if (options.immediate !== false && latestSnapshot) cb(latestSnapshot);
  return () => listeners.delete(cb);
}

export function triggerPoll(): Promise<void> {
  return poll();
}

// Re-export ring buffer accessors for use in routers
export { getAllHistories, getHistory, buildActivitySummary };

/** Returns true when the poller is running in demo mode (DEMO_MODE env var or auto-fallback). */
export function isDemoMode(): boolean {
  return config.demoMode;
}

export function getBpftoolPath(): string {
  return config.bpftoolPath;
}

export function isSudoEnabled(): boolean {
  return config.sudo;
}
