import { z } from "zod";

export const MAX_SNAPSHOT_PROGRAMS = 100_000;
export const MAX_SNAPSHOT_MAPS = 100_000;
export const MAX_SNAPSHOT_NET_ENTRIES = 20_000;
export const MAX_SNAPSHOT_CGROUPS = 100_000;
export const MAX_SNAPSHOT_LINKS = 100_000;
export const MAX_SNAPSHOT_NETNS = 256;
export const MAX_MAP_DUMP_MAPS = 10_000;

const idSchema = z.number().int().min(0).refine(Number.isFinite, "must be finite");
const finiteNumberSchema = z.number().refine(Number.isFinite, "must be finite");
const optionalTextSchema = z.string().max(4096).optional();
const hexByteSchema = z.string().regex(/^0x[0-9a-fA-F]{1,2}$/, "expected a hex byte like 0x00");
const hexBytesSchema = z.array(hexByteSchema);

const jsonValueSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.string(),
    finiteNumberSchema,
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ])
);

const btfValueSchema = z.union([hexBytesSchema, jsonValueSchema]);

export const rawBpfProgSchema = z.object({
  id: idSchema,
  type: z.string().min(1),
}).catchall(z.unknown());

export const rawBpfMapSchema = z.object({
  id: idSchema,
  type: z.string().min(1),
}).catchall(z.unknown());

export const rawNetSnapshotSchema = z.record(z.string(), z.unknown());

export const rawNetnsLinkSchema = z.object({
  ifindex: finiteNumberSchema,
  ifname: z.string().max(256),
}).catchall(z.unknown());

export const rawNetnsSnapshotSchema = z.object({
  id: z.string().min(1).max(128),
  label: z.string().min(1).max(256),
  net: z.array(rawNetSnapshotSchema).max(MAX_SNAPSHOT_NET_ENTRIES),
  links: z.array(rawNetnsLinkSchema).max(MAX_SNAPSHOT_NET_ENTRIES).optional(),
}).catchall(z.unknown());

export const rawBpfLinkSchema = z.object({
  id: idSchema,
  type: z.string().min(1),
}).catchall(z.unknown());

export const rawCgroupEntrySchema = z.object({
  cgroup: z.string().min(1),
  programs: z.array(z.object({
    id: idSchema,
    attach_type: z.string().optional(),
  }).catchall(z.unknown())).optional(),
}).catchall(z.unknown());

export const rawSnapshotPayloadSchema = z.object({
  progs: z.array(rawBpfProgSchema).max(MAX_SNAPSHOT_PROGRAMS),
  maps: z.array(rawBpfMapSchema).max(MAX_SNAPSHOT_MAPS).optional(),
  net: z.array(rawNetSnapshotSchema).max(MAX_SNAPSHOT_NET_ENTRIES).optional(),
  tcFilters: z.array(z.unknown()).max(MAX_SNAPSHOT_NET_ENTRIES).optional(),
  cgroups: z.array(rawCgroupEntrySchema).max(MAX_SNAPSHOT_CGROUPS).optional(),
  cgroupsEffective: z
    .array(rawCgroupEntrySchema)
    .max(MAX_SNAPSHOT_CGROUPS)
    .optional(),
  links: z.array(rawBpfLinkSchema).max(MAX_SNAPSHOT_LINKS).optional(),
  netns: z.array(rawNetnsSnapshotSchema).max(MAX_SNAPSHOT_NETNS).optional(),
});

const bpfAttachmentSchema = z.object({
  kind: z.string().min(1),
  detail: z.string(),
  ifname: z.string().optional(),
  cgroupPath: z.string().optional(),
  attachFlags: z.string().optional(),
  direction: z.enum(["ingress", "egress"]).optional(),
}).catchall(z.unknown());

const bpfProgramSchema = z.object({
  id: idSchema,
  type: z.string().min(1),
  rawType: z.string().min(1),
  name: z.string(),
  tag: z.string(),
  gplCompatible: z.boolean(),
  loadedAt: finiteNumberSchema,
  orphaned: z.boolean(),
  bytesXlated: finiteNumberSchema,
  jited: z.boolean(),
  memlock: finiteNumberSchema,
  mapIds: z.array(idSchema),
  btfId: idSchema.optional(),
  runTimeNs: finiteNumberSchema.optional(),
  runCnt: finiteNumberSchema.optional(),
  pids: z.array(z.object({
    pid: idSchema,
    comm: z.string(),
  })).optional(),
  attachments: z.array(bpfAttachmentSchema),
  osiLayer: z.string().min(1),
  color: z.string().min(1),
}).catchall(z.unknown());

const networkLayersSchema = z.object({
  L2: z.array(bpfProgramSchema),
  L3: z.array(bpfProgramSchema),
  L4: z.array(bpfProgramSchema),
  L7: z.array(bpfProgramSchema),
});

const cgroupNodeSchema: z.ZodType<unknown> = z.lazy(() => z.object({
  path: z.string().min(1),
  name: z.string(),
  depth: idSchema,
  programs: z.array(bpfProgramSchema),
  children: z.array(cgroupNodeSchema),
}).catchall(z.unknown()));

const kernelZoneSchema = z.object({
  zone: z.string().min(1),
  label: z.string(),
  description: z.string(),
  programs: z.array(bpfProgramSchema),
  osiLayer: z.string().min(1),
}).catchall(z.unknown());

const programChainSchema = z.object({
  hookId: z.string(),
  hookLabel: z.string(),
  hookType: z.enum(["cgroup", "tc", "xdp", "netfilter"]),
  attachPoint: z.string(),
  attachType: z.string(),
  programs: z.array(z.object({
    id: idSchema,
    position: z.number().int().min(1),
    name: z.string(),
    attachFlags: z.string().optional(),
  }).catchall(z.unknown())),
  chainSource: z
    .enum(["kernel-effective", "inferred", "tc-filter", "bpftool-net"])
    .optional(),
  canShortCircuit: z.boolean(),
  packetContext: z.object({
    family: z.enum(["xdp", "tc", "cgroup_skb", "cgroup_sock_addr", "cgroup_sock", "netfilter", "unknown"]),
    direction: z.enum(["ingress", "egress", "bidirectional", "unknown"]),
    summary: z.string(),
    semantics: z.object({
      pass: z.array(z.string()),
      passValues: z.array(finiteNumberSchema).optional(),
      drop: z.array(z.string()),
      dropValues: z.array(finiteNumberSchema).optional(),
      redirect: z.array(z.string()),
      redirectValues: z.array(finiteNumberSchema).optional(),
      other: z.array(z.string()),
      otherValues: z.array(finiteNumberSchema).optional(),
    }).catchall(z.unknown()),
  }).catchall(z.unknown()).optional(),
}).catchall(z.unknown());

export const ebpfSnapshotSchema = z.object({
  timestamp: z.number().int().min(0).refine(Number.isFinite, "must be finite"),
  hostname: z.string(),
  kernelVersion: z.string(),
  bpftoolVersion: z.string(),
  demoMode: z.boolean(),
  programs: z.array(bpfProgramSchema).max(MAX_SNAPSHOT_PROGRAMS),
  networkInterfaces: z.array(z.object({
    name: z.string(),
    ifindex: finiteNumberSchema,
    kind: z.enum(["nic", "sockmap"]),
    layers: networkLayersSchema,
    allPrograms: z.array(bpfProgramSchema),
  }).catchall(z.unknown())),
  cgroupTree: z.array(cgroupNodeSchema).max(MAX_SNAPSHOT_CGROUPS),
  kernelZones: z.array(kernelZoneSchema),
  programChains: z.array(programChainSchema),
  stats: z.object({
    total: finiteNumberSchema,
    byType: z.record(z.string(), finiteNumberSchema),
    jited: finiteNumberSchema,
    orphaned: finiteNumberSchema,
  }),
}).catchall(z.unknown());

export const bpfMapSchema = z.object({
  id: idSchema,
  type: z.string().min(1),
  rawType: z.string().min(1),
  name: z.string(),
  flags: finiteNumberSchema,
  bytesKey: finiteNumberSchema,
  bytesValue: finiteNumberSchema,
  maxEntries: finiteNumberSchema,
  bytesMemlock: finiteNumberSchema,
  frozen: z.boolean(),
  pinnedPaths: z.array(z.string()),
  btfId: idSchema.optional(),
  usedByProgIds: z.array(idSchema),
  color: z.string(),
  category: z.enum(["data", "event", "control", "socket", "other"]),
}).catchall(z.unknown());

export const rawMapEntrySchema = z.object({
  key: btfValueSchema,
  value: btfValueSchema.optional(),
  values: z.array(z.object({
    cpu: idSchema,
    value: btfValueSchema,
  }).catchall(z.unknown())).optional(),
  formatted: z.object({
    key: btfValueSchema,
    value: btfValueSchema,
  }).partial().optional(),
}).catchall(z.unknown()).refine(
  entry => entry.value !== undefined || entry.values !== undefined,
  "map entry must include 'value' or 'values'"
);

const numericIdKeySchema = z.string().regex(/^(0|[1-9]\d*)$/, "map dump keys must be numeric map IDs");

const mapDumpRecordSchema = z
  .record(numericIdKeySchema, z.array(rawMapEntrySchema))
  .superRefine((record, ctx) => {
    if (Object.keys(record).length > MAX_MAP_DUMP_MAPS) {
      ctx.addIssue({
        code: "custom",
        message: `mapDumps contains too many maps; maximum is ${MAX_MAP_DUMP_MAPS}`,
      });
    }
  });

export const rawSnapshotInputSchema = z.object({
  raw: rawSnapshotPayloadSchema,
  hostname: optionalTextSchema,
  kernelVersion: optionalTextSchema,
  bpftoolVersion: optionalTextSchema,
  capturedAt: optionalTextSchema,
  timestamp: z.number().int().min(0).refine(Number.isFinite, "must be finite").optional(),
});

export const snapshotUploadSchema = z.object({
  _ebpfVizSnapshot: z.literal(true),
  _version: z.number().int().min(1).optional(),
  capturedAt: optionalTextSchema,
  timestamp: z.number().int().min(0).refine(Number.isFinite, "must be finite").optional(),
  hostname: optionalTextSchema,
  kernelVersion: optionalTextSchema,
  bpftoolVersion: optionalTextSchema,
  demoMode: z.boolean().optional(),
  raw: rawSnapshotPayloadSchema.optional(),
  snapshot: ebpfSnapshotSchema.optional(),
  maps: z.array(bpfMapSchema).max(MAX_SNAPSHOT_MAPS).optional(),
}).superRefine((value, ctx) => {
  if (!value.raw && !value.snapshot) {
    ctx.addIssue({
      code: "custom",
      path: ["snapshot"],
      message: "snapshot file must include either 'snapshot' or 'raw'",
    });
  }
});

export const parseMapDumpsInputSchema = z.object({
  mapDumps: mapDumpRecordSchema,
  maps: z.array(z.object({
    id: idSchema,
    rawType: z.string().min(1),
    name: z.string(),
  })).max(MAX_SNAPSHOT_MAPS).optional(),
});

export const mapDumpsUploadSchema = z.object({
  _ebpfVizMapDumps: z.literal(true),
  _version: z.number().int().min(1).optional(),
  capturedAt: optionalTextSchema,
  hostname: optionalTextSchema,
  snapshotFile: optionalTextSchema,
  mapDumps: mapDumpRecordSchema,
});

export function formatValidationError(prefix: string, error: z.ZodError): string {
  const details = error.issues.slice(0, 6).map(issue => {
    const path = issue.path.length > 0 ? issue.path.join(".") : "root";
    return `${path}: ${issue.message}`;
  });
  const suffix = error.issues.length > details.length
    ? `\n...and ${error.issues.length - details.length} more validation errors`
    : "";
  return `${prefix}\n${details.join("\n")}${suffix}`;
}
