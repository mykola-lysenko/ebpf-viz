#!/usr/bin/env tsx
import { execFileSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { basename, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { parseXlatedJson } from "../server/ebpf-dump";
import { analyzeXlatedReturns } from "../server/xlated-return-analysis";

interface RawCgroupProgram {
  id: number;
  attach_type?: string;
  attach_flags?: string;
  name?: string;
}

interface RawCgroupEntry {
  cgroup: string;
  programs?: RawCgroupProgram[];
}

interface RawBpfProg {
  id: number;
  type: string;
  name?: string;
}

interface ProgramAnalysis {
  id: number;
  name: string;
  rawType: string;
  attachTypes: string[];
  observedConstants: Array<{ value: number; exitCount: number }>;
  exitCount: number;
  unknownExitCount: number;
  tailCallCount: number;
  sideEffectLabels: string[];
}

interface AttachTypeSummary {
  attachType: string;
  programCount: number;
  exitCount: number;
  constants: Map<number, number>;
  unknownProgramCount: number;
  tailCallProgramCount: number;
  sideEffects: Map<string, number>;
  examples: string[];
}

function usage(): never {
  console.error(
    [
      "Usage:",
      "  pnpm analyze:cgroup-archive -- <archive.tar.gz|extracted-dir> [--json]",
      "",
      "Default archive: ./ebpf-viz-network-latest.tar.gz",
    ].join("\n")
  );
  process.exit(2);
}

function readJson<T>(path: string, fallback: T): T {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return fallback;
  }
}

function findCaptureRoot(baseDir: string): string {
  const queue = [baseDir];
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const dir = queue[cursor];
    const names = readdirSync(dir);
    if (
      names.includes("prog-show.json") &&
      names.includes("cgroup-tree.json") &&
      names.includes("prog")
    ) {
      return dir;
    }
    for (const name of names) {
      const path = join(dir, name);
      if (lstatSync(path).isDirectory()) queue.push(path);
    }
  }
  throw new Error(`Could not find collector root under ${baseDir}`);
}

function resolveCaptureRoot(inputPath: string): {
  root: string;
  cleanup: () => void;
} {
  const absolutePath = resolve(inputPath);
  if (!existsSync(absolutePath)) {
    throw new Error(`Archive or directory does not exist: ${absolutePath}`);
  }

  if (lstatSync(absolutePath).isDirectory()) {
    return { root: findCaptureRoot(absolutePath), cleanup: () => {} };
  }

  const tempDir = mkdtempSync(join(tmpdir(), "ebpf-viz-cgroup-analysis-"));
  execFileSync("tar", ["-xzf", absolutePath, "-C", tempDir], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  return {
    root: findCaptureRoot(tempDir),
    cleanup: () => rmSync(tempDir, { recursive: true, force: true }),
  };
}

function addProgramAttachType(
  attachTypesById: Map<number, Set<string>>,
  program: RawCgroupProgram
) {
  if (!program.attach_type) return;
  const attachTypes = attachTypesById.get(program.id) ?? new Set<string>();
  attachTypes.add(program.attach_type);
  attachTypesById.set(program.id, attachTypes);
}

function collectAttachTypes(
  directCgroups: RawCgroupEntry[],
  effectiveCgroups: RawCgroupEntry[]
): Map<number, Set<string>> {
  const attachTypesById = new Map<number, Set<string>>();
  for (const cgroup of [...directCgroups, ...effectiveCgroups]) {
    for (const program of cgroup.programs ?? []) {
      addProgramAttachType(attachTypesById, program);
    }
  }
  return attachTypesById;
}

function xlatedFiles(progDir: string): string[] {
  return readdirSync(progDir)
    .filter(file => file.endsWith(".xlated.json"))
    .sort((a, b) => Number(a.split("_")[0]) - Number(b.split("_")[0]));
}

function analyzePrograms(root: string): {
  programs: ProgramAnalysis[];
  hasEffectiveCgroupTree: boolean;
} {
  const progs = readJson<RawBpfProg[]>(join(root, "prog-show.json"), []);
  const directCgroups = readJson<RawCgroupEntry[]>(
    join(root, "cgroup-tree.json"),
    []
  );
  const effectiveCgroups = readJson<RawCgroupEntry[]>(
    join(root, "cgroup-tree-effective.json"),
    []
  );
  const attachTypesById = collectAttachTypes(directCgroups, effectiveCgroups);
  const progById = new Map(progs.map(prog => [prog.id, prog]));
  const progDir = join(root, "prog");

  const analyses: ProgramAnalysis[] = [];
  for (const file of xlatedFiles(progDir)) {
    const id = Number(file.split("_")[0]);
    const attachTypes = Array.from(attachTypesById.get(id) ?? []).sort();
    if (attachTypes.length === 0) continue;

    const xlated = parseXlatedJson(readFileSync(join(progDir, file), "utf8"));
    const analysis = analyzeXlatedReturns(xlated);
    const rawProg = progById.get(id);
    analyses.push({
      id,
      name: rawProg?.name ?? basename(file).replace(/\.xlated\.json$/, ""),
      rawType: rawProg?.type ?? "unknown",
      attachTypes,
      observedConstants: analysis.observedConstants,
      exitCount: analysis.exitCount,
      unknownExitCount: analysis.unknownExits.length,
      tailCallCount: analysis.tailCallIndices.length,
      sideEffectLabels: analysis.sideEffects.labels,
    });
  }

  return {
    programs: analyses,
    hasEffectiveCgroupTree: effectiveCgroups.length > 0,
  };
}

function increment(map: Map<number, number>, key: number, amount: number) {
  map.set(key, (map.get(key) ?? 0) + amount);
}

function incrementText(map: Map<string, number>, key: string) {
  map.set(key, (map.get(key) ?? 0) + 1);
}

function summarizeByAttachType(
  programs: ProgramAnalysis[]
): AttachTypeSummary[] {
  const byAttachType = new Map<string, AttachTypeSummary>();
  for (const program of programs) {
    for (const attachType of program.attachTypes) {
      const summary =
        byAttachType.get(attachType) ??
        ({
          attachType,
          programCount: 0,
          exitCount: 0,
          constants: new Map<number, number>(),
          unknownProgramCount: 0,
          tailCallProgramCount: 0,
          sideEffects: new Map<string, number>(),
          examples: [],
        } satisfies AttachTypeSummary);

      summary.programCount += 1;
      summary.exitCount += program.exitCount;
      if (program.unknownExitCount > 0) summary.unknownProgramCount += 1;
      if (program.tailCallCount > 0) summary.tailCallProgramCount += 1;
      for (const observed of program.observedConstants) {
        increment(summary.constants, observed.value, observed.exitCount);
      }
      for (const label of program.sideEffectLabels) {
        incrementText(summary.sideEffects, label);
      }
      if (summary.examples.length < 4) {
        summary.examples.push(`${program.id}:${program.name}`);
      }
      byAttachType.set(attachType, summary);
    }
  }

  return Array.from(byAttachType.values()).sort((a, b) =>
    a.attachType.localeCompare(b.attachType)
  );
}

function mapToObject<T extends string | number>(
  map: Map<T, number>
): Record<string, number> {
  return Object.fromEntries(
    Array.from(map.entries())
      .sort(([a], [b]) => String(a).localeCompare(String(b)))
      .map(([key, value]) => [String(key), value])
  );
}

function formatCountMap<T extends string | number>(
  map: Map<T, number>
): string {
  const entries = Array.from(map.entries()).sort(([a], [b]) =>
    String(a).localeCompare(String(b))
  );
  return entries.length > 0
    ? entries.map(([key, value]) => `${key}:${value}`).join(", ")
    : "none";
}

function printTextReport(
  archivePath: string,
  root: string,
  hasEffectiveCgroupTree: boolean,
  programs: ProgramAnalysis[],
  summaries: AttachTypeSummary[]
) {
  console.log("Cgroup Archive Analysis");
  console.log(`Archive: ${archivePath}`);
  console.log(`Root: ${root}`);
  console.log(
    `Effective cgroup tree: ${hasEffectiveCgroupTree ? "present" : "missing"}`
  );
  console.log(`Analyzed cgroup programs: ${programs.length}`);
  console.log("");
  console.log("By Attach Type");
  for (const summary of summaries) {
    console.log(
      `${summary.attachType}: programs=${summary.programCount}, exits=${summary.exitCount}, constants=[${formatCountMap(summary.constants)}], unknownPrograms=${summary.unknownProgramCount}, tailCallPrograms=${summary.tailCallProgramCount}`
    );
    console.log(`  effects: ${formatCountMap(summary.sideEffects)}`);
    console.log(`  examples: ${summary.examples.join(", ")}`);
  }
}

function main() {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const positional = args.filter(arg => arg !== "--" && arg !== "--json");
  if (positional.includes("-h") || positional.includes("--help")) usage();
  if (positional.length > 1) usage();

  const archivePath = positional[0] ?? "ebpf-viz-network-latest.tar.gz";
  const { root, cleanup } = resolveCaptureRoot(archivePath);
  try {
    const { programs, hasEffectiveCgroupTree } = analyzePrograms(root);
    const summaries = summarizeByAttachType(programs);
    if (json) {
      console.log(
        JSON.stringify(
          {
            archive: archivePath,
            root,
            hasEffectiveCgroupTree,
            analyzedProgramCount: programs.length,
            summaries: summaries.map(summary => ({
              attachType: summary.attachType,
              programCount: summary.programCount,
              exitCount: summary.exitCount,
              constants: mapToObject(summary.constants),
              unknownProgramCount: summary.unknownProgramCount,
              tailCallProgramCount: summary.tailCallProgramCount,
              sideEffects: mapToObject(summary.sideEffects),
              examples: summary.examples,
            })),
          },
          null,
          2
        )
      );
    } else {
      printTextReport(
        archivePath,
        root,
        hasEffectiveCgroupTree,
        programs,
        summaries
      );
    }
  } finally {
    cleanup();
  }
}

main();
