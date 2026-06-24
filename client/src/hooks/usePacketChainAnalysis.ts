import { useMemo } from "react";
import { trpc } from "@/lib/trpc";
import type { AppMode } from "@/contexts/EbpfContext";
import type {
  BpfMap,
  BpfProgram,
  MapDumpResult,
  ProgramChain,
  ProgramReturnAnalysisResult,
} from "../../../shared/ebpf-types";

const MAX_RETURN_ANALYSIS_PROGRAMS = 64;
const MAX_TAIL_CALL_MAP_DUMPS = 16;
const MAX_TAIL_CALL_TARGET_ANALYSIS_PROGRAMS = 32;

export function usePacketChainAnalysis({
  chains,
  filteredPrograms,
  searchQuery,
  appMode,
  maps,
  snapshotMapDumps,
}: {
  chains: ProgramChain[];
  filteredPrograms: BpfProgram[];
  searchQuery: string;
  appMode: AppMode;
  maps: BpfMap[];
  snapshotMapDumps: Record<number, MapDumpResult>;
}) {
  const filteredProgramIds = useMemo(
    () =>
      searchQuery ? new Set(filteredPrograms.map(program => program.id)) : null,
    [filteredPrograms, searchQuery]
  );

  const returnAnalysisProgramIds = useMemo(() => {
    const ids = new Set<number>();
    for (const chain of chains) {
      if (!chain.packetContext) continue;
      for (const program of chain.programs) {
        if (filteredProgramIds && !filteredProgramIds.has(program.id)) continue;
        ids.add(program.id);
      }
    }
    return Array.from(ids).slice(0, MAX_RETURN_ANALYSIS_PROGRAMS);
  }, [chains, filteredProgramIds]);

  const returnAnalysisQuery = trpc.ebpf.progReturnAnalysis.useQuery(
    { ids: returnAnalysisProgramIds },
    {
      enabled: appMode !== "snapshot" && returnAnalysisProgramIds.length > 0,
      retry: 1,
      staleTime: 5 * 60_000,
    }
  );

  const baseReturnAnalysisById = useMemo(() => {
    const map = new Map<number, ProgramReturnAnalysisResult>();
    for (const result of returnAnalysisQuery.data ?? []) {
      map.set(result.progId, result);
    }
    return map;
  }, [returnAnalysisQuery.data]);

  const tailCallMapIds = useMemo(() => {
    const progArrayMapIds = new Set(
      maps
        .filter(
          map => map.rawType.toLowerCase().replace(/-/g, "_") === "prog_array"
        )
        .map(map => map.id)
    );
    const ids = new Set<number>();
    for (const result of Array.from(baseReturnAnalysisById.values())) {
      for (const tailCall of result.returnAnalysis?.tailCalls ?? []) {
        if (
          tailCall.mapId !== undefined &&
          progArrayMapIds.has(tailCall.mapId)
        ) {
          ids.add(tailCall.mapId);
        }
      }
    }
    return Array.from(ids).slice(0, MAX_TAIL_CALL_MAP_DUMPS);
  }, [baseReturnAnalysisById, maps]);

  const progArrayDumpQueries = trpc.useQueries(t =>
    tailCallMapIds.map(mapId =>
      t.ebpf.mapDump(
        { id: mapId },
        {
          enabled: appMode !== "snapshot",
          retry: 1,
          staleTime: 30_000,
        }
      )
    )
  );

  const progArrayTargets = useMemo(() => {
    if (appMode === "snapshot") {
      return tailCallMapIds.flatMap(
        mapId => snapshotMapDumps[mapId]?.progArrayTargets ?? []
      );
    }
    return progArrayDumpQueries.flatMap(
      query => query.data?.progArrayTargets ?? []
    );
  }, [appMode, progArrayDumpQueries, snapshotMapDumps, tailCallMapIds]);

  const tailCallTargetProgramIds = useMemo(() => {
    const baseIds = new Set(returnAnalysisProgramIds);
    const ids = new Set<number>();
    for (const target of progArrayTargets) {
      if (!baseIds.has(target.targetProgId)) {
        ids.add(target.targetProgId);
      }
    }
    return Array.from(ids).slice(0, MAX_TAIL_CALL_TARGET_ANALYSIS_PROGRAMS);
  }, [progArrayTargets, returnAnalysisProgramIds]);

  const tailCallTargetAnalysisQuery = trpc.ebpf.progReturnAnalysis.useQuery(
    { ids: tailCallTargetProgramIds },
    {
      enabled: appMode !== "snapshot" && tailCallTargetProgramIds.length > 0,
      retry: 1,
      staleTime: 5 * 60_000,
    }
  );

  const returnAnalysisById = useMemo(() => {
    const map = new Map(baseReturnAnalysisById);
    for (const result of tailCallTargetAnalysisQuery.data ?? []) {
      map.set(result.progId, result);
    }
    return map;
  }, [baseReturnAnalysisById, tailCallTargetAnalysisQuery.data]);

  const returnAnalysisLoading =
    returnAnalysisQuery.isLoading ||
    returnAnalysisQuery.isFetching ||
    tailCallTargetAnalysisQuery.isLoading ||
    tailCallTargetAnalysisQuery.isFetching;

  return {
    returnAnalysisById,
    returnAnalysisLoading,
    progArrayTargets,
  };
}
