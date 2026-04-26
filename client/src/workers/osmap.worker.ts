import { buildOsMapLayout } from "../hooks/useOsMapLayout";

self.onmessage = (e: MessageEvent) => {
  const { snapshot, maps, lod, maxCgroupDepth, focusedProgIds, reqId } = e.data;
  
  const layout = buildOsMapLayout(snapshot, maps, lod, maxCgroupDepth, focusedProgIds);
  
  self.postMessage({ reqId, layout });
};
