import { instance } from "@viz-js/viz";

type CfgRenderWorkerRequest = {
  id: number;
  dot: string;
};

type CfgRenderWorkerResponse =
  | {
      id: number;
      ok: true;
      svg: string;
    }
  | {
      id: number;
      ok: false;
      error: string;
    };

let vizPromise: ReturnType<typeof instance> | null = null;

function getViz() {
  if (!vizPromise) {
    vizPromise = instance();
  }
  return vizPromise;
}

self.onmessage = async (event: MessageEvent<CfgRenderWorkerRequest>) => {
  const { id, dot } = event.data;

  try {
    const viz = await getViz();
    const svg = viz.renderString(dot, { format: "svg" });
    self.postMessage({ id, ok: true, svg } satisfies CfgRenderWorkerResponse);
  } catch (error) {
    self.postMessage({
      id,
      ok: false,
      error: errorMessage(error, "Failed to render CFG"),
    } satisfies CfgRenderWorkerResponse);
  }
};

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

export {};
