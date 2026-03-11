// Stub for vite — only used in the standalone production bundle.
// The setupVite() function is never called in production (NODE_ENV=production),
// so these exports are never invoked at runtime.
export async function createServer() { throw new Error("Vite is not available in standalone mode"); }
export function defineConfig(c) { return c; }
export default { createServer, defineConfig };
