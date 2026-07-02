import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
    },
  },
  envDir: path.resolve(import.meta.dirname),
  optimizeDeps: {
    // Lazily imported by the Code Inspector CFG tab; without pre-bundling,
    // the first CFG render triggers an on-the-fly optimize + full page reload.
    include: ["@viz-js/viz"],
  },
  root: path.resolve(import.meta.dirname, "client"),
  publicDir: path.resolve(import.meta.dirname, "client", "public"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
    // The Viz.js renderer is a lazy, opt-in CFG chunk. Keep the warning limit
    // just above that known module while the app shell remains below 500 kB.
    chunkSizeWarningLimit: 1500,
  },
  server: {
    host: true,
    fs: {
      strict: true,
      deny: ["**/.*"],
    },
  },
});
