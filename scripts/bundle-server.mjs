#!/usr/bin/env node
// bundle-server.mjs — esbuild JS API with plugin to stub vite.config.ts
// This avoids import.meta.dirname (Node 21+) appearing in the production bundle.
import * as esbuild from 'esbuild';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..');
const STUBS_DIR = path.resolve(projectRoot, '.standalone-stubs');

// Plugin: intercept the local vite.config.ts import and replace with a no-op stub.
// vite.config.ts uses import.meta.dirname at module level (Node 21+ only).
// In production the setupVite() path is never taken, so the config is never needed.
const viteConfigStubPlugin = {
  name: 'vite-config-stub',
  setup(build) {
    build.onResolve({ filter: /vite\.config/ }, () => ({
      path: path.join(STUBS_DIR, 'vite-config.mjs'),
    }));
  },
};

await esbuild.build({
  entryPoints: [path.join(projectRoot, 'server/_core/index.ts')],
  platform: 'node',
  bundle: true,
  format: 'esm',
  outfile: path.join(projectRoot, 'dist/server.js'),
  banner: {
    // CJS compatibility shim: lets CommonJS modules (dotenv, mysql2, etc.) work
    // inside an ESM bundle via createRequire.
    js: "import { createRequire } from 'module'; const require = createRequire(import.meta.url);",
  },
  alias: {
    'vite': path.join(STUBS_DIR, 'vite.mjs'),
    'vite-plugin-manus-runtime': path.join(STUBS_DIR, 'vite-plugin-manus-runtime.mjs'),
    '@builder.io/vite-plugin-jsx-loc': path.join(STUBS_DIR, 'vite-plugin-jsx-loc.mjs'),
    '@tailwindcss/vite': path.join(STUBS_DIR, 'tailwindcss-vite.mjs'),
    '@vitejs/plugin-react': path.join(STUBS_DIR, 'vitejs-plugin-react.mjs'),
  },
  plugins: [viteConfigStubPlugin],
  define: {
    'process.env.NODE_ENV': '"production"',
  },
});

console.log('  dist/server.js  bundled \u2713');
