import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

/**
 * Builds one of the `smoke/*.ts` harnesses to `dist-ssr/` so it can run under
 * plain node. Select the harness with SMOKE_ENTRY, e.g.
 *
 *   SMOKE_ENTRY=contract npm run smoke:build && node dist-ssr/smoke.mjs
 *
 * This is verification tooling, not part of the shipped application.
 */
const entry = process.env.SMOKE_ENTRY ?? 'ssr-smoke'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  build: {
    ssr: true,
    outDir: 'dist-ssr',
    emptyOutDir: true,
    minify: false,
    rollupOptions: {
      input: fileURLToPath(new URL(`./smoke/${entry}.ts`, import.meta.url)),
      output: { entryFileNames: 'smoke.mjs' },
    },
  },
})
