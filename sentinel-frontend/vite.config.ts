import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The dev server must be reachable on the VM's LAN address as well as on
// loopback: the browser under test opens http://192.168.182.128:5173, and a
// server bound to 127.0.0.1 alone would refuse that. 0.0.0.0 still accepts
// http://localhost:5173, so the local workflow is unaffected.
//
// The API CORS allowlist (correlation/api/cors.py) covers
// http://127.0.0.1:5173 and http://localhost:5173 only; a different origin --
// for example http://192.168.182.128:5173 -- needs a matching
// ANALYTICS_API_ALLOWED_ORIGINS (or FRONTEND_ORIGIN) on the server side.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
  },
  preview: {
    host: '0.0.0.0',
    port: 5173,
  },
})
