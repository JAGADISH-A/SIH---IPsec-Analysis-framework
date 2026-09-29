import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The dev server is pinned to 5173 because the analytics API's CORS allowlist
// (correlation/api/cors.py) covers http://127.0.0.1:5173 and
// http://localhost:5173 only. A different port needs a matching
// ANALYTICS_API_ALLOWED_ORIGINS on the server side.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
  preview: {
    host: '127.0.0.1',
    port: 5173,
  },
})
