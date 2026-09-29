/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_ANALYTICS_API_URL?: string
  readonly VITE_CONTROL_API_URL?: string
  readonly VITE_EXPERIMENT_POLL_MS?: string
  readonly VITE_API_TIMEOUT_MS?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
