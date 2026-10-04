/**
 * Single source of truth for backend endpoints.
 *
 * Components must never build a backend URL. Everything goes through
 * `analyticsApi` / `controlApi` in `src/api/`, which read these values.
 */

function readNumber(raw: string | undefined, fallback: number): number {
  const parsed = Number(raw)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function readBaseUrl(raw: string | undefined, fallback: string): string {
  const value = (raw ?? fallback).trim().replace(/\/+$/, '')
  return value === '' ? fallback : value
}

/**
 * The host this page was actually opened from.
 *
 * The frontend is served on the testbed VM and opened either as
 * `http://localhost:5173` on that VM or as `http://<lan-ip>:5173` from another
 * machine. `127.0.0.1` only ever means "this machine", so it is correct for the
 * first browser and wrong for the second -- a browser on another host would
 * send the request to *itself* and get ERR_CONNECTION_REFUSED.
 *
 * Deriving the API host from the page's own hostname keeps both workflows
 * working with one configuration: the browser calls the same host it already
 * reached successfully. It is not hard-coded anywhere in the bundle, so a
 * moved or re-addressed VM needs no rebuild.
 *
 * Falls back to `127.0.0.1` where there is no page context (SSR / smoke builds
 * running in Node, where `window` is undefined).
 */
function pageHostname(): string {
  if (typeof window !== 'undefined' && window.location?.hostname) {
    return window.location.hostname
  }
  return '127.0.0.1'
}

/** Absolute base URL for a backend plane, using the page's own host. */
function apiUrl(port: number): string {
  return `http://${pageHostname()}:${port}`
}

/**
 * Every plane can still be pinned explicitly with the matching `VITE_*_API_URL`
 * variable (see `.env.example`); an explicit value always wins over the
 * hostname-derived default below.
 */

/** Server A — read-only analytics plane. */
export const ANALYTICS_API_URL = readBaseUrl(
  import.meta.env.VITE_ANALYTICS_API_URL,
  apiUrl(8081),
)

/** Server B — mutating control plane. */
export const CONTROL_API_URL = readBaseUrl(
  import.meta.env.VITE_CONTROL_API_URL,
  apiUrl(8000),
)

/**
 * Server C — read-only IPsec explanation plane.
 *
 * Deliberately a third plane rather than a route on the analytics API. The
 * analytics plane is GET-only by contract, and a follow-up question has no
 * business in a query string, a browser history or an access log. This service
 * decides nothing and writes nothing; the only verb that does anything is the
 * POST that carries a question.
 */
export const AI_API_URL = readBaseUrl(import.meta.env.VITE_AI_API_URL, apiUrl(8082))

/** Per-request timeout for a single backend call. */
export const API_TIMEOUT_MS = readNumber(import.meta.env.VITE_API_TIMEOUT_MS, 30_000)

/** How often the Run Assessment page polls a running job. */
export const EXPERIMENT_POLL_MS = readNumber(
  import.meta.env.VITE_EXPERIMENT_POLL_MS,
  2_000,
)

/**
 * How often the live traffic monitor re-queries the analysis audit journal.
 *
 * The analytics plane is a read-only query over a JSONL file, not a stream, so
 * this is polling. The default keeps the monitor responsive without turning a
 * read-only file projection into a load test.
 */
export const TRAFFIC_POLL_MS = readNumber(import.meta.env.VITE_TRAFFIC_POLL_MS, 2_500)

/**
 * Hard cap on rows held in the in-memory ring buffer.
 *
 * The buffer exists so an analyst can scroll back through recent activity; it
 * is not a store, and the journal remains the only source of truth. Anything
 * evicted here is still fully readable through the audit routes.
 */
export const TRAFFIC_BUFFER_LIMIT = readNumber(
  import.meta.env.VITE_TRAFFIC_BUFFER_LIMIT,
  2_000,
)

export const isDev = import.meta.env.DEV
