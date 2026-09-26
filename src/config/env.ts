/**
 * Typed access to the build-time environment.
 *
 * Only `VITE_`-prefixed variables reach the browser. Nothing secret may be added
 * here: everything in this object ships to the client, so credentials belong in
 * a backend or an httpOnly cookie, never in a `VITE_` variable.
 */

function readString(value: string | undefined, fallback: string): string {
  const trimmed = value?.trim()
  return trimmed ? trimmed : fallback
}

function readNumber(value: string | undefined, fallback: number): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function readBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback
  return value.trim().toLowerCase() === 'true'
}

export const env = {
  /** Serve simulated data from the frontend. */
  useMockData: readBoolean(import.meta.env.VITE_USE_MOCK_DATA, true),
  /** Base URL of the future REST API. Unused while mock data is on. */
  apiBaseUrl: readString(import.meta.env.VITE_API_BASE_URL, '/api/v1'),
  /** Default dashboard/session refresh cadence in milliseconds. */
  refreshIntervalMs: readNumber(import.meta.env.VITE_REFRESH_INTERVAL_MS, 30_000),
  /** Poll cadence for live monitor events. */
  liveEventIntervalMs: readNumber(import.meta.env.VITE_LIVE_EVENT_INTERVAL_MS, 2_600),
  appName: readString(import.meta.env.VITE_APP_NAME, 'IPsec Sentinel'),
} as const

export type Env = typeof env
