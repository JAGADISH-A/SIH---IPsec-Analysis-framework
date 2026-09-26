/* ------------------------------------------------------------------ */
/* Shared display-format helpers. Pure and backend-agnostic.           */
/* ------------------------------------------------------------------ */

const pad = (n: number, width = 2): string => String(n).padStart(width, '0')

/** Format an ISO arrival timestamp as HH:MM:SS.mmm in local time. */
export function formatArrivalTime(iso: string): string {
  const d = new Date(iso)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
}

export function formatDuration(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000))
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  return hours > 0
    ? `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`
    : `${pad(minutes)}:${pad(seconds)}`
}

/** Locale-comma count, e.g. 12,345. */
export function formatCompact(value: number): string {
  return value.toLocaleString('en-US')
}

/**
 * Compact day-and-time stamp for "when did this happen" readouts.
 *
 * Today and yesterday are named rather than dated — an operator reading a
 * capture list cares about recency first and the exact date second.
 */
export function formatDayTime(iso: string | null): string {
  if (!iso) return 'No capture yet'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'Unknown'
  const time = `${pad(date.getHours())}:${pad(date.getMinutes())}`
  const startOfToday = new Date()
  startOfToday.setHours(0, 0, 0, 0)
  const dayMs = 24 * 60 * 60 * 1000
  if (date.getTime() >= startOfToday.getTime()) return `Today, ${time}`
  if (date.getTime() >= startOfToday.getTime() - dayMs) return `Yesterday, ${time}`
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + `, ${time}`
}

export function formatBitsPerSecond(bps: number): string {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mbps`
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} kbps`
  return `${Math.round(bps)} bps`
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} kB`
  return `${bytes} B`
}
/**
 * A confidence estimate, as a whole percentage.
 *
 * A `null` estimate renders as an explicit `Unknown`: an absent estimate and a
 * zero estimate mean very different things, so they must never look alike.
 */
export function formatPercent(value: number | null): string {
  if (value === null) return 'Unknown'
  return `${Math.round(Math.min(1, Math.max(0, value)) * 100)}%`
}
