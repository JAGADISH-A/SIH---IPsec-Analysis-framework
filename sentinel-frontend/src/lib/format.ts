import type { Severity } from '@/types'

/* ------------------------------------------------------------------ severity */

/**
 * Severity is the product's core question, so this is the one palette where
 * colour is allowed to carry meaning.
 *
 * Each band is a light, desaturated tone that stays legible as text on the
 * dark canvas, paired with a translucent tint for the chip background. The
 * bands also differ in lightness, not only hue, so the ramp survives greyscale
 * and the common forms of colour blindness.
 *
 * `hex` exists for Recharts, which cannot use Tailwind class names.
 */
export const SEVERITY_STYLE: Record<
  string,
  { text: string; bg: string; border: string; dot: string; bar: string; hex: string }
> = {
  CRITICAL: {
    text: 'text-critical',
    bg: 'bg-critical/8',
    border: 'ring-critical/25',
    dot: 'bg-critical',
    bar: 'bg-critical',
    hex: '#f87171',
  },
  HIGH: {
    text: 'text-high',
    bg: 'bg-high/10',
    border: 'ring-high/25',
    dot: 'bg-high',
    bar: 'bg-high',
    hex: '#fb923c',
  },
  MEDIUM: {
    text: 'text-medium',
    bg: 'bg-medium/10',
    border: 'ring-medium/25',
    dot: 'bg-medium',
    bar: 'bg-medium',
    hex: '#fbbf24',
  },
  LOW: {
    text: 'text-low',
    bg: 'bg-low/8',
    border: 'ring-low/25',
    dot: 'bg-low',
    bar: 'bg-low',
    hex: '#60a5fa',
  },
  INFO: {
    text: 'text-ink-dim',
    bg: 'bg-panel-3',
    border: 'ring-edge',
    dot: 'bg-ink-faint',
    bar: 'bg-ink-faint',
    hex: '#9aa2ad',
  },
}

const UNKNOWN_SEVERITY = {
  text: 'text-ink-dim',
  bg: 'bg-panel-3',
  border: 'ring-edge',
  dot: 'bg-ink-faint',
  bar: 'bg-ink-faint',
  hex: '#9aa2ad',
}

export function severityStyle(severity: string | null | undefined) {
  if (!severity) return UNKNOWN_SEVERITY
  return SEVERITY_STYLE[severity.toUpperCase()] ?? UNKNOWN_SEVERITY
}

/** Chart-ready hex for a severity, so Recharts matches the UI palette. */
export function severityHex(severity: string | null | undefined): string {
  return severityStyle(severity).hex
}

/* ---------------------------------------------------------------- correlation */

export const COMPARISON_STYLE: Record<string, { text: string; bg: string; border: string; hex: string }> = {
  MATCH: { text: 'text-good', bg: 'bg-good/8', border: 'border-good/25', hex: '#34d399' },
  MISMATCH: {
    text: 'text-critical',
    bg: 'bg-critical/8',
    border: 'border-critical/25',
    hex: '#f87171',
  },
  UNKNOWN: { text: 'text-ink-faint', bg: 'bg-panel-3', border: 'border-edge', hex: '#9aa2ad' },
  NOT_APPLICABLE: {
    text: 'text-ink-faint',
    bg: 'bg-panel-2',
    border: 'border-edge-soft',
    hex: '#9aa2ad',
  },
}

export function comparisonStyle(status: string) {
  return COMPARISON_STYLE[status] ?? COMPARISON_STYLE.UNKNOWN
}

/* --------------------------------------------------------------- formatting */

/**
 * The backend emits nanosecond epoch integers. These render them as wall-clock
 * times; the raw integer is always shown alongside so nothing is lost.
 */
export function nsToDate(ns: number | null | undefined): Date | null {
  if (ns === null || ns === undefined || !Number.isFinite(ns) || ns <= 0) return null
  // Timestamps below this threshold are seconds, not nanoseconds.
  const ms = ns < 1e12 ? ns * 1000 : ns / 1e6
  const date = new Date(ms)
  return Number.isNaN(date.getTime()) ? null : date
}

function toDate(value: number | string | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null
  if (typeof value === 'string') {
    const parsed = new Date(value)
    return Number.isNaN(parsed.getTime()) ? null : parsed
  }
  return nsToDate(value)
}

export function formatDateTime(ns: number | string | null | undefined): string {
  const date = toDate(ns)
  if (!date) return '—'
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatUtc(ns: number | string | null | undefined): string {
  const date = toDate(ns)
  if (!date) return '—'
  return `${date.toISOString().replace('T', ' ').slice(0, 19)}Z`
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—'
  return value.toLocaleString()
}

export function formatPercent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—'
  return `${(value * 100).toFixed(digits)}%`
}

/** Renders any backend value as a compact, readable cell value. */
export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') return formatNumber(value)
  if (typeof value === 'string') return value === '' ? '—' : value
  return JSON.stringify(value)
}

/** A short, human label for a snake_case token. */
export function humanize(token: string): string {
  if (!token) return ''
  return token
    .replace(/[._-]+/g, ' ')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(' ')
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

export function truncate(value: string, max: number): string {
  if (value.length <= max) return value
  return `${value.slice(0, max - 1)}…`
}

/**
 * Coarse relative time, for "latest activity" and "assessed 4m ago" labels.
 *
 * Deliberately coarse: an analyst needs to know whether an assessment is recent
 * or historical, not the exact second, and the absolute timestamp is one hover
 * away. Anything under a minute reads as "just now" rather than as a jittery
 * per-second counter.
 */
export function formatRelative(value: number | string | null | undefined): string {
  const date = toDate(value)
  if (!date) return '—'
  const seconds = Math.round((Date.now() - date.getTime()) / 1000)
  const future = seconds < 0
  const abs = Math.abs(seconds)
  const suffix = future ? 'from now' : 'ago'

  if (abs < 45) return future ? 'in a moment' : 'just now'
  if (abs < 3600) return `${Math.round(abs / 60)} min ${suffix}`
  if (abs < 86_400) {
    const hours = Math.round(abs / 3600)
    return `${hours} ${hours === 1 ? 'hour' : 'hours'} ${suffix}`
  }
  const days = Math.round(abs / 86_400)
  if (days < 30) return `${days} ${days === 1 ? 'day' : 'days'} ${suffix}`
  return formatDateTime(value)
}

/**
 * The one string for "the backend did not report this".
 *
 * Distinguishing "absent" from "zero" is the whole discipline of this product:
 * an absent measurement must never render as a value, so every unknown in the
 * UI funnels through here.
 */
export const NOT_OBSERVABLE = 'Not observable'

export function shortHash(hash: string | null | undefined, head = 10, tail = 6): string {
  if (!hash) return '—'
  if (hash.length <= head + tail + 1) return hash
  return `${hash.slice(0, head)}…${hash.slice(-tail)}`
}

/** The last path segment of an artifact path, for a compact label. */
export function artifactName(path: string | null | undefined): string {
  if (!path) return '—'
  const parts = path.split('/')
  return parts[parts.length - 1] || path
}

export type SortDirection = 'asc' | 'desc'

export function compareValues(a: unknown, b: unknown): number {
  if (a === b) return 0
  if (a === null || a === undefined) return 1
  if (b === null || b === undefined) return -1
  if (typeof a === 'number' && typeof b === 'number') return a - b
  if (typeof a === 'boolean' && typeof b === 'boolean') {
    return Number(a) - Number(b)
  }
  return String(a).localeCompare(String(b), undefined, { numeric: true })
}

export function severityRank(severity: string | null | undefined): number {
  const order: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
  const index = order.indexOf((severity ?? '').toUpperCase() as Severity)
  return index === -1 ? order.length : index
}
