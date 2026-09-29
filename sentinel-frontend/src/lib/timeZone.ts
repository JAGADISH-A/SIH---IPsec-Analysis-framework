/**
 * Wall-clock rendering for canonical nanosecond timestamps.
 *
 * The capture pipeline serves one canonical value: absolute realtime epoch
 * nanoseconds in `timestamp_ns` (converted once by the streaming adapter from
 * the sensor's CLOCK_MONOTONIC). `timestamp_ns` is an *absolute instant* — it
 * does not belong to any place on Earth — so the only remaining choice is how
 * to display it.
 *
 * Sentinel renders packet times in the **browser's own local timezone** (the
 * analyst's machine). No zone is hard-coded: two analysts in different places
 * see the same instant expressed in their own local wall clock, and the zone
 * label, when shown, is the browser's resolved zone. UTC is rendered alongside
 * in technical detail views so the absolute instant stays verifiable.
 *
 * An ISO-8601 string with an explicit offset (`Z`, `+05:30`) is parsed by the
 * `Date` object as the same absolute instant and renders identically, so no
 * offset is ever re-interpreted by hand.
 */

/**
 * Backend timestamps are nanosecond epoch integers; a few legacy values are
 * second-precision (see `nsToDate` in lib/format.ts). ISO strings carrying an
 * explicit offset/UTC are accepted too and parsed as an absolute instant.
 * Nothing else is treated as a date.
 */
export function toInstantMs(value: number | string | null | undefined): number | null {
  if (value === null || value === undefined) return null
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value <= 0) return null
    const ms = value < 1e12 ? value * 1000 : value / 1e6
    return Number.isFinite(ms) ? ms : null
  }
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? ms : null
}

export function epochToDate(value: number | string | null | undefined): Date | null {
  const ms = toInstantMs(value)
  if (ms === null) return null
  const date = new Date(ms)
  return Number.isNaN(date.getTime()) ? null : date
}

/** The browser's resolved IANA timezone (e.g. `Asia/Kolkata`), never a guess. */
export function localTimeZoneId(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

function pad(value: number, width = 2): string {
  return String(value).padStart(width, '0')
}

export type LocalTimeParts = {
  year: number
  month: number
  day: number
  hours: number
  minutes: number
  seconds: number
  milliseconds: number
}

/**
 * Calendar fields of the instant in the *browser's* local timezone. These are
 * plain `Date` accessors, so they read the machine's own zone — the same zone
 * the analyst's clock is set to — with no offset arithmetic.
 */
export function localParts(value: number | string | null | undefined): LocalTimeParts | null {
  const ms = toInstantMs(value)
  if (ms === null) return null
  const date = new Date(ms)
  return {
    year: date.getFullYear(),
    month: date.getMonth() + 1,
    day: date.getDate(),
    hours: date.getHours(),
    minutes: date.getMinutes(),
    seconds: date.getSeconds(),
    milliseconds: date.getMilliseconds(),
  }
}

/** The packet-list clock, browser-local: `HH:MM:SS.mmm`. */
export function formatLocalClock(value: number | string | null | undefined): string {
  const parts = localParts(value)
  if (!parts) return '—'
  return `${pad(parts.hours)}:${pad(parts.minutes)}:${pad(parts.seconds)}.${pad(
    parts.milliseconds,
    3,
  )}`
}

/** Full evidence timestamp, browser-local: `YYYY-MM-DD HH:MM:SS.mmm (Zone)`. */
export function formatLocalFull(value: number | string | null | undefined): string {
  const parts = localParts(value)
  if (!parts) return '—'
  return `${parts.year}-${pad(parts.month)}-${pad(parts.day)} ${pad(parts.hours)}:${pad(
    parts.minutes,
  )}:${pad(parts.seconds)}.${pad(parts.milliseconds, 3)} (${localTimeZoneId()})`
}

/** The matching UTC instant for technical details: `YYYY-MM-DD HH:MM:SS.mmm UTC`. */
export function formatUtcFull(value: number | string | null | undefined): string {
  const date = epochToDate(value)
  if (!date) return '—'
  return `${date.toISOString().replace('T', ' ').slice(0, 23)} UTC`
}
