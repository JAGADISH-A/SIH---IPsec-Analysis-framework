/**
 * Deterministic clock smoke — the packet clock is the visible contract of the
 * timestamp change, so it is pinned with fixed inputs rather than asserted
 * against the live feed (whose values move).
 *
 * The pipeline serves one canonical value: an absolute realtime instant
 * (realtime epoch nanoseconds). The UI renders it in the **browser's own local
 * timezone** — no zone is hard-coded. Three representations of the same instant
 * (UTC `Z`, an explicit `+05:30` offset, and raw epoch nanoseconds) must render
 * identically, and UTC is rendered alongside in technical detail views.
 *
 * If a "fix" ever shifts the minute/hour of a known instant, starts printing a
 * hard-coded `IST` (or any fixed zone), or turns sensor uptime into wall time,
 * this smoke fails.
 */
let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}

const { formatLocalClock, formatLocalFull, formatUtcFull, localParts, localTimeZoneId, epochToDate } =
  await import('@/lib/timeZone')

function pad(value: number, width = 2) {
  return String(value).padStart(width, '0')
}

// 2026-09-28T18:34:56.789Z, given three ways. All are the same instant.
const EVENING_NS = 1790620496789000000
const EVENING_Z = '2026-09-28T18:34:56.789Z'
const EVENING_PLUS_0530 = '2026-09-29T00:04:56.789+05:30'

const fromNs = formatLocalClock(EVENING_NS)
const fromZ = formatLocalClock(EVENING_Z)
const fromOffset = formatLocalClock(EVENING_PLUS_0530)
check(
  'UTC, +05:30 and epoch-nanosecond inputs render the same absolute instant',
  fromNs === fromZ && fromZ === fromOffset,
  `${fromNs} | ${fromZ} | ${fromOffset}`,
)
check(
  'the clock is HH:MM:SS.mmm with millisecond precision',
  /^\d{2}:\d{2}:\d{2}\.\d{3}$/.test(fromNs),
  fromNs,
)
check('the clock ends with the input milliseconds', fromNs.endsWith('.789'), fromNs)
check(
  'no hard-coded IST (or any fixed zone) is appended',
  !/IST/.test(fromNs) && !/IST/.test(formatLocalFull(EVENING_NS)),
  formatLocalFull(EVENING_NS),
)

// The rendered clock must equal what the browser's own Date yields: i.e. it is
// the machine's local wall clock, not an offset applied by hand.
const localDate = new Date(EVENING_NS / 1e6)
const browserLocal = `${pad(localDate.getHours())}:${pad(localDate.getMinutes())}:${pad(
  localDate.getSeconds(),
)}.${pad(localDate.getMilliseconds(), 3)}`
check('the clock matches the browser-local Date fields', fromNs === browserLocal, `${fromNs} vs ${browserLocal}`)
check(
  'the full timestamp names the browser-resolved timezone',
  formatLocalFull(EVENING_NS).endsWith(`(${localTimeZoneId()})`),
  formatLocalFull(EVENING_NS),
)

// UTC detail keeps the original absolute instant, independent of local zone.
check(
  'UTC detail keeps the original instant',
  formatUtcFull(EVENING_NS) === '2026-09-28 18:34:56.789 UTC',
  formatUtcFull(EVENING_NS),
)

// 2025-07-25T09:00:00Z given in *seconds*: the seconds guard must recover it.
const SECONDS_VALUE = 1753434000
check(
  'seconds-precision values are still recovered',
  formatUtcFull(SECONDS_VALUE) === '2025-07-25 09:00:00.000 UTC',
  formatUtcFull(SECONDS_VALUE),
)

// A raw CLOCK_MONOTONIC uptime (what xdp_monitor produced before the adapter
// mapped it to the wall clock) must never read as current wall time. This is a
// real value from the sensor journal.
const UPTIME_NS = 187_845_198_053_099
const uptimeYear = epochToDate(UPTIME_NS)?.getFullYear() ?? 0
check('sensor uptime never renders as current wall time', uptimeYear < 2000, `estimated year ${uptimeYear}`)

// Values at or below zero are rejected outright; a positive sub-1e12 value is
// seconds-precision by contract (see SECONDS_VALUE above).
check('missing timestamps render as an em dash', formatLocalClock(null) === '—' && formatLocalFull(undefined) === '—')
check('non-positive timestamps are rejected', epochToDate(-1) === null && epochToDate(0) === null)
check('unparseable strings are rejected, not guessed', epochToDate('not-a-time') === null && localParts('not-a-time') === null)

console.log(failures === 0 ? 'TIMESTAMP CLOCK OK' : `${failures} TIMESTAMP CHECK(S) FAILED`)
if (failures > 0) process.exitCode = 1
