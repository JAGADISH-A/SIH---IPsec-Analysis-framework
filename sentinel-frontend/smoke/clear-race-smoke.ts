/**
 * Clear durability + race regression smoke.
 *
 * This drives the REAL `useCaptureFeed` state machine in jsdom with an
 * injected page fetcher over a scripted, append-only journal, so every
 * assertion is deterministic (no network, no lab, no timing luck) while still
 * exercising the exact production code path: byte-cursor tail, bounded buffer,
 * the `current` verdict, and the Clear button the analyst clicks.
 *
 * What is pinned here:
 *
 *   1. Mounting onto a journal that already holds rows shows NONE of them.
 *      Those rows are recorded history; only rows appended after this view
 *      opened are live.
 *   2. Clear empties the buffer AND moves the resume watermark to the
 *      journal's end, so cleared packets can never be re-read — the counters
 *      read `0 shown · 0 buffered · N in journal` with N untouched.
 *   3. Clear while a poll is in flight: the in-flight page is discarded, so a
 *      stale response can never repopulate the buffer. Its own (pre-Clear)
 *      size still tightens the watermark, so rows written before the click
 *      stay excluded forever.
 *   4. Clear is repeatable while polling continues: the next new packet shows,
 *      the previous one never returns, and the journal row count only ever
 *      grows (Clear is a view/buffer operation; evidence is never touched).
 */
import { JSDOM } from 'jsdom'

const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>', {
  url: 'http://127.0.0.1:5173/',
  pretendToBeVisual: true,
})
const g = globalThis as unknown as Record<string, unknown>
const define = (key: string, value: unknown) =>
  Object.defineProperty(g, key, { value, configurable: true, writable: true })
define('window', dom.window)
define('document', dom.window.document)
define('navigator', dom.window.navigator)
define('HTMLElement', dom.window.HTMLElement)
define('Element', dom.window.Element)
define('Node', dom.window.Node)
define('SVGElement', dom.window.SVGElement)
define('MutationObserver', dom.window.MutationObserver)
define('getComputedStyle', dom.window.getComputedStyle)
define('requestAnimationFrame', dom.window.requestAnimationFrame)
define('cancelAnimationFrame', dom.window.cancelAnimationFrame)
define('IS_REACT_ACT_ENVIRONMENT', true)

const consoleErrors: string[] = []
const origError = console.error
console.error = (...args: unknown[]) => {
  const detail = args.map((a) => (a instanceof Error ? a.message : String(a))).join(' ')
  // React's "not wrapped in act(...)" notice is a jsdom/timer-harness artifact
  // (the hook's async poll resolves outside an act window by design here), and
  // this harness's own FAIL lines are its, not the app's. Real render errors
  // are still collected.
  if (!detail.includes('not wrapped in act') && !detail.startsWith('FAIL ')) consoleErrors.push(detail)
  origError(...args)
}

const { createRoot } = await import('react-dom/client')
const { act, createElement, useMemo } = await import('react')
const { useCaptureFeed } = await import('@/hooks/useCaptureFeed')
const { toCaptureRows } = await import('@/lib/packetRows')
type CaptureEventsResponse = import('@/types').CaptureEventsResponse
type CapturePacket = import('@/types').CapturePacket

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const settle = (ms = 260) => act(async () => { await wait(ms) })

/* ------------------------------------------------------- scripted journal */

type Row = { id: string; start: number; end: number }
const rows: Row[] = []
let endByte = 0
let seq = 0

/** Append one packet line to the journal, exactly as a writer would. */
function append(id: string) {
  const bytes = 40 + (id.length % 7)
  rows.push({ id, start: endByte, end: endByte + bytes })
  endByte += bytes
}
const appendMany = (n: number, prefix: string) => {
  for (let i = 1; i <= n; i += 1) append(`${prefix}${i}`)
}

function buildPage(cursor: number, limit: number): CaptureEventsResponse {
  // The server reads the journal when it builds the response, so a deferred
  // response reflects everything written by the time it is released.
  const from = rows.findIndex((row) => row.end > cursor)
  const slice = from === -1 ? [] : rows.slice(from, from + limit)
  const next = slice.length > 0 ? slice[slice.length - 1].end : cursor
  const events = slice.map((row) => packet(row, rows.indexOf(row)))
  return {
    api: 'analytics',
    schema: 'sentinel.analytics.capture.events.v1',
    state: 'available',
    read_only: true,
    present: rows.length > 0,
    reason: rows.length > 0 ? null : 'live_events.jsonl is empty',
    source: 'live_events.jsonl',
    frame: 'capture',
    cursor: next,
    start_cursor: cursor,
    size: endByte,
    total: rows.length,
    count: events.length,
    limit,
    has_more: next < endByte,
    current: true,
    freshness_window_ms: 2000,
    last_write_age_ms: 0,
    journal_mtime_ms: 0,
    server_time_ms: Date.now(),
    events,
  } as unknown as CaptureEventsResponse
}

function packet(row: Row, index: number): CapturePacket {
  seq += 1
  return {
    id: row.id,
    source: 'live_events.jsonl',
    offset: row.start,
    timestamp_ns: 1_790_620_496_789_000_000 + index * 1_000_000,
    schema: 'sentinel.analytics.capture.packet.v1',
    packet: {
      timestamp: 1_790_620_496_789_000_000 + index * 1_000_000,
      interface: 'eth1',
      protocol: 50,
      source: '10.10.2.20',
      destination: '10.10.2.10',
      spi: 0x11223344,
      sequence: index,
      packet_length: 128,
      source_port: 0,
      destination_port: 0,
      classification: 'ESP',
      direction: 'inbound',
      sensor_type: 'xdp',
    },
    protocol_label: 'ESP',
    info: 'SPI=0x11223344',
    spi: 0x11223344,
    direction: 'inbound',
    risk: { present: false },
  } as unknown as CapturePacket
}

type Held = { cursor: number; limit: number; resolve: (page: CaptureEventsResponse) => void }
let holding = false
const held: Held[] = []
/** Arm the fetcher so the NEXT request hangs until `releaseHeld()`. */
const holdNextPoll = () => {
  holding = true
}
const releaseHeld = () => {
  holding = false
  for (const request of held.splice(0)) request.resolve(buildPage(request.cursor, request.limit))
}
const fetchPage = (cursor: number, limit: number): Promise<CaptureEventsResponse> => {
  if (!holding) return Promise.resolve(buildPage(cursor, limit))
  return new Promise((resolve) => {
    held.push({ cursor, limit, resolve })
  })
}
const heldCount = () => held.length

/* ------------------------------------------------------------- harness */

const INTERVAL_MS = 60
const BUFFER_LIMIT = 3

const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)

function Harness() {
  const feed = useCaptureFeed({
    intervalMs: INTERVAL_MS,
    bufferLimit: BUFFER_LIMIT,
    pageLimit: 3,
    fetchPage,
  })
  const rowsShown = useMemo(() => toCaptureRows(feed.packets), [feed.packets])
  return createElement(
    'div',
    null,
    createElement('div', { 'data-testid': 'ids' }, feed.packets.map((p) => p.id).join(',')),
    createElement(
      'div',
      { 'data-testid': 'counters' },
      `${rowsShown.length} shown · ${feed.packets.length} buffered · ${feed.serverTotal} in journal`,
    ),
    createElement('div', { 'data-testid': 'state' }, feed.state),
    createElement('div', { 'data-testid': 'cursor' }, String(feed.cursor)),
    createElement('button', { 'data-testid': 'clear', onClick: feed.clear }, 'Clear'),
  )
}

const q = (testid: string) => host.querySelector(`[data-testid="${testid}"]`)?.textContent ?? ''
const ids = () => (q('ids') ? q('ids').split(',') : [])
const counters = () => q('counters')
const journalCount = (s: string) => Number((s.match(/([\d,]+) in journal/) ?? ['', '0'])[1].replace(/,/g, ''))
const clear = async () => {
  await act(async () => {
    ;(host.querySelector('[data-testid="clear"]') as HTMLElement).click()
  })
}
const waitForHeld = async (ms = 2000) => {
  const started = Date.now()
  while (Date.now() - started < ms) {
    if (heldCount() > 0) return true
    await settle(20)
  }
  return heldCount() > 0
}

/* ------------------------------------------------------------- scenario */

// The journal already holds recorded rows before the view opens.
appendMany(12, 'old')

await act(async () => {
  root.render(createElement(Harness))
})
await settle()

check(
  'mounting onto a journal that already holds rows shows none of them',
  ids().length === 0,
  `buffered=${ids().join(',')}`,
)
check('the feed still reports the full journal', q('counters') === `0 shown · 0 buffered · 12 in journal`, counters())
check('the feed is live', q('state') === 'live', q('state'))

// Only packets appended while the view is open are live. The buffer keeps
// capture order (the table reverses it for display).
appendMany(2, 'a')
await settle()
check('only packets appended after opening appear', ids().join(',') === 'a1,a2', ids().join(','))

// Clear while a poll is in flight: the in-flight page must be discarded, and
// it must not be able to repopulate the buffer.
const journalBefore = counters()
holdNextPoll()
const armed = await waitForHeld()
check('a poll is in flight to clear against', armed, `held=${heldCount()}`)
append('b1')
await clear()
check('Clear empties the table immediately', ids().length === 0, `buffered=${ids().join(',')}`)
check(
  'the counters read 0 shown · 0 buffered with the journal count untouched',
  counters().startsWith('0 shown · 0 buffered') && journalCount(counters()) === journalCount(journalBefore),
  `${counters()} (was ${journalBefore})`,
)
releaseHeld()
await settle()
await settle()
check('the in-flight (stale) response never repopulates the buffer', ids().length === 0, `buffered=${ids().join(',')}`)
check(
  'the rows written before the Clear stay excluded',
  !ids().includes('b1'),
  ids().join(','),
)

// A packet captured after the Clear is the only thing that may show.
append('c1')
await settle()
check('only the post-Clear packet appears', ids().join(',') === 'c1', ids().join(','))

// Clear is repeatable while polling keeps running.
append('d1')
await settle()
check('the next packet arrives while polling', ids().join(',') === 'd1,c1', ids().join(','))
holdNextPoll()
await waitForHeld()
append('e1')
await clear()
check('the second Clear empties the table immediately', ids().length === 0, `buffered=${ids().join(',')}`)
releaseHeld()
await settle()
await settle()
check('a stale response after the second Clear changes nothing', ids().length === 0, `buffered=${ids().join(',')}`)
append('f1')
await settle()
check('only the newest post-Clear packet appears', ids().join(',') === 'f1', ids().join(','))
check('cleared packets never return', !['a1', 'a2', 'b1', 'c1', 'd1', 'e1'].some((id) => ids().includes(id)), ids().join(','))

// The buffer cap still applies to the live buffer only, and the journal row
// count is the server's own and never decreases.
appendMany(4, 'g')
await settle()
await settle()
check(`the live buffer is capped at ${BUFFER_LIMIT}`, ids().length === BUFFER_LIMIT, ids().join(','))
check(
  'the journal row count only grows (evidence is never truncated)',
  counters().endsWith('23 in journal'),
  counters(),
)
check('no console errors during the run', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '))

console.log(' ')
console.log('CLEAR / POLL RACE SUMMARY')
console.log(`  final counters     : ${counters()}`)
console.log(`  final buffer       : ${ids().join(',') || '—'}`)
console.log(`  rows ever written  : ${rows.length} (pre-existing 12 + appended ${rows.length - 12})`)
console.log(failures === 0 ? 'CLEAR DURABILITY OK' : `${failures} CLEAR CHECK(S) FAILED`)
process.exit(failures > 0 ? 1 : 0)
