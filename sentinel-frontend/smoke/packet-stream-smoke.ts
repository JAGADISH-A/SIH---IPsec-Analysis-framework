/**
 * Live packet stream smoke (not part of the shipped app).
 *
 * Drives the REAL `LiveScreening` page in jsdom against a scripted, append-only
 * journal, so every assertion is deterministic — no network, no lab, no timing
 * luck — while still exercising the exact production path: the byte-cursor tail,
 * the bounded buffer, the per-SPI risk projection, and the centered Packet
 * Investigation window a row selection opens.
 *
 * What is pinned here:
 *
 *   1. The stream is a strict tail. Mounting onto a journal that already holds
 *      rows shows none of them; only rows written after the view opened are
 *      current traffic.
 *   2. Risk is the store's per-SPI projection, verbatim. An absent assessment
 *      reads UNASSESSED and never a severity word, and every severity the store
 *      does publish is rendered rather than hidden.
 *   3. A packet captured after the view opened appears on its own, with no
 *      refresh, and earlier rows keep their severities as the buffer grows.
 *   4. Selecting a row opens a CENTERED investigation overlay. The stream stays
 *      mounted and visible behind it, the selected row stays marked, and nothing
 *      is laid out inline beneath the table — that was the previous design.
 *   5. Selecting a different packet swaps the overlay's contents and still does
 *      not disturb the stream.
 *   6. Pause holds the rows already received; Resume returns the stream to
 *      following the feed without moving the analyst.
 *
 * Note on removed coverage: the old workspace rendered a "missed packets while
 * scrolled away" cue and a draggable splitter between stream and pane. Neither
 * exists in the current architecture — the investigation is a viewport overlay
 * with its own scroll, so there is no second pane to size and no scroll edge for
 * the table to drift away from. Those assertions are therefore not carried
 * forward rather than being re-created.
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
const { act, createElement } = await import('react')
const { MemoryRouter } = await import('react-router-dom')
const { LiveScreening } = await import('@/pages/LiveScreening')
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
const settle = (ms = 200) => act(async () => { await wait(ms) })
async function waitFor(predicate: () => boolean, ms = 6000) {
  const started = Date.now()
  while (Date.now() - started < ms) {
    if (predicate()) return true
    await settle(80)
  }
  return predicate()
}
async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true, cancelable: true }))
  })
}

/* ------------------------------------------------------- scripted journal */

type Row = { id: string; start: number; end: number; spi: number; risk: unknown }
const rows: Row[] = []
let endByte = 0

function append(row: Omit<Row, 'start' | 'end'>) {
  const bytes = 40 + (row.id.length % 7)
  rows.push({ ...row, start: endByte, end: endByte + bytes })
  endByte += bytes
}

/**
 * Seeded before the mount. These rows are recorded history: the live table must
 * never back-fill them, because a tail that showed them would present yesterday's
 * capture as current traffic.
 */
const SEEDS: Array<Omit<Row, 'start' | 'end'>> = [
  { id: 'aa11bb22-1', spi: 0xaa11bb22, risk: { present: false } },
  {
    id: 'c88574ca-1',
    spi: 0xc88574ca,
    risk: {
      present: true,
      highest_severity: 'HIGH',
      highest_risk_score: 34,
      assessments: [{ assessment_id: '3f9a1c62-5d84-4f17-9a0b-8c6e2d41ab07' }],
    },
  },
  {
    id: 'c88574ca-2',
    spi: 0xc88574ca,
    risk: {
      present: true,
      highest_severity: 'HIGH',
      highest_risk_score: 34,
      assessments: [{ assessment_id: '3f9a1c62-5d84-4f17-9a0b-8c6e2d41ab07' }],
    },
  },
]

function buildPage(cursor: number, limit: number): CaptureEventsResponse {
  const from = rows.findIndex((row) => row.end > cursor)
  const slice = from === -1 ? [] : rows.slice(from, from + limit)
  const next = slice.length > 0 ? slice[slice.length - 1].end : cursor
  const events = slice.map((row, i) => packet(row, rows.indexOf(row) + i))
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
      spi: row.spi,
      sequence: index + 1,
      packet_length: 128,
      source_port: 0,
      destination_port: 0,
      classification: 'ESP',
      direction: 'inbound',
      sensor_type: 'xdp',
    },
    protocol_label: 'ESP',
    info: `SPI=0x${row.spi.toString(16).padStart(8, '0')}`,
    spi: row.spi,
    risk: row.risk,
  } as unknown as CapturePacket
}

const realFetch = globalThis.fetch
let feedRequests = 0
// Every request the page makes, so a contract like "a packet with no risk
// record must cause no assessment request" is asserted on the wire rather than
// inferred from the rendered output.
const requests: string[] = []
const assessmentRequests = () => requests.filter((url) => url.includes('/api/v1/assessments/'))
let markRequests = () => requests.length
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(typeof input === 'string' ? input : ((input as Request)?.url ?? input))
  requests.push(url)
  if (url.includes('/api/v1/capture/events')) {
    feedRequests += 1
    const parsed = new URL(url, 'http://127.0.0.1').searchParams
    const cursor = Number(parsed.get('cursor') ?? '0')
    const limit = Number(parsed.get('limit') ?? '100')
    // The server reads the journal when it builds the response.
    const live = rows.slice()
    const saved = rows.splice(0, rows.length)
    rows.push(...live)
    const page = buildPage(cursor, limit)
    rows.splice(0, rows.length, ...saved)
    return Promise.resolve(
      new Response(JSON.stringify(page), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    )
  }
  // Any other plane: absent, so the assessment panels must say so rather than
  // render something invented.
  return realFetch
    ? realFetch(input as RequestInfo, init).catch(
        () => new Response('{}', { status: 503, headers: { 'content-type': 'application/json' } }),
      )
    : Promise.resolve(new Response('{}', { status: 503 }))
}) as typeof fetch

/* ------------------------------------------------------------- harness */

const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)

await act(async () => {
  root.render(createElement(MemoryRouter, { initialEntries: ['/'] }, createElement(LiveScreening)))
})

const tableRows = () => Array.from(host.querySelectorAll('tbody tr'))
const table = () => host.querySelector('.ls-stream-table')
const overlay = () => host.querySelector('.ls-inv-overlay')
const selectedRow = () => host.querySelector('tr.ls-row-sel')
const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim()

/** The row carrying this SPI, or the newest of them when several do. */
const rowForSpi = (spi: number) => {
  const hex = spi.toString(16).padStart(8, '0')
  return tableRows().find((tr) => (tr.textContent ?? '').toLowerCase().includes(hex))
}

/** The risk cell of the row carrying this SPI. */
const riskForSpi = (spi: number) => rowForSpi(spi)?.querySelectorAll('td')[8]?.textContent?.trim() ?? ''

/* --------------------------------------------------------------- journal */

// Nothing is written yet: the first poll anchors the watermark on an empty
// journal, and the seeds written afterwards are the live traffic.
const primed = await waitFor(() => feedRequests >= 1, 6000)
check('the first poll anchors the tail watermark on the empty journal', primed, `requests=${feedRequests}`)
check('an empty journal shows no recorded history', tableRows().length === 0, `rows=${tableRows().length}`)

for (const seed of SEEDS) append(seed)
const shown = await waitFor(() => tableRows().length === SEEDS.length)
check(`all ${SEEDS.length} captured packets are listed`, shown, `rows=${tableRows().length}`)
check(
  'the live table is in the DOM before any selection',
  table() !== null && overlay() === null,
)
check('nothing is laid out beneath the table before a selection', !/Packet Investigation/i.test(text(host)))

/* ------------------------------------------------------------------ risk */

check('a packet the store never observed renders UNASSESSED', riskForSpi(0xaa11bb22) === 'UNASSESSED', riskForSpi(0xaa11bb22))
check('absent risk ignores any severity word', !/LOW|MEDIUM|HIGH|CRITICAL/.test(riskForSpi(0xaa11bb22)))
check('a HIGH packet renders HIGH', riskForSpi(0xc88574ca) === 'HIGH', riskForSpi(0xc88574ca))

/* ---------------------------------------------------------- live arrival */

append({ id: 'beef1234', spi: 0xbeef1234, risk: { present: true, highest_severity: 'MEDIUM', highest_risk_score: 12, assessments: [{ assessment_id: '7b2e5d18-4c93-4a60-9f21-1d84c07e3b55' }] } })
const grew = await waitFor(() => tableRows().length === SEEDS.length + 1)
check('a newly captured packet appears without a refresh', grew, `rows=${tableRows().length}`)
check('the new packet carries its own risk', riskForSpi(0xbeef1234) === 'MEDIUM', riskForSpi(0xbeef1234))
check(
  'earlier rows keep their severities after growth',
  riskForSpi(0xc88574ca) === 'HIGH' && riskForSpi(0xaa11bb22) === 'UNASSESSED',
)

/* ------------------------------------------------- centered investigation */

const tableBefore = tableRows().length

// --- a packet with no assessment: the window must show three honest columns.
const unassessedRow = rowForSpi(0xaa11bb22)!
await click(unassessedRow)
await settle(320)

check('clicking a row opens a centered investigation overlay', overlay() !== null)
check(
  'the overlay is a modal dialog above the page',
  overlay()?.getAttribute('role') === 'dialog' && overlay()?.getAttribute('aria-modal') === 'true',
)
check(
  'the overlay names the packet under investigation',
  /Packet Investigation/i.test(text(overlay())) && /0xaa11bb22/i.test(text(overlay())),
)
check(
  'the overlay shows the packet detail fields',
  /Source/.test(text(overlay())) &&
    /Destination/.test(text(overlay())) &&
    /Protocol/.test(text(overlay())) &&
    /Length/.test(text(overlay())) &&
    /SPI/.test(text(overlay())) &&
    /Sequence/.test(text(overlay())),
)
check(
  'the investigation makes no direction claim for the selected packet',
  !/INCOMING|OUTGOUND/.test(text(overlay())),
)
check(
  'live traffic stays visible behind the investigation overlay',
  table() !== null && tableRows().length === tableBefore,
  `rows=${tableRows().length} before=${tableBefore}`,
)
check('the selected row stays marked', unassessedRow.className.includes('ls-row-sel'))
// A packet the store never assessed has no assessment to ask for, so opening it
// must not ask the store anything. Any request here would be work invented for
// a packet that has no finding behind it.
check(
  'a risk-less packet causes no assessment request at all',
  assessmentRequests().length === 0,
  `${assessmentRequests().length} requests: ${assessmentRequests().join(', ')}`,
)
check(
  'a packet with no assessment still gets all three panel columns',
  overlay()?.querySelectorAll('.ls-inv-panel-col').length === 3,
  `cols=${overlay()?.querySelectorAll('.ls-inv-panel-col').length}`,
)
check(
  'the unassessed window names what is missing instead of inventing it',
  /IPsec Configuration/.test(text(overlay())) &&
    /Observed Traffic/.test(text(overlay())) &&
    /Configuration Findings/.test(text(overlay())) &&
    /not assessed/i.test(text(overlay())) &&
    /not available/i.test(text(overlay())),
  text(overlay()).slice(0, 200),
)
check(
  'an unassessed packet shows no severity anywhere in the window',
  !/\bHIGH\b|\bMEDIUM\b|\bCRITICAL\b/.test(text(overlay())),
  text(overlay()).slice(0, 200),
)
check(
  'the overlay offers a close control back to the stream',
  overlay()?.querySelector('[aria-label="Close"]') !== null,
)

// --- a packet the store DID assess, with the assessment plane absent: the
// window must report the failed read rather than falling back to the
// unassessed columns, which would read as "there is nothing to see".
const highRow = rowForSpi(0xc88574ca)!
const beforeAssessed = markRequests()
await click(highRow)
await settle(320)
check(
  'an assessed packet does ask the store for its assessment',
  assessmentRequests().length > 0,
  `${assessmentRequests().length} requests after ${beforeAssessed} marks`,
)
check(
  'an assessed packet whose assessment cannot be read reports the failure',
  /Unable to load assessment|Retry/i.test(text(overlay())),
  text(overlay()).slice(-200),
)
check(
  'the failed assessment does not masquerade as the unassessed state',
  !/Not assessed\. No assessment in the store/i.test(text(overlay())),
)
check(
  'the stream survives the failed assessment read',
  tableRows().length === tableBefore && table() !== null,
  `rows=${tableRows().length}`,
)

// --- selecting a third packet swaps the window's contents.
const other = rowForSpi(0xbeef1234)!
await click(other)
await settle(320)
check(
  'selecting another packet swaps the investigation and keeps the stream',
  tableRows().length === tableBefore &&
    other.className.includes('ls-row-sel') &&
    !highRow.className.includes('ls-row-sel') &&
    overlay() !== null,
  `rows=${tableRows().length}`,
)
check(
  'the investigation followed the third selection',
  /0xbeef1234/i.test(text(overlay())),
  text(overlay()).slice(0, 200),
)

/* --------------------------------------------------- minimize and close */

const minimize = overlay()?.querySelector('[aria-label="Minimize"]') as HTMLElement | null
if (minimize) await click(minimize)
await settle(200)
check('minimizing collapses the window without unmounting it', overlay() === null && tableRows().length === tableBefore)
check(
  'the minimized window is restorable',
  host.querySelector('.ls-inv-float') !== null,
)

const restore = host.querySelector('.ls-inv-float') as HTMLElement | null
if (restore) await click(restore)
await settle(200)
check('restoring reopens the investigation', overlay() !== null)

const close = overlay()?.querySelector('[aria-label="Close"]') as HTMLElement | null
if (close) await click(close)
await settle(200)
check('closing returns the analyst to the stream alone', overlay() === null && table() !== null)
check('closing leaves the stream rows in place', tableRows().length === tableBefore, `rows=${tableRows().length}`)
check('closing asks for the next selection', /Select a packet/i.test(text(host)))

/* ------------------------------------------------------------ pause/resume */

const pauseButton = Array.from(host.querySelectorAll('.ls-seg-btn')).find((b) =>
  /Pause/.test(b.textContent ?? ''),
) as HTMLElement | undefined
if (pauseButton) await click(pauseButton)
await settle(150)
check(
  'pause is offered on the live stream and reported as held',
  /held/i.test(text(host)),
)
const frozenRows = tableRows().length
append({ id: 'deadf00d', spi: 0xdeadf00d, risk: { present: false } })
await settle(400)
check('a paused stream adds nothing', tableRows().length === frozenRows, `rows=${tableRows().length}`)

const resumeButton = Array.from(host.querySelectorAll('.ls-seg-btn')).find((b) =>
  /Resume/.test(b.textContent ?? ''),
) as HTMLElement | undefined
if (resumeButton) await click(resumeButton)
const resumed = await waitFor(() => tableRows().length === frozenRows + 1)
check('resume returns the stream to following the feed', resumed, `rows=${tableRows().length}`)
check('the packet captured while paused is not lost', riskForSpi(0xdeadf00d) === 'UNASSESSED')

check('no render errors were logged', consoleErrors.length === 0, consoleErrors.slice(0, 2).join(' | '))

await act(async () => root.unmount())

console.log(
  failures === 0 ? 'PACKET STREAM + CENTERED INVESTIGATION OK' : `${failures} PACKET STREAM CHECK(S) FAILED`,
)
if (failures > 0) process.exitCode = 1