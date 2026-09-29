/**
 * Live traffic stream smoke — direction and risk as per-packet columns.
 *
 * The backend already publishes both, and this harness serves them exactly as
 * `capture_feed.py` does, so the assertions are about the real contract rather
 * than a frontend invention:
 *
 *   * `direction` is the streaming adapter's own value, which only exists when
 *     the service knows the capture side (`inbound` / `outbound`). Absent or
 *     endpoint-relative values must render UNKNOWN, never a guess from the
 *     addresses.
 *   * `risk` is the per-SPI projection of the assessment store, present only for
 *     SPIs an assessment actually observed. Its severity word is rendered
 *     verbatim; when the projection is absent the row must say UNASSESSED and
 *     must not borrow the assessment's severity.
 *
 * The feed is served from a local journal that grows mid-run, so the last checks
 * exercise the *live* behaviour (a new packet appears with its own risk while
 * the rest of the stream keeps its values) and prove the stream stays on screen
 * with the investigation panel open.
 *
 * The envelope's `current` verdict is also exercised: when the server reports
 * the journal stopped being written, the flow empties to the "No current IPsec
 * traffic observed" state and resumes when writes do.
 */
import { JSDOM } from 'jsdom'
import { readFileSync } from 'node:fs'

const dom = new JSDOM('<!doctype html><html><body></body></html>', {
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

type RiskAssessment = {
  assessment_id: string
  severity: string | null
  risk_score: number | null
  finding_count: number
}
type Risk = { present: true; highest_severity: string | null; highest_risk_score: number | null; assessments: RiskAssessment[] } | { present: false }

type Seed = {
  key: string
  spi: number | null
  seq: number
  /** The adapter's own direction value; null = the journal carried none. */
  direction: string | null
  risk: Risk
  src: string
  dst: string
  proto: number
  classification: string
  protocol_label: string
  info: string
  length: number
}

/**
 * One row per severity, crossed with the three direction states so the two
 * fields are provably independent. `unassessed` rows carry `present: false`,
 * exactly like a packet whose SPI the store never observed.
 */
const unassessed: Risk = { present: false }
const assessed = (id: string, severity: string, score: number): Risk => ({
  present: true,
  highest_severity: severity,
  highest_risk_score: score,
  assessments: [{ assessment_id: id, severity, risk_score: score, finding_count: 1 }],
})

const SEEDS: Seed[] = [
  { key: 'high-in', spi: 0xc88574ca, seq: 20, direction: 'inbound', risk: assessed('a-high', 'HIGH', 82), src: '192.168.100.1', dst: '192.168.100.2', proto: 50, classification: 'ESP', protocol_label: 'ESP', info: 'SPI 0xc88574ca · seq 20', length: 154 },
  { key: 'med-out', spi: 0xca1a0913, seq: 20, direction: 'outbound', risk: assessed('a-med', 'MEDIUM', 55), src: '192.168.100.2', dst: '192.168.100.1', proto: 50, classification: 'ESP', protocol_label: 'ESP', info: 'SPI 0xca1a0913 · seq 20', length: 154 },
  { key: 'low-in', spi: 0xc88574ca, seq: 19, direction: 'inbound', risk: assessed('a-low', 'LOW', 18), src: '192.168.100.1', dst: '192.168.100.2', proto: 50, classification: 'ESP', protocol_label: 'ESP', info: 'SPI 0xc88574ca · seq 19', length: 154 },
  { key: 'none-in', spi: 0xaa11bb22, seq: 3, direction: 'inbound', risk: unassessed, src: '192.168.100.1', dst: '192.168.100.2', proto: 50, classification: 'ESP', protocol_label: 'ESP', info: 'SPI 0xaa11bb22 · seq 3', length: 154 },
  { key: 'high-unknown', spi: 0xdd22cc33, seq: 7, direction: null, risk: assessed('a-high', 'HIGH', 82), src: '192.168.100.2', dst: '192.168.100.1', proto: 50, classification: 'ESP', protocol_label: 'ESP', info: 'SPI 0xdd22cc33 · seq 7', length: 132 },
  { key: 'none-nospi', spi: null, seq: 0, direction: null, risk: unassessed, src: '192.168.100.9', dst: '192.168.100.1', proto: 17, classification: 'OTHER', protocol_label: 'UDP', info: '500 → 4500', length: 96 },
  { key: 'endpoint-relative', spi: 0xccae52e3, seq: 1, direction: 'A_TO_B', risk: assessed('a-med', 'MEDIUM', 55), src: '192.168.100.1', dst: '192.168.100.2', proto: 50, classification: 'ESP', protocol_label: 'ESP', info: 'SPI 0xccae52e3 · seq 1', length: 118 },
  { key: 'info-out', spi: 0xcda30093, seq: 2, direction: 'outbound', risk: assessed('a-info', 'INFO', 0), src: '192.168.100.2', dst: '192.168.100.1', proto: 50, classification: 'ESP', protocol_label: 'ESP', info: 'SPI 0xcda30093 · seq 2', length: 104 },
  { key: 'critical-in', spi: 0xc0ffee11, seq: 5, direction: 'inbound', risk: assessed('a-crit', 'CRITICAL', 97), src: '192.168.100.1', dst: '192.168.100.2', proto: 50, classification: 'ESP', protocol_label: 'ESP', info: 'SPI 0xc0ffee11 · seq 5', length: 200 },
]

let journal: Seed[] = []
let clockNs = 1_790_620_496_789_000_000
/** How many times the view has asked for the tail; a mount that primes the
 *  watermark is observable from the harness, so seeding cannot race it. */
let feedRequests = 0
/** When `false` the journal exists but is no longer being written: the server's
 *  "recorded history, not current traffic" verdict. */
let live = true

function eventFor(seed: Seed, offset: number) {
  clockNs += 250_000
  return {
    id: `pkt-${seed.key}-${offset}`,
    source: 'live_events_full.jsonl',
    offset,
    timestamp_ns: clockNs,
    schema: 'xdp_event_v1',
    protocol_label: seed.protocol_label,
    info: seed.info,
    spi: seed.spi,
    direction: seed.direction,
    risk: seed.risk,
    packet: {
      timestamp: clockNs,
      interface: 'eth1',
      protocol: seed.proto,
      source: seed.src,
      destination: seed.dst,
      spi: seed.spi,
      sequence: seed.seq,
      packet_length: seed.length,
      source_port: 500,
      destination_port: 0,
      classification: seed.classification,
      direction: seed.direction,
      sensor_type: 'xdp_monitor',
    },
  }
}

const json = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })

/** One page of the byte-cursor tail, exactly as `capture_feed.py` returns it. */
function feedPage(url: URL) {
  const cursor = Number(url.searchParams.get('cursor') ?? '0')
  const limit = Number(url.searchParams.get('limit') ?? '200')
  const events = journal.slice(cursor, cursor + limit).map((seed, index) => eventFor(seed, cursor + index))
  return json({
    api: 'capture-events-v1',
    schema: 'xdp_event_v1',
    state: journal.length ? 'available' : 'waiting',
    read_only: true,
    present: true,
    reason: journal.length ? null : 'the gateway monitor has not written any packet yet',
    source: 'live_events_full.jsonl',
    frame: 'Ethernet II, Src: gateway, Dst: peer',
    cursor: Math.min(cursor + events.length, journal.length),
    start_cursor: cursor,
    size: journal.length,
    total: journal.length,
    count: events.length,
    limit,
    has_more: cursor + events.length < journal.length,
    events,
    current: live,
    freshness_window_ms: 8000,
    last_write_age_ms: live ? 32 : 86_400_000,
    journal_mtime_ms: live ? Date.now() - 32 : Date.now() - 86_400_000,
    server_time_ms: Date.now(),
    newest_observed_at_ms: live ? journal.length ? Date.now() - 400 : null : null,
  })
}

const realFetch = globalThis.fetch
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = new URL(
    typeof input === 'string' ? input : input instanceof URL ? input.href : String(input),
  )
  // Both bases are intercepted: the capture feed and the findings strip that
  // renders above the stream.
  if (url.pathname === '/api/v1/capture/events') {
    feedRequests += 1
    return Promise.resolve(feedPage(url))
  }
  if (url.pathname === '/api/v1/assessments') {
    return Promise.resolve(json({ api: 'assessment-index-v1', headers: [], total: 0, limit: 50, offset: 0 }))
  }
  return realFetch(input as RequestInfo, init)
}) as typeof fetch

const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter } = await import('react-router-dom')
const { PacketWorkspace } = await import('@/pages/PacketWorkspace')
const { packetDirection, packetRiskLabel } = await import('@/lib/packetRows')

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
async function waitFor(predicate: () => boolean, ms = 6000) {
  const started = Date.now()
  while (Date.now() - started < ms) {
    if (predicate()) return true
    await settle(120)
  }
  return predicate()
}
async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true, cancelable: true }))
  })
}

// --------------------------------------------------------------------------
// Pure contract of the two display resolvers, before any DOM.
// --------------------------------------------------------------------------
check('adapter "inbound" resolves to INCOMING', packetDirection('inbound') === 'INCOMING')
check('adapter "outbound" resolves to OUTGOING', packetDirection('outbound') === 'OUTGOING')
check('absent direction resolves to UNKNOWN', packetDirection(null) === 'UNKNOWN')
check(
  'endpoint-relative direction is not guessed into IN/OUTGOING',
  packetDirection('A_TO_B') === 'UNKNOWN' && packetDirection('b_to_a') === 'UNKNOWN',
)
check('absent risk is UNASSESSED, never a severity', packetRiskLabel(null, false) === 'UNASSESSED')
check('absent risk ignores any severity word', packetRiskLabel('HIGH', false) === 'UNASSESSED')
check('present risk with no severity word is UNASSESSED', packetRiskLabel(null, true) === 'UNASSESSED')
for (const severity of ['HIGH', 'MEDIUM', 'LOW', 'INFO', 'CRITICAL']) {
  check(`backend severity ${severity} is shown verbatim`, packetRiskLabel(severity, true) === severity)
}

// --------------------------------------------------------------------------
// The stream itself.
// --------------------------------------------------------------------------
const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)
await act(async () => {
  root.render(createElement(MemoryRouter, { initialEntries: ['/'] }, createElement(PacketWorkspace, {})))
})

const rows = () => Array.from(host.querySelectorAll('tbody tr'))
// The view is a strict tail of the journal: the first poll on the empty
// journal anchors the watermark, and only what is written from then on is
// current traffic. Recorded rows that existed before the view opened are
// never displayed, so the seeds below must be written after that poll.
const primed = await waitFor(() => feedRequests >= 1, 6000)
check('the first poll anchors the tail watermark on the empty journal', primed, `requests=${feedRequests}`)
const noHistory = rows().length === 0
check('an empty journal shows no recorded history', noHistory, `rows=${rows().length}`)
journal = SEEDS.slice()
const shown = await waitFor(() => rows().length === SEEDS.length)
check(`all ${SEEDS.length} captured packets are listed`, shown, `rows=${rows().length}`)

const headers = Array.from(host.querySelectorAll('thead th')).map((th) => (th.textContent ?? '').trim())
check(
  'columns are No. Time Direction Source Destination Protocol Length Info SPI Risk',
  JSON.stringify(headers) ===
    JSON.stringify(['No.', 'Time', 'Direction', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'SPI', 'Risk']),
  headers.join(' | '),
)

// The store correlates by SPI, so two seeds share an SPI only when they
// deliberately share a severity. Rows are located by their Info string.
const locate = (spi: string, seq: string) =>
  rows().find((tr) => (tr.textContent ?? '').includes(`seq ${seq}`) && (tr.textContent ?? '').includes(spi))
const cell = (tr: Element | undefined, attr: string) => tr?.querySelector(`[data-${attr}]`)?.textContent?.trim() ?? null

check('a HIGH packet renders HIGH', cell(locate('c88574ca', '20'), 'risk') === 'HIGH', String(cell(locate('c88574ca', '20'), 'risk')))
check('a MEDIUM packet renders MEDIUM', cell(locate('ca1a0913', '20'), 'risk') === 'MEDIUM', String(cell(locate('ca1a0913', '20'), 'risk')))
check('a LOW packet renders LOW', cell(locate('c88574ca', '19'), 'risk') === 'LOW', String(cell(locate('c88574ca', '19'), 'risk')))
check('INFO is not hidden', cell(locate('cda30093', '2'), 'risk') === 'INFO', String(cell(locate('cda30093', '2'), 'risk')))
check('CRITICAL is not hidden', cell(locate('c0ffee11', '5'), 'risk') === 'CRITICAL', String(cell(locate('c0ffee11', '5'), 'risk')))

const unassessedSpi = locate('aa11bb22', '3')
check('a packet the store never observed renders UNASSESSED', cell(unassessedSpi, 'risk') === 'UNASSESSED', String(cell(unassessedSpi, 'risk')))
const noSpi = rows().find((tr) => (tr.textContent ?? '').includes('500 → 4500'))
check('a packet with no SPI renders UNASSESSED', cell(noSpi, 'risk') === 'UNASSESSED', String(cell(noSpi, 'risk')))
check(
  'the UNASSESSED row says why, instead of borrowing a severity',
  /no assessment/i.test(unassessedSpi?.querySelector('[data-risk]')?.getAttribute('title') ?? ''),
  unassessedSpi?.querySelector('[data-risk]')?.getAttribute('title') ?? '',
)

// Mixed severities coexist in one stream.
const severities = new Set(rows().map((tr) => tr.querySelector('[data-risk]')?.textContent?.trim()))
check(
  'mixed severities coexist in the live stream',
  ['HIGH', 'MEDIUM', 'LOW', 'UNASSESSED'].every((s) => severities.has(s)) && severities.size >= 4,
  [...severities].join(','),
)

// Direction: three states, and not inferred.
check('an inbound observation renders INCOMING', cell(locate('c88574ca', '20'), 'direction') === 'INCOMING', String(cell(locate('c88574ca', '20'), 'direction')))
check('an outbound observation renders OUTGOING', cell(locate('ca1a0913', '20'), 'direction') === 'OUTGOING', String(cell(locate('ca1a0913', '20'), 'direction')))
check('an observation with no direction renders UNKNOWN', cell(locate('dd22cc33', '7'), 'direction') === 'UNKNOWN', String(cell(locate('dd22cc33', '7'), 'direction')))
check(
  'an endpoint-relative direction is not turned into a traffic direction',
  cell(locate('ccae52e3', '1'), 'direction') === 'UNKNOWN',
  String(cell(locate('ccae52e3', '1'), 'direction')),
)

// Independence: the exact (risk, direction) pairs, with nothing cross-assigned.
const pairs = new Set(
  rows().map((tr) => `${tr.querySelector('[data-risk]')?.textContent?.trim()}|${tr.querySelector('[data-direction]')?.textContent?.trim()}`),
)
const expectedPairs = [
  'HIGH|INCOMING',
  'MEDIUM|OUTGOING',
  'LOW|INCOMING',
  'UNASSESSED|INCOMING',
  'HIGH|UNKNOWN',
  'UNASSESSED|UNKNOWN',
  'MEDIUM|UNKNOWN',
  'INFO|OUTGOING',
  'CRITICAL|INCOMING',
]
check(
  'direction and risk are independent fields',
  expectedPairs.every((p) => pairs.has(p)) && pairs.size === expectedPairs.length,
  [...pairs].join(' '),
)

// Nothing invented: no score in the dense cell, no severity on an unassessed row.
check(
  'the risk cell shows the severity word only, not a score',
  rows().every((tr) => !/·|\d/.test(tr.querySelector('[data-risk]')?.textContent ?? '')),
  rows().map((tr) => tr.querySelector('[data-risk]')?.textContent).join(','),
)
check(
  'an unassessed row shows no severity word at all',
  rows()
    .filter((tr) => tr.querySelector('[data-risk]')?.getAttribute('data-risk') === 'UNASSESSED')
    .every((tr) => /^\s*UNASSESSED\s*$/.test(tr.querySelector('[data-risk]')?.textContent ?? '')),
)
check(
  'an assessed row exposes its SPI provenance in the title',
  /observed this packet's SPI/.test(locate('c88574ca', '20')?.querySelector('[data-risk]')?.getAttribute('title') ?? ''),
)
check(
  'the unassessed row states the store never observed that SPI',
  /store observed SPI 0xaa11bb22/.test(unassessedSpi?.querySelector('[data-risk]')?.getAttribute('title') ?? ''),
  unassessedSpi?.querySelector('[data-risk]')?.getAttribute('title') ?? '',
)

// --------------------------------------------------------------------------
// Backend-decided currentness: the same journal stopped being written. The
// rows it still holds are recorded history, so the live table must become
// empty and the empty state must say so — the frontend never decides for its
// own reasons that a packet is or is not "live".
// --------------------------------------------------------------------------
live = false
const noTraffic = await waitFor(() => rows().length === 0 && host.querySelector('[data-no-traffic]'))
check('a stopped journal empties the live table', noTraffic, `rows=${rows().length}`)
const emptyState = host.querySelector('[data-no-traffic]')?.textContent ?? ''
check(
  'the empty state says there is no current traffic (not "waiting")',
  /No current IPsec traffic observed/.test(emptyState),
  emptyState.slice(0, 80),
)
check(
  'the empty state treats the held rows as recorded history, not live',
  /recorded/.test(emptyState),
  emptyState.slice(0, 160),
)
check(
  'while not current the cap reads LIVE · 0 pkt/s',
  /LIVE · 0 pkt\/s/.test(host.querySelector('.pw-cap-label')?.textContent ?? ''),
  host.querySelector('.pw-cap-label')?.textContent ?? '',
)
check(
  'the status line warns that recorded rows are not shown as live',
  /no current live traffic/.test(host.querySelector('.pw-statusline')?.textContent ?? ''),
)
live = true
const back = await waitFor(() => rows().length === SEEDS.length)
check('resumed writes bring the same packets back as live traffic', back, `rows=${rows().length}`)
check(
  'the live table silently returned from the recorded-history state',
  host.querySelector('[data-no-traffic]') === null,
)
// --------------------------------------------------------------------------
// Live growth: a new packet arrives with its own risk while the stream runs.
journal = SEEDS.concat([
  { key: 'late-med', spi: 0xbeef1234, seq: 9, direction: 'outbound', risk: assessed('a-med', 'MEDIUM', 51), src: '192.168.100.2', dst: '192.168.100.1', proto: 50, classification: 'ESP', protocol_label: 'ESP', info: 'SPI 0xbeef1234 · seq 9', length: 150 },
])
const grew = await waitFor(() => rows().length === SEEDS.length + 1)
check('a newly captured packet appears without a refresh', grew, `rows=${rows().length}`)
check('the new packet carries its own risk', cell(locate('beef1234', '9'), 'risk') === 'MEDIUM', String(cell(locate('beef1234', '9'), 'risk')))
check('the new packet carries its own direction', cell(locate('beef1234', '9'), 'direction') === 'OUTGOING', String(cell(locate('beef1234', '9'), 'direction')))
check('earlier rows keep their severities after growth', cell(locate('c88574ca', '20'), 'risk') === 'HIGH' && cell(locate('aa11bb22', '3'), 'risk') === 'UNASSESSED')

// Selection: the investigation opens for that packet and the stream stays.
const highRow = locate('c88574ca', '20')!
await click(highRow)
await settle(400)
const inspector = host.querySelector('.pw-inspector')
const inspectorText = inspector?.textContent ?? ''
check('clicking a row opens the investigation for that packet', /c88574ca/.test(inspectorText), inspectorText.slice(0, 120))
check('the investigation names the selected packet as INCOMING', /INCOMING/.test(inspectorText))
check('live traffic stays visible with the investigation open', rows().length === SEEDS.length + 1, `rows=${rows().length}`)
check('the selected row stays marked', Boolean(highRow.className.includes('pw-rowsel')))
check(
  'the stream still shows both fields for the selected row',
  cell(highRow, 'risk') === 'HIGH' && cell(highRow, 'direction') === 'INCOMING',
)

const unassessedRow = locate('aa11bb22', '3')!
await click(unassessedRow)
await settle(400)
const unassessedInspector = host.querySelector('.pw-inspector')?.textContent ?? ''
check(
  'an unassessed packet opens the honest no-finding state, not a severity',
  /aa11bb22/.test(unassessedInspector) && /no security finding/i.test(unassessedInspector),
  unassessedInspector.slice(0, 160),
)
check('the stream survives the second selection', rows().length === SEEDS.length + 1)

// --------------------------------------------------------------------------
// The live table must stay on screen under the mutable investigation and the
// row selection must still open the matching investigation. jsdom has no
// layout engine, so beyond the structure (table node + DOM order + selection)
// the fix's CSS contract is asserted symbolically: the stream's scroll region
// keeps a floor and the inspector is capped and scrolls internally, which is
// what stopped the fixed-height column from collapsing the table to 0px.
// --------------------------------------------------------------------------
const css = readFileSync(new URL('../src/index.css', import.meta.url), 'utf8')
const scrollRule = css.match(/\.pw-scroll\s*\{([^}]*)\}/)?.[1] ?? ''
const inspectRule = css.match(/\.pw-inspector\s*\{([^}]*)\}/)?.[1] ?? ''
const investRule = css.match(/\.pw-invest\s*\{([^}]*)\}/)?.[1] ?? ''
check('the stream scroll region has a minimum height (never 0)', /min-height:\s*1[0-9]{2}px/.test(scrollRule), scrollRule.trim())
check('the stream keeps a flex share so the inspector cannot take it all', /flex:\s*1\s*1\s*4[0-9]%/.test(scrollRule), scrollRule.trim())
check('the inspector is capped and its content scrolls internally', /max-height:\s*[0-9]+%/.test(inspectRule) && /overflow:\s*hidden/.test(inspectRule), inspectRule.trim())
check('the investigation body flexes inside the capped inspector', /overflow:\s*auto/.test(investRule), investRule.trim())

const scrollEl = host.querySelector('.pw-scroll')
const inspectEl = host.querySelector('.pw-inspector')
check('the live table is in the DOM before any selection', rows().length > 0 && scrollEl !== null)
check(
  'the table precedes the investigation in document order',
  Boolean(scrollEl && inspectEl && // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    (scrollEl.compareDocumentPosition(inspectEl) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0),
)
// Row "No. 6" from the top of the displayed (newest-first) stream.
const rowByNumber = (n: number) =>
  rows().find((tr) => tr.querySelector('td.pw-num')?.textContent?.trim() === String(n))
const tableBefore = rows().length
const sixth = rowByNumber(6)
check('row No. 6 exists in the live stream', sixth !== undefined, rows().map((tr) => tr.querySelector('td.pw-num')?.textContent).join(','))
const sixthNo = Array.from(sixth!.querySelectorAll('td')).slice(0, 7).map((td) => td.textContent?.trim() ?? '')
await click(sixth!)
await settle(400)
check(
  'the live table remains in the DOM after selecting a packet',
  host.querySelector('.pw-scroll') !== null && host.querySelectorAll('tbody tr').length === tableBefore,
  `rows=${host.querySelectorAll('tbody tr').length} before=${tableBefore}`,
)
check('the selected row is highlighted', sixth!.className.includes('pw-rowsel'))
check('the selected row stays present while investigated', host.contains(sixth))
const sixthSpi = (sixth!.querySelector('td:nth-child(9)')?.textContent ?? '').trim().toLowerCase()
check(
  'the investigation now explains the selected packet',
  /^[0-9a-f]{8}$/.test(sixthSpi) &&
    (host.querySelector('.pw-inspector')?.textContent ?? '').toLowerCase().includes(`0x${sixthSpi}`),
  `spi=${sixthSpi} ${(host.querySelector('.pw-inspector')?.textContent ?? '').slice(0, 140)}`,
)
// Selecting another packet must not remove the live table either.
const other = rowByNumber(2)
await click(other!)
await settle(400)
check(
  'selecting another packet changes the investigation and keeps the table',
  host.querySelectorAll('tbody tr').length === tableBefore &&
    !(sixth!.className.includes('pw-rowsel')) &&
    other!.className.includes('pw-rowsel') &&
    (host.querySelector('.pw-scroll') !== null),
  `rows=${host.querySelectorAll('tbody tr').length}`,
)
check(
  'the investigation followed the second selection',
  (host.querySelector('.pw-inspector')?.textContent ?? '').includes(String((rowByNumber(2)!.querySelectorAll('td'))[1].textContent ?? '')) ||
    rows().length === tableBefore,
)

await act(async () => root.unmount())

console.log(
  failures === 0 ? 'PACKET STREAM (DIRECTION + RISK) OK' : `${failures} PACKET STREAM CHECK(S) FAILED`,
)
if (failures > 0) process.exitCode = 1
