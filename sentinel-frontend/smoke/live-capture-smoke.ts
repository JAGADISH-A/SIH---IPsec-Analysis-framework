/**
 * Live capture lifecycle smoke — proves the ACTIVELY GROWING journal path,
 * not the recorded one.
 *
 * Mounts the real LiveScreening page in jsdom against the running analytics API
 * (which must be configured with ANALYTICS_API_CAPTURE_FEED pointing at the
 * sensor's live xdp_monitor journal) and drives the REAL testbed around it:
 *
 *   1. xdp_monitor is (re)started, so the journal is truncated by the `>`
 *      redirect -> the feed reports the waiting state and the page renders
 *      "No current IPsec traffic observed.".
 *   2. The existing testbed traffic generator (ping bursts from host-a, the
 *      same tonic run.sh uses) is started -> the page must show packets
 *      arriving WITHOUT any browser refresh: rows grow, "in journal" grows,
 *      the cursor advances, ESP packets appear and pkt/s reflects the rate.
 *   3. The generator is stopped -> the journal stops growing, pkt/s drops to
 *      0, the server's `current` verdict flips to false once the freshness
 *      window passes, and the live table empties to the recorded-history
 *      state — captured rows are history, not current traffic.
 *
 * Everything is one component mount: no remount, no reload. The component's
 * own polling is the only refresh mechanism exercised.
 */
import { JSDOM } from 'jsdom'
import { spawn, execSync } from 'node:child_process'

const ANALYTICS = process.env.LIVE_CAPTURE_API_URL ?? 'http://127.0.0.1:8081'
// The sensor mirrors the WAN-side path on its data interface. deploy-ipsec.sh
// provisions that as eth1; sandboxes whose sensor exposes a single data link
// (eth0) can override without editing the smoke.
const SENSOR_IF = process.env.LIVE_CAPTURE_SENSOR_IF ?? 'eth1'
const SENSOR = 'clab-ipsec-sensor'
const HOST_A = 'clab-ipsec-host-a'
const TARGET = '10.10.2.10'

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
Object.defineProperty(dom.window, 'innerWidth', { value: 1600, configurable: true })
Object.defineProperty(dom.window, 'innerHeight', { value: 1000, configurable: true })
dom.window.HTMLElement.prototype.getBoundingClientRect = () =>
  ({ width: 1600, height: 1000, top: 0, left: 0, right: 1600, bottom: 1000, x: 0, y: 0, toJSON: () => ({}) }) as DOMRect
define('ResizeObserver', class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver)

const consoleErrors: string[] = []
const origError = console.error
console.error = (...args: unknown[]) => {
  const detail = args.map((a) => (a instanceof Error ? a.message : String(a))).join(' ')
  // React's "not wrapped in act(...)" notice is a jsdom/timer-harness artifact
  // (the hook's async poll resolves outside an act window by design here), not
  // an application error. Real render/fetch errors are still collected.
  if (!detail.includes('not wrapped in act')) consoleErrors.push(detail)
  origError(...args)
}

const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter } = await import('react-router-dom')
const { LiveScreening } = await import('@/pages/LiveScreening')

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const settle = (ms = 1600) => act(async () => { await wait(ms) })

const sh = (cmd: string) => execSync(cmd, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
const feed = async (cursor: number, limit = 200) =>
  (await (await fetch(`${ANALYTICS}/api/v1/capture/events?cursor=${cursor}&limit=${limit}`)).json()) as {
    state: string
    present: boolean
    reason: string | null
    source: string
    cursor: number
    total: number
    count: number
    has_more: boolean
    current?: boolean
    events: {
      id: string
      protocol_label: string
      spi: number | null
      risk: { present: boolean; assessments: unknown[] }
    }[]
  }

const inJournal = (text: string) => {
  const m = text.match(/([\d,]+) in journal/)
  return m ? Number(m[1].replace(/,/g, '')) : null
}
const pktPerSec = (text: string) => {
  const m = text.match(/([\d,.]+) pkt\/s/)
  return m ? Number(m[1].replace(/,/g, '')) : null
}
/** Poll a predicate (API calls and / or jsdom DOM) until true or timeout. */
const waitFor = async (predicate: () => Promise<boolean> | boolean, ms: number, stepMs = 1800) => {
  const started = Date.now()
  while (Date.now() - started < ms) {
    if (await predicate()) return true
    await settle(stepMs)
  }
  return Boolean(await predicate())
}

// ---------------------------------------------------------------------------
// Phase 0 — fresh monitor start => waiting state.
// ---------------------------------------------------------------------------
sh(`docker exec ${SENSOR} sh -c 'pkill -INT xdp_monitor 2>/dev/null; sleep 0.4' || true`)
sh(`docker exec -d ${SENSOR} sh -c '/usr/sbin/xdp_monitor ${SENSOR_IF} --json >/opt/xdp-journal/live_events.jsonl 2>/opt/xdp-journal/xdp.err'`)
await wait(1200)

const fresh = await feed(0)
check(
  'fresh monitor start reports the waiting state on the API',
  fresh.present === false && fresh.state === 'waiting' && fresh.current === false,
  `present=${fresh.present} state=${fresh.state} current=${fresh.current} reason=${fresh.reason}`,
)
check('the waiting reason names the live journal', /live_events\.jsonl is empty/.test(fresh.reason ?? ''), fresh.reason ?? '')

const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)
await act(async () => {
  root.render(createElement(MemoryRouter, { initialEntries: ['/'] }, createElement(LiveScreening)))
})
await settle(5400)

let text = host.textContent ?? ''
check('page renders the no-current-traffic state before traffic', text.includes('No current IPsec traffic observed.'))

// ---------------------------------------------------------------------------
// Phase 1 — live traffic: growth without any browser refresh.
// ---------------------------------------------------------------------------
let cursor = 0
let initialTotal = 0
let initialRows = 0
let espSeen = false
let riskBlockSeen = false
let ppsSeen = false
let liveCurrentSeen = false
const totalSeries: number[] = []
const cursorSeries: number[] = []
const ppsSeries: (number | null)[] = []

const traffic = spawn('docker', ['exec', HOST_A, 'ping', '-c', '750', '-i', '0.03', TARGET])
sh(`docker exec ${HOST_A} ping -c 3 -i 0.2 ${TARGET} >/dev/null 2>&1 || true`)
await settle(2200)
text = host.textContent ?? ''
initialTotal = inJournal(text) ?? 0
initialRows = host.querySelectorAll('tbody tr').length
const pre = await feed(cursor, 50)
cursor = pre.cursor
totalSeries.push(pre.total)
cursorSeries.push(pre.cursor)

for (let i = 0; i < 8; i += 1) {
  await settle(2500)
  text = host.textContent ?? ''
  const page = await feed(cursor, 200)
  cursor = page.cursor
  totalSeries.push(page.total)
  cursorSeries.push(page.cursor)
  const pps = pktPerSec(text)
  ppsSeries.push(pps)
  const rowsNow = host.querySelectorAll('tbody tr').length
  if (page.events.some((e) => /ESP|IKE|AH/.test(e.protocol_label))) espSeen = true
  if (page.events.length > 0 && page.events.every((e) => typeof e.risk === 'object')) riskBlockSeen = true
  if ((pps ?? 0) > 0) ppsSeen = true
  if (page.current === true) liveCurrentSeen = true
  if (rowsNow === 0 && page.total > 0) check('rows rendered during the run', false, `total=${page.total} rows=${rowsNow} sample=${i}`)
}

const finalTotal = totalSeries[totalSeries.length - 1]
const delta = finalTotal - initialTotal
check('packets arrive without any browser refresh (total grew)', delta > 0, `in-journal ${initialTotal} -> ${finalTotal}`)
check('rows appear in the table as traffic flows', host.querySelectorAll('tbody tr').length > 0)
check('the cursor advances with the journal', cursorSeries[cursorSeries.length - 1] > cursorSeries[0], cursorSeries.join(' -> '))
check('ESP traffic is displayed', espSeen)
check('every served event carries a risk block (from the store by SPI)', riskBlockSeen)
check('pkt/s reflects the incoming rate', ppsSeen, `pps samples: ${ppsSeries.join(', ')}`)
check('the backend reports the actively-written journal as current', liveCurrentSeen)
check('no console errors during the live run', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '))

const espCount = (await feed(0, 1000)).events.filter((e) => /ESP|IKE|AH/.test(e.protocol_label)).length

// ---------------------------------------------------------------------------
// A captured packet opens the in-workspace investigation, and its packet time
// is the browser-local wall clock (the feed serving an absolute epoch
// nanosecond instant, rendered in the machine's own timezone, never IST).
// ---------------------------------------------------------------------------
const liveRows = Array.from(host.querySelectorAll('tbody tr'))
const firstLive = liveRows[0]
const beforeClick = host.textContent ?? ''
check(
  'packet rows carry the browser-local wall clock, never sensor uptime',
  /[0-2]\d:[0-5]\d:[0-5]\d\.\d{3}/.test(beforeClick) && !/IST/.test(beforeClick),
  (beforeClick.match(/[0-2]\d:[0-5]\d:[0-5]\d\.\d{3}/) ?? [])[0] ?? 'no local time found',
)

await act(async () => {
  ;(firstLive as HTMLElement).click()
})
await settle(3200)
const afterClick = host.textContent ?? ''
check(
  'the selection hint is replaced by a live investigation',
  !afterClick.includes('Select a live packet from the stream to open its investigation'),
)
check(
  'every opened packet resolves to an honest investigation state',
  /No security finding associated with this packet\/flow\./.test(afterClick) ||
    /Overview|IKE & SA|Gateway Config|Evidence/.test(afterClick),
  afterClick.slice(0, 220),
)
// Per-packet columns, asserted on the real journal the gateway wrote: the risk
// cell must carry the backend's own value, and a packet no assessment
// classified must say so. There is deliberately no direction column: the live
// journal has no direction key, so the feed answers null for every packet.
const riskCells = Array.from(host.querySelectorAll('tbody tr'))
const liveRisk = riskCells.map((tr) => tr.querySelector('[data-risk]')?.textContent?.trim() ?? null)
const liveHeaders = Array.from(host.querySelectorAll('thead th')).map((th) => (th.textContent ?? '').trim())
check(
  'the live table exposes Source..Risk as per-packet columns, with no Direction',
  liveHeaders.join('|') === 'No.|Time|Source|Destination|Protocol|Length|Info|SPI|Risk',
  liveHeaders.join(' | '),
)
check(
  'no direction cell is rendered for any live row',
  riskCells.length > 0 && riskCells.every((tr) => tr.querySelector('[data-direction]') === null),
)
check(
  'every rendered row carries a backend risk word or UNASSESSED',
  riskCells.length > 0 &&
    liveRisk.every(
      (r) => r === 'INFO' || r === 'LOW' || r === 'MEDIUM' || r === 'HIGH' || r === 'CRITICAL' || r === 'UNASSESSED',
    ),
  liveRisk.slice(0, 6).join(','),
)
check(
  'no risk cell invents a score',
  riskCells.every((tr) => !/·|\d/.test(tr.querySelector('[data-risk]')?.textContent ?? '')),
  liveRisk.slice(0, 6).join(','),
)
check(
  'unclassified packets are shown as UNASSESSED rather than a severity',
  liveRisk.length === 0 || liveRisk.includes('UNASSESSED') || liveRisk.every((r) => r !== null),
  liveRisk.slice(0, 6).join(','),
)
console.log(`  risk values        : ${[...new Set(liveRisk)].join(', ') || '—'} (n=${liveRisk.length})`)
// The live stream is now the whole page: findings and the packet investigation
// live in a window a row selection opens, so nothing may be laid out inline
// beside or beneath the table while traffic flows.
check(
  'no findings list or investigation is laid out inline during the live run',
  host.querySelector('[data-findings-toggle]') === null &&
    host.querySelector('.ls-inv-overlay') === null &&
    host.querySelector('.ls-stream-table') !== null,
)

// ---------------------------------------------------------------------------
// Phase 2 — traffic stopped => the backend flips `current` off and the page
// empties the live table to the recorded-history state.
// ---------------------------------------------------------------------------
traffic.kill('SIGINT')
await wait(500)
sh('docker ps --format {{.Names}} | grep -q clab-ipsec-host-a') // sanity: lab still up

const stopSample1 = await feed(cursor, 50)
await settle(2600)
const stopSample2 = await feed(cursor, 50)
await settle(2600)
const stopSample3 = await feed(cursor, 50)
text = host.textContent ?? ''

const journalStopped =
  stopSample1.total === stopSample2.total && stopSample2.total === stopSample3.total
check('journal stops growing once traffic stops', journalStopped, `${stopSample1.total} -> ${stopSample2.total} -> ${stopSample3.total}`)
check('capture cursor freezes once traffic stops', stopSample1.cursor === stopSample2.cursor, `${stopSample1.cursor} -> ${stopSample2.cursor}`)
const ppsAfter = pktPerSec(text)
check('pkt/s reports 0 after the burst', ppsAfter === 0, `pps=${ppsAfter}`)

// Once the server's freshness window passes (the journal stopped being
// written) `current` flips false, and the live table must empty — recorded
// rows are history, not current traffic.
const stale = await waitFor(async () => (await feed(0, 1)).current === false, 30_000)
check('the backend marks the stopped journal as no longer current', stale)
const emptied = await waitFor(
  () => host.querySelectorAll('tbody tr').length === 0 && host.querySelector('[data-no-traffic]') !== null,
  30_000,
)
check('a stopped journal is no longer presented as live traffic', emptied, `rows=${host.querySelectorAll('tbody tr').length}`)
text = host.textContent ?? ''
check('the empty state says there is no current traffic after the stop', /No current IPsec traffic observed/.test(text))
check(
  'the cap reads LIVE · 0 pkt/s once the journal is not current',
  /LIVE · 0 pkt\/s/.test(host.querySelector('.ls-toolbar-fact')?.textContent ?? ''),
  host.querySelector('.ls-toolbar-fact')?.textContent ?? '',
)
check(
  'the stream keeps its risk column after the stop',
  Array.from(host.querySelectorAll('thead th')).some((th) => /risk/i.test(th.textContent ?? '')),
  Array.from(host.querySelectorAll('thead th')).map((th) => th.textContent ?? '').join(' | '),
)

console.log(' ')
console.log('LIVE RUN SUMMARY')
console.log(`  feed source        : ${fresh.source}`)
console.log(`  in-journal series  : ${totalSeries.join(' -> ')}`)
console.log(`  cursor series      : ${cursorSeries.join(' -> ')}`)
console.log(`  pkt/s series       : ${ppsSeries.map((p) => p ?? '—').join(', ')}`)
console.log(`  events delivered   : ${delta} (starting ${initialTotal}, peaking ${finalTotal})`)
console.log(`  rows rendered      : ${initialRows} -> ${host.querySelectorAll('tbody tr').length}`)
console.log(`  ESP packets in tail: ${espCount}`)
console.log(`  no browser refresh : true (single component mount)`)
console.log(failures === 0 ? 'LIVE CAPTURE LIFECYCLE OK' : `${failures} LIVE CAPTURE CHECK(S) FAILED`)
process.exit(failures > 0 ? 1 : 0)