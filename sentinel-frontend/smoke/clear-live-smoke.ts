/**
 * Live Clear acceptance smoke — the analyst's exact sequence against the REAL
 * capture feed, on a journal that already holds thousands of recorded rows and
 * is still being appended to.
 *
 * Mounts the real LiveScreening page in jsdom against the running analytics API
 * (its ANALYTICS_API_CAPTURE_FEED must point at a journal that is actively being
 * written) and drives the page as an analyst would, with no browser refresh.
 *
 * Because a live writer keeps appending, "the table is empty" is only true for
 * an instant. The contract pinned here is therefore the honest one: **every row
 * on screen is a packet that was appended after the watermark** — nothing that
 * was already in the journal when the view opened or when Clear was clicked may
 * ever be displayed. That is checked exactly, by intersecting the rendered rows
 * with the byte window the journal grew by.
 *
 * The forced-race half (a response held in flight across a Clear) is pinned
 * deterministically by smoke/clear-race-smoke.ts; this smoke covers the real
 * API, real byte cursor and real journal file.
 */
import { JSDOM } from 'jsdom'
import { statSync, existsSync, readFileSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'

const ANALYTICS = process.env.LIVE_CAPTURE_API_URL ?? 'http://127.0.0.1:8081'
const POLL_MS = 2_500

/** The evidence file, only used to prove Clear never truncates or deletes it. */
const JOURNAL = (() => {
  const given = process.env.LIVE_CAPTURE_JOURNAL ?? 'results/observed-state/demo/live_events.jsonl'
  const candidates = [given, resolve('..', given)].map((p) => (isAbsolute(p) ? p : resolve(process.cwd(), p)))
  return candidates.find((p) => existsSync(p)) ?? candidates[0]
})()
const journalBytes = () => (existsSync(JOURNAL) ? statSync(JOURNAL).size : -1)
const journalLines = () =>
  existsSync(JOURNAL) ? readFileSync(JOURNAL, 'utf-8').split('\n').length - 1 : -1

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
  if (!detail.includes('not wrapped in act') && !detail.startsWith('FAIL ')) consoleErrors.push(detail)
  origError(...args)
}

const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter } = await import('react-router-dom')
const { LiveScreening } = await import('@/pages/LiveScreening')
const { formatLocalClock } = await import('@/lib/timeZone')

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
const waitFor = async (predicate: () => boolean, ms: number, stepMs = 1600) => {
  const started = Date.now()
  while (Date.now() - started < ms) {
    if (predicate()) return true
    await settle(stepMs)
  }
  return predicate()
}

type FeedEvent = { id: string; timestamp_ns: number; info: string }
const probe = async (cursor: number, limit: number) =>
  (await (
    await fetch(`${ANALYTICS}/api/v1/capture/events?cursor=${cursor}&limit=${limit}`)
  ).json()) as {
    present: boolean
    current?: boolean
    size: number
    total: number
    cursor: number
    has_more: boolean
    events: FeedEvent[]
  }
/** Every packet appended after a byte offset, keyed the way a row renders. */
const windowSince = async (offset: number) => {
  const keys = new Set<string>()
  let cursor = offset
  for (let guard = 0; guard < 20; guard += 1) {
    const page = await probe(cursor, 500)
    for (const event of page.events) keys.add(`${formatLocalClock(event.timestamp_ns)}|${event.info}`)
    if (!page.has_more) break
    cursor = page.cursor
  }
  return keys
}

const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)

const text = () => host.textContent ?? ''
const rows = () => host.querySelectorAll('tbody tr').length
const num = (s: string) => Number(s.replace(/,/g, ''))
const counters = () => {
  const m = text().match(/([\d,]+) shown · ([\d,]+) buffered · ([\d,]+) in journal/)
  return m ? { shown: num(m[1]), buffered: num(m[2]), journal: num(m[3]) } : null
}
/** Rendered row keys, exactly as drawn: the local clock + the Info string. */
const rowKeys = (): string[] =>
  Array.from(host.querySelectorAll('tbody tr')).map((tr) => {
    const cells = (tr as HTMLTableRowElement).cells
    return `${cells[1]?.textContent?.trim() ?? ''}|${cells[7]?.textContent?.trim() ?? ''}`
  })
const clickClear = async () => {
  const button = Array.from(host.querySelectorAll<HTMLElement>('button')).find(
    (b) => b.textContent?.trim() === 'Clear',
  )
  if (!button) throw new Error('Clear button not found')
  await act(async () => {
    button.click()
  })
}

// ---------------------------------------------------------------------------
// 1. Open the workspace on a journal that already holds recorded rows.
// ---------------------------------------------------------------------------
const before = await probe(0, 1)
const recorded = Number(before.total ?? 0)
check('the feed reports a journal that already holds recorded rows', recorded > 0, `total=${recorded}`)
check(
  'the feed is the actively-written journal',
  before.present === true && before.current === true,
  `present=${before.present} current=${before.current}`,
)

const bytesAtOpen = journalBytes()
const linesAtOpen = journalLines()
await act(async () => {
  root.render(createElement(MemoryRouter, { initialEntries: ['/'] }, createElement(LiveScreening)))
})
await settle(3_600)

const atOpen = counters()
check(
  'the journal is reported in full while the table holds nothing recorded',
  atOpen !== null && atOpen.journal >= recorded,
  JSON.stringify(atOpen),
)
check('the journal file is the one under test', bytesAtOpen > 0, `${JOURNAL} (${bytesAtOpen} bytes)`)

const openedWith = await waitFor(() => rows() > 0, 90_000)
check('packets captured after opening appear without a refresh', openedWith, `rows=${rows()}`)
const allowedAtOpen = await windowSince(bytesAtOpen)
const strayAtOpen = rowKeys().filter((k) => !allowedAtOpen.has(k))
check(
  'no row from before the view opened is ever displayed',
  strayAtOpen.length === 0,
  `stray=${strayAtOpen.slice(0, 3).join(' ; ')}`,
)
check(
  'the rows shown are no more than the packets written since opening',
  rows() <= journalLines() - linesAtOpen,
  `rows=${rows()} appended=${journalLines() - linesAtOpen}`,
)
check('the page renders risk from the store', /CRITICAL|HIGH|MEDIUM|LOW|INFO|—/.test(text()))

// ---------------------------------------------------------------------------
// 2. Clear empties the view, keeps the journal count, and never touches the file.
// ---------------------------------------------------------------------------
const beforeClear = counters()
const bytesBeforeClear = journalBytes()
const linesBeforeClear = journalLines()
await clickClear()
const afterClear = counters()
check('Clear empties the table immediately', rows() === 0, `rows=${rows()}`)
check(
  'the counters read 0 shown · 0 buffered with the journal count unchanged',
  afterClear !== null &&
    afterClear.shown === 0 &&
    afterClear.buffered === 0 &&
    afterClear.journal === beforeClear?.journal,
  `${JSON.stringify(afterClear)} (was ${JSON.stringify(beforeClear)})`,
)
check(
  'Clear does not truncate the journal',
  journalBytes() === bytesBeforeClear && journalLines() === linesBeforeClear,
  `${journalBytes()} vs ${bytesBeforeClear} bytes`,
)
const keysBeforeClear = rowKeys()

// ---------------------------------------------------------------------------
// 3. Only packets captured after the Clear may appear.
// ---------------------------------------------------------------------------
for (let i = 0; i < 3; i += 1) await settle(POLL_MS + 400)
const returned = await waitFor(() => rows() > 0, 90_000)
check('a packet captured after the Clear appears', returned, `rows=${rows()}`)
// The byte window is read once the rows are on screen: everything the journal
// grew by since the click, which is a superset of what the page may show.
const allowedAfterClear = await windowSince(bytesBeforeClear)
const strayAfterClear = rowKeys().filter((k) => !allowedAfterClear.has(k))
check(
  'no packet from before the Clear comes back',
  strayAfterClear.length === 0,
  `stray=${strayAfterClear.slice(0, 3).join(' ; ')} shown=${rowKeys().join(' ; ')}`,
)
check(
  'the rows shown are no more than the packets written since the Clear',
  rows() <= journalLines() - linesBeforeClear,
  `rows=${rows()} appended=${journalLines() - linesBeforeClear}`,
)
const keysAfterClear = rowKeys()

// ---------------------------------------------------------------------------
// 4. Clear again with polling active; the same contract holds.
// ---------------------------------------------------------------------------
const bytesBeforeSecond = journalBytes()
await clickClear()
check('the second Clear empties the table immediately', rows() === 0, `rows=${rows()}`)
for (let i = 0; i < 3; i += 1) await settle(POLL_MS + 400)
const arrivedAgain = await waitFor(() => rows() > 0, 90_000)
check('the next new packet appears after the second Clear', arrivedAgain, `rows=${rows()}`)
const allowedAfterSecond = await windowSince(bytesBeforeSecond)
const strayAfterSecond = rowKeys().filter((k) => !allowedAfterSecond.has(k))
check(
  'only packets captured after the second Clear are shown',
  strayAfterSecond.length === 0,
  `stray=${strayAfterSecond.slice(0, 3).join(' ; ')}`,
)
const cameBack = rowKeys().filter((k) => keysBeforeClear.includes(k))
check('a packet shown before a Clear never reappears', cameBack.length === 0, cameBack.slice(0, 3).join(' ; '))

// ---------------------------------------------------------------------------
// The evidence file only ever grew.
// ---------------------------------------------------------------------------
check(
  'the journal was never truncated or deleted',
  journalBytes() >= bytesAtOpen && journalLines() >= linesAtOpen && journalBytes() > bytesAtOpen,
  `${linesAtOpen} -> ${journalLines()} lines, ${bytesAtOpen} -> ${journalBytes()} bytes`,
)
check(
  'the rendered clock is browser-local with no hard-coded zone',
  /[0-2]\d:[0-5]\d:[0-5]\d\.\d{3}/.test(text()) && !/IST/.test(text()),
  (text().match(/[0-2]\d:[0-5]\d:[0-5]\d\.\d{3}/) ?? [])[0] ?? 'no local clock found',
)
check('no console errors during the run', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '))

console.log(' ')
console.log('LIVE CLEAR SUMMARY')
console.log(`  analytics          : ${ANALYTICS}`)
console.log(`  journal            : ${JOURNAL}`)
console.log(`  recorded at open   : ${recorded} rows (${linesAtOpen} lines / ${bytesAtOpen} bytes)`)
console.log(`  journal at the end : ${journalLines()} lines / ${journalBytes()} bytes`)
console.log(`  counters at open   : ${JSON.stringify(atOpen)}`)
console.log(`  before 1st Clear   : ${JSON.stringify(beforeClear)} rows=${keysBeforeClear.length}`)
console.log(`  after  1st Clear   : ${JSON.stringify(afterClear)}`)
console.log(`  after 1st, new rows: ${keysAfterClear.slice(0, 3).join(' ; ') || '—'}`)
console.log(failures === 0 ? 'LIVE CLEAR ACCEPTANCE OK' : `${failures} LIVE CLEAR CHECK(S) FAILED`)
process.exit(failures > 0 ? 1 : 0)
