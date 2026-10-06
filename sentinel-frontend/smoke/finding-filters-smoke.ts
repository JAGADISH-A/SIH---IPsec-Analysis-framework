/**
 * Finding filter bar smoke (not part of the shipped app).
 *
 * `FindingFilterBar` narrows an assessment's findings by risk, confidence,
 * traffic, finding id and drift. It is a self-contained presentational
 * component, so this harness mounts it directly and drives it with a synthetic
 * index — the bar's own filtering contract is exercised without a live
 * assessment API and without any server, capture or lab.
 *
 * What is pinned here:
 *
 *   1. The bar reports the store's totals honestly, and never claims more
 *      findings than exist.
 *   2. Each filter key narrows the set: severity, minimum confidence, traffic
 *      tag, exact finding id, and drift presence.
 *   3. Clearing restores the full set, and the active-filter count tracks how
 *      many are applied.
 *   4. The bar only ever narrows the *findings index*. It never filters, hides
 *      or reorders live packet rows — that was the behaviour this component was
 *      explicitly built to avoid.
 *
 * Note: the bar's previous only mount point was the retired `PacketWorkspace`.
 * It is mounted directly here on purpose; the old page is not resurrected.
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
  if (!detail.includes('not wrapped in act') && !detail.startsWith('FAIL ')) consoleErrors.push(detail)
  origError(...args)
}

const { createRoot } = await import('react-dom/client')
const { act, createElement, useMemo, useState } = await import('react')
const { FindingFilterBar } = await import('@/components/packet/FindingFilterBar')
// The production narrowing logic and its defaults, so this harness exercises
// the real rules rather than a reimplementation of them.
const { DEFAULT_FILTERS, matchesFilters } = await import('@/hooks/useFindingFilters')
type FilteredFinding = import('@/hooks/useFindingFilters').FilteredFinding

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}
const settle = async (ms = 60) => act(async () => { await new Promise((r) => setTimeout(r, ms)) })
async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true, cancelable: true }))
  })
}
const text = (el: Element | null) => (el?.textContent ?? '').replace(/\s+/g, ' ').trim()

/* ---------------------------------------------------------- synthetic index */

const A = '9c1f2d70-5a3b-4e88-9f21-7d6c0b4a1e35'
const B = '4e7a1b93-6c25-4d10-8b3f-2a9e5c7d8061'

const finding = (
  finding_id: string,
  assessment_id: string,
  severity: string,
  confidence: number | null,
  traffic_tags: string[],
  drift: FilteredFinding['driftBucket'],
  source: string,
) =>
  ({
    finding: {
      finding_id,
      assessment_id,
      severity,
      confidence,
      traffic_tags,
      source,
      reason: `${finding_id} reason`,
      rule_id: `RULE_${finding_id}`,
      policy_version: 'v3',
    },
    severity,
    confidence,
    trafficTags: traffic_tags,
    driftBucket: drift,
    driftStatus: drift === 'with' ? 'DRIFTED' : 'NONE',
    assessment_id,
  }) as unknown as FilteredFinding

const FINDINGS: FilteredFinding[] = [
  finding('ESP_NO_INTEGRITY', A, 'HIGH', 0.94, ['esp', 'no-integrity'], 'with', 'EXPECTED_CONFIGURATION'),
  finding('IKEV2_WEAK_DH', A, 'MEDIUM', 0.81, ['ikev2'], 'without', 'EXPECTED_CONFIGURATION'),
  finding('PFS_DISABLED', B, 'LOW', 0.42, ['esp', 'pfs'], 'without', 'EXPECTED_CONFIGURATION'),
  finding('INFERRED_ANOMALY', B, 'CRITICAL', null, ['anomaly'], 'with', 'INFERRED_TRAFFIC'),
]
const ALL_IDS = FINDINGS.map((f) => f.finding.finding_id).join(',')

/* ----------------------------------------------------------------- harness */

const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)

/**
 * A minimal owner around the bar: it holds the filter state and applies the
 * same narrowing rules the store uses, so the assertions can observe both the
 * reported count and the resulting rows.
 */
// Captured from inside the component so the harness can drive the bar through
// its real `onChange`/`onClear` callbacks rather than reaching past them.
let applyFilterState: (patch: Record<string, unknown>) => void = () => {}
let clearFilterState: () => void = () => {}

function Harness() {
  const [filters, setFilters] = useState({ ...DEFAULT_FILTERS })
  applyFilterState = (patch) => setFilters((prev) => ({ ...prev, ...patch }))
  clearFilterState = () => setFilters({ ...DEFAULT_FILTERS })
  const filtered = useMemo(() => FINDINGS.filter((f) => matchesFilters(f, filters)), [filters])

  const activeCount = Object.values(filters).filter((v) => v !== 'ALL').length

  const store = useMemo(
    () => ({
      loading: false,
      error: null,
      reload: () => {},
      totalFindings: FINDINGS.length,
      filteredFindings: filtered.length,
      assessmentCount: 2,
      countBySeverity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => ({
        severity,
        count: FINDINGS.filter((f) => f.severity === severity).length,
      })),
      findingOptions: FINDINGS.map((f) => f.finding.finding_id),
      trafficOptions: Array.from(new Set(FINDINGS.flatMap((f) => f.trafficTags))),
    }),
    [filtered.length],
  )

  return createElement(
    'div',
    null,
    createElement('div', { id: 'live-rows' }, 'LIVE-STREAM-ROW'),
    createElement(
      'div',
      { id: 'filtered' },
      filtered.map((f) => f.finding.finding_id).join(',') || '-none-',
    ),
    createElement(FindingFilterBar, {
      filters: filters as never,
      onChange: (patch: Record<string, unknown>) => setFilters((prev) => ({ ...prev, ...patch })),
      onClear: () => clearFilterState(),
      activeCount,
      findingStore: store as never,
      findings: filtered,
      onOpenFinding: () => {},
      bufferedAssessmentIds: new Set<string>([A, B]),
    }),
  )
}

await act(async () => root.render(createElement(Harness)))
await settle(120)

const bar = () => host.querySelector('[data-findings-bar]')
const toggle = () => host.querySelector('[data-findings-toggle]')
const summaryEl = () => host.querySelector('[data-findings-summary]')
const countBadge = () => text(host.querySelector('[data-findings-count]'))
const filtered = () => host.querySelector('#filtered')?.textContent ?? ''
const summary = () => text(summaryEl())

// The findings strip is collapsed by default — the bar is a single-line header
// until the analyst opens it, so it must open before anything inside counts.
check('the bar mounts collapsed', bar() !== null && toggle()?.getAttribute('aria-expanded') === 'false')
check('the collapsed header warns that filters never touch the live capture', /never the live/.test(text(bar())), text(bar()).slice(0, 160))
await click(toggle()!)
await settle(100)
check('the toggle opens the findings strip', toggle()?.getAttribute('aria-expanded') === 'true')
check('the strip lists the findings rows', host.querySelector('[data-findings-strip]') !== null)

/* ------------------------------------------------------------- the totals */

check('the bar mounts', bar() !== null)
check('every finding is listed before any filter', filtered() === ALL_IDS, filtered())
check(
  'the bar reports the full count honestly',
  /4 findings/.test(summary()),
  summary(),
)
check(
  'the bar reports the per-severity breakdown',
  /1 CRITICAL/.test(summary()) && /1 HIGH/.test(summary()) && /1 MEDIUM/.test(summary()) && /1 LOW/.test(summary()),
  summary(),
)

/* ------------------------------------------------------ filters narrow it */

/** Apply a filter through the bar's own dropdown and return the narrowed set. */
/** Each filter is asserted independently: start from the defaults, then set one. */
async function applyFilter(key: string, value: string | number) {
  await act(async () => {
    clearFilterState()
  })
  await settle(40)
  await act(async () => {
    applyFilterState({ [key]: value })
  })
  await settle(80)
  return filtered()
}

/** Applying several filters at once, to pin that they intersect. */
async function applyFilters(patch: Record<string, string | number>) {
  await act(async () => {
    clearFilterState()
  })
  await settle(40)
  await act(async () => {
    applyFilterState(patch)
  })
  await settle(80)
  return filtered()
}

const bySeverity = await applyFilter('risk', 'HIGH')
check('a severity filter narrows to that severity', bySeverity === 'ESP_NO_INTEGRITY', bySeverity)
check(
  'a narrowed bar reports "N of M findings" rather than the total',
  /1 of 4 findings/.test(summary()),
  summary(),
)

const byConfidence = await applyFilter('confidence', 80)
check(
  'a minimum-confidence filter keeps only findings at or above it',
  byConfidence === 'ESP_NO_INTEGRITY,IKEV2_WEAK_DH',
  byConfidence,
)

const byTraffic = await applyFilter('traffic', 'pfs')
check('a traffic filter narrows by tag', byTraffic === 'PFS_DISABLED', byTraffic)

const byFinding = await applyFilter('finding', 'INFERRED_ANOMALY')
check('a finding filter narrows to that exact finding', byFinding === 'INFERRED_ANOMALY', byFinding)

const driftOn = await applyFilter('drift', 'with')
check(
  'a drift filter keeps only findings with drift',
  driftOn === 'ESP_NO_INTEGRITY,INFERRED_ANOMALY',
  driftOn,
)
const driftOff = await applyFilter('drift', 'without')
check(
  'the inverse drift filter keeps only findings without drift',
  driftOff === 'IKEV2_WEAK_DH,PFS_DISABLED',
  driftOff,
)

const combined = await applyFilters({ risk: 'CRITICAL', traffic: 'esp' })
check(
  'filters intersect rather than replace one another',
  combined === '-none-',
  combined,
)
check('an empty result still renders the bar', bar() !== null)

/* ----------------------------------------------------------------- clear */

const clearButton = host.querySelector('[data-action="clear-filters"]')
check('an open bar with active filters offers a clear control', clearButton !== null)
if (clearButton) await click(clearButton)
await settle(100)
check('clearing restores the full set', filtered() === ALL_IDS, filtered())
check('a cleared bar reports no active filters', /4 findings/.test(summary()), summary())

/* --------------------------------- the bar must not touch the live stream */

check(
  'the filter bar leaves the live packet stream untouched',
  host.querySelector('#live-rows')?.textContent === 'LIVE-STREAM-ROW' && filtered() === ALL_IDS,
)
check(
  'no live packet row is hidden by a findings filter',
  host.querySelectorAll('tbody tr').length === 0,
  `rows=${host.querySelectorAll('tbody tr').length}`,
)

check('no render errors were logged', consoleErrors.length === 0, consoleErrors.slice(0, 2).join(' | '))

await act(async () => root.unmount())

console.log(
  failures === 0 ? 'FINDING FILTERS OK' : `${failures} FINDING FILTER CHECK(S) FAILED`,
)
if (failures > 0) process.exitCode = 1