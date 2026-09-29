/**
 * Finding Filters smoke — proves the horizontal FINDINGS filter bar on the
 * Packet Analysis workspace against the LIVE analytics store.
 *
 * The bar narrows *findings* (never the live packet stream) by Risk /
 * Confidence / Traffic / Finding / Drift, all with values derived from the
 * store, client-side and deterministic (AND across filters). It also covers
 * the risk-colour triage contract in the packet table: the severity chips are
 * the exact backend values, readable as text, one shared RiskChip, and no-risk
 * packets keep an honest fallback.
 *
 * Expected counts are computed from the live store first (not hard-coded), so
 * this does not silently stop covering the dataset when a new run lands.
 */
import { JSDOM } from 'jsdom'

const ANALYTICS = process.env.FINDING_FILTERS_API_URL ?? 'http://127.0.0.1:8081'

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

const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter } = await import('react-router-dom')
const { PacketWorkspace } = await import('@/pages/PacketWorkspace')
const { RiskChip } = await import('@/components/packet/primitives')
const { getAssessment, getAssessmentDrift, getAssessments, getFindings } = await import('@/api/analytics')
import type { AssessmentDriftResponse, AssessmentHeader, Finding, MlResult } from '@/types'

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const settle = (ms = 2200) => act(async () => { await wait(ms) })

async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true, cancelable: true }))
  })
}

// ---------------------------------------------------------------------------
// Expected values, computed from the LIVE store (mirror of the client filter).
// ---------------------------------------------------------------------------
const findingsRes = await getFindings({ limit: 500 })
const assessmentsRes = await getAssessments({ limit: 100 })
const findings = findingsRes.findings
const headers = new Map(assessmentsRes.headers.map((h) => [h.assessment_id, h]))

const ml: Map<string, MlResult> = new Map()
for (const header of assessmentsRes.headers.filter((h) => h.ml_present)) {
  const bundle = await getAssessment(header.assessment_id).catch(() => null)
  if (bundle) ml.set(header.assessment_id, bundle.ml)
}

const drift: Map<string, AssessmentDriftResponse> = new Map()
for (const header of assessmentsRes.headers) {
  const record = await getAssessmentDrift(header.assessment_id).catch(() => null)
  if (record) drift.set(header.assessment_id, record)
}

function tagsFor(assessmentId: string): string[] {
  const assessment = headers.get(assessmentId)
  const tags: string[] = []
  if (assessment?.traffic_profile) tags.push(assessment.traffic_profile.toLowerCase())
  const mlResult = ml.get(assessmentId)
  if (mlResult?.present && mlResult.traffic_class) tags.push(mlResult.traffic_class.toLowerCase())
  return [...new Set(tags)]
}

function driftStatus(assessmentId: string): 'with' | 'without' {
  const record = drift.get(assessmentId)
  if (!record || record.drift_detected === true) return 'with' // conservative: no record -> not 'without'
  return 'without'
}

const total = findings.length
const bySeverity = (severity: string) =>
  findings.filter((f) => (f.severity ?? '').toUpperCase() === severity).length
const byTraffic = (tag: string) => findings.filter((f) => tagsFor(f.assessment_id).includes(tag)).length
const byFindingId = (id: string) => findings.filter((f) => f.finding_id === id).length
const byDrift = (bucket: 'with' | 'without') =>
  findings.filter((f) => driftStatus(f.assessment_id) === bucket).length
const confidenceMatches = (threshold: number) =>
  findings.filter((f) => f.confidence !== null && f.confidence * 100 >= threshold).length

const mlFinding = findings.find((f) => f.confidence !== null)
const mlAssessmentId = mlFinding?.assessment_id ?? null

// ---------------------------------------------------------------------------
// RiskChip severity matrix — every label is the exact backend word, readable
// as text; null severity has an honest fallback.
// ---------------------------------------------------------------------------
{
  const host = dom.window.document.createElement('div')
  dom.window.document.body.appendChild(host)
  const root = createRoot(host)
  await act(async () => {
    root.render(
      createElement(
        'div',
        null,
        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((severity) =>
          createElement(RiskChip, { key: severity, severity, score: null }),
        ),
        createElement(RiskChip, { key: 'none', severity: null, score: null }),
      ),
    )
  })
  const chipText = (host.textContent ?? '').split('\n').join(' ').trim()
  for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
    check(`risk chip renders the exact backend label ${severity}`, chipText.includes(severity), chipText)
  }
  check('risk chip gives a missing risk an honest fallback', chipText.includes('—'), chipText)
  await act(async () => root.unmount())
  host.remove()
}

// ---------------------------------------------------------------------------
// The workspace with the findings filter bar.
// ---------------------------------------------------------------------------
const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)
await act(async () => {
  root.render(createElement(MemoryRouter, { initialEntries: ['/'] }, createElement(PacketWorkspace)))
})
// Findings index + per-assessment drift + ml bundle all settle first.
await settle(3800)

let text = host.textContent ?? ''
// The findings section is SECONDARY: the live capture sits above it, and the
// section is collapsed until an analyst expands it.
const liveSection = host.querySelector('[data-live-section]')
const findingsSectionEl = host.querySelector('[data-findings-section]')
const findingsToggle = host.querySelector<HTMLElement>('[data-findings-toggle]')
check(
  'the primary section is LIVE IPSEC TRAFFIC and findings sit below it',
  Boolean(
    liveSection &&
      findingsSectionEl &&
      /LIVE IPSEC TRAFFIC/.test(liveSection.textContent ?? '') &&
      (liveSection.compareDocumentPosition(findingsSectionEl) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0,
  ),
  text.slice(0, 120),
)
check(
  'the findings section is collapsed by default',
  findingsToggle?.getAttribute('aria-expanded') === 'false',
  findingsToggle?.getAttribute('aria-expanded') ?? 'no toggle',
)
check('the collapsed findings section still labels itself FINDINGS', text.includes('FINDINGS'), text.slice(0, 120))
if (findingsToggle) await click(findingsToggle)
await settle(250)
text = host.textContent ?? ''
for (const key of ['risk', 'confidence', 'traffic', 'finding', 'drift']) {
  check(`filter bar carries the ${key} dropdown`, host.querySelector(`button[data-filter="${key}"]`) !== null)
}
check('filter bar offers Clear Filters', host.querySelector('[data-action="clear-filters"]') !== null)
check('filter bar shows the summary line', /findings/.test(text) && /assessments/.test(text), text.slice(0, 180))

const stripRows = () => host.querySelectorAll('[data-finding-row]').length
check('no filters -> every store finding is listed', stripRows() === total, `rows=${stripRows()} expected=${total}`)
check(
  'summary counts are derived from the store',
  text.includes(`${total} findings`) && text.includes(`${bySeverity('MEDIUM')} MEDIUM`) && text.includes(`${bySeverity('LOW')} LOW`),
  text.slice(0, 200),
)

// Open the risk menu to inspect its options, then close it.
const riskTrigger = host.querySelector<HTMLElement>('button[data-filter="risk"]')!
await click(riskTrigger)
await settle(150)
{
  const menu = host.querySelector('[data-filter-menu="risk"]')
  const options = menu ? [...menu.querySelectorAll('[role="menuitemradio"]')].map((b) => b.textContent) : []
  check(
    'risk options are exactly All, CRITICAL, HIGH, MEDIUM, LOW, INFO',
    options.join(',') === 'All,CRITICAL,HIGH,MEDIUM,LOW,INFO',
    options.join(','),
  )
  // Close the menu by selecting "All" (no-op) — equivalent to a close.
  const allOption = [...(menu?.querySelectorAll('button') ?? [])].find((b) => b.textContent === 'All')
  if (allOption) await click(allOption)
  await settle(150)
}

async function pick(filterKey: string, label: string) {
  const trigger = host.querySelector<HTMLElement>(`button[data-filter="${filterKey}"]`)
  if (!trigger) throw new Error(`no trigger for ${filterKey}`)
  await click(trigger)
  await settle(120)
  const menu = host.querySelector(`[data-filter-menu="${filterKey}"]`)
  const option = [...(menu?.querySelectorAll('button') ?? [])].find((b) => b.textContent?.trim() === label)
  if (!option) throw new Error(`no option "${label}" in ${filterKey}`)
  await click(option)
  await settle(150)
}

// --- Risk filter alone.
await pick('risk', 'MEDIUM')
text = host.textContent ?? ''
check('risk=MEDIUM narrows to MEDIUM findings', stripRows() === bySeverity('MEDIUM'), `rows=${stripRows()} expected=${bySeverity('MEDIUM')}`)
await pick('risk', 'LOW')
check('risk=LOW narrows to LOW findings', stripRows() === bySeverity('LOW'), `rows=${stripRows()} expected=${bySeverity('LOW')}`)
await pick('risk', 'HIGH')
text = host.textContent ?? ''
check(
  'risk=HIGH with no matches shows the honest empty state',
  stripRows() === 0 && text.includes('No findings match the selected filters.'),
  text.slice(0, 160),
)
const emptyClear = host.querySelector('[data-empty-state] [data-action="clear-filters"]')
check('empty state offers Clear Filters', emptyClear !== null)
if (emptyClear) await click(emptyClear)
await settle(150)

// --- Confidence filter alone (backend finding.confidence only).
await pick('confidence', '≥50%')
check(
  'confidence ≥50% shows only findings with a backend confidence',
  stripRows() === confidenceMatches(50),
  `rows=${stripRows()} expected=${confidenceMatches(50)}`,
)
await pick('confidence', '≥90%')
check(
  'confidence ≥90% is an honest zero-result for this store',
  stripRows() === confidenceMatches(90) && (stripRows() === 0 || stripRows() === confidenceMatches(90)),
  `rows=${stripRows()}`,
)
await pick('confidence', 'All')
check('confidence=All restores all findings', stripRows() === total, `rows=${stripRows()}`)

// --- Traffic filter alone (derived store labels only).
await pick('traffic', 'Email')
check('traffic=Email narrows to email-profile findings', stripRows() === byTraffic('email'), `rows=${stripRows()} expected=${byTraffic('email')}`)
await pick('traffic', 'All')
{
  // The traffic options are DERIVED: only tags present on actual findings are
  // offered. VoIP/Video profiles have zero findings in this store, so they must
  // NOT appear as filter options (nothing is hard-coded).
  const trigger = host.querySelector<HTMLElement>('button[data-filter="traffic"]')!
  await click(trigger)
  await settle(120)
  const menu = host.querySelector('[data-filter-menu="traffic"]')
  const options = menu ? [...menu.querySelectorAll('[role="menuitemradio"]')].map((b) => b.textContent?.trim() ?? '') : []
  check(
    'traffic options come only from store findings (no VoIP/video hard-coded)',
    options.includes('Email') && options.includes('ICMP') && !options.includes('VoIP') && !options.includes('Video'),
    options.join(','),
  )
  const allOption = [...(menu?.querySelectorAll('button') ?? [])].find((b) => b.textContent?.trim() === 'All')
  if (allOption) await click(allOption)
  await settle(150)
}
await pick('traffic', 'ICMP')
check(
  'traffic=ICMP narrows to the ML-inferred finding',
  stripRows() === byTraffic('icmp'),
  `rows=${stripRows()} expected=${byTraffic('icmp')}`,
)
await pick('traffic', 'All')

// --- Finding-type filter alone (actual finding ids from the store).
await pick('finding', mlFinding?.finding_id ?? 'RISK-ML-CLASSIFICATION')
check(
  'finding filter narrows to the exact rule id',
  stripRows() === byFindingId(mlFinding?.finding_id ?? 'RISK-ML-CLASSIFICATION'),
  `rows=${stripRows()}`,
)
await pick('finding', 'All')

// --- Drift filter alone (backend drift state; this store has no baseline).
check(
  'drift=without matches every finding while no baseline is configured',
  byDrift('without') === total,
  `without=${byDrift('without')}`,
)
await pick('drift', 'Without drift')
check('drift=without selects the store-wide reported no-drift findings', stripRows() === byDrift('without'), `rows=${stripRows()} expected=${byDrift('without')}`)
await pick('drift', 'With drift')
check(
  'drift=with is the honest zero-result when nothing drifted',
  byDrift('with') === 0 && stripRows() === 0 && (host.textContent ?? '').includes('No findings match the selected filters.'),
  `rows=${stripRows()} with=${byDrift('with')}`,
)
await pick('drift', 'All')

// --- AND combination: MEDIUM risk + Email traffic.
const expectedAnd = findings.filter(
  (f) => (f.severity ?? '').toUpperCase() === 'MEDIUM' && tagsFor(f.assessment_id).includes('email'),
).length
await pick('risk', 'MEDIUM')
await pick('traffic', 'Email')
check('AND combination (MEDIUM · Email) intersects the filters', stripRows() === expectedAnd, `rows=${stripRows()} expected=${expectedAnd}`)

// --- Clear Filters resets everything.
const clearFilters = host.querySelector<HTMLElement>('button[data-action="clear-filters"]')
if (clearFilters) await click(clearFilters)
await settle(150)
text = host.textContent ?? ''
check('Clear Filters restores the full finding list', stripRows() === total, `rows=${stripRows()}`)
check('Clear Filters restores the unfiltered summary', text.includes(`${total} findings`), text.slice(0, 160))

// --- The live packet table is untouched by findings filters. The table only
// --- renders while the backend reports current traffic; with a recorded/stale
// --- journal it must be the explicit recorded-history empty state instead.
// --- Probe the real feed for the backend's own verdict.
text = host.textContent ?? ''
check('the live feed row still reports the journal', /buffered|in journal/.test(text), text.slice(0, 200))
const captureProbe = await fetch(`${ANALYTICS}/api/v1/capture/events`).then((r) => r.json().catch(() => null))
const liveFeed = Boolean(captureProbe && captureProbe.current === true)
if (liveFeed) {
  const tableRows = host.querySelectorAll('tbody tr').length
  check('the live packet table renders while the feed is current', tableRows > 0, `rows=${tableRows}`)
  check(
    'the packet table keeps the browser-local clock column',
    /[0-2]\d:[0-5]\d:[0-5]\d\.\d{3}/.test(text) && !/IST/.test(text),
    text.slice(0, 120),
  )
  check('the packet table carries the shared risk chip', /INFO|MEDIUM|LOW|HIGH|CRITICAL|—/.test(text), text.slice(0, 200))

  // --- Clicking a packet row opens its real investigation (INFO, no finding).
  const firstPacket = host.querySelector<HTMLElement>('tbody tr')
  if (firstPacket) {
    await click(firstPacket)
    await settle(3600)
    text = host.textContent ?? ''
    check(
      'packet click opens the investigation either with the honest no-finding state or tabs',
      text.includes('No security finding associated with this packet/flow.') ||
        /Overview|IKE & SA|Gateway Config|Evidence/.test(text),
      text.slice(0, 200),
    )
    check(
      'risk label in the packet row is the backend severity word, not fabricated',
      /INFO|LOW|MEDIUM|HIGH|CRITICAL/.test(text),
    )
  }
} else {
  const empty = host.querySelector('[data-no-traffic]')
  check(
    'a non-current feed renders the recorded-history empty state instead of rows',
    empty !== null && /No current IPsec traffic observed/.test(empty.textContent ?? ''),
    empty?.textContent?.slice(0, 120) ?? 'no [data-no-traffic]',
  )
  check('no live table rows are fabricated from the recorded journal', host.querySelectorAll('tbody tr').length === 0)
}

// --- Clicking a finding (no buffered packet) opens the assessment's
// --- investigation through the shared anchor (real store data only).
await pick('finding', mlFinding?.finding_id ?? 'RISK-ML-CLASSIFICATION')
const mlRow = [...host.querySelectorAll<HTMLElement>('[data-finding-row]')].find((row) =>
  row.textContent?.includes(mlFinding?.finding_id ?? 'RISK-ML-CLASSIFICATION'),
)
check('the ML finding is listed under its own finding-type filter', mlRow !== undefined)
if (mlRow) {
  await click(mlRow)
  await settle(4200)
  text = host.textContent ?? ''
  check(
    'finding click opens the real assessment investigation (anchor, no fabricated packet)',
    /RISK-ML-CLASSIFICATION|Overview|IKE & SA|Gateway Config|Evidence|Why flagged|Relevant configuration/.test(text),
    text.slice(0, 240),
  )
  check(
    'the anchor investigation is explicit that no current live packet is available',
    /no current live packet/.test(text),
  )
  if (mlFinding && mlAssessmentId) {
    check(
      'the investigation resolves the finding to its real assessment',
      host.querySelector(`a[href*="${encodeURIComponent(mlAssessmentId)}"]`) !== null,
      mlAssessmentId,
    )
  }
}

// ---------------------------------------------------------------------------
// Risk vs finding severity — the two concepts must never be blended.
//
// The Risk filter keys on finding.severity, while the packet table and the
// investigation render the ASSESSMENT's highest_severity. A real assessment in
// this store has a severity that differs from one of its findings, which is the
// regression this section pins down.
// ---------------------------------------------------------------------------
{
  // A finding id can repeat across assessments (two configurations can trip the
  // same rule), so the split must be chosen on a finding id that is UNIQUE in
  // this store — otherwise the row matched by id text could be a different
  // assessment's row.
  const idCounts = new Map<string, number>()
  for (const finding of findings) idCounts.set(finding.finding_id, (idCounts.get(finding.finding_id) ?? 0) + 1)
  const split = findings.find((f) => {
    const header = headers.get(f.assessment_id)
    return (
      header &&
      (header.severity ?? '').toUpperCase() !== (f.severity ?? '').toUpperCase() &&
      idCounts.get(f.finding_id) === 1
    )
  })
  if (!split) {
    console.log('skip  (no assessment severity differs from a finding severity in this store)')
  } else {
    const splitHeader = headers.get(split.assessment_id)!
    const assessmentSeverity = (splitHeader.severity ?? '').toUpperCase()
    const findingSeverity = (split.severity ?? '').toUpperCase()
    check(
      'the store contains an assessment severity that differs from one of its findings',
      assessmentSeverity !== findingSeverity,
      `assessment=${assessmentSeverity} finding=${findingSeverity}`,
    )

    // Risk filter = finding.severity. Selecting the ASSESSMENT severity must not
    // pull in a finding of a different severity. (The finding filter is cleared
    // first so this section measures the Risk filter alone.)
    await pick('finding', 'All')
    await pick('risk', assessmentSeverity)
    const chipSeverity = (el: Element | null) => (el?.textContent ?? '').split('\u00b7')[0]!.trim()
    const listedChips = [...host.querySelectorAll('[data-finding-row] .pw-risk')].map(chipSeverity)
    check(
      `risk=${assessmentSeverity} never returns a ${findingSeverity} finding from a ${assessmentSeverity} assessment`,
      listedChips.length === bySeverity(assessmentSeverity) && !listedChips.includes(findingSeverity),
      `chips=${listedChips.join(',')} expected=${bySeverity(assessmentSeverity)}`,
    )

    // ...and the finding is found under ITS OWN severity.
    await pick('risk', findingSeverity)
    const splitRow = [...host.querySelectorAll<HTMLElement>('[data-finding-row]')].find((row) =>
      row.textContent?.includes(split.finding_id),
    )
    check(
      `risk=${findingSeverity} finds the finding of a ${assessmentSeverity} assessment`,
      splitRow !== undefined && stripRows() === bySeverity(findingSeverity),
      `rows=${stripRows()} expected=${bySeverity(findingSeverity)}`,
    )

    // The packet table's RISK column is assessment-level, never a finding severity.
    if (liveFeed) {
      const tableChips = [...host.querySelectorAll('tbody [data-risk]')].map(chipSeverity)
      const storeSeverities = new Set(
        [...headers.values()].map((h) => (h.severity ?? '').toUpperCase()),
      )
      check(
        'the packet table RISK column carries assessment severities, not finding severities',
        tableChips.length > 0 && tableChips.every((chip) => chip === 'UNASSESSED' || storeSeverities.has(chip)),
        tableChips.join(','),
      )
    }

    // Opening that finding must keep the two apart: the packet risk chip is the
    // ASSESSMENT severity, the finding keeps its own severity, and the note
    // spells the difference out.
    if (splitRow) {
      await click(splitRow)
      await settle(4600)
      const investigation = host.querySelector('.pw-inspector') ?? host
      check(
        'the click opened the split finding\'s own assessment',
        investigation.querySelector(`a[href*="${encodeURIComponent(split.assessment_id)}"]`) !== null,
        split.assessment_id,
      )
      const packetRiskChip = chipSeverity(investigation.querySelector('.pw-strip .pw-risk'))
      check(
        'the opened finding shows the ASSESSMENT severity as the packet risk',
        packetRiskChip === assessmentSeverity,
        `chip=${packetRiskChip} expected=${assessmentSeverity}`,
      )
      const note = investigation.querySelector('[data-risk-vs-severity]')
      check(
        'the opened finding states the risk / severity difference explicitly',
        note !== null &&
          (note.textContent ?? '').includes(assessmentSeverity) &&
          (note.textContent ?? '').includes(findingSeverity),
        note?.textContent ?? 'no note rendered',
      )
      check(
        'the finding severity is still shown as its own value',
        [...investigation.querySelectorAll('.pw-risk')].map(chipSeverity).includes(findingSeverity),
      )
    }
  }
  await pick('risk', 'All')
}

await act(async () => root.unmount())

console.log(
  failures === 0
    ? 'FINDING FILTERS + RISK TRIAGE OK'
    : `${failures} FINDING FILTER CHECK(S) FAILED`,
)
if (failures > 0) process.exitCode = 1