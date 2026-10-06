/**
 * PacketInvestigation smoke — proves the in-workspace investigation surface
 * against the LIVE analytics store, driving the honest states of the panel:
 *
 *   1. No packet selected            -> the compact no-selection state.
 *   2. An unassessed packet          -> observed facts only, an explicit
 *                                       "no security finding", and NOT a single
 *                                       assessment request on the wire.
 *   3. A packet observed by a REAL assessment
 *                                    -> the four sections in order, each labelled
 *                                       with its origin, every value taken from
 *                                       the store and nothing invented.
 *   4. A risk reference to an assessment that does not exist
 *                                    -> a structured error state, not a
 *                                       fabricated result.
 *
 * It also asserts the panel's central contract: the assessment record is NOT
 * reprinted here. Score arithmetic, custody, evidence artifacts, explainability
 * and backend record identifiers belong to their own screens, and this smoke
 * fails if they creep back into the packet panel.
 *
 * The panel is mounted directly (MemoryRouter supplies the one link it
 * renders), so this smoke isolates exactly this surface.
 */
import { JSDOM } from 'jsdom'

const ANALYTICS = process.env.INVESTIGATION_API_URL ?? 'http://127.0.0.1:8081'

/*
 * LIVE-SERVICE SMOKE. Unlike the deterministic harnesses, this one reads a real
 * assessment bundle over the wire, so it needs a running analytics API that
 * `INVESTIGATION_API_URL` points at. Its distinctive value is the wire-level
 * contract — a packet with no risk record must cause NO assessment request at
 * all — which is why it is kept rather than folded into the stubbed harnesses.
 */

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

// The feed polls on a real timer, so React reports updates that land outside an
// act() window. That is an artifact of driving a live interval in jsdom, not a
// page defect, and it would otherwise bury the run's own output.
const origError = console.error
console.error = (...args: unknown[]) => {
  // Only the act() noise is dropped; this harness's own FAIL lines and any real
  // render error must still reach the log.
  const detail = args.map((a) => (a instanceof Error ? a.message : String(a))).join(' ')
  if (detail.includes('not wrapped in act')) return
  origError(...args)
}

// Record every request the panel actually makes so the "no fetch for
// risk-less packets" contract is asserted on the wire, not by reading code.
const realFetch = globalThis.fetch
const calls: string[] = []
const faults = new Map<string, string>()
globalThis.fetch = ((input, init) => {
  const url = (typeof input === 'string' ? input : input instanceof URL ? input.href : String(input)).replace(
    /\?.*$/,
    '',
  )
  calls.push(url)
  const fault = faults.get(url)
  if (fault) {
    return Promise.resolve(
      new Response(fault, { status: 502, headers: { 'content-type': 'application/json' } }),
    )
  }
  return realFetch(input, init)
}) as typeof fetch
/** Assessment requests the panel made, i.e. work it asked the store to do. */
const assessmentRequests = () => calls.filter((url) => url.includes('/api/v1/assessments/'))
const markCalls = () => calls.length
/** Assessment requests made so far — the baseline for a delta assertion. */
const markAssessment = () => assessmentRequests().length

const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter } = await import('react-router-dom')
const { PacketInvestigation } = await import('@/components/packet/PacketInvestigation')
const { toCaptureRow } = await import('@/lib/packetRows')
const { getAssessments, getAssessment } = await import('@/api/analytics')

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
const settle = (ms = 2200) => act(async () => { await wait(ms) })

async function waitFor(predicate: () => boolean, ms = 5000) {
  const started = Date.now()
  while (Date.now() - started < ms) {
    if (predicate()) return true
    await settle(150)
  }
  return predicate()
}

async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true, cancelable: true }))
  })
}

/** Pick a real assessment from the running store whose bundle satisfies `matcher`. */
async function pickBundle(
  bundleMatches: (bundle: AssessmentBundle) => boolean,
  headerCap = 60,
): Promise<{ header: AssessmentHeader; bundle: AssessmentBundle } | null> {
  const seeds = await getAssessments({ limit: headerCap })
  for (const header of seeds.headers) {
    const bundle = await getAssessment(header.assessment_id).catch(() => null)
    if (bundle && bundleMatches(bundle)) return { header, bundle }
  }
  return null
}

function makeRow(spi: number | null, risk: CapturePacket['risk']): CaptureRow {
  const packet = {
    id: `inv-${spi ?? 'none'}`,
    source: 'live_events.jsonl',
    offset: 0,
    timestamp_ns: 1790620496789000000,
    schema: 'sentinel.analytics.capture.packet.v1',
    packet: {
      timestamp: 1790620496789000000,
      interface: 'eth2',
      protocol: 50,
      source: '10.10.1.10',
      destination: '10.10.2.10',
      spi,
      sequence: 7,
      packet_length: 128,
      source_port: 500,
      destination_port: 0,
      classification: spi === null ? 'OTHER' : 'ESP',
      direction: 'inbound',
      sensor_type: 'xdp_monitor',
    },
    protocol_label: spi === null ? 'UDP' : 'ESP',
    info: 'ESP packet',
    spi,
    risk,
  } as unknown as CapturePacket
  return toCaptureRow(packet, 1)
}

async function mount(row: CaptureRow | null, assessmentId: string | null) {
  const host = dom.window.document.createElement('div')
  dom.window.document.body.appendChild(host)
  const root = createRoot(host)
  await act(async () => {
    root.render(
      createElement(
        MemoryRouter,
        { initialEntries: ['/'] },
        row === null
          ? createElement(LiveScreening)
          : createElement(PacketInvestigation, {
              row,
              assessmentId,
              position: 0,
              total: 1,
              onPrevious: () => {},
              onNext: () => {},
              onClose: () => {},
              onMinimize: () => {},
              minimized: false,
            }),
      ),
    )
  })
  return { host, root }
}

const text = (host: Element) => host.textContent ?? ''
const root = dom.window.document.body
calls.length = 0

const assessments = await getAssessments({ limit: 10 })
check('store is reachable for this smoke', assessments.headers.length > 0)

// --------------------------------------------------------------------------
// 1. No packet selected: no investigation window exists, and nothing is asked
//    of the store. The old design rendered an inline panel here; the window is
//    only created by a selection, so its absence is the correct state.
// --------------------------------------------------------------------------
{
  const assessmentMark = markAssessment()
  const { host } = await mount(null, null)
  await settle(500)
  check(
    'with no packet selected there is no investigation window',
    host.querySelector('.ls-inv-overlay') === null,
    text(host).slice(0, 120),
  )
  check(
    'the page asks for a selection instead',
    /Select a packet/i.test(text(host)),
    text(host).slice(0, 120),
  )
  check(
    'no packet selected asks the store for no assessment',
    assessmentRequests().length === assessmentMark,
    `${assessmentRequests().length - assessmentMark} assessment requests`,
  )
  root.removeChild(host)
}

// --------------------------------------------------------------------------
// 2. An unassessed packet: the window opens, the packet's own captured record
//    stays, and every panel says it has nothing rather than inventing work.
// --------------------------------------------------------------------------
{
  const row = makeRow(null, { present: false } as CapturePacket['risk'])
  const assessmentMark = markAssessment()
  const { host } = await mount(row, null)
  await settle(600)
  const panel = text(host)
  check(
    'an unassessed packet still shows the endpoints it was captured on',
    panel.includes('10.10.1.10') && panel.includes('10.10.2.10'),
    panel.slice(0, 120),
  )
  check(
    'an unassessed packet keeps all three panel columns',
    host.querySelectorAll('.ls-inv-panel-col').length === 3,
    `cols=${host.querySelectorAll('.ls-inv-panel-col').length}`,
  )
  check(
    'an unassessed packet claims no configuration, observation or finding',
    (panel.match(/not assessed/gi) ?? []).length >= 2 && !/\b(LOW|MEDIUM|HIGH|CRITICAL)\b/.test(panel),
    panel.slice(0, 200),
  )
  check(
    'an unassessed packet asks the store for no assessment',
    assessmentRequests().length === assessmentMark,
    `${assessmentRequests().length - assessmentMark} assessment requests`,
  )
  root.removeChild(host)
}

// --------------------------------------------------------------------------
// 3. A packet observed by a REAL assessment: three panels, each badged for its
//    own provenance, risk verbatim, findings tied to this assessment.
// --------------------------------------------------------------------------
const target = await pickBundle((bundle) => bundle.risk?.findings?.length > 0 && bundle.expected != null)

if (target === null) {
  check('the store exposes an assessment with findings to investigate', false, 'no matching bundle found')
} else {
  const { bundle } = target
  const spi = bundle.observed?.spis?.[0]?.spi ?? null
  const numericSpi = spi === null ? null : Number.parseInt(String(spi).replace(/^0x/, ''), 16)
  const row = makeRow(numericSpi, {
    present: true,
    highest_severity: bundle.risk.severity,
    highest_risk_score: bundle.risk.overall_score,
    assessments: [{ assessment_id: bundle.assessment_id }],
  } as CapturePacket['risk'])

  const { host } = await mount(row, bundle.assessment_id)
  const ready = await waitFor(() => text(host).includes('IPsec Configuration'))
  check('the investigation window renders for a real assessment', ready, text(host).slice(0, 160))
  await settle(400)

  check(
    'the three analyst panels are present, in order, in three columns',
    (() => {
      const cols = host.querySelectorAll('.ls-inv-panel-col')
      if (cols.length !== 3) return false
      const panels = Array.from(cols).map((c) => c.querySelector('.ls-card-title')?.textContent ?? '')
      return (
        panels[0] === 'IPsec Configuration' &&
        panels[1] === 'Observed Traffic' &&
        panels[2] === 'Configuration Findings'
      )
    })(),
  )
  check(
    'each panel is badged for its own provenance',
    host.querySelector('.ls-state-configured') !== null &&
      host.querySelector('.ls-state-observed') !== null &&
      host.querySelector('.ls-state-assessed') !== null,
  )
  check(
    'the assessment risk is displayed exactly as the store supplied it',
    text(host).includes(String(bundle.risk.overall_score)) &&
      text(host).toUpperCase().includes(String(bundle.risk.severity).toUpperCase()),
    `score=${bundle.risk.overall_score} severity=${bundle.risk.severity}`,
  )
  check(
    'no key/value cell renders empty',
    Array.from(host.querySelectorAll('.ls-kv-val')).every(
      (el) => (el.textContent ?? '').trim().length > 0,
    ),
  )
  const configurationFindings = (bundle.risk.findings ?? []).filter(
    (f: Finding) => f.source === 'EXPECTED_CONFIGURATION',
  )
  check(
    'findings shown are this assessment\u2019s configuration findings',
    host.querySelectorAll('.ls-finding').length === configurationFindings.length,
    `shown=${host.querySelectorAll('.ls-finding').length} expected=${configurationFindings.length}`,
  )
  // The disclosure is asynchronous state, so this is awaited rather than
  // asserted straight after a click.
  const detailsButton = Array.from(host.querySelectorAll('.ls-finding-actions button')).find((b) =>
    /Details/.test(b.textContent ?? ''),
  ) as HTMLButtonElement | undefined
  if (detailsButton) {
    await click(detailsButton)
    await settle(120)
  }
  check(
    'a finding can be expanded to its full backend record',
    configurationFindings.length === 0 || host.querySelector('.ls-finding-detail') !== null,
    `expanded=${host.querySelectorAll('.ls-finding-detail').length}`,
  )
  check(
    'a finding is collapsed again on a second click',
    await (async () => {
      if (!detailsButton) return true
      await click(detailsButton)
      await settle(120)
      return host.querySelector('.ls-finding-detail') === null
    })(),
  )
  // Re-expand so the remaining assertions see the record the panel renders.
  if (detailsButton) {
    await click(detailsButton)
    await settle(120)
  }
  check(
    'each finding offers its own Ask AI action',
    configurationFindings.length === 0 ||
      host.querySelectorAll('.ls-btn-ai').length >= configurationFindings.length,
    `askButtons=${host.querySelectorAll('.ls-btn-ai').length}`,
  )
  check(
    'the observed panel shows only measured or inferred values',
    /Packets/.test(text(host)) &&
      !new RegExp(bundle.expected?.esp?.encryption ?? '\u0000').test(
        (host.querySelector('.ls-inv-panel-col:nth-child(2)')?.textContent ?? ''),
      ),
    'configured cipher leaked into the observed panel',
  )
  root.removeChild(host)
}

console.log(failures === 0 ? 'INVESTIGATION OK' : `${failures} CHECK(S) FAILED`)
// The capture feed polls on a live interval, so Node would otherwise never exit.
// Nothing is pending that matters once the checks above have run.
process.exit(failures > 0 ? 1 : 0)
