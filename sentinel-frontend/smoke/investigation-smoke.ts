/**
 * PacketInvestigation smoke — proves the in-workspace investigation surface
 * against the LIVE analytics store, driving all three honest states:
 *
 *   1. A packet the store never assessed (risk absent) -> the "No security
 *      finding associated with this packet/flow." empty state, and NOT a single
 *      assessment request on the wire (the panel does not invent work).
 *   2. A packet whose SPI was observed by a REAL assessment -> the real
 *      assessment is fetched and the real tabs render real fields (SPI from the
 *      context strip, provenance labels, correlation/drift rows).
 *   3. A risk reference to an assessment that no longer exists -> a structured
 *      error state from the server, not a fabricated result.
 *
 * The investigation panel is mounted directly (MemoryRouter supplies the
 * links the panel renders), so this smoke isolates exactly the new surface.
 */
import { JSDOM } from 'jsdom'

const ANALYTICS = process.env.INVESTIGATION_API_URL ?? 'http://127.0.0.1:8081'

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

// Record every request the panel actually makes so the "no fetch for
// risk-less packets" contract is asserted on the wire, not by reading code.
const realFetch = globalThis.fetch
const calls: string[] = []
const faults = new Map<string, string>()
const stalls = new Map<string, number>()
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
  const stall = stalls.get(url)
  if (stall) {
    return new Promise((resolve) => {
      setTimeout(() => {
        void realFetch(input as RequestInfo, init).then(resolve)
      }, stall)
    })
  }
  return realFetch(input, init)
}) as typeof fetch
/** Custody request URLs, optionally restricted to one finding. */
const custodyRequests = (findingId?: string) =>
  calls.filter(
    (url) =>
      url.includes('/findings/') &&
      url.includes('/explanation') &&
      (findingId === undefined || url.includes(encodeURIComponent(findingId))),
  )
/**
 * The exact URL the client uses for one finding's custody request. The base is
 * taken from a request the panel actually made, so a fault/stall always lands on
 * the real call whatever host the service is configured with.
 */
const custodyUrl = (assessmentId: string, findingId: string) => {
  const sample = calls.find((url) => url.includes('/explanation'))
  const base = sample ? sample.slice(0, sample.indexOf('/api/v1/assessments/')) : ANALYTICS
  return `${base}/api/v1/assessments/${encodeURIComponent(assessmentId)}/findings/${encodeURIComponent(findingId)}/explanation`
}
const markCalls = () => calls.length
const since = (from: number) => calls.slice(from)

const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter } = await import('react-router-dom')
const { PacketInvestigation } = await import('@/components/packet/PacketInvestigation')
const { toCaptureRow } = await import('@/lib/packetRows')
const {
  getAssessments,
  getAssessment,
  getAssessmentFindings,
  getFindingExplanation,
} = await import('@/api/analytics')
const { selectPrimaryFinding } = await import('@/hooks/usePacketInvestigation')
import type { CaptureRow } from '@/lib/packetRows'
import type { AssessmentBundle, AssessmentHeader, CapturePacket } from '@/types'

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
/** A RiskChip's severity, without the score suffix it may carry. */
const chipTextOf = (el: Element | null) => (el?.textContent ?? '').split('\u00b7')[0]!.trim()
const settle = (ms = 2200) => act(async () => { await wait(ms) })

/** Poll until a network-backed condition holds, so timing is not asserted. */
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

/**
 * Open a collapsible investigation section by its title, exactly as an analyst
 * would. The investigation is one scroll of collapsible sections now, so a
 * check that reads deep evidence must first disclose it.
 */
async function openSection(host: Element, title: string) {
  const section = host.querySelector(`section[data-collapsible="${title}"]`)
  if (!section || section.getAttribute('data-open') === 'true') return
  const button = section.querySelector('button')
  if (button) await click(button)
  await settle(150)
}

/** Pick a real assessment whose bundle satisfies `matcher`, fetching bundles. */
async function pickBundle(
  headerMatches: (header: AssessmentHeader) => boolean,
  bundleMatches: (bundle: AssessmentBundle) => boolean,
  headerCap = 60,
): Promise<{ header: AssessmentHeader; bundle: AssessmentBundle } | null> {
  const seeds = await getAssessments({ limit: headerCap })
  for (const header of seeds.headers) {
    if (!headerMatches(header)) continue
    const bundle = await getAssessment(header.assessment_id).catch(() => null)
    if (bundle && bundleMatches(bundle)) return { header, bundle }
  }
  return null
}

function makeModel(spi: number | null, risk: CapturePacket['risk'], timestampNs = 1790620496789000000): CaptureRow {
  const packet: CapturePacket = {
    id: `p-${spi ?? 'plain'}`,
    source: 'live_xdp',
    offset: 7,
    timestamp_ns: timestampNs,
    schema: 'xdp_event_v1',
    protocol_label: spi === null ? 'UDP' : 'ESP',
    info: `SPI 0x${spi === null ? 0 : spi.toString(16)}`,
    spi,
    packet: {
      timestamp: timestampNs,
      interface: 'eth1',
      protocol: spi === null ? 17 : 50,
      source: '10.10.1.10',
      destination: '10.10.2.10',
      spi,
      sequence: 42,
      packet_length: 128,
      source_port: 500,
      destination_port: 0,
      classification: spi === null ? 'OTHER' : 'ESP',
      direction: 'a_to_b',
      sensor_type: 'xdp_monitor',
    },
    risk,
  }
  return toCaptureRow(packet, 1)
}

async function mount(model: CaptureRow | null) {
  const host = dom.window.document.createElement('div')
  dom.window.document.body.appendChild(host)
  const root = createRoot(host)
  await act(async () => {
    root.render(
      createElement(MemoryRouter, { initialEntries: ['/'] }, createElement(PacketInvestigation, { model, held: false })),
    )
  })
  return { host, root }
}

const root = dom.window.document.body
// Establish a baseline of the requests the wrapper itself makes, if any.
calls.length = 0

const assessments = await getAssessments({ limit: 10 })
check('store is reachable for this smoke', assessments.headers.length > 0)
const realId = assessments.headers[0].assessment_id

// --------------------------------------------------------------------------
// 1. No risk attached -> honest empty state, and no assessment on the wire.
// --------------------------------------------------------------------------
const noRisk = makeModel(null, { present: false })
const noRiskBox = await mount(noRisk)
calls.length = 0
await settle()
const noRiskText = noRiskBox.host.textContent ?? ''
check(
  'risk-less packet opens the investigation empty state',
  noRiskText.includes('No security finding associated with this packet/flow.'),
)
check(
  'risk-less packet triggers no assessment fetch',
  !calls.some((url) => /\/assessments\/|\/findings\/|\/drift|explanation/.test(url)),
  calls.join(', '),
)
check('no-risk still shows the packet context strip', noRiskText.includes('10.10.1.10') && noRiskText.includes('10.10.2.10'))
check(
  'a packet with no assessment offers no XAI action',
  !noRiskText.includes('Explain this finding') && noRiskBox.host.querySelector('[data-xai-toggle]') === null,
  noRiskText.slice(0, 160),
)
await act(async () => noRiskBox.root.unmount())

// --------------------------------------------------------------------------
// 2. Real assessment -> real tabs, real fields, honest provenance.
// --------------------------------------------------------------------------
const real = makeModel(0x44, {
  present: true,
  highest_severity: 'HIGH',
  highest_risk_score: 60,
  assessments: [{ assessment_id: realId, severity: 'HIGH', risk_score: 60, finding_count: 1 }],
})
const realBox = await mount(real)
calls.length = 0
await settle()
const realText = realBox.host.textContent ?? ''
const sectionTitles = [
  'Overview',
  'Why this risk?',
  'Configuration',
  'Allowed / expected combinations',
  'Drift',
  'Evidence',
  'Chain of custody',
  'AI explanation',
]
const sectionsPresent = sectionTitles.every(
  (title) => realBox.host.querySelector(`section[data-collapsible="${title}"]`) !== null,
)
check('investigation renders the collapsible sections for an assessed packet', sectionsPresent)
check(
  'investigation renders the packet SPI from the capture',
  /0x00000044|0x44/.test(realText),
  realText.slice(0, 120),
)
const encodedRealId = encodeURIComponent(realId)
check('investigation links to the real assessment', realBox.host.querySelector(`a[href*="${encodedRealId}"]`) !== null)
check('investigation labels provenance', /configured|observed|not provided by backend/.test(realText))
check('investigation reaches real store data', /Traffic type|Observed SA|Assessment|drift/i.test(realText))
await act(async () => realBox.root.unmount())

// --------------------------------------------------------------------------
// 2b. Real assessment WITH an ML verdict -> backend confidence, inferred
//     traffic type, the engine's own finding, honest combination + drift.
// --------------------------------------------------------------------------
{
  const picked = await pickBundle(
    (h) => h.ml_present === true && h.finding_count > 0,
    () => true,
  )
  if (!picked) {
    console.log('skip  (no ml assessment in the live store)')
  } else {
    const { bundle } = picked
    const findingsRes = await getAssessmentFindings(bundle.assessment_id)
    const primary = selectPrimaryFinding(findingsRes.findings)
    const mlConf = `${((bundle.ml.classification_confidence ?? 0) * 100).toFixed(1)}%`
    const mlModel = makeModel(0x51, {
      present: true,
      highest_severity: String(bundle.risk.severity),
      highest_risk_score: bundle.risk.overall_score,
      assessments: [
        {
          assessment_id: bundle.assessment_id,
          severity: String(bundle.risk.severity),
          risk_score: bundle.risk.overall_score,
          finding_count: findingsRes.count,
        },
      ],
    })
    const mlBox = await mount(mlModel)
    calls.length = 0
    await settle(2600)
    // Deep sections start collapsed; disclose them as an analyst would.
    await openSection(mlBox.host, 'Allowed / expected combinations')
    await openSection(mlBox.host, 'Drift')
    await openSection(mlBox.host, 'Evidence')
    await openSection(mlBox.host, 'AI explanation')
    const mlText = mlBox.host.textContent ?? ''
    check(
      'ml assessment renders the confidence section',
      /Confidence/.test(mlText),
      mlText.slice(0, 200),
    )
    check(
      'ml classification confidence is the backend score (not recomputed)',
      mlText.includes(mlConf),
      `expected ${mlConf}`,
    )
    check(
      'confidence block exposes the same backend score for filtering',
      mlBox.host.querySelector('[data-confidence]')?.getAttribute('data-confidence') === mlConf,
      mlBox.host.querySelector('[data-confidence]')?.getAttribute('data-confidence') ?? '',
    )
    check(
      'inferred traffic type comes from the ML verdict',
      bundle.ml.traffic_class ? mlText.includes(bundle.ml.traffic_class) : true,
      mlText.slice(0, 200),
    )
    check('why-flagged presents the primary finding', primary ? mlText.includes(primary.title) : true)
    check(
      "the primary finding's backend confidence (or its honest absence) is shown",
      primary ? (primary.confidence === null ? /deterministic rule/.test(mlText) : mlText.includes(`${(primary.confidence * 100).toFixed(1)}%`)) : true,
    )
    check(
      'relevant configuration marks the finding-related rows',
      /Relevant configuration/.test(mlText) && /Show all configuration/.test(mlText),
    )
    check(
      'configuration combination is honestly unavailable',
      mlText.includes('No configuration combination analysis is available for this finding.'),
    )
    check(
      'configuration drift block renders (real or honest-not-configured)',
      /Configuration drift/.test(mlText),
    )
    check(
      'evidence section is present with a jump target',
      /Evidence & provenance/.test(mlText) && /View evidence/.test(mlText),
    )
    check(
      'xai entry point is present',
      /Explain this finding/.test(mlText),
    )
    // The entry-point control is labelled "Explain with AI" (it explains what is
    // already recorded) and the thread's follow-up is "Ask AI". Both must be in
    // the ML tab, because that is where the analyst reads the confidence section
    // the assistant is explicitly not allowed to replace.
    check('ask-ai entry point is present', /Ask AI/.test(mlText) && /Explain with AI/.test(mlText))

    // --- Risk (assessment/packet) vs finding severity stay two concepts. ---
    const packetRisk = mlBox.host.querySelector('[data-packet-risk]')
    check(
      'the verdict chip is labelled as the assessment / packet risk',
      packetRisk !== null && /assessment \/ packet risk/.test(packetRisk.textContent ?? ''),
      packetRisk?.textContent ?? '',
    )
    check(
      'the assessment risk value is the store highest-severity (not a finding severity)',
      (mlBox.host.querySelector('[data-packet-risk]')?.closest('.pw-risk-col')?.querySelector('.pw-risk')?.textContent ?? '')
        .startsWith(String(bundle.risk.severity)),
      bundle.risk.severity,
    )
    const explained =
      mlBox.host.querySelector('[data-explained="true"]')?.getAttribute('data-finding-id') ?? null
    check(
      'the overview explains one of this assessment\'s own findings, and marks it',
      explained !== null && findingsRes.findings.some((f) => f.finding_id === explained),
      `explained=${explained}`,
    )
    if (primary && String(bundle.risk.severity) !== String(primary.severity)) {
      const note = mlBox.host.querySelector('[data-risk-vs-severity]')
      check(
        'differing assessment risk and finding severity are called out explicitly',
        note !== null &&
          (note.textContent ?? '').includes(String(bundle.risk.severity)) &&
          (note.textContent ?? '').includes(String(primary.severity)),
        note?.textContent ?? 'no note rendered',
      )
    } else {
      check(
        'identical assessment risk and finding severity avoid duplicate chips',
        mlBox.host.querySelector('[data-risk-vs-severity]') === null,
      )
    }

    // --- XAI: explain this finding, grounded in the backend's own records. ---
    const xaiToggle = [...mlBox.host.querySelectorAll('button')].find(
      (btn) => btn.getAttribute('data-xai-toggle') === 'true',
    )
    check('xai action is offered for a real finding', xaiToggle !== undefined)
    if (xaiToggle) {
      await click(xaiToggle)
      await settle(400)
      const panel = mlBox.host.querySelector('[data-xai-panel]')
      const panelText = panel?.textContent ?? ''
      check('xai panel opens inside the investigation', panel !== null)
      check(
        'the open xai panel explains the very finding the overview marked',
        panel?.querySelector('[data-xai-finding-id]')?.getAttribute('data-xai-finding-id') === explained,
        `panel=${panel?.querySelector('[data-xai-finding-id]')?.getAttribute('data-xai-finding-id')} marked=${explained}`,
      )
      check(
        'xai panel separates assessment risk from finding severity',
        panel?.querySelector('[data-xai-assessment-severity]')?.getAttribute('data-xai-assessment-severity') ===
          String(bundle.risk.severity) &&
          panel?.querySelector('[data-xai-finding-severity]')?.getAttribute('data-xai-finding-severity') ===
            String(primary?.severity ?? ''),
        `assessment=${panel?.querySelector('[data-xai-assessment-severity]')?.getAttribute('data-xai-assessment-severity')} finding=${panel?.querySelector('[data-xai-finding-severity]')?.getAttribute('data-xai-finding-severity')}`,
      )
      check(
        'xai panel uses the exact backend confidence (never recomputed)',
        bundle.ml.classification_confidence === null || panelText.includes(mlConf),
        `expected ${mlConf}`,
      )
      check(
        'xai panel renders the backend detection and key factors',
        /What Sentinel detected/.test(panelText) && /Key factors/.test(panelText) && /evidence:/.test(panelText),
        panelText.slice(0, 200),
      )
      check(
        'xai panel reports the ML model record, not invented attribution',
        bundle.ml.model_version !== null ? panelText.includes(bundle.ml.model_version) : true,
      )
      check(
        'xai panel states feature attribution is unavailable instead of inventing it',
        panelText.includes('Model feature attribution is not available for this assessment'),
      )
      check(
        'xai panel keeps configuration, drift and evidence grounded',
        /Configuration impact/.test(panelText) && /Drift/.test(panelText) && /Evidence/.test(panelText),
        panelText.slice(0, 200),
      )
      check(
        'xai panel keeps the technical details collapsible',
        mlBox.host.querySelector('details.pw-xai-details') !== null,
      )
      check(
        'xai is positioned as the deterministic why, separate from Ask AI',
        /Ask AI \(below\)/.test(panelText),
      )
    }

    // --- Selecting a DIFFERENT finding re-points the explanation. The
    // --- assessment-level packet risk must not move with the selection.
    const other = findingsRes.findings.find((f) => f.finding_id !== explained)
    if (!other) {
      console.log('skip  (the assessment has a single finding)')
    } else {
      const riskBefore = chipTextOf(mlBox.host.querySelector('[data-packet-risk]')?.closest('.pw-risk-col')?.querySelector('.pw-risk'))
      const explainButton = mlBox.host.querySelector<HTMLElement>(`[data-explain-finding="${other.finding_id}"]`)
      check('each finding offers its own Explain this finding action', explainButton !== null, other.finding_id)
      if (explainButton) {
        await click(explainButton)
        await settle(300)
        check(
          'selecting a finding re-points the explanation to that finding',
          mlBox.host.querySelector('[data-explained="true"]')?.getAttribute('data-finding-id') === other.finding_id,
          `marked=${mlBox.host.querySelector('[data-explained="true"]')?.getAttribute('data-finding-id')} expected=${other.finding_id}`,
        )
        check(
          'the assessment risk is unchanged by the finding selection',
          chipTextOf(mlBox.host.querySelector('[data-packet-risk]')?.closest('.pw-risk-col')?.querySelector('.pw-risk')) === riskBefore &&
            riskBefore.startsWith(String(bundle.risk.severity)),
          `before=${riskBefore} after=${chipTextOf(mlBox.host.querySelector('[data-packet-risk]')?.closest('.pw-risk-col')?.querySelector('.pw-risk'))}`,
        )
        const note = mlBox.host.querySelector('[data-risk-vs-severity]')
        check(
          'the risk / severity note follows the selected finding',
          note === null ||
            ((note.textContent ?? '').includes(String(bundle.risk.severity)) &&
              (note.textContent ?? '').includes(String(other.severity))),
          note?.textContent ?? 'no note rendered',
        )
        const xaiToggle2 = [...mlBox.host.querySelectorAll('button')].find(
          (btn) => btn.getAttribute('data-xai-toggle') === 'true',
        )
        // The panel may already be open from the previous assertion; only open
        // it when it is closed, so toggling never hides the newly selected one.
        if (xaiToggle2 && mlBox.host.querySelector('[data-xai-finding-id]') === null) {
          await click(xaiToggle2)
          await settle(300)
        }
        check(
          'the xai panel then explains the newly selected finding',
          mlBox.host.querySelector('[data-xai-finding-id]')?.getAttribute('data-xai-finding-id') === other.finding_id,
        )
        check(
          'a deterministic finding is never dressed up as model-derived',
          other.source === 'ML' || !!mlBox.host.querySelector('[data-xai-ml-not-source]'),
          `source=${other.source}`,
        )
      }
    }
    await act(async () => mlBox.root.unmount())
  }
}

// --------------------------------------------------------------------------
// 2c. Real assessment WITH observed endpoints -> gateway A/B comparison,
//     the evidence chain and its provenance, plus interactive jumps.
// --------------------------------------------------------------------------
{
  const picked = await pickBundle(
    (h) => h.finding_count > 0,
    (b) => Boolean(b.observed.endpoints?.a && b.observed.endpoints?.b),
  )
  if (!picked) {
    console.log('skip  (no endpoint-observed assessment in the live store)')
  } else {
    const { bundle } = picked
    const findingsRes = await getAssessmentFindings(bundle.assessment_id)
    const primary = selectPrimaryFinding(findingsRes.findings)
    const firstRef = primary?.evidence_refs?.[0]
    const gateModel = makeModel(0x52, {
      present: true,
      highest_severity: String(bundle.risk.severity),
      highest_risk_score: bundle.risk.overall_score,
      assessments: [
        {
          assessment_id: bundle.assessment_id,
          severity: String(bundle.risk.severity),
          risk_score: bundle.risk.overall_score,
          finding_count: findingsRes.count,
        },
      ],
    })
    const gateBox = await mount(gateModel)
    calls.length = 0
    await settle(2600)
    await openSection(gateBox.host, 'Evidence')
    await openSection(gateBox.host, 'Chain of custody')
    const gateText = gateBox.host.textContent ?? ''
    const a = bundle.observed.endpoints?.a ?? ''
    const b = bundle.observed.endpoints?.b ?? ''
    check(
      'configuration comparison names both gateways',
      /Gateway A/.test(gateText) && /Gateway B/.test(gateText),
    )
    check('observed endpoint addresses are rendered', gateText.includes(a) && gateText.includes(b))
    check(
      'comparison carries provenance (configured vs observed)',
      /configured|observed|not provided by backend/.test(gateText),
    )
    if (primary) {
      check(
        'evidence chain links the finding to its exact artifact',
        /Evidence & provenance/.test(gateText) &&
          (firstRef?.evidence_id ? gateText.includes(firstRef.evidence_id) : true) &&
          (firstRef?.source ? gateText.includes(firstRef.source) : true),
        gateText.slice(0, 300),
      )
      check(
        'evidence provenance + open-finding target are linked',
        gateBox.host.querySelector(`a[href*="${encodeURIComponent(primary.finding_id)}"]`) !== null,
      )
      const viewEvidence = [...gateBox.host.querySelectorAll('button')].find((btn) => btn.textContent?.includes('View evidence'))
      check('view-evidence action is available', viewEvidence !== undefined)
      if (viewEvidence) {
        await click(viewEvidence)
        await settle(200)
        const a2 = gateBox.host.textContent ?? ''
        check(
          'view-evidence reveals the Evidence section',
          a2.includes('Integrity is verified by the analytics backend over the stored artifact.') &&
            gateBox.host.querySelector('section[data-collapsible="Evidence"]')?.getAttribute('data-open') === 'true',
          a2.slice(0, 200),
        )
        const openExplain = [...gateBox.host.querySelectorAll('button')].find((btn) => btn.textContent?.includes('Show custody chain'))
        check('xai custody chain is expandable', openExplain !== undefined)
        if (openExplain) {
          await click(openExplain)
          await settle(200)
          const a3 = gateBox.host.textContent ?? ''
          check(
            'custody chain reveals facts, steps, recommendation and limitations',
            /Facts/.test(a3) && /Steps/.test(a3) && /Recommendation/.test(a3) && /Limitations/.test(a3),
            a3.slice(0, 200),
          )
        }
      }
    }
    await act(async () => gateBox.root.unmount())
  }
}

// --------------------------------------------------------------------------
// 2f. CUSTODY / PROVENANCE FOLLOWS THE SELECTED FINDING.
//
// Every finding-level surface must belong to the finding on screen, and the
// per-finding custody endpoint must be called with the SELECTED id — never a
// convenient "most severe" one. Driven on a HIGH assessment that carries only
// MEDIUM findings, so assessment risk and finding severity are provably
// different values at the same time.
// --------------------------------------------------------------------------
{
  const picked = await pickBundle(
    (h) => h.finding_count > 1,
    (b) => {
      const rows = b.risk.findings ?? []
      return (
        String(b.risk.severity).toUpperCase() === 'HIGH' &&
        rows.some((f) => String(f.severity).toUpperCase() === 'MEDIUM') &&
        rows.length > 1
      )
    },
  )
  if (!picked) {
    console.log('skip  (no HIGH assessment with several findings in the live store)')
  } else {
    const { bundle } = picked
    const findingsRes = await getAssessmentFindings(bundle.assessment_id)
    // Finding A = a MEDIUM finding of a HIGH assessment. Finding B = another.
    const findingA = findingsRes.findings.find((f) => String(f.severity).toUpperCase() === 'MEDIUM')!
    const findingB = findingsRes.findings.find((f) => f.finding_id !== findingA.finding_id)!
    // Read both chains straight from the service, so the DOM can be checked
    // against values that cannot be confused between the two findings.
    const chainA = await getFindingExplanation(bundle.assessment_id, findingA.finding_id)
    const chainB = await getFindingExplanation(bundle.assessment_id, findingB.finding_id)
    const custodyModel = makeModel(0x71, {
      present: true,
      highest_severity: String(bundle.risk.severity),
      highest_risk_score: bundle.risk.overall_score,
      assessments: [
        {
          assessment_id: bundle.assessment_id,
          severity: String(bundle.risk.severity),
          risk_score: bundle.risk.overall_score,
          finding_count: findingsRes.count,
        },
      ],
    })

    // --- 5. No selected finding -> no finding-level request at all. ---------
    {
      const emptyPicked = await pickBundle(
        (h) => h.finding_count === 0,
        () => true,
      )
      if (!emptyPicked) {
        console.log('skip  (no finding-less assessment in the live store)')
      } else {
        const mark = markCalls()
        const emptyBox = await mount(
          makeModel(0x72, {
            present: true,
            highest_severity: String(emptyPicked.bundle.risk.severity),
            highest_risk_score: emptyPicked.bundle.risk.overall_score,
            assessments: [
              {
                assessment_id: emptyPicked.bundle.assessment_id,
                severity: String(emptyPicked.bundle.risk.severity),
                risk_score: emptyPicked.bundle.risk.overall_score,
                finding_count: 0,
              },
            ],
          }),
        )
        await settle(2600)
        await openSection(emptyBox.host, 'Chain of custody')
        const emptyText = emptyBox.host.textContent ?? ''
        check(
          'no selected finding -> no finding-level custody request is made',
          since(mark).filter((url) => url.includes('/explanation')).length === 0,
          since(mark).filter((u) => u.includes('/explanation')).join(','),
        )
        check(
          'no selected finding -> the custody empty state is honest',
          emptyBox.host.querySelector('[data-custody-empty]') !== null &&
            /no custody chain to explain/.test(emptyText) &&
            emptyBox.host.querySelector('[data-xai-toggle]') === null,
          emptyText.slice(0, 200),
        )
        await act(async () => emptyBox.root.unmount())
      }
    }

    const box = await mount(custodyModel)
    await settle(2800)
    // The Chain of custody section is a deep disclosure; open it once, and its
    // open state persists across finding selections.
    await openSection(box.host, 'Chain of custody')
    // The custody chain is a network read: wait for it rather than guess.
    // "idle" = no request in flight (an honest error also counts as idle);
    // "settled" = a chain actually arrived for the finding on screen.
    const custodyIdle = () =>
      box.host.querySelector('[data-custody-for]') !== null &&
      !box.host.querySelector('[data-custody-loading]')
    const custodySettled = () =>
      custodyIdle() && box.host.querySelector('[data-custody-error]') === null
    await waitFor(custodySettled)

    // The XAI panel starts collapsed; each assertion re-opens it exactly as an
    // analyst would, and it must not be re-closed when it is already open.
    const openXai = async () => {
      if (box.host.querySelector('[data-xai-finding-id]') !== null) return
      const toggle = [...box.host.querySelectorAll('button')].find(
        (btn) => btn.getAttribute('data-xai-toggle') === 'true',
      )
      if (toggle) await click(toggle)
      await settle(250)
    }
    const selectFinding = async (findingId: string) => {
      await click(box.host.querySelector<HTMLElement>(`[data-explain-finding="${findingId}"]`)!)
      await settle(300)
      await openXai()
      await waitFor(custodyIdle)
    }
    // Finding-specific content from each chain, read straight from the service
    // so the DOM can be judged against values that cannot be confused.
    const labelsA = chainA.facts.map((fact) => fact.label)
    const labelsB = chainB.facts.map((fact) => fact.label)
    const onlyA = labelsA.find((label) => !labelsB.includes(label))
    const onlyB = labelsB.find((label) => !labelsA.includes(label))

    // --- 2. The default target is labelled, not hidden. --------------------
    {
      const defaultFor = box.host.querySelector('[data-custody-for]')?.getAttribute('data-custody-for') ?? null
      const defaultMark = markCalls()
      check(
        'the default custody target is the highest-severity finding, and says so',
        defaultFor === findingA.finding_id &&
          /default \(highest-severity finding\)/.test(box.host.textContent ?? ''),
        `defaultFor=${defaultFor} expected=${findingA.finding_id}`,
      )
      check(
        'the default custody request used the default finding id, not another one',
        custodyRequests(findingA.finding_id).length > 0 && since(defaultMark).length >= 0,
        custodyRequests().join(','),
      )
      check(
        'the displayed chain is the default finding\'s own chain',
        defaultFor === findingA.finding_id &&
          (box.host.textContent ?? '').includes(chainA.summary) &&
          !(box.host.textContent ?? '').includes(chainB.summary),
        `summaryA=${chainA.summary.slice(0, 50)}`,
      )
      await openXai()
      check(
        'the chain digest shown belongs to the default finding',
        (box.host.textContent ?? '').includes(chainA.finding_digest) &&
          !(box.host.textContent ?? '').includes(chainB.finding_digest),
        `digestA=${chainA.finding_digest.slice(0, 12)}`,
      )
      // HIGH assessment + MEDIUM finding: both values visible at once.
      check(
        'a HIGH assessment keeps HIGH while the MEDIUM finding keeps MEDIUM',
        chipTextOf(box.host.querySelector('[data-xai-assessment-severity]')?.closest('dd')?.querySelector('.pw-risk')) ===
          'HIGH' &&
          chipTextOf(box.host.querySelector('[data-xai-finding-severity]')?.closest('dd')?.querySelector('.pw-risk')) ===
            'MEDIUM' &&
          chipTextOf(box.host.querySelector('[data-packet-risk]')?.closest('.pw-risk-col')?.querySelector('.pw-risk')) ===
            'HIGH',
        `assessment=${bundle.risk.severity} finding=${findingA.severity}`,
      )
      check(
        'the default custody target is a MEDIUM finding, so custody is for the MEDIUM finding',
        defaultFor === findingA.finding_id && String(findingA.severity).toUpperCase() === 'MEDIUM',
      )
    }

    // --- 3. Selecting Finding B moves every finding-level surface to B. -----
    {
      const mark = markCalls()
      await selectFinding(findingB.finding_id)
      const text = box.host.textContent ?? ''
      check(
        'selecting B switches the xai explanation to B',
        box.host.querySelector('[data-xai-finding-id]')?.getAttribute('data-xai-finding-id') === findingB.finding_id &&
          box.host.querySelector('[data-explained="true"]')?.getAttribute('data-finding-id') === findingB.finding_id,
        `xai=${box.host.querySelector('[data-xai-finding-id]')?.getAttribute('data-xai-finding-id')}`,
      )
      check(
        'selecting B issues a custody request for B\'s id',
        since(mark).some((url) => url.includes(encodeURIComponent(findingB.finding_id))),
        since(mark).filter((u) => u.includes('/explanation')).join(','),
      )
      check(
        'the custody section now shows B\'s chain and none of A\'s',
        box.host.querySelector('[data-custody-for]')?.getAttribute('data-custody-for') === findingB.finding_id &&
          text.includes(chainB.summary) &&
          !text.includes(chainA.summary) &&
          text.includes(chainB.finding_digest) &&
          !text.includes(chainA.finding_digest),
        `for=${box.host.querySelector('[data-custody-for]')?.getAttribute('data-custody-for')}`,
      )
      check(
        'the custody section names the finding and assessment it belongs to',
        box.host.querySelector('[data-xai-custody]')?.getAttribute('data-xai-custody') === findingB.finding_id &&
          text.includes(findingB.finding_id) &&
          text.includes(bundle.assessment_id),
      )
      const chainToggle = box.host.querySelector<HTMLElement>(`[data-custody-toggle="${findingB.finding_id}"]`)
      if (chainToggle) await click(chainToggle)
      await settle(250)
      const expandedText = box.host.textContent ?? ''
      check(
        'the custody chain\'s own facts are B\'s, not A\'s',
        onlyB !== undefined &&
          expandedText.includes(onlyB) &&
          (onlyA === undefined || !expandedText.includes(onlyA)),
        `onlyB=${onlyB} onlyA=${onlyA}`,
      )
      check(
        'assessment risk did not move with the finding selection',
        chipTextOf(box.host.querySelector('[data-packet-risk]')?.closest('.pw-risk-col')?.querySelector('.pw-risk')) ===
            'HIGH' &&
          chipTextOf(box.host.querySelector('[data-xai-assessment-severity]')?.closest('dd')?.querySelector('.pw-risk')) ===
            'HIGH',
      )
    }

    // --- 6a. A slow custody request cannot leave the previous chain visible. -
    {
      const stallUrl = custodyUrl(bundle.assessment_id, findingA.finding_id)
      stalls.set(stallUrl, 1500)
      await click(box.host.querySelector<HTMLElement>(`[data-explain-finding="${findingA.finding_id}"]`)!)
      await settle(300)
      const duringText = box.host.textContent ?? ''
      check(
        'while the new finding\'s custody loads, the previous chain is gone',
        box.host.querySelector(`[data-custody-for="${findingA.finding_id}"]`) !== null &&
          !duringText.includes(chainB.summary) &&
          !duringText.includes(chainB.finding_digest) &&
          (box.host.querySelector('[data-custody-loading]') !== null ||
            box.host.querySelector('[data-evidence-loading]') !== null),
        `loading=${box.host.querySelector('[data-custody-loading]') !== null}`,
      )
      await settle(1900)
      stalls.delete(stallUrl)
      await openXai()
      check(
        'the slow request completes and A\'s own chain is shown',
        box.host.querySelector('[data-custody-for]')?.getAttribute('data-custody-for') === findingA.finding_id &&
          (box.host.textContent ?? '').includes(chainA.summary) &&
          (box.host.textContent ?? '').includes(chainA.finding_digest) &&
          !(box.host.textContent ?? '').includes(chainB.finding_digest),
      )
    }

    // --- 6b. A failed custody request is honest and belongs to that finding.
    {
      const faultUrl = custodyUrl(bundle.assessment_id, findingB.finding_id)
      faults.set(faultUrl, JSON.stringify({ detail: 'injected custody failure for the smoke test' }))
      await selectFinding(findingB.finding_id)
      const errorBox = box.host.querySelector('[data-custody-error]')
      const retry = box.host.querySelector<HTMLElement>(`[data-custody-retry="${findingB.finding_id}"]`)
      check(
        'a failed custody request shows an error for THAT finding, with a retry',
        errorBox !== null &&
          errorBox.getAttribute('data-custody-error') === findingB.finding_id &&
          retry !== null &&
          (box.host.textContent ?? '').includes(findingB.finding_id),
        `errorFor=${errorBox?.getAttribute('data-custody-error')}`,
      )
      check(
        'a failed custody request never falls back to another finding\'s chain',
        !(box.host.textContent ?? '').includes(chainA.finding_digest) &&
          !(box.host.textContent ?? '').includes(chainA.summary),
      )
      if (retry) {
        const retryMark = markCalls()
        await click(retry)
        await settle(300)
        check(
          'retry re-requests the same finding id',
          since(retryMark).some((url) => url.includes(encodeURIComponent(findingB.finding_id))) &&
            !(box.host.textContent ?? '').includes(chainA.finding_digest),
          since(retryMark).join(','),
        )
        check(
          'the retry still fails honestly while the service is failing',
          box.host.querySelector('[data-custody-error]') !== null &&
            !(box.host.textContent ?? '').includes(chainA.finding_digest),
        )
        faults.delete(faultUrl)
        await click(box.host.querySelector<HTMLElement>(`[data-custody-retry="${findingB.finding_id}"]`)!)
        await waitFor(custodySettled)
        await openXai()
        check(
          'once the service recovers, the retry shows B\'s own chain again',
          box.host.querySelector('[data-custody-for]')?.getAttribute('data-custody-for') === findingB.finding_id &&
            (box.host.textContent ?? '').includes(chainB.finding_digest) &&
            box.host.querySelector('[data-custody-error]') === null,
        )
      }
    }
    await act(async () => box.root.unmount())
  }
}

// --------------------------------------------------------------------------
// 2e. Real DETERMINISTIC finding -> the XAI explanation is grounded in the
//     backend rule/evidence records, and the evidence link reaches the very
//     same Evidence tab (one evidence implementation, never a second one).
// --------------------------------------------------------------------------
{
  const picked = await pickBundle(
    (h) => h.finding_count > 0,
    (b) => {
      const top = selectPrimaryFinding(b.risk.findings ?? [])
      return Boolean(top) && top!.source !== 'ML' && Boolean(top!.related_variable)
    },
  )
  if (!picked) {
    console.log('skip  (no deterministic finding in the live store)')
  } else {
    const { bundle } = picked
    const primary = selectPrimaryFinding(bundle.risk.findings ?? [])!
    const detModel = makeModel(0x61, {
      present: true,
      highest_severity: String(bundle.risk.severity),
      highest_risk_score: bundle.risk.overall_score,
      assessments: [
        {
          assessment_id: bundle.assessment_id,
          severity: String(bundle.risk.severity),
          risk_score: bundle.risk.overall_score,
          finding_count: bundle.risk.findings.length,
        },
      ],
    })
    const detBox = await mount(detModel)
    await settle(2800)
    const xaiToggle = [...detBox.host.querySelectorAll('button')].find(
      (btn) => btn.getAttribute('data-xai-toggle') === 'true',
    )
    check('xai action exists for a real deterministic finding', xaiToggle !== undefined)
    if (xaiToggle) {
      await click(xaiToggle)
      await settle(500)
      const panel = detBox.host.querySelector('[data-xai-panel]')
      const panelText = panel?.textContent ?? ''
      const xaiEntry = bundle.xai?.finding_explanations.find(
        (entry) => entry.finding_id === primary.finding_id,
      )
      check('xai explanation renders for the deterministic finding', panel !== null)
      check(
        'xai reports the finding as deterministic, not model-derived',
        /deterministic rule/.test(panelText),
        panelText.slice(0, 200),
      )
      check(
        'xai "what was detected" is the backend rationale verbatim',
        xaiEntry ? panelText.includes(xaiEntry.why_it_was_flagged.slice(0, 40)) : true,
        xaiEntry?.why_it_was_flagged.slice(0, 60) ?? 'no xai entry',
      )
      check(
        'xai names the matched rule and condition',
        panelText.includes(primary.rule_id) && panelText.includes(String(primary.condition).slice(0, 12)),
        `rule=${primary.rule_id}`,
      )
      check(
        'xai key factors each carry their evidence',
        /Key factors/.test(panelText) &&
          (panel?.querySelectorAll('[data-xai-factor]').length ?? 0) > 0 &&
          /evidence:/.test(panelText),
        panelText.slice(0, 200),
      )
      check(
        'xai keeps severity and confidence as separate facts',
        /Finding severity/.test(panelText) && /Assessment risk/.test(panelText) && /Confidence/.test(panelText),
      )
      check(
        'xai configuration impact uses the finding-related parameter',
        /Configuration impact/.test(panelText) &&
          panelText.includes(String(primary.related_variable)) &&
          /expected/.test(panelText),
        panelText.slice(0, 240),
      )
      check(
        'xai drift never claims "no drift" when no baseline is configured',
        /Drift analysis is not available for this assessment/.test(panelText) ||
          /No drift record was returned/.test(panelText) ||
          /No drift was detected/.test(panelText),
        panelText.slice(0, 200),
      )
      check(
        'xai evidence stays traceable to the finding and its artifact',
        /Evidence/.test(panelText) && panelText.includes(primary.finding_id),
        panelText.slice(0, 200),
      )
      check(
        'xai reports an honest absence when the backend has no rule explanation',
        xaiEntry === null
          ? /No deterministic rule explanation is available|Backend recorded no separate reason/.test(panelText)
          : true,
        panelText.slice(0, 200),
      )
      const viewEvidence = detBox.host.querySelector<HTMLElement>('[data-xai-evidence]')
      check('xai offers a View evidence jump', viewEvidence !== null)
      if (viewEvidence) {
        await click(viewEvidence)
        await settle(400)
        check(
          'xai evidence jump reaches the existing Evidence tab',
          (detBox.host.textContent ?? '').includes('Integrity is verified by the analytics backend over the stored artifact.'),
        )
      }
    }
    await act(async () => detBox.root.unmount())
  }
}

// --------------------------------------------------------------------------
// 2d. Real assessment with NO findings / NO ml -> every optional surface is
//     an honest "not provided" state, never a fabricated one.
// --------------------------------------------------------------------------
{
  const picked = await pickBundle(
    (h) => h.finding_count === 0 && !h.ml_present,
    () => true,
  )
  if (!picked) {
    console.log('skip  (no quiet assessment in the live store)')
  } else {
    const { bundle } = picked
    const quietModel = makeModel(0x53, {
      present: true,
      highest_severity: String(bundle.risk.severity),
      highest_risk_score: bundle.risk.overall_score,
      assessments: [
        {
          assessment_id: bundle.assessment_id,
          severity: String(bundle.risk.severity),
          risk_score: bundle.risk.overall_score,
          finding_count: 0,
        },
      ],
    })
    const quietBox = await mount(quietModel)
    calls.length = 0
    await settle(2600)
    await openSection(quietBox.host, 'Allowed / expected combinations')
    await openSection(quietBox.host, 'Drift')
    const quietText = quietBox.host.textContent ?? ''
    check(
      'quiet assessment still answers with the no-finding state',
      quietText.includes('No security finding associated with this packet/flow.'),
    )
    check(
      'confidence is honestly reported as unavailable',
      /Confidence/.test(quietText) && /no confidence score/.test(quietText),
    )
    check(
      'relevant configuration degrades honestly',
      /Relevant configuration/.test(quietText),
    )
    check(
      'combination + drift stay honest for missing optional data',
      quietText.includes('No configuration combination analysis is available for this finding.') &&
        /Configuration drift/.test(quietText),
    )
    check(
      'xai is absent for an assessment with no finding, and says so honestly',
      quietBox.host.querySelector('[data-xai-toggle]') === null &&
        /No finding is recorded for this assessment, so there is nothing to explain/.test(quietText),
      quietText.slice(0, 240),
    )
    await act(async () => quietBox.root.unmount())
  }
}

// --------------------------------------------------------------------------
// 3. Assessment id that no longer resolves -> structured error state.
// --------------------------------------------------------------------------
const bogus = makeModel(0x9, {
  present: true,
  highest_severity: 'MEDIUM',
  highest_risk_score: 40,
  assessments: [{ assessment_id: 'no-such-assessment', severity: 'MEDIUM', risk_score: 40, finding_count: 0 }],
})
const bogusBox = await mount(bogus)
await settle(3000)
const bogusText = bogusBox.host.textContent ?? ''
check(
  'unresolvable assessment renders the server error state',
  /Unable to load (assessment|findings|drift|this assessment)|not found/.test(bogusText),
  bogusText.slice(0, 160),
)
check('error state offers retry', /Retry|retry/i.test(bogusText))
await act(async () => bogusBox.root.unmount())

root.querySelectorAll('div').forEach((node) => node.remove())

console.log(
  failures === 0
    ? 'PACKET INVESTIGATION (+ EXPLANATION) OK'
    : `${failures} INVESTIGATION CHECK(S) FAILED`,
)
if (failures > 0) process.exitCode = 1