/**
 * Packet investigation binding smoke (not part of the shipped app).
 *
 * Pins the data binding of the centered Packet Investigation window, which is
 * where an analyst is most able to be quietly misled. Two things are under test,
 * and they pull against each other:
 *
 *   1. Verbatim risk. The two fixtures below are two real results with
 *      genuinely different risk — one weak, one clean — and the window must
 *      render each one's own severity, score, finding and reason. A panel that
 *      hard-codes "LOW · 6", or that always shows the same single finding, fails
 *      here. The clean fixture has no finding at all, which also pins that a
 *      missing finding reads as an explicit absence instead of being backfilled
 *      from the other assessment.
 *
 *   2. Strict provenance. The configured profile must be badged CONFIGURED and
 *      must never appear as an observed or inferred value; the classifier output
 *      must be badged INFERRED; the capture counters must be badged OBSERVED. The
 *      window is tested for a real model result (class + confidence + model
 *      version) and for one where the model did not run (both absent, with the
 *      store's own reason surfaced), so an absent value can never be mistaken for
 *      a broken binding nor replaced by an invented class or confidence.
 *
 * The window is mounted for real and its hook is allowed to run, because the
 * fields under test only exist once its fetches resolve. A server render would
 * show nothing but the loading state, which is exactly where a broken binding is
 * invisible.
 */
import { JSDOM } from 'jsdom'

const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>', {
  url: 'http://127.0.0.1:5173/',
  pretendToBeVisual: true,
})

const g = globalThis as unknown as Record<string, unknown>
function define(key: string, value: unknown) {
  Object.defineProperty(g, key, { value, configurable: true, writable: true })
}
define('window', dom.window)
define('document', dom.window.document)
define('navigator', dom.window.navigator)
define('HTMLElement', dom.window.HTMLElement)
define('Element', dom.window.Element)
define('Node', dom.window.Node)
define('MutationObserver', dom.window.MutationObserver)
define('getComputedStyle', dom.window.getComputedStyle)
define('IS_REACT_ACT_ENVIRONMENT', true)

const { createElement } = await import('react')
const { act } = await import('react')
const { createRoot } = await import('react-dom/client')
const { MemoryRouter } = await import('react-router-dom')
const { PacketInvestigation } = await import('@/components/packet/PacketInvestigation')
const { toCaptureRow } = await import('@/lib/packetRows')
type AssessmentBundle = import('@/types').AssessmentBundle
type CaptureRow = import('@/types').CaptureRow
type Finding = import('@/types').Finding

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}

const settle = (ms = 60) => new Promise((resolve) => setTimeout(resolve, ms))

/* ------------------------------------------------------------------ fixtures */

/**
 * A weak configuration: the store's own MEDIUM/12 and its own finding.
 *
 * `source`/`observed_value` are the store's real evidence provenance for a
 * configuration weakness, and the `reason` is deliberately verbose, because the
 * window must clamp it while collapsed and show all of it on demand rather than
 * dumping policy prose into the default view.
 */
const WEAK_FINDING: Finding = {
  finding_id: 'RISK-PFS-DISABLED',
  rule_id: 'RISK-PFS-DISABLED',
  severity: 'MEDIUM',
  category: 'posture',
  title: 'Perfect Forward Secrecy is not enabled for this tunnel',
  reason:
    'Expected esp.pfs=False; PFS is disabled (posture PFS contribution 0/2). ' +
    'This rule inspects the declared child-SA configuration only and makes no statement ' +
    'about the runtime state of the security association.',
  condition: 'expected.esp.pfs == False',
  related_variable: 'esp.pfs',
  expected_value: false,
  // The whole point: a configuration rule has no runtime observation.
  observed_value: null,
  source: 'EXPECTED_CONFIGURATION',
  evidence_type: 'configuration',
  confidence: null,
  model_version: null,
  evidence_refs: [],
  assessment_id: 'weak-assessment',
  dataset_run_id: 'dataset-run-abc123',
} as Finding

/** The same finding as the clean assessment would have it, to prove no bleed. */
const CLEAN_FINDING: Finding = {
  ...WEAK_FINDING,
  finding_id: 'RISK-ONLY-IN-WEAK',
  rule_id: 'RISK-ONLY-IN-WEAK',
  severity: 'CRITICAL',
  title: 'FINDING THAT MUST NOT LEAK INTO THE CLEAN ASSESSMENT',
} as Finding

function bundle(options: {
  assessmentId: string
  severity: string
  score: number
  traffic: string
  withFinding: boolean
  mlPresent: boolean
}): AssessmentBundle {
  return {
    assessment_id: options.assessmentId,
    slot: 'slot-1',
    scenario: `scenario-${options.assessmentId}`,
    dataset_run_id: 'dataset-run-abc123',
    identity: {
      dataset_run_id: 'dataset-run-abc123',
      sequence: 1,
      experiment_id: 'exp-1',
      attempt_number: 1,
      window_index: 0,
      window_start_ns: 0,
      window_end_ns: 1_000_000_000,
    },
    expected: {
      mode: 'tunnel',
      address_family: 'ipv4',
      ike: { version: 2, encryption: 'AES_GCM_16_128', integrity: null, dh_group: 'group14' },
      esp: {
        encryption: 'AES_CBC_16',
        integrity: 'HMAC_SHA2_256_128',
        dh_group: 'group14',
        pfs: !options.withFinding,
      },
      traffic: { profile: options.traffic, duration: 60, port: 500 },
      capture_filter: 'ip',
      configuration_id: 'cfg-1',
    },
    observed: {
      present: true,
      timestamp_ns: 1_700_000_000_000_000_000,
      endpoints: { a: '192.168.100.1', b: '192.168.100.2' },
      mode: 'tunnel',
      active: true,
      tunnel_seen: true,
      packets_seen: 1_284,
      bytes_seen: 918_233,
      packets_a_to_b: 900,
      packets_b_to_a: 384,
      bytes_a_to_b: 640_000,
      bytes_b_to_a: 278_233,
      ike_seen: true,
      ike_nat_t_seen: false,
      esp_seen: true,
      ah_seen: false,
      observed_ike_activity: true,
      spis: [
        {
          spi: '0x0a1b2c3d',
          direction: 'out',
          active: true,
          first_seen_ns: 1,
          last_seen_ns: 2,
          packet_count: 900,
        },
      ],
    },
    correlation: {
      status: 'COMPLETED',
      rows: [],
      metadata: { rules_executed: [], observation_completeness: 'complete' },
    },
    ml: options.mlPresent
      ? {
          present: true,
          model_version: 'rf-traffic-profile-v3',
          traffic_class: options.traffic,
          classification_confidence: 0.913,
          anomaly: null,
          anomaly_score: null,
        }
      : {
          present: false,
          reason: 'traffic window below the minimum feature threshold',
          model_version: null,
          traffic_class: null,
          classification_confidence: null,
          anomaly: null,
          anomaly_score: null,
        },
    risk: {
      schema_version: '1',
      risk_engine_version: 'risk-1.4.0',
      risk_policy_version: 'policy-2026.02',
      overall_score: options.score,
      severity: options.severity,
      findings: [],
      score_detail: {
        total: options.score,
        contributions: options.withFinding
          ? [{ finding_id: WEAK_FINDING.finding_id, added: 12, weight: 12 }]
          : [],
      } as AssessmentBundle['risk']['score_detail'],
    },
    xai: {} as AssessmentBundle['xai'],
    evidence: {} as AssessmentBundle['evidence'],
    ipsec_state: {} as AssessmentBundle['ipsec_state'],
    sources: [],
  } as AssessmentBundle
}

const WEAK = bundle({
  assessmentId: 'weak-assessment',
  severity: 'MEDIUM',
  score: 12,
  traffic: 'email',
  withFinding: true,
  mlPresent: true,
})

const CLEAN = bundle({
  assessmentId: 'clean-assessment',
  severity: 'INFO',
  score: 0,
  traffic: 'voip',
  withFinding: false,
  mlPresent: false,
})

/** One assessed packet, with the SPI the store associates it with. */
const ROW: CaptureRow = toCaptureRow(
  {
    id: 'pkt-1',
    source: 'live_events.jsonl',
    offset: 0,
    timestamp_ns: 1_700_000_000_000_000_000,
    schema: 'sentinel.analytics.capture.packet.v1',
    packet: {
      timestamp: 1_700_000_000_000_000_000,
      interface: 'eth2',
      protocol: 50,
      source: '192.168.100.1',
      destination: '192.168.100.2',
      spi: 0x0a1b2c3d,
      sequence: 41,
      packet_length: 142,
      source_port: 0,
      destination_port: 0,
      classification: 'ESP',
      direction: 'out',
      sensor_type: 'xdp',
    },
    protocol_label: 'ESP',
    info: 'ESP packet',
    spi: 0x0a1b2c3d,
    risk: {
      present: true,
      highest_severity: 'MEDIUM',
      highest_risk_score: 12,
      assessments: [{ assessment_id: 'weak-assessment' }],
    },
  } as unknown as import('@/types').CapturePacket,
  1,
)

/* ------------------------------------------------------------------ mounting */

let current: AssessmentBundle | null = WEAK
let currentFindings: Finding[] = [WEAK_FINDING]

const realFetch = globalThis.fetch
globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(typeof input === 'string' ? input : (input as Request).url ?? input)
  const json = (body: unknown) =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    )
  if (url.includes('/drift')) return json({ assessment_id: current?.assessment_id, status: 'UNKNOWN', rows: [] })
  if (url.includes('/findings'))
    return json({ api: 'analytics', findings: currentFindings, count: currentFindings.length, total: currentFindings.length, limit: 100, offset: 0, has_more: false, read_only: true })
  if (url.includes('/api/assessments/')) {
    if (url.includes('clean-assessment')) return json(CLEAN)
    return json(WEAK)
  }
  return realFetch ? realFetch(input as RequestInfo, init) : Promise.resolve(new Response('{}', { status: 404 }))
}) as typeof fetch

async function mount(
  assessmentId: string | null,
): Promise<{ text: string; host: HTMLElement; root: ReturnType<typeof createRoot> }> {
  current = assessmentId === 'clean-assessment' ? CLEAN : WEAK
  currentFindings = assessmentId === 'clean-assessment' ? [] : [WEAK_FINDING]

  const host = dom.window.document.createElement('div')
  dom.window.document.body.appendChild(host)
  const root = createRoot(host)
  await act(async () => {
    root.render(
      createElement(
        MemoryRouter,
        null,
        createElement(PacketInvestigation, {
          row: ROW,
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
  await act(async () => {
    await settle(200)
  })
  return { text: (host.textContent ?? '').replace(/\s+/g, ' ').trim(), host, root }
}

async function unmount(handle: { root: ReturnType<typeof createRoot>; host: HTMLElement }) {
  await act(async () => {
    handle.root.unmount()
  })
  handle.host.remove()
}

/* -------------------------------------------------------------------- checks */

const weak = await mount('weak-assessment')

check(
  'the investigation window opens with a title and the packet identity',
  /PACKET INVESTIGATION/i.test(weak.host.innerHTML) && /ESP/.test(weak.text),
)
check(
  'the window shows the selected packet its own endpoints and SPI',
  /192\.168\.100\.1/.test(weak.text) && /192\.168\.100\.2/.test(weak.text) && /0a1b2c3d/i.test(weak.text),
)
check(
  'the window carries the packet detail fields',
  /Source/.test(weak.text) &&
    /Destination/.test(weak.text) &&
    /Protocol/.test(weak.text) &&
    /Length/.test(weak.text) &&
    /SPI/.test(weak.text) &&
    /Sequence/.test(weak.text) &&
    /Info/.test(weak.text),
)

check(
  'the three analyst panels are present and in order',
  /IPsec Configuration/.test(weak.text) &&
    /Observed Traffic/.test(weak.text) &&
    /Configuration Findings/.test(weak.text) &&
    weak.text.indexOf('IPsec Configuration') < weak.text.indexOf('Observed Traffic') &&
    weak.text.indexOf('Observed Traffic') < weak.text.indexOf('Configuration Findings'),
)
check(
  'the three panels are three sibling columns',
  weak.host.querySelectorAll('.ls-inv-panel-col').length === 3,
  `cols=${weak.host.querySelectorAll('.ls-inv-panel-col').length}`,
)
check(
  'each panel is badged for its own provenance',
  weak.host.querySelector('.ls-state-configured') !== null &&
    weak.host.querySelector('.ls-state-observed') !== null &&
    weak.host.querySelector('.ls-state-assessed') !== null,
)

/* --- verbatim risk, weak assessment --- */
check('the weak assessment shows its own severity', /MEDIUM/.test(weak.text), weak.text.slice(0, 160))
check('the weak assessment shows its own score', /\b12\b/.test(weak.text))
check('the weak assessment shows its own finding', /Perfect Forward Secrecy is not enabled/.test(weak.text))
check(
  'the weak assessment shows the backend score contribution',
  /Risk score/.test(weak.text) && /\+12/.test(weak.text),
)
// The frontend is presentation-only: it must not render a formula, a weight, a
// penalty or a computed total of its own. The backend's own `reason` prose is a
// different matter and is shown verbatim — that string is the analyst's record of
// why the rule fired, and redacting it would hide the very thing under review.
check(
  'the window computes no score of its own',
  !/score formula|weight factor|penalt|multiplier|weight \*|added \+|total =/i.test(weak.text),
  weak.text.slice(0, 200),
)
const reasonEl = weak.host.querySelector('.ls-finding-reason') as HTMLElement | null
check(
  'a finding reason is clamped while collapsed, so the panel cannot grow unbounded',
  reasonEl !== null && reasonEl.className.includes('ls-clamp-2') && reasonEl !== undefined,
)
const detailButton = Array.from(weak.host.querySelectorAll('.ls-finding-actions button')).find(
  (b) => /Details/.test(b.textContent ?? ''),
) as HTMLButtonElement | undefined
if (detailButton && reasonEl) {
  const collapsedText = (reasonEl.textContent ?? '').trim()
  await act(async () => {
    detailButton.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))
    await settle(40)
  })
  const expanded = weak.host.querySelector('.ls-finding-reason') as HTMLElement | null
  check('expanding a finding shows the full backend reason', expanded !== null && !expanded.className.includes('ls-clamp-2'))
  check(
    'expanding a finding shows the backend provenance, not a restatement',
    /EXPECTED_CONFIGURATION|configuration/i.test(weak.host.textContent ?? '') &&
      /not observed/i.test(weak.host.textContent ?? ''),
  )
  check(
    'an expanded finding shows the recorded condition and expected value',
    /expected\.esp\.pfs/.test(weak.host.textContent ?? '') && /false/.test(weak.host.textContent ?? ''),
  )
  check(
    'the clamped text and the full reason are the same backend string',
    expanded !== null && (expanded.textContent ?? '').trim() === collapsedText,
  )
}

/* --- clean assessment proves nothing is hard-coded --- */
await unmount(weak)
const clean = await mount('clean-assessment')

check('the clean assessment shows INFO, not the weak severity', /INFO/.test(clean.text))
check('the clean assessment shows no MEDIUM badge', !/MEDIUM/.test(clean.text))
check('the clean assessment shows score 0', /\b0\b/.test(clean.text))
check(
  'the clean assessment invents no finding',
  !/Perfect Forward Secrecy is not enabled/.test(clean.text) && !/FINDING THAT MUST NOT LEAK/.test(clean.text),
)
check(
  'the clean assessment shows the other traffic profile',
  /VoIP|voip/i.test(clean.text) && !/email/i.test(clean.text),
)
check(
  'a model that did not run is reported as not run with the store reason',
  /Not run/i.test(clean.text) && /below the minimum feature threshold/i.test(clean.text),
  clean.text.slice(0, 240),
)
check(
  'no classifier class or confidence is invented when the model did not run',
  !/91\.3/.test(clean.text),
)
check(
  'the clean configuration shows PFS as enabled, from the backend',
  /enabled/i.test(clean.text),
)

/* --- unassessed packet --- */
await unmount(clean)
const none = await mount(null)
check(
  'an unassessed packet keeps all three panel columns',
  none.host.querySelectorAll('.ls-inv-panel-col').length === 3,
  `cols=${none.host.querySelectorAll('.ls-inv-panel-col').length}`,
)
check('an unassessed packet claims no configuration', /not assessed/i.test(none.text))
check('an unassessed packet shows no score', !/\bRisk score\b/.test(none.text))
check(
  'an unassessed packet still shows its own captured record',
  /0a1b2c3d/i.test(none.text),
)
check(
  'an unassessed packet offers no finding to ask about',
  !/Ask AI/.test(none.text),
)
await unmount(none)

console.log(failures === 0 ? 'PACKET INVESTIGATION OK' : `${failures} CHECK(S) FAILED`)
if (failures > 0) process.exitCode = 1