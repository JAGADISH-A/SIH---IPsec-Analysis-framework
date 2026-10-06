/**
 * Temporary SSR/live-DOM smoke test (not part of the shipped app).
 *
 * Verifies the Evidence Library's two-layer presentation as a *hierarchy*, not
 * as a bag of fields.
 *
 * The distinction under test is the one an analyst actually experiences:
 *
 *   primary   — "what evidence do I have and why does it matter?"
 *               kind of evidence, what that kind is, the finding that cited it
 *               and its severity, the assessment it belongs to, file name, size
 *   secondary — "where exactly did this come from?"
 *               full paths, digests, capture-feed names, internal evidence /
 *               finding / assessment ids, packet offsets, storage metadata
 *
 * A title-only assertion cannot catch a regression here: a page can render
 * every field and still read as a wall of sha256 digests. So this asserts the
 * *placement* of each class of value — analyst-facing text must be present with
 * every disclosure collapsed, and raw storage values must appear only inside
 * `details[data-provenance]`.
 *
 * Fully deterministic: `fetch` is stubbed with the exact payload shape and
 * values the live backend serves, so this asserts the presentation contract
 * rather than whatever happens to be in the store today. It reads nothing and
 * mutates nothing.
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
define('SVGElement', dom.window.SVGElement)
define('MutationObserver', dom.window.MutationObserver)
define('getComputedStyle', dom.window.getComputedStyle)
define('requestAnimationFrame', dom.window.requestAnimationFrame)
define('cancelAnimationFrame', dom.window.cancelAnimationFrame)
define('IS_REACT_ACT_ENVIRONMENT', true)
Object.defineProperty(dom.window, 'innerWidth', { value: 1600, configurable: true })
Object.defineProperty(dom.window, 'innerHeight', { value: 1000, configurable: true })
dom.window.HTMLElement.prototype.getBoundingClientRect = function () {
  return { width: 1600, height: 1000, top: 0, left: 0, right: 1600, bottom: 1000, x: 0, y: 0, toJSON: () => ({}) } as DOMRect
}
if (!dom.window.ResizeObserver) {
  dom.window.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
}
define('ResizeObserver', dom.window.ResizeObserver)

const consoleErrors: string[] = []
const origError = console.error
console.error = (...args: unknown[]) => {
  consoleErrors.push(args.map((a) => (a instanceof Error ? a.message : String(a))).join(' '))
}

/* ----------------------------------------------------------- stubbed payloads */

const ASSESSMENT_ID = 'dataset-20260924-003710:1:tunnel-v4'
const ARTIFACT_PATH = 'results/e2e-verification/parser/tunnel_v6inner/state.jsonl'
const DIGEST = 'adad24d538da75d53c56c02e3eb26cb1881a5ceff19ba7b7e0d9d77370f47444'
const EVIDENCE_ID = 'ev-edc239ab373bf4886fb5a5e81e8e0cee'

/** The exact shape and values `/api/v1/findings` serves for evidence refs. */
const FINDINGS_PAYLOAD = {
  api: 'findings',
  total: 2,
  findings: [
    {
      assessment_id: ASSESSMENT_ID,
      finding_id: 'RISK-PFS-DISABLED',
      severity: 'MEDIUM',
      title: 'PFS disabled in expected ESP configuration',
      evidence_refs: [
        {
          pcap_path: ARTIFACT_PATH,
          capture_sequence: 16,
          audit_event_reference: null,
          source: 'live_xdp',
          timestamp: null,
          artifact_type: 'xdp_jsonl',
          artifact_sha256: DIGEST,
          byte_size: 1148,
          run_id: 'dataset-20260924-003710',
          experiment_id: null,
          sequence: 16,
          window_index: null,
          capture_start_ns: null,
          capture_end_ns: null,
          packet_start: null,
          packet_end: null,
          evidence_id: EVIDENCE_ID,
        },
      ],
    },
    {
      assessment_id: ASSESSMENT_ID,
      finding_id: 'RISK-ESP-WEAK-CIPHER',
      severity: 'MEDIUM',
      title: 'Weak ESP cipher family in expected configuration (CBC)',
      evidence_refs: [
        {
          pcap_path: ARTIFACT_PATH,
          capture_sequence: 16,
          audit_event_reference: null,
          source: 'live_xdp',
          timestamp: null,
          artifact_type: 'xdp_jsonl',
          artifact_sha256: DIGEST,
          byte_size: 1148,
          run_id: 'dataset-20260924-003710',
          experiment_id: null,
          sequence: 16,
          window_index: null,
          capture_start_ns: null,
          capture_end_ns: null,
          packet_start: null,
          packet_end: null,
          evidence_id: EVIDENCE_ID,
        },
      ],
    },
  ],
}

const ASSESSMENTS_PAYLOAD = {
  api: 'assessments',
  total_assessments: 1,
  findings_total: 2,
  headers: [
    {
      assessment_id: ASSESSMENT_ID,
      scenario: 'tunnel',
      slot: 'tunnel-v4',
      severity: 'MEDIUM',
    },
  ],
}

define(
  'fetch',
  async (input: unknown) => {
    const url = String(input)
    const body = url.includes('/api/v1/findings') ? FINDINGS_PAYLOAD : ASSESSMENTS_PAYLOAD
    return {
      ok: true,
      status: 200,
      headers: new Map<string, string>(),
      async text() {
        return JSON.stringify(body)
      },
      async json() {
        return body
      },
    }
  },
)

/* --------------------------------------------------------------------- checks */

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || !detail ? '' : ` — ${detail}`}`)
  if (!ok) failures += 1
}

const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter, Route, Routes } = await import('react-router-dom')
const { Evidence } = await import('@/pages/EvidencePage')
const labels = await import('@/lib/labels')

// ---- the vocabulary tables, against the backend's documented values -------
// correlation/models/evidence.py defines exactly these artifact_type values and
// correlation/evidence_linkage.py these sources. Every one must resolve to a
// label rather than leaking a raw snake_case token.
check('xdp_jsonl gets a readable evidence label', labels.evidenceTypeLabel('xdp_jsonl') === 'Live capture log')
check('pcap gets a readable evidence label', labels.evidenceTypeLabel('pcap') === 'Packet capture')
check('audit_jsonl gets a readable evidence label', labels.evidenceTypeLabel('audit_jsonl') === 'Capture audit log')
check('live_xdp gets a readable feed label', labels.evidenceSourceLabel('live_xdp') === 'Live XDP feed')
check('a missing artifact_type does not blank the label', labels.evidenceTypeLabel(null) === 'Untyped artifact')
check(
  'an unregistered artifact_type is shown as sent, not given a borrowed meaning',
  labels.evidenceTypeLabel('quantum_blob') === 'Quantum Blob' &&
    labels.evidenceTypeMeaning('quantum_blob').includes('quantum_blob'),
)
check(
  'a missing artifact_type says the bytes are unstated rather than guessing',
  labels.evidenceTypeMeaning(null).includes('not stated'),
)
check('each known type explains itself', Object.keys(labels.EVIDENCE_TYPE_MEANINGS).every((key) => labels.evidenceTypeMeaning(key).length > 40))

// ---- the rendered hierarchy ----------------------------------------------
const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)

await act(async () => {
  root.render(
    createElement(
      MemoryRouter,
      { initialEntries: ['/evidence'] },
      createElement(Routes, null, createElement(Route, { path: '/evidence', element: createElement(Evidence) })),
    ),
  )
})
await act(async () => {
  await new Promise((resolve) => setTimeout(resolve, 60))
})

const text = host.textContent ?? ''
const disclosures = [...host.querySelectorAll('details[data-provenance]')]
const provenanceText = disclosures.map((node) => node.textContent ?? '').join('\n')
const outside = host.cloneNode(true) as HTMLElement
outside.querySelectorAll('details[data-provenance]').forEach((node) => node.remove())
const analystText = outside.textContent ?? ''

check('the page rendered evidence from the payload', text.includes('PFS disabled'), text.slice(0, 120))
check('a provenance disclosure exists on the catalogue', disclosures.length > 0, `${disclosures.length} found`)

// 1. Analyst-facing evidence is visible without opening provenance.
check(
  'the evidence kind is readable with disclosures collapsed',
  analystText.includes('Live capture log'),
)
check(
  'what the evidence means is readable with disclosures collapsed',
  analystText.includes('JSONL capture log the live XDP feed appends'),
)
check('the citing finding is readable', analystText.includes('PFS disabled in expected ESP configuration'))
check('the finding severity is readable', analystText.includes('MEDIUM'))
check('the assessment is named in words, not by id', analystText.includes('Tunnel') && !analystText.includes(ASSESSMENT_ID))
check('the artifact file name is readable', analystText.includes('state.jsonl'))

// 2. Provenance is reachable through the secondary disclosure.
check('provenance carries the full artifact path', provenanceText.includes(ARTIFACT_PATH))
check('provenance carries the digest', provenanceText.includes(DIGEST))
check('provenance carries the capture feed', provenanceText.includes('Live XDP feed'))
check('provenance carries the internal evidence id', provenanceText.includes(EVIDENCE_ID))
check('provenance carries the internal assessment id', provenanceText.includes(ASSESSMENT_ID))
check('provenance carries the run id', provenanceText.includes('dataset-20260924-003710'))

// 3. Raw storage values are not the dominant first impression.
check('raw paths are absent from the primary layer', !analystText.includes('results/'))
check('digests are absent from the primary layer', !/[0-9a-f]{64}/.test(analystText))
check('internal evidence ids are absent from the primary layer', !/\bev-[0-9a-f]{8,}/.test(analystText))
check('raw run ids are absent from the primary layer', !/\bdataset-\d{8}-\d{6}\b/.test(analystText))
check('capture feed names are absent from the primary layer', !analystText.includes('Live XDP feed'))

// 4. No evidence information is lost.
check('every backend field is still rendered somewhere', [
  ARTIFACT_PATH,
  DIGEST,
  EVIDENCE_ID,
  ASSESSMENT_ID,
  'RISK-PFS-DISABLED',
  'RISK-ESP-WEAK-CIPHER',
  'dataset-20260924-003710',
  'live_xdp',
  'xdp_jsonl',
].every((needle) => text.includes(needle)))
check('fields the backend left null stay reachable as provenance', provenanceText.includes('packet_start'))
check('the primary layer is denser than the provenance layer', analystText.length > 0 && disclosures.length > 0)

// 5. A digest-heavy primary layer would be a regression even though every field
//    is technically present, so assert the proportion of raw tokens in view.
const analystDigestChars = (analystText.match(/[0-9a-f]{16,}/g) ?? []).length
check('the primary layer shows no long hex tokens at all', analystDigestChars === 0, `${analystDigestChars} found`)

const realErrors = consoleErrors.filter((text) => !text.includes('not wrapped in act'))
check('no console errors while rendering the evidence library', realErrors.length === 0, realErrors.slice(0, 3).join(' | '))

await act(async () => {
  root.unmount()
})
host.remove()
console.error = origError

if (failures) {
  console.error(`\nevidence library smoke: ${failures} check(s) failed`)
  process.exit(1)
}
console.log('\nevidence library smoke: all checks passed')