/**
 * Sentinel drift lifecycle smoke (not part of the shipped app).
 *
 * Pins the two properties that make the drift surface honest, using the exact
 * payload shapes the analytics backend emits (`DriftAssessment.to_dict()` and
 * `FieldChange.to_dict()`) rather than a shape invented for the test:
 *
 *  1. Sentinel reads the comparison from its own read-only per-assessment
 *     endpoint, addressed by the backend-issued assessment id, and renders
 *     whatever that response says. The genericity check below feeds the panel a
 *     drift it has never seen (mode transport -> tunnel, a HIGH finding) and
 *     requires it to render that, while asserting the IP-addressing case it was
 *     developed against does not leak into the output. A panel that had
 *     memorised "ipv4 -> ipv6" fails this test.
 *  2. An assessment with no comparison is shown as having no comparison. While
 *     an experiment is still running the finalized comparison does not exist
 *     yet, so the API answers `not_configured`; the panel must render that and
 *     must not manufacture a drift verdict, a finding, or a severity.
 *
 * Refresh/retry is deliberately the existing `useResource.reload()` path rather
 * than a live socket: after a run completes and is persisted, an explicit
 * reload is what brings the comparison in. The real waiting for that to land is
 * covered by the end-to-end run, not simulated here.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { AssessmentDriftBlock } from '@/components/packet/AssessmentDriftBlock'
import { getAssessmentDrift } from '@/api/analytics'
import type { AssessmentDriftResponse } from '@/types'

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}

const render = (drift: AssessmentDriftResponse | null) =>
  renderToStaticMarkup(createElement(AssessmentDriftBlock, { drift }))

/**
 * The rendered text with every tag collapsed to a space. Assertions read values
 * through this rather than through raw markup, so a label and its value stay
 * comparable whether the component puts them in one node or in two — what is
 * being checked is that the value reached the screen, not how it is nested.
 */
const flat = (html: string) => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ')

/* ------------------------------------------------------------------ wiring */

const calls: string[] = []
const originalFetch = globalThis.fetch
globalThis.fetch = (async (input: RequestInfo | URL) => {
  const url = typeof input === 'string' ? input : String(input)
  calls.push(url)
  const body = JSON.stringify({ api: 'drift', read_only: true, status: 'not_configured' })
  return {
    ok: true,
    status: 200,
    text: async () => body,
    headers: new Headers(),
  } as unknown as Response
}) as typeof fetch

const JOB_ID = 'b5dbc272-97c9-4b28-adb7-4b2ad3b1ef94'
const ASSESSMENT_ID = `testbed-${JOB_ID}:1:current`

await getAssessmentDrift(ASSESSMENT_ID)

check(
  'reads the backend-issued assessment by id from the read-only drift endpoint',
  calls.length === 1 && decodeURIComponent(calls[0] ?? '').endsWith(
    `/api/v1/assessments/${ASSESSMENT_ID}/drift`,
  ),
  JSON.stringify(calls),
)
check(
  'the assessment id is passed through verbatim, not rebuilt',
  decodeURIComponent(calls[0] ?? '').includes(`:1:current`),
)
check(
  'the assessment detail does not fall back to the store-wide drift summary',
  !(calls ?? []).some((url) => url.endsWith('/api/v1/drift')),
  JSON.stringify(calls),
)

globalThis.fetch = originalFetch

/* --------------------------------------------------- the recorded real case */

/** The accepted end-to-end result: an IPv4 baseline compared with an IPv6 run. */
const RECORDED: AssessmentDriftResponse = {
  api: 'drift',
  read_only: true,
  assessment_id: ASSESSMENT_ID,
  status: 'drift',
  drift_detected: true,
  reason: null,
  baseline: {
    baseline_id: 'baseline-transport-ipv4',
    validation_status: 'validated',
    state_digest: '460f5d9a4a12',
    baseline_digest: '460f5d9a4a12',
    validated_at: '2026-02-02T10:15:00Z',
    validated_by: 'security-engineer',
    asset_id: 'gateway-a',
  },
  current: {
    state_digest: '460f5d9a4a12',
    source_ref: 'journal:b5dbc272',
    run_id: ASSESSMENT_ID,
    sequence: 1,
    source: { kind: 'recorded' },
  },
  changed_fields: [
    {
      variable: 'address_family',
      label: 'Address family',
      baseline_value: 'ipv4',
      current_value: 'ipv6',
      comparison_rule: 'baseline_state != current_state',
      security_relevance: true,
      drift_category: 'network_topology',
      finding_id: 'RISK-DRIFT-ADDRESS-FAMILY',
      severity: 'MEDIUM',
    },
  ],
  unchanged_variables: ['esp.presence', 'ah.presence'],
  unknown_variables: [],
  drift_categories: ['network_topology'],
  risk: {
    overall_score: 45,
    severity: 'MEDIUM',
    findings: [
      {
        finding_id: 'RISK-DRIFT-ADDRESS-FAMILY',
        severity: 'MEDIUM',
        category: 'configuration_mismatch',
        related_variable: 'address_family',
        reason: 'address family differs from the validated baseline',
      },
    ],
  },
  model_version: 'drift-1',
  rule_id: 'RISK-DRIFT',
}

const recordedHtml = render(RECORDED)

check('reports drift for the recorded comparison', /DRIFT DETECTED/.test(recordedHtml))
check('shows the API status verbatim', /drift/.test(recordedHtml))
check('names the changed variable', /Address family/.test(recordedHtml))
check('shows the baseline value from the API', /ipv4/.test(recordedHtml))
check('shows the current value from the API', /ipv6/.test(recordedHtml))
check('shows the API finding id', /RISK-DRIFT-ADDRESS-FAMILY/.test(recordedHtml))
check('shows the API severity verbatim', /MEDIUM/.test(recordedHtml))
check('shows the baseline identity', /baseline-transport-ipv4/.test(recordedHtml))
check(
  'shows the provenance of the run the assessment came from',
  recordedHtml.includes(ASSESSMENT_ID) || recordedHtml.includes('testbed-b5dbc272'),
)
check('shows the sequence recorded for that run', /Sequence 1/.test(flat(recordedHtml)))

/* ------------------------------------------------------------ genericity */

/**
 * A drift the panel was never developed against. If any part of the rendering
 * were specialised to the recorded case above, this would render the wrong
 * variable, the wrong values, or the wrong severity.
 */
const UNSEEN: AssessmentDriftResponse = {
  ...RECORDED,
  assessment_id: 'testbed-00000000-0000-0000-0000-000000000000:1:current',
  status: 'drift',
  changed_fields: [
    {
      variable: 'mode',
      label: 'IPsec mode',
      baseline_value: 'transport',
      current_value: 'tunnel',
      finding_id: 'RISK-DRIFT-MODE',
      severity: 'HIGH',
    },
  ],
  risk: {
    severity: 'HIGH',
    findings: [{ finding_id: 'RISK-DRIFT-MODE', severity: 'HIGH' }],
  },
  unknown_variables: ['ah.presence'],
}

const unseenHtml = render(UNSEEN)
check('renders an unseen drift variable', /IPsec mode/.test(unseenHtml))
check('renders its baseline value', /transport/.test(unseenHtml))
check('renders its current value', /tunnel/.test(unseenHtml))
check("renders the API's own finding id for it", /RISK-DRIFT-MODE/.test(unseenHtml))
check("renders the API's own severity for it", /HIGH/.test(unseenHtml))
check(
  'does not leak the developed-against values into an unrelated drift',
  !/ipv6/.test(unseenHtml),
  'the panel must render the response, not a remembered case',
)
check(
  'surfaces variables the comparison could not establish',
  /Not established/i.test(flat(unseenHtml)) && /ah\.presence/.test(flat(unseenHtml)),
)

/* ------------------------------------------------------ lifecycle: no verdict */

/**
 * The response the backend serves for an assessment that exists but has no
 * finalized comparison — which is every assessment while its run is still in
 * flight, and every assessment in a store with no baseline configured.
 */
const NOT_CONFIGURED: AssessmentDriftResponse = {
  api: 'drift',
  read_only: true,
  assessment_id: ASSESSMENT_ID,
  status: 'not_configured',
  drift_detected: false,
  reason:
    'no validated baseline was configured for this store, so no longitudinal ' +
    'comparison was made for this assessment and no drift is claimed',
  baseline: null,
  current: null,
  changed_fields: [],
  unchanged_variables: [],
  unknown_variables: [],
  drift_categories: [],
  risk: null,
}

const notConfiguredHtml = render(NOT_CONFIGURED)
check(
  "shows the backend's own reason",
  notConfiguredHtml.includes('no validated baseline was configured for this store'),
)
check(
  'does not claim drift for a run that has not been compared',
  !/DRIFT DETECTED/.test(notConfiguredHtml),
)
check(
  'does not claim "no drift" either',
  !/No drift detected/.test(notConfiguredHtml),
)
check(
  'does not invent a finding, severity or changed field',
  !/RISK-DRIFT/.test(notConfiguredHtml) &&
    !/MEDIUM|HIGH|LOW|CRITICAL|INFO/.test(notConfiguredHtml),
)
check(
  'states plainly that this is not a finding of no drift',
  /not a\s+finding of/i.test(notConfiguredHtml.replace(/<[^>]+>/g, ' ')),
)

/* `indeterminate` is served with drift_detected=false but claims neither drift
   nor agreement, so it must not be presented as clean. */
const INDETERMINATE: AssessmentDriftResponse = {
  ...NOT_CONFIGURED,
  status: 'indeterminate',
  reason: 'the current observation carried no usable evidence',
}
const indeterminateHtml = render(INDETERMINATE)
check('an indeterminate comparison is not rendered as clean', !/No drift detected/.test(indeterminateHtml))
check('an indeterminate comparison is not rendered as drift', !/DRIFT DETECTED/.test(indeterminateHtml))

/* ---------------------------------------------------------------- no_drift */

const NO_DRIFT: AssessmentDriftResponse = {
  ...RECORDED,
  status: 'no_drift',
  drift_detected: false,
  changed_fields: [],
  unchanged_variables: ['address_family', 'esp.presence'],
  risk: null,
}
const noDriftHtml = render(NO_DRIFT)
check('a clean comparison reads as no drift', /No drift detected/.test(noDriftHtml))
check(
  'a clean comparison still shows provenance',
  /baseline-transport-ipv4/.test(noDriftHtml) && /Sequence 1/.test(flat(noDriftHtml)),
)
check('a missing drift record is stated, not silently blank', /No drift record/.test(render(null)))

/* ------------------------------------------------------------------ wiring */

const detailSource = readFileSync(
  fileURLToPath(new URL('../src/pages/AssessmentDetail.tsx', import.meta.url)),
  'utf8',
)
check(
  'the assessment detail page reads and renders the comparison',
  detailSource.includes('getAssessmentDrift') && detailSource.includes('AssessmentDriftBlock'),
)
check(
  'the assessment detail page offers a refresh of the comparison',
  detailSource.includes('resource.reload'),
)

console.log('')
if (failures) {
  console.error(`${failures} check(s) failed`)
  process.exit(1)
}
console.log('drift lifecycle smoke passed')
process.exit(0)