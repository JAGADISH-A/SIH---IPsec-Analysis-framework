/**
 * Testbed frontend contract smoke (not part of the shipped app).
 *
 * Loads the *real* operator UI — the shipped `frontend/index.html` and
 * `frontend/app.js` — into jsdom, drives a real click on Run, and records every
 * request the page makes. Two things are being pinned here, both of which are
 * architectural boundaries rather than styling:
 *
 *  1. The Testbed frontend owns experiment triggering and nothing else. It must
 *     talk only to the controller's experiment API. In particular it must never
 *     reach for Sentinel's drift surface (`/api/v1/drift`,
 *     `/api/v1/assessments/{id}/drift`): that surface is read-only, lives on a
 *     different service, and cross-calling it would turn one app into a client
 *     of the other.
 *  2. The controller's job id must survive completion. It is the only
 *     identifier the controller issues, and it is what the completed run is
 *     known by downstream, so the page has to keep and show it in full rather
 *     than the 8-character abbreviation used while the run is in flight.
 *
 * The assessment id that Sentinel lists is deliberately NOT reconstructed here.
 * Only the backend assigns it, and this smoke would fail if the page ever began
 * inventing one.
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath, URL } from 'node:url'
import { JSDOM } from 'jsdom'

const repoRoot = fileURLToPath(new URL('../../', import.meta.url))
const html = readFileSync(`${repoRoot}frontend/index.html`, 'utf8')
const appSource = readFileSync(`${repoRoot}frontend/app.js`, 'utf8')

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}

/* The job id the stubbed controller issues. A real UUID, used verbatim: the
   point is that whatever the controller returns is what the page retains. */
const JOB_ID = 'b5dbc272-97c9-4b28-adb7-4b2ad3b1ef94'
const ASSESSMENT_ID = `${'testbed'}-${JOB_ID}:1:current`

const calls: string[] = []
const jsonResponse = (body: unknown) => ({
  ok: true,
  status: 200,
  json: async () => body,
  text: async () => JSON.stringify(body),
})

const CONFIGURATIONS = {
  modes: ['tunnel', 'transport'],
  address_families: ['ipv4', 'ipv6'],
  ike: {
    version: [2],
    encryption: ['aes128', 'aes256'],
    integrity: ['sha256'],
    dh_groups: ['modp2048'],
  },
  esp: {
    encryption: ['aes128gcm16'],
    integrity: ['sha256', 'null'],
    dh_groups: ['modp2048'],
  },
  traffic: { profiles: ['icmp'], duration: { min: 10, max: 120, default: 10 } },
}

function stubFetch(url: string) {
  calls.push(url)
  if (url.endsWith('/health')) return jsonResponse({ status: 'ok' })
  if (url.endsWith('/experiments/configurations')) return jsonResponse(CONFIGURATIONS)
  if (url.endsWith('/dataset-runs/settings')) {
    return jsonResponse({ maximum_target_samples: 100, target_samples: 0 })
  }
  if (url.endsWith('/experiments')) return jsonResponse({ job_id: JOB_ID, status: 'QUEUED' })
  if (url.includes(`/experiments/${JOB_ID}`)) {
    return jsonResponse({
      job_id: JOB_ID,
      status: 'COMPLETED',
      stage: 'COMPLETED',
      result: {
        status: 'PASS',
        ipsec: { mode: 'TRANSPORT' },
        connectivity: { status: 'PASS', packet_loss: 0 },
      },
    })
  }
  return jsonResponse({})
}

const dom = new JSDOM(html, {
  url: 'http://127.0.0.1:8000/',
  pretendToBeVisual: true,
  runScripts: 'outside-only',
})
const { window } = dom

// jsdom does not implement these; app.js only needs them to exist.
window.fetch = ((input: RequestInfo | URL) => {
  const url = typeof input === 'string' ? input : String(input)
  return Promise.resolve(stubFetch(url))
}) as typeof window.fetch
;(window as unknown as Record<string, unknown>).fetch = window.fetch

// The page's own init runs on DOMContentLoaded; readyState is already
// "complete" here, so app.js initialises immediately on evaluation.
window.eval(appSource)

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

// Poll interval is 800ms; give init plus a couple of poll cycles.
await wait(400)

const runButton = window.document.querySelector('#runBtn') as HTMLButtonElement | null
check('run button is enabled after configurations load', runButton?.disabled === false)

runButton?.dispatchEvent(new window.Event('click', { bubbles: true }))

// Wait for the run to reach its terminal state (QUEUED -> COMPLETED).
let waited = 0
while (waited < 6000) {
  await wait(100)
  waited += 100
  if (calls.some((url) => url.includes(`/experiments/${JOB_ID}`))) break
}
await wait(1200)

const passJobId = window.document.querySelector('#passJobId')?.textContent ?? ''
const fullJobId = window.document.querySelector('#passFullJobId')?.textContent ?? ''
const handoff = window.document.querySelector('#passHandoff')
const note = window.document.querySelector('#passHandoffNote')?.textContent ?? ''

console.log(`\nrequests made by the Testbed frontend (${calls.length}):`)
for (const url of [...new Set(calls)]) console.log(`  ${url}`)

console.log('')
check(
  'triggered the experiment API',
  calls.some((url) => url.endsWith('/experiments')),
  JSON.stringify(calls),
)
check(
  'polled the job it was given',
  calls.some((url) => url.endsWith(`/experiments/${JOB_ID}`)),
)
check(
  'never calls the Sentinel drift summary',
  !calls.some((url) => url.includes('/api/v1/drift')),
)
check(
  'never calls a per-assessment drift endpoint',
  !calls.some((url) => url.includes('/drift')),
)
check(
  'calls no service other than the controller experiment API',
  calls.every(
    (url) =>
      url.startsWith('/health') ||
      url.startsWith('/experiments') ||
      url.startsWith('/dataset-runs'),
  ),
  JSON.stringify(calls),
)
check('experiment completion is shown', /EXPERIMENT PASSED/i.test(window.document.body.textContent ?? ''))
check(
  'the full job id is retained and displayed',
  fullJobId === JOB_ID,
  `got ${JSON.stringify(fullJobId)}`,
)
check(
  'the retained id is not the truncated in-flight abbreviation',
  fullJobId !== JOB_ID.slice(0, 8) && fullJobId.length === JOB_ID.length,
)
check(
  'the completed-run block is visible',
  handoff !== null && !handoff.classList.contains('is-hidden'),
)
check(
  'the baseline-then-current workflow is explained',
  /baseline/i.test(note) && /Sentinel/i.test(note),
  JSON.stringify(note),
)
check(
  'no assessment id is fabricated by the Testbed frontend',
  !window.document.body.innerHTML.includes(ASSESSMENT_ID),
  'the page must not reconstruct a Sentinel assessment id',
)
check(
  'the job id shown is the one the controller returned, not a guess',
  passJobId.includes(JOB_ID.slice(0, 8)),
  `got ${JSON.stringify(passJobId)}`,
)

console.log('')
if (failures) {
  console.error(`${failures} check(s) failed`)
  process.exit(1)
}
console.log('testbed frontend contract smoke passed')
process.exit(0)