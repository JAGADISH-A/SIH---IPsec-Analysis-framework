/**
 * Temporary experiment-roundtrip smoke test (not part of the shipped app).
 *
 * Drives the real control plane: POST a configuration the backend advertises,
 * poll to completion, then render the result page against the live job. This is
 * the only path that proves the experiment flow works end to end — including
 * the claim that a completed job produces no new assessment id.
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
Object.defineProperty(dom.window, 'innerWidth', { value: 1600, configurable: true })
Object.defineProperty(dom.window, 'innerHeight', { value: 1000, configurable: true })
dom.window.HTMLElement.prototype.getBoundingClientRect = () =>
  ({ width: 1600, height: 1000, top: 0, left: 0, right: 1600, bottom: 1000, x: 0, y: 0, toJSON: () => ({}) }) as DOMRect
dom.window.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
define('ResizeObserver', dom.window.ResizeObserver)

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}

const { createExperiment, getExperimentConfigurations, getExperiment } = await import('@/api/control')

// 1. Build a request from the options the backend advertises, never from a
//    hardcoded list, then check every field came from the live response.
const options = await getExperimentConfigurations()
const config = {
  mode: options.modes[0],
  address_family: options.address_families[0],
  ike: {
    version: options.ike.version,
    encryption: options.ike.encryption[options.ike.encryption.length - 1],
    integrity: options.ike.integrity[0],
    dh_group: options.ike.dh_groups[0],
  },
  esp: {
    encryption: options.esp.encryption[options.esp.encryption.length - 1],
    integrity: options.esp.integrity[0],
    dh_group: options.esp.dh_groups[0],
    pfs: false,
  },
  traffic: { profile: options.traffic.profiles[0], duration: options.traffic.duration.min },
}
console.log(`note submitting: ${JSON.stringify(config)}`)

// 2. Submit and poll to a terminal state.
const created = await createExperiment(config as never)
check('POST /experiments returned a job id', typeof created.job_id === 'string' && created.job_id.length > 0)
console.log(`note job ${created.job_id} status ${created.status}`)

let job = created
const deadline = Date.now() + 6 * 60 * 1000
while (Date.now() < deadline && (job.status === 'QUEUED' || job.status === 'RUNNING')) {
  await new Promise((resolve) => setTimeout(resolve, 5000))
  job = await getExperiment(created.job_id)
  console.log(`note ${job.status}/${job.stage}`)
}
check('job reached a terminal state', job.status === 'COMPLETED' || job.status === 'FAILED', `${job.status}/${job.stage}`)

if (job.status === 'FAILED') {
  console.log(`note job error: ${job.error}`)
  console.log(failures === 0 ? 'EXPERIMENT FAILED FOR ENVIRONMENT REASONS' : `${failures} CHECK(S) FAILED`)
  process.exit(1)
}

const result = job.result as Record<string, never> | null
check('result carries the lab verdict', result?.status === 'PASS' || result?.status === 'FAIL', String(result?.status))
check('result echoes the submitted config', (result?.mode as unknown) === config.mode)
check('result reports SA verification', Boolean(result?.ipsec))
check('result reports connectivity', Boolean(result?.connectivity))
check('result reports the traffic run', Boolean(result?.traffic))

// 3. Render the live job through the real page.
const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter, Route, Routes } = await import('react-router-dom')
const { AppLayout } = await import('@/layouts/AppLayout')
const { ExperimentResult } = await import('@/pages/ExperimentResult')

const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)
await act(async () => {
  root.render(
    createElement(
      MemoryRouter,
      { initialEntries: [`/experiments/${created.job_id}`] },
      createElement(
        Routes,
        null,
        createElement(
          Route,
          { path: '/', element: createElement(AppLayout) },
          createElement(Route, { path: '/experiments/:jobId', element: createElement(ExperimentResult) }),
        ),
      ),
    ),
  )
})
await act(async () => {
  await new Promise((resolve) => setTimeout(resolve, 2000))
})
const text = host.textContent ?? ''
check('result page renders the completed job', text.length > 400 && !/Loading[^<]*…$/.test(text.trimEnd()))
check('result page shows the lab verdict', text.includes(String(result?.status)))
check('result page shows the SA state', text.includes('ESTABLISHED') && text.includes('INSTALLED'))
check('result page shows packet loss', /0(\.0)?%/.test(text))
console.log(`note rendered ${text.length} chars`)

// 4. The result must not invent a link to a new assessment.
check('result page does not claim a new assessment id', !/assessment id:.*\S/.test(text.replace(/assessment id is stored/g, '')))

await act(async () => root.unmount())
console.log(failures === 0 ? 'EXPERIMENT ROUNDTRIP OK' : `${failures} CHECK(S) FAILED`)
if (failures > 0) process.exitCode = 1
