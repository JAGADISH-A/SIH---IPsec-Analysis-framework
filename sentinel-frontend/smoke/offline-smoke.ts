/**
 * Temporary offline smoke test (not part of the shipped app).
 *
 * Verifies the app's promise that a down backend reads as a failure rather than
 * a healthy-looking default. Point the two API URLs at a closed port, mount the
 * status, dashboard and analyst-console pages, and assert nothing claims to be
 * connected.
 *
 * The console is checked hardest here, because "no data" is exactly the state
 * in which a monitoring UI is most likely to invent something: an empty table
 * that reads as "no traffic", a zeroed KPI row, or a risk figure with nothing
 * behind it.
 */
import { JSDOM } from 'jsdom'

process.env.VITE_ANALYTICS_API_URL = 'http://127.0.0.1:9'
process.env.VITE_CONTROL_API_URL = 'http://127.0.0.1:9'

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

const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter, Route, Routes } = await import('react-router-dom')
const { AppLayout } = await import('@/layouts/AppLayout')
const { SystemStatus } = await import('@/pages/SystemStatus')
const { PacketWorkspace } = await import('@/pages/PacketWorkspace')
const { Activity } = await import('@/pages/AnalystConsole')
const { Assessments } = await import('@/pages/Assessments')

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}

async function mount(name: string, path: string, Component: never) {
  const host = dom.window.document.createElement('div')
  dom.window.document.body.appendChild(host)
  const root = createRoot(host)
  await act(async () => {
    root.render(
      createElement(
        MemoryRouter,
        { initialEntries: [path] },
        createElement(
          Routes,
          null,
          createElement(
            Route,
            { path: '/', element: createElement(AppLayout) },
            createElement(Route, { path, element: createElement(Component) }),
          ),
        ),
      ),
    )
  })
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 2500))
  })
  const text = host.textContent ?? ''
  const rows = host.querySelectorAll('tbody tr').length
  await act(async () => root.unmount())
  host.remove()
  console.log(`note ${name}: ${text.length} chars`)
  return { text, rows }
}

const status = await mount('SystemStatus', '/system', SystemStatus as never)
check('status reports an unreachable plane', /unreachable|not connected|could not reach/i.test(status.text))
check('status never claims connected', !/\bconnected\b(?![^.]*unreachable)/i.test(status.text.replace(/unreachable/gi, '')))
check('status shows a retry affordance', /re-?check|retry/i.test(status.text))

const workspace = await mount('PacketWorkspace', '/', PacketWorkspace as never)
// The workspace is a packet-style console built from real journal data. With
// the plane down it must report the failure, not present an empty packet list
// that could read as "no traffic on the link".
check('workspace surfaces a failure, not a fake packet list', /could not reach|Unable|unreachable|Retry|re-?check/i.test(workspace.text))
check('workspace does not claim packets were received', !/No packets received|packets received/i.test(workspace.text))
check('workspace does not render a packet table when down', workspace.rows === 0, `rows=${workspace.rows}`)
check('workspace never presents risk as a live measurement', !/CRITICAL|HIGH|MEDIUM|LOW/.test(workspace.text))

const assessments = await mount('Assessments', '/assessments', Assessments as never)
check('assessment index reports the failure', /could not reach|Unable|unreachable|Retry/i.test(assessments.text))
check(
  'assessment index does not claim the store is empty because it is down',
  !/No assessments in the store/i.test(assessments.text),
)

const activity = await mount('Activity', '/activity', Activity as never)
check('activity reports the analytics plane as unreachable', /could not reach|Unable|unreachable/i.test(activity.text))
// The monitor must not present an empty list as "no activity observed".
check(
  'activity does not claim the link is quiet when it is down',
  !/no (events|traffic|activity) (observed|recorded)|nothing (seen|recorded)/i.test(activity.text),
)
// And it must not present zeroes as measurements.
check(
  'activity does not show fabricated KPI figures',
  !/Live events0|Assessments0|Findings0/.test(activity.text.replace(/\s/g, '')),
)
check('activity offers a retry path', /Retry|re-check|Reconnect/i.test(activity.text))

console.log(failures === 0 ? 'OFFLINE BEHAVIOUR CORRECT' : `${failures} OFFLINE CHECK(S) FAILED`)
if (failures > 0) process.exitCode = 1
