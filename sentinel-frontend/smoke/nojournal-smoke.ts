/**
 * On-demand smoke test for the "no audit journal attached" state.
 *
 * Deliberately NOT part of `npm run smoke`: the normal suites need a healthy
 * backend, but this one needs an analytics API that is up yet has no journal
 * attached, which is a second server on a second port. Start it with
 *
 *   python -m correlation.api.app --host 127.0.0.1 --port 8099 --phase10 --no-static
 *
 * then run `npm run smoke:nojournal` (override NOJOURNAL_API_URL if you used a
 * different port).
 *
 * The console is the screen most likely to lie here: with no journal the audit
 * endpoint answers 503 `audit_unavailable`, and the tempting failure is an
 * empty table that reads as "no traffic on the link". This asserts the monitor
 * says the source is unavailable instead.
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

const { createRoot } = await import('react-dom/client')
const { act, createElement } = await import('react')
const { MemoryRouter } = await import('react-router-dom')
const { Activity } = await import('@/pages/AnalystConsole')

let failures = 0
const check = (label: string, ok: boolean, detail = '') => {
  if (ok) console.log(`ok   ${label}`)
  else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}

const host = dom.window.document.createElement('div')
dom.window.document.body.appendChild(host)
const root = createRoot(host)
await act(async () => {
  root.render(
    createElement(MemoryRouter, { initialEntries: ['/activity'] }, createElement(Activity)),
  )
})
await act(async () => {
  await new Promise((r) => setTimeout(r, 2500))
})

const text = host.textContent ?? ''
const rows = host.querySelectorAll('tbody tr').length

check('activity still renders the store surfaces', /Live Traffic Monitor/.test(text))
check('monitor reports the source as unavailable', /Live source unavailable/.test(text), text.slice(0, 200))
check('it explains how to attach a journal', /--audit-journal|--phase10/.test(text))
check('it does not render a traffic table', rows === 0, `rows=${rows}`)
check(
  'it does not claim the link is quiet',
  !/no (events|traffic|activity) (observed|recorded)/i.test(text),
)
check('it offers a re-check affordance', /Re-check/.test(text))
// The rest of the console is still live, because the store itself is fine.
check('the rest of the activity page still shows store data', /dataset-/.test(text))

console.log(failures === 0 ? 'NO-JOURNAL STATE CORRECT' : `${failures} NO-JOURNAL CHECK(S) FAILED`)
if (failures > 0) process.exitCode = 1
process.exit(failures > 0 ? 1 : 0)
