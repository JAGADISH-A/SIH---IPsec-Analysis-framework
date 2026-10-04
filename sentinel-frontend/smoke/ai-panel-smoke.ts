/**
 * The AI explanation panel, mounted against the running backends.
 *
 * The contract smoke asserts the *payload*; this one asserts the *panel*, which
 * is where the provenance requirement actually has to hold. It clicks the real
 * button and then insists that the four origins appear as four visibly separate
 * elements, that severity and score are rendered from the backend's own block
 * rather than scraped from the prose, and that the ML strip says the assistant
 * has no confidence of its own.
 *
 * It also exercises the follow-up thread, because a first answer that is
 * grounded but a second one that is not would be a worse defect than having no
 * thread at all.
 */
import { JSDOM } from 'jsdom'

const AI_URL = process.env.VITE_AI_API_URL ?? 'http://127.0.0.1:8082'
const ANALYTICS_URL = process.env.VITE_ANALYTICS_API_URL ?? 'http://127.0.0.1:8081'

let failures = 0
function check(label: string, ok: boolean, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail && !ok ? ` — ${detail}` : ''}`)
  if (!ok) failures += 1
}

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
  return { width: 1200, height: 800, top: 0, left: 0, right: 1200, bottom: 800, x: 0, y: 0, toJSON: () => ({}) } as DOMRect
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
  origError(...args)
}

const { createElement } = await import('react')
const { createRoot } = await import('react-dom/client')
const { act } = await import('react')
const { AiExplainer } = await import('@/components/packet/AiExplainer')

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const settle = (ms = 1500) => act(async () => { await wait(ms) })
/*
 * Wait for a condition rather than for a fixed number of milliseconds.
 *
 * With no model configured the service answers from its template in
 * milliseconds, and with a live model the same call takes seconds. Sleeping a
 * fixed 2s asserted nothing about either: it passed vacuously against an
 * unconfigured provider and failed spuriously against a real one. Polling for
 * the state under test makes this smoke assert the same thing either way.
 */
async function waitFor(what: string, done: () => boolean, capMs = 30_000) {
  const deadline = Date.now() + capMs
  while (Date.now() < deadline) {
    if (done()) return true
    await act(async () => { await wait(150) })
  }
  console.log(`     (waited ${capMs}ms for: ${what})`)
  return done()
}
async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true, cancelable: true }))
    await wait(50)
  })
}
function button(host: HTMLElement, label: string): HTMLButtonElement | null {
  const match = Array.from(host.querySelectorAll('button')).find((b) =>
    (b.textContent ?? '').trim().toLowerCase().includes(label.toLowerCase()),
  )
  return (match as HTMLButtonElement | undefined) ?? null
}
function byText(host: HTMLElement, selector: string, text: string): boolean {
  return Array.from(host.querySelectorAll(selector)).some((el) =>
    (el.textContent ?? '').trim().toLowerCase().includes(text.toLowerCase()),
  )
}

/* ------------------------------------------------------------------ setup */

const health = await fetch(`${AI_URL}/ai/health`).then((r) => (r.ok ? r.json() : null)).catch(() => null)
if (!health) {
  console.log('FAIL AI explanation service is not reachable; start it with: python -m correlation.ai.service')
  process.exitCode = 1
} else {
  const index = await fetch(`${ANALYTICS_URL}/api/v1/assessments?limit=50`).then((r) => r.json())
  const header = index.assessments?.find((a: { finding_count: number }) => a.finding_count > 0)
  if (!header) {
    console.log('FAIL the store has no assessment with a finding to explain')
    process.exitCode = 1
  } else {
    const bundle = await fetch(`${ANALYTICS_URL}/api/v1/assessments/${encodeURIComponent(header.assessment_id)}`).then((r) => r.json())
    const finding = bundle.risk?.findings?.[0]

    /* -------------------------------------------------------- first answer */

    const host = dom.window.document.createElement('div')
    dom.window.document.body.appendChild(host)
    const root = createRoot(host)

    /*
     * The experiment id is the one thing this panel cannot show on screen, so
     * the only honest way to assert it is to read the request it actually
     * sends. Spying on `fetch` rather than on the component internals keeps
     * the check UI-originated: it is what a browser would put on the wire.
     */
    const explainBodies: Record<string, unknown>[] = []
    const realFetch = globalThis.fetch
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url.includes('/ai/explain') && typeof init?.body === 'string') {
        try {
          explainBodies.push(JSON.parse(init.body) as Record<string, unknown>)
        } catch {
          explainBodies.push({ __unparseable: init.body })
        }
      }
      return realFetch(input as RequestInfo, init)
    }) as typeof fetch

    await act(async () => {
      root.render(
        createElement(AiExplainer, {
          assessmentId: header.assessment_id,
          findingId: finding.finding_id,
          // Exactly what `AssessmentExplanation` passes: the bundle's own id.
          experimentId: bundle.identity?.experiment_id,
          severity: finding.severity,
          hasEvidence: (bundle.evidence?.total_refs ?? 0) > 0,
          context: [
            `Assessment ${header.assessment_id}`,
            `Finding ${finding.finding_id} (${finding.severity})`,
            `Assessment severity ${bundle.risk.severity}, score ${bundle.risk.overall_score}`,
          ].join('\n'),
        }),
      )
    })
    await settle(300)

    check('panel renders before any request', (host.textContent ?? '').includes('Explain with AI'))

    const explain = button(host, 'Explain with AI')
    check('an Explain with AI control exists', explain !== null)
    if (explain) await click(explain)
    /*
     * Wait for the authoritative strip, not for the string "AI EXPLANATION":
     * the legend renders all four origin chips before any request is made, so
     * that string is present from the start and would make this wait vacuous.
     * The fact values only exist once an answer has actually been applied.
     */
    await waitFor(
      'the first answer',
      () => (host.querySelectorAll('.pw-ai-fact-val').length ?? 0) >= 3,
    )

    const text = host.textContent ?? ''

    check('the answer reached the DOM', text.length > 300, `${text.length} chars`)

    /* --- the four origins, as four separate labelled elements --- */
    const chips = Array.from(host.querySelectorAll('.pw-ai-origin')).map((c) => (c.textContent ?? '').trim())
    const unique = new Set(chips)
    check('all four origins are labelled', unique.size >= 4, [...unique].join(' | '))
    for (const label of ['OBSERVED FACT', 'DETERMINISTIC ASSESSMENT', 'ML INFERENCE', 'AI EXPLANATION']) {
      check(`origin "${label}" is present`, chips.includes(label))
    }
    // Four visually distinct treatments, not one class reused four times.
    const classes = new Set(Array.from(host.querySelectorAll('.pw-ai-origin')).map((c) => c.className))
    check('the four origins are visually distinct', classes.size >= 4, `${classes.size} distinct classes`)

    /* --- severity and score come from the backend block, unchanged --- */
    const backendSeverity = bundle.risk.severity as string
    const backendScore = bundle.risk.overall_score as number
    const findingSeverity = finding.severity as string
    check(
      'the assessment severity is shown and is the backend severity',
      byText(host, '.pw-ai-fact-val', backendSeverity),
      `looking for ${backendSeverity}`,
    )
    check(
      'the recorded risk score is shown and is the backend score',
      byText(host, '.pw-ai-fact-val', String(backendScore)),
      `looking for ${backendScore}`,
    )
    check(
      'the selected finding keeps its own severity',
      byText(host, '.pw-ai-fact-val', findingSeverity),
      `looking for ${findingSeverity}`,
    )
    if (findingSeverity !== backendSeverity) {
      check(
        'a finding severity that differs from the assessment is stated, not hidden',
        (host.textContent ?? '').includes('separate verdicts'),
      )
    }

    /* --- the ML strip may not imply an assistant confidence --- */
    check('ML is labelled as inference', chips.includes('ML INFERENCE'))
    check(
      'the assistant states it has no confidence of its own',
      text.includes('no confidence of its own'),
    )
    check(
      'no invented AI confidence percentage is shown',
      !/\b\d{1,3}% confidence in this explanation\b/i.test(text),
    )

    /* --- the explanation is marked as generated, and as explanation only --- */
    check('the answer is labelled as an explanation', chips.includes('AI EXPLANATION'))

    /* --- context disclosure --- */
    const showContext = button(host, 'Show context')
    check('a context disclosure exists', showContext !== null)
    if (showContext) {
      await click(showContext)
      await settle(300)
      check(
        'the context shown is the investigation context, not an invention',
        (host.textContent ?? '').includes(header.assessment_id),
      )
    }

    /* ---------------------------------------------------------- follow-up */

    const input = host.querySelector('.pw-ai-input') as HTMLInputElement | null
    check('a follow-up input exists', input !== null)
    if (input) {
      const setter = Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, 'value')?.set
      await act(async () => {
        setter?.call(input, 'What does PFS mean?')
        input.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
        await wait(80)
      })
      const ask = button(host, 'Ask AI')
      check('an Ask AI control exists', ask !== null)
      if (ask) await click(ask)
      await waitFor(
        'the follow-up answer',
        () => (host.textContent ?? '').includes('Perfect Forward Secrecy'),
      )
      await waitFor(
        'the thread to render the prior turn',
        () => (host.querySelectorAll('.pw-ai-turn').length ?? 0) >= 1,
      )

      const after = host.textContent ?? ''
      check('the follow-up was answered', after.includes('Perfect Forward Secrecy'), after.slice(0, 120))
      check('the prior turn is retained in the thread', (host.querySelectorAll('.pw-ai-turn').length ?? 0) >= 1)
      check(
        'the answer still shows the backend severity after a follow-up',
        byText(host, '.pw-ai-fact-val', backendSeverity),
      )
      check(
        'the answer still shows the finding severity after a follow-up',
        byText(host, '.pw-ai-fact-val', findingSeverity),
      )
    }

        check('no console errors were raised', consoleErrors.length === 0, consoleErrors.slice(0, 2).join(' | '))

    /* ------------------------------------------- the experiment id on the wire */

    const recordedExperiment = bundle.identity?.experiment_id as string | undefined
    check(
      'the bundle the panel rendered carries an experiment id',
      typeof recordedExperiment === 'string' && recordedExperiment.length > 0,
      `got ${JSON.stringify(recordedExperiment)}`,
    )
    check('an /ai/explain request body was observed', explainBodies.length >= 1, `${explainBodies.length} bodies`)
    const sent = explainBodies[0] ?? {}
    check(
      'the request carried the bundle experiment id unchanged',
      sent.experiment_id === recordedExperiment,
      `sent ${JSON.stringify(sent.experiment_id)}, bundle ${JSON.stringify(recordedExperiment)}`,
    )
    check(
      'the request did not substitute a different identifier',
      typeof sent.experiment_id === 'string' && sent.experiment_id !== '' && sent.experiment_id !== header.assessment_id,
      `sent ${JSON.stringify(sent.experiment_id)}`,
    )
    check(
      'the follow-up request also carried it',
      explainBodies.length < 2 || explainBodies[1].experiment_id === recordedExperiment,
      `${JSON.stringify(explainBodies[1]?.experiment_id)}`,
    )

    /*
     * The negative twin, and the one that matters more: a surface that does not
     * know the job must send nothing rather than guess. An invented id would
     * resolve against a different experiment and the assistant would explain
     * another run's root cause.
     */
    const blindHost = dom.window.document.createElement('div')
    dom.window.document.body.appendChild(blindHost)
    const blindRoot = createRoot(blindHost)
    explainBodies.length = 0
    await act(async () => {
      blindRoot.render(
        createElement(AiExplainer, {
          assessmentId: header.assessment_id,
          findingId: finding.finding_id,
          severity: finding.severity,
          hasEvidence: false,
        }),
      )
    })
    await settle(300)
    const blindExplain = button(blindHost, 'Explain with AI')
    if (blindExplain) await click(blindExplain)
    await waitFor('the blind request body', () => explainBodies.length >= 1)
    const blindSent = explainBodies[0] ?? {}
    check(
      'with no known experiment the request sends null, not a guess',
      blindSent.experiment_id === null,
      `sent ${JSON.stringify(blindSent.experiment_id)}`,
    )
    await act(async () => { blindRoot.unmount() })

    globalThis.fetch = realFetch
    await act(async () => { root.unmount() })
  }
}

console.log(failures === 0 ? 'AI EXPLANATION PANEL OK' : `${failures} AI PANEL CHECK(S) FAILED`)
if (failures > 0) process.exitCode = 1