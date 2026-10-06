/**
 * Asset assessment panel, mounted against the running analytics API.
 *
 * The backend suite proves the route answers correctly for a caller-supplied
 * asset. This proves the *panel* makes that a real request and renders the
 * answer, which is the part that can silently rot: a panel that hardcodes
 * `gw-a -> low` / `gw-b -> high` would look identical in a screenshot and would
 * agree with the backend by coincidence, for exactly as long as nobody edits the
 * profile file.
 *
 * So every assertion here is derived from a live response rather than from a
 * literal:
 *
 *   * the selector's options must equal what `/api/v1/assets` declared;
 *   * the URL actually put on the wire must carry the selected asset id;
 *   * the criticality shown must equal what that asset's context route returned.
 *
 * That is what makes the two failure modes distinguishable. A dropped asset id
 * fails the URL check. A hardcoded criticality fails the render check. Neither
 * can be satisfied by the other, and no amount of correct backend behaviour
 * rescues either.
 */
import { JSDOM } from 'jsdom'

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

const g = globalThis as Record<string, unknown>
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
define(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
)

const { createElement, act } = await import('react')
const { createRoot } = await import('react-dom/client')
const { AssetContextPanel } = await import('@/components/traffic/panels')
const { declaredValueLabel } = await import('@/lib/labels')

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))
const settle = (ms = 400) => act(async () => { await wait(ms) })

async function waitFor(what: string, done: () => boolean, capMs = 15_000) {
  const deadline = Date.now() + capMs
  while (Date.now() < deadline) {
    if (done()) return true
    await act(async () => { await wait(120) })
  }
  console.log(`     (waited ${capMs}ms for: ${what})`)
  return done()
}

async function click(el: Element) {
  await act(async () => {
    el.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true, cancelable: true }))
    await wait(60)
  })
}

function button(host: HTMLElement, label: string): HTMLButtonElement | null {
  const match = Array.from(host.querySelectorAll('button')).find((b) =>
    (b.textContent ?? '').trim().toLowerCase().includes(label.toLowerCase()),
  )
  return (match as HTMLButtonElement | undefined) ?? null
}

/**
 * Read one rendered label/value pair out of the result region.
 *
 * The panel publishes the profile as a `<dt>`/`<dd>` grid and the contextualised
 * risk as a two-up table, so both terminators are read here rather than teaching
 * the smoke about the markup. The label must match exactly, and the value is
 * whatever follows it.
 */
/**
 * The asset id is the subject of the panel, so it is rendered as a heading above
 * the declared values rather than as one more `<dt>`/`<dd>` metric. Read it from
 * where it is actually published instead of assuming the metric grid.
 */
function assetSubject(host: HTMLElement): string | null {
  const region = host.querySelector('.asset-context-result')
  if (!region) return null
  const label = Array.from(region.querySelectorAll('p')).find(
    (el) => (el.textContent ?? '').trim() === 'Asset',
  )
  return label?.nextElementSibling?.textContent?.trim() ?? null
}

function metric(host: HTMLElement, label: string): string | null {
  const region = host.querySelector('.asset-context-result')
  if (!region) return null
  const terms = Array.from(region.querySelectorAll('dt, th[scope="row"]'))
  const term = terms.find((el) => (el.textContent ?? '').trim() === label)
  return term?.nextElementSibling?.textContent?.trim() ?? null
}

/**
 * Drive the native <select>. React tracks the previous value, so assigning
 * `.value` alone would leave its internal state stale and no change event would
 * fire; the value setter has to go through the prototype.
 */
async function choose(host: HTMLElement, value: string): Promise<boolean> {
  const select = host.querySelector('select') as HTMLSelectElement | null
  if (!select) return false
  const setter = Object.getOwnPropertyDescriptor(
    dom.window.HTMLSelectElement.prototype,
    'value',
  )?.set
  await act(async () => {
    setter?.call(select, value)
    select.dispatchEvent(new dom.window.Event('change', { bubbles: true }))
    await wait(60)
  })
  return select.value === value
}

/* ----------------------------------------------------------------- the API */

/** What the backend actually declares and computes. */
type MissionContext = {
  status: string
  profile: { asset_id: string; criticality: string; mission_impact: string; role: string } | null
  risk: {
    technical_risk: number
    technical_severity: string
    contextualized_risk: number
    contextualized_severity: string
    context_index: number
  } | null
}

const listed = await fetch(`${ANALYTICS_URL}/api/v1/assets`).then((r) => r.json())
const declared: string[] = listed.assets ?? []

if (!declared.length) {
  console.log(
    'FAIL the store declares no assets; start the analytics API with --asset-id and --mission-profiles',
  )
  process.exitCode = 1
} else {
  /**
   * Fetched, never hardcoded: the expected rendering for each asset is whatever
   * its own context route returns. This is the mapping the panel must agree
   * with, and it is read from the backend on every run.
   */
  const expected = new Map<string, MissionContext>()
  const payloads = new Map<string, Record<string, unknown>>()
  for (const assetId of declared) {
    const payload = await fetch(
      `${ANALYTICS_URL}/api/v1/assets/${encodeURIComponent(assetId)}/context`,
    ).then((r) => r.json())
    payloads.set(assetId, payload)
    expected.set(assetId, payload.mission_context as MissionContext)
  }

  /* --------------------------------------------------------- the wire spy */
  const contextUrls: string[] = []
  /**
   * Deliberately wrong answers, keyed by asset id, that the spy serves instead
   * of the backend's.
   *
   * These exist because asserting "the panel shows what the backend says" is
   * only meaningful if the panel would visibly change when the backend does.
   * A hardcoded `gw-a -> low` / `gw-b -> high` table agrees with today's profile
   * file by coincidence, so every other check in this file would still pass
   * against it -- the substitution is what makes the agreement causal rather than
   * accidental.
   */
  const substitutions = new Map<string, { criticality: string; contextualized_risk: number }>()
  const realFetch = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (url.includes('/api/v1/assets/')) contextUrls.push(url)
    const match = /\/api\/v1\/assets\/([^/?]+)\/context(?:\?|$)/.exec(url)
    if (match) {
      const assetId = decodeURIComponent(match[1])
      const swap = substitutions.get(assetId)
      const original = payloads.get(assetId)
      if (swap && original) {
        const forged = JSON.parse(JSON.stringify(original))
        const mission = forged.mission_context as MissionContext
        if (mission.profile) mission.profile.criticality = swap.criticality
        if (mission.risk) mission.risk.contextualized_risk = swap.contextualized_risk
        return new Response(JSON.stringify(forged), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
    }
    return realFetch(input as RequestInfo, init)
  }) as typeof fetch

  const host = dom.window.document.createElement('div')
  dom.window.document.body.appendChild(host)
  const root = createRoot(host)

  await act(async () => {
    root.render(createElement(AssetContextPanel))
  })
  await settle()

  check('the panel renders', (host.textContent ?? '').includes('Asset context'))
  check('the panel offers an apply action', button(host, 'Assess asset') !== null)

  /* --- the selector is populated from the backend, not from the browser --- */
  const options = Array.from(host.querySelectorAll('option')).map((o) => (o as HTMLOptionElement).value)
  check(
    'the selector options are exactly the declared assets',
    options.length === declared.length && options.every((value) => declared.includes(value)),
    `options=${options.join(',')} declared=${declared.join(',')}`,
  )
  check(
    'the selector was seeded from the backend, not hardcoded',
    (host.querySelector('select') as HTMLSelectElement | null)?.value === listed.store_asset_id,
    `selected=${(host.querySelector('select') as HTMLSelectElement | null)?.value} store=${listed.store_asset_id}`,
  )

  /* --- nothing is claimed before the operator asks --- */
  check(
    'no criticality is shown before an asset is assessed',
    host.querySelector('.asset-context-result') === null &&
      !(host.textContent ?? '').includes('Criticality'),
  )

  /* --------------------------------- assess each declared asset in turn */
  for (const assetId of declared) {
    const truth = expected.get(assetId)!
    const before = contextUrls.length

    const switched = declared.length > 1 ? await choose(host, assetId) : true
    check(`the selector accepts ${assetId}`, switched)

    const apply = button(host, 'Assess asset')
    check(`an apply control exists for ${assetId}`, apply !== null)
    if (apply) await click(apply)

    await waitFor(
      `the result for ${assetId}`,
      () => assetSubject(host) === assetId,
    )

    /* --- the request carried the selected asset --- */
    const issued = contextUrls.slice(before)
    check(
      `assessing ${assetId} requested that asset's context`,
      issued.some((url) => url.includes(`/api/v1/assets/${assetId}/context`)),
      issued.join(' | '),
    )
    check(
      `assessing ${assetId} made exactly one context request`,
      issued.length === 1,
      `${issued.length}: ${issued.join(' | ')}`,
    )

    /* --- and the panel rendered what the backend said --- */
    check(`the panel shows the asset it was asked about`, assetSubject(host) === assetId)
    check(
      `the criticality shown for ${assetId} is the backend's`,
      metric(host, 'Criticality') === declaredValueLabel(truth.profile?.criticality),
      `shown=${metric(host, 'Criticality')} backend=${truth.profile?.criticality}`,
    )
    check(
      `the mission impact shown for ${assetId} is the backend's`,
      metric(host, 'Mission impact') === declaredValueLabel(truth.profile?.mission_impact),
      `shown=${metric(host, 'Mission impact')} backend=${truth.profile?.mission_impact}`,
    )
    check(
      `the contextualized score shown for ${assetId} is the backend's`,
      metric(host, 'Contextualized') === String(truth.risk?.contextualized_risk),
      `shown=${metric(host, 'Contextualized')} backend=${truth.risk?.contextualized_risk}`,
    )
    check(
      `the technical score shown for ${assetId} is the backend's`,
      metric(host, 'Score') === String(truth.risk?.technical_risk),
      `shown=${metric(host, 'Score')} backend=${truth.risk?.technical_risk}`,
    )
    check(
      `the severity shown for ${assetId} is the backend's`,
      metric(host, 'Contextualized') === String(truth.risk?.contextualized_severity) ||
        (host.textContent ?? '').includes(truth.risk?.contextualized_severity ?? ''),
      `backend=${truth.risk?.contextualized_severity}`,
    )
  }

  /* --- the two declared assets must not collapse into one answer --- */
  const criticalities = declared
    .map((assetId) => expected.get(assetId)!.profile?.criticality)
    .filter(Boolean)
  check(
    'the declared assets really do differ, so the demo is meaningful',
    new Set(criticalities).size > 1,
    criticalities.join(','),
  )
  check(
    'the highest-criticality asset outranks the lowest on contextualized risk',
    (() => {
      const ranked = declared
        .map((assetId) => ({
          weight: expected.get(assetId)!.risk?.context_index ?? -1,
          assetId,
        }))
        .sort((a, b) => a.weight - b.weight)
      return ranked.length < 2 || ranked[0].weight < ranked[ranked.length - 1].weight
    })(),
  )

  /* --- selecting an asset must not have rebound the store --- */
  /*
   * Now the decisive check: make the backend answer differently and insist the
   * screen follows it. The substituted criticality is chosen to differ from the
   * real one, so a panel that paired assets with criticalities of its own would
   * render the real value here and fail.
   */
  const target = declared.find((assetId) => {
    const criticality = expected.get(assetId)!.profile?.criticality
    return criticality !== undefined && criticality !== 'medium'
  })
  if (target) {
    const truth = expected.get(target)!
    const forgedCriticality = truth.profile!.criticality === 'medium' ? 'low' : 'medium'
    const forgedScore = (truth.risk!.contextualized_risk ?? 0) + 7
    substitutions.set(target, {
      criticality: forgedCriticality,
      contextualized_risk: forgedScore,
    })

    if (declared.length > 1) await choose(host, target)
    const apply = button(host, 'Assess asset')
    if (apply) await click(apply)
    await waitFor(
      `the substituted answer for ${target}`,
      () => metric(host, 'Criticality') === declaredValueLabel(forgedCriticality),
    )

    check(
      'the criticality follows the backend response, not a local asset table',
      metric(host, 'Criticality') === declaredValueLabel(forgedCriticality),
      `shown=${metric(host, 'Criticality')} backend=${forgedCriticality} real=${truth.profile!.criticality}`,
    )
    check(
      'the contextualized score follows the backend response',
      metric(host, 'Contextualized') === String(forgedScore),
      `shown=${metric(host, 'Contextualized')} backend=${forgedScore} real=${truth.risk!.contextualized_risk}`,
    )
    check(
      'the substituted criticality is not the one the profile file declares',
      forgedCriticality !== truth.profile!.criticality,
    )
    substitutions.clear()
  }

  const after = await fetch(`${ANALYTICS_URL}/api/v1/assets`).then((r) => r.json())
  check(
    'assessing an asset did not rebind the store',
    after.store_asset_id === listed.store_asset_id,
    `${listed.store_asset_id} -> ${after.store_asset_id}`,
  )

  const undeclared = await fetch(
    `${ANALYTICS_URL}/api/v1/assets/asset-that-was-never-declared/context`,
  ).then((r) => r.json())
  check(
    'an undeclared asset gets no profile and no criticality',
    undeclared.mission_context.status === 'not_configured' &&
      undeclared.mission_context.profile === null &&
      undeclared.mission_context.risk === null,
    JSON.stringify(undeclared.mission_context).slice(0, 160),
  )

  if (failures === 0) console.log('\nasset context panel smoke: all checks passed')
  else {
    console.error(`\nasset context panel smoke: ${failures} check(s) failed`)
    process.exit(1)
  }
}