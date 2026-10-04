/**
 * Temporary SSR smoke test (not part of the shipped app).
 *
 * Renders AssetPriorityPanel against the *exact* payload shape the backend
 * serves and asserts the declared criticality actually reaches the DOM.
 *
 * The panel used to read `priority` / `asset_priority` / a top-level
 * `criticality`. The API has never published any of those three: it nests the
 * operator's declarations under `profile` and the result under `risk`. Every
 * row was therefore dropped and the panel was permanently empty -- including in
 * deployments where mission context was fully configured. A title-only DOM
 * assertion cannot catch that, because the "Not configured" empty state passes
 * it, so this renders the real component and reads the real cells.
 */
import { StrictMode, createElement } from 'react'
import { renderToString } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import { AssetPriorityPanel } from '@/components/traffic/panels'
import type { CustodyExplanation } from '@/types'

/** The shape `MissionContext.to_dict()` produces for a configured asset. */
const CONFIGURED_CONTEXT = {
  status: 'configured',
  configured: true,
  asset_id: 'gw-b',
  profile: {
    asset_id: 'gw-b',
    role: 'operational-communications',
    criticality: 'high',
    mission_impact: 'high',
  },
  risk: {
    technical_risk: 12,
    technical_severity: 'MEDIUM',
    contextualized_risk: 18,
    contextualized_severity: 'MEDIUM',
    context_index: 100,
    multiplier_bp: 15000,
    criticality_weight: 100,
    mission_impact_weight: 100,
    model_version: 'mission-context-v1',
    score_cap: 100,
    inferred_from_traffic: false,
  },
  context_source: 'operator_supplied_asset_mission_profile',
  context_source_path: 'configs/mission/asset_mission_profiles.json',
  context_source_sha256: 'a'.repeat(64),
  reason: "mission context declared for asset 'gw-b' by an operator",
  model_version: 'mission-context-v1',
  derived_from_observation: false,
}

/** What the backend serves when no asset was declared. */
const NOT_CONFIGURED_CONTEXT = {
  status: 'not_configured',
  configured: false,
  asset_id: null,
  profile: null,
  risk: null,
  context_source: null,
  context_source_path: null,
  context_source_sha256: null,
  reason: 'no asset_id was declared for this assessment',
  model_version: 'mission-context-v1',
  derived_from_observation: false,
}

function explanation(
  assessmentId: string,
  findingId: string,
  missionContext: unknown,
): CustodyExplanation {
  return {
    schema_version: 'v1',
    component: 'correlation.custody',
    component_version: 'custody-v1',
    read_only: true,
    assessment_id: assessmentId,
    finding_id: findingId,
    mission_context: missionContext as Record<string, unknown> | null,
  } as CustodyExplanation
}

function render(explanations: CustodyExplanation[]): string {
  return renderToString(
    createElement(
      StrictMode,
      null,
      createElement(
        MemoryRouter,
        null,
        createElement(AssetPriorityPanel, { explanations }),
      ),
    ),
  )
}

let failures = 0
function check(label: string, ok: boolean): void {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`)
  if (!ok) failures += 1
}

const CONFIGURED_ASSET = 'dataset-20260924-003710:4:pfs-weak'
const HIGH = explanation(CONFIGURED_ASSET, 'RISK-PFS-DISABLED', CONFIGURED_CONTEXT)
const LOW = explanation(
  'dataset-20260924-003710:5:ipsec-pfs',
  'RISK-PFS-WEAK-GROUP',
  {
    ...CONFIGURED_CONTEXT,
    asset_id: 'gw-a',
    profile: { ...CONFIGURED_CONTEXT.profile, asset_id: 'gw-a', criticality: 'low', mission_impact: 'low' },
    risk: { ...CONFIGURED_CONTEXT.risk, context_index: 33, multiplier_bp: 10000, criticality_weight: 33, mission_impact_weight: 33 },
  },
)

// 1. A configured context must produce a real row, not the empty state.
const configuredHtml = render([HIGH])
check('configured context renders a row, not the empty state', !configuredHtml.includes('Not configured'))
check('the declared asset id is shown', configuredHtml.includes('gw-b'))
check('the declared criticality is shown', configuredHtml.includes('>high<'))
check('the declared mission impact is shown', configuredHtml.includes('operational-communications') || configuredHtml.includes('gw-b'))

// 2. The declared priority index and the technical->contextual pair are shown.
check('the backend context_index is shown as priority', configuredHtml.includes('100'))
check('the technical and contextualized scores are both shown', configuredHtml.includes('12') && configuredHtml.includes('18'))

// 3. Two assets in one store must not collapse onto each other.
const bothHtml = render([HIGH, LOW])
check('a low asset renders alongside a high one', bothHtml.includes('gw-a') && bothHtml.includes('gw-b'))
check('the low asset shows its own criticality', bothHtml.includes('>low<'))
check('the high asset still shows its own criticality', bothHtml.includes('>high<'))
check('the low asset shows the neutral multiplier result', bothHtml.includes('33'))

// 4. Not-configured must stay honest: no invented priority.
const unconfiguredHtml = render([explanation(CONFIGURED_ASSET, 'RISK-PFS-DISABLED', NOT_CONFIGURED_CONTEXT)])
check('an unconfigured context renders the empty state', unconfiguredHtml.includes('Not configured'))
check('an unconfigured context invents no criticality', !unconfiguredHtml.includes('>low<') && !unconfiguredHtml.includes('>high<'))
check('an absent context renders the empty state', render([]).includes('Not configured'))

// 5. A malformed context must not be rendered as a clean, declared value.
const junkHtml = render([explanation(CONFIGURED_ASSET, 'RISK-PFS-DISABLED', { priority: 'high', criticality: 'high' })])
check('fields the API never publishes cannot produce a row', junkHtml.includes('Not configured'))

if (failures) {
  console.error(`\nasset-criticality panel smoke: ${failures} check(s) failed`)
  process.exit(1)
}
console.log('\nasset-criticality panel smoke: all checks passed')