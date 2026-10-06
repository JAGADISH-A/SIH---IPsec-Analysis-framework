import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { getAssetContext, getAssets, getDriftBaselines, getDriftSummary } from '@/api/analytics'
import { generateReport } from '@/api/reports'
import { useResource } from '@/hooks/useResource'
import { EmptyState, ErrorState, LoadingPanel, Spinner } from '@/components/states'
import { Panel, StatusPill } from '@/components/ui'
import { IdRow, ProvenanceDetails } from '@/components/kit'
import { ProvenanceChip, NotObservable } from '@/components/traffic/parts'
import { NOT_OBSERVABLE, formatNumber, severityHex } from '@/lib/format'
import { declaredValueLabel } from '@/lib/labels'
import type {
  AssessmentHeader,
  CustodyExplanation,
  Finding,
  ReportKind,
  ReportResult,
  StoreOverview,
} from '@/types'

const CHART_AXIS = '#5d6d85'
const CHART_GRID = '#1b2537'

/**
 * A JSON value as a string, or null when it is absent. Mission-context fields
 * arrive untyped, so a label helper needs to know whether there is a value to
 * word-case rather than receiving the literal string "undefined".
 */
function asString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() !== '' ? value : null
}

function TooltipBox({
  active,
  payload,
  label,
}: {
  active?: boolean
  payload?: { name?: string; value?: number | string; color?: string }[]
  label?: string | number
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="popover px-2.5 py-1.5 text-xs">
      <p className="mb-0.5 font-medium text-ink">{label}</p>
      {payload.map((entry, index) => (
        <p key={index} className="mono tnum text-ink-dim">
          {entry.name ?? 'count'}: {formatNumber(Number(entry.value))}
        </p>
      ))}
    </div>
  )
}

function Kpi({
  label,
  value,
  sub,
  accent,
}: {
  label: string
  value: React.ReactNode
  sub: React.ReactNode
  accent: string
}) {
  return (
    <div className="panel relative overflow-hidden p-3.5">
      <span
        className="absolute inset-x-0 top-0 h-px opacity-70"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}, transparent)` }}
        aria-hidden="true"
      />
      <p className="label text-ink-faint">{label}</p>
      <p className="mono tnum mt-1.5 text-2xl font-semibold leading-none text-ink">{value}</p>
      <div className="mt-1.5 text-xs leading-snug text-ink-faint">{sub}</div>
    </div>
  )
}

/* ------------------------------------------------------------------ drift */

export function DriftPanel() {
  const summary = useResource((signal) => getDriftSummary(signal))
  const baselines = useResource((signal) => getDriftBaselines(signal))

  const configured = summary.data?.configured === true

  return (
    <Panel
      title="Drift"
      subtitle="longitudinal comparison against a validated baseline"
      action={
        <StatusPill
          status={configured ? 'configured' : 'not_configured'}
          tone={configured ? 'good' : 'warn'}
          label={configured ? 'CONFIGURED' : 'NOT CONFIGURED'}
        />
      }
    >
      {summary.loading ? (
        <LoadingPanel label="Loading drift" rows={2} />
      ) : summary.error ? (
        <div className="p-3">
          <ErrorState error={summary.error} onRetry={summary.reload} compact />
        </div>
      ) : summary.data ? (
        <div className="space-y-3 p-3.5">
          {!configured && (
            <div className="rounded border border-medium/30 bg-medium/[0.06] p-2.5">
              <p className="text-sm font-medium text-medium">No baseline is configured</p>
              <p className="mt-1 text-sm leading-relaxed text-ink-dim">
                {summary.data.reason ??
                  'No validated baseline registry was supplied to this store.'}
              </p>
              <p className="mt-1.5 text-xs leading-relaxed text-ink-faint">
                This is deliberately not rendered as &ldquo;no drift detected&rdquo;. An absent
                comparison and a clean comparison are different facts, and only the second one
                supports a claim about stability.
              </p>
            </div>
          )}
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Metric label="Assessments" value={formatNumber(summary.data.assessment_count ?? null)} />
            <Metric label="Compared" value={formatNumber(summary.data.compared_count ?? null)} />
            <Metric
              label="Drift detected"
              value={formatNumber(summary.data.drift_detected_count ?? null)}
            />
            <Metric label="Baselines" value={formatNumber(baselines.data?.baseline_ids?.length ?? null)} />
          </dl>
          {baselines.data?.baselines && baselines.data.baselines.length > 0 && (
            <ul className="space-y-1">
              {baselines.data.baselines.map((baseline, index) => (
                <li
                  key={index}
                  className="mono truncate rounded-md border border-edge bg-panel-2 px-2.5 py-1.5 text-xs text-ink-dim"
                >
                  {String(baseline.baseline_id ?? JSON.stringify(baseline))}
                </li>
              ))}
            </ul>
          )}
          <p className="text-xs leading-relaxed text-ink-faint">
            Baselines are established out of band by the drift layer. This surface is read-only: it
            cannot create, amend or remove one.
          </p>
        </div>
      ) : (
        <NotObservable what="no drift summary was returned" />
      )}
    </Panel>
  )
}

function Metric({ label, value }: { label: string; value: string | number | null }) {
  return (
    <div className="min-w-0">
      <dt className="label text-ink-faint">{label}</dt>
      <dd className="tnum truncate text-lg leading-tight text-ink" title={String(value ?? '')}>
        {value === null || value === undefined || value === '' ? NOT_OBSERVABLE : value}
      </dd>
    </div>
  )
}

/* -------------------------------------------------------------- integrity */

/**
 * Evidence integrity, as the backend reports it.
 *
 * There is no mutation control here and there will not be one: the analytics
 * plane is read-only, and a browser-side "tamper" button could only ever
 * redraw a digest it computed itself, which would be a claim with no authority
 * behind it. What an analyst needs is the verification state, so that is what
 * this shows.
 */
export function IntegrityPanel({ findings }: { findings: Finding[] }) {
  const withEvidence = useMemo(
    () => findings.filter((finding) => (finding.evidence_refs ?? []).length > 0),
    [findings],
  )

  const total = useMemo(
    () => withEvidence.reduce((sum, finding) => sum + (finding.evidence_refs?.length ?? 0), 0),
    [withEvidence],
  )

  const digests = useMemo(() => {
    const seen = new Set<string>()
    for (const finding of withEvidence) {
      for (const ref of finding.evidence_refs ?? []) {
        if (ref.artifact_sha256) seen.add(ref.artifact_sha256)
      }
    }
    return seen
  }, [withEvidence])

  return (
    <Panel
      title="Evidence integrity"
      subtitle="recorded digests; verification is the backend's, and read-only"
      action={
        <StatusPill
          status="read_only"
          tone="info"
          label="NO MUTATION PATH"
        />
      }
    >
      <div className="space-y-3 p-3.5">
        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <Metric label="Evidence refs" value={formatNumber(total)} />
          <Metric label="Distinct digests" value={formatNumber(digests.size)} />
          <Metric label="Findings backed" value={formatNumber(withEvidence.length)} />
        </dl>
        {digests.size > 0 && (
          <ul className="max-h-[132px] space-y-1 overflow-y-auto">
            {[...digests].slice(0, 24).map((digest) => (
              <li
                key={digest}
                className="mono flex items-center gap-2 rounded-md border border-edge bg-panel-2 px-2.5 py-1 text-xs text-ink-dim"
              >
                <ProvenanceChip provenance="OBSERVED" />
                <span className="truncate" title={digest}>
                  {digest}
                </span>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs leading-relaxed text-ink-faint">
          These are the digests recorded alongside each finding. Selecting an artifact in the
          evidence tab asks the backend for its verification status; the browser never re-hashes a
          file, and cannot mark an artifact verified on its own authority.
        </p>
      </div>
    </Panel>
  )
}

/* ------------------------------------------------------------ asset priority */

/**
 * Asset priority, read from backend mission context only.
 *
 * The custody explanation is the one place the backend publishes mission
 * context, so that is the only source consulted. When it is absent or
 * unconfigured, priority stays unknown — an analyst-facing priority that the
 * backend did not assign is exactly the kind of invented fact this console
 * exists to avoid.
 */
export function AssetPriorityPanel({ explanations }: { explanations: CustodyExplanation[] }) {
  const rows = useMemo(
    () =>
      explanations
        .map((explanation) => {
          const context = explanation.mission_context
          if (!context || typeof context !== 'object') return null
          const record = context as Record<string, unknown>
          // The API nests the operator's declarations under `profile` and the
          // result they produced under `risk`. Reading them from the top level
          // yields nothing for every row, which is why this panel used to be
          // permanently empty even when mission context was configured.
          const profile = (record.profile ?? null) as Record<string, unknown> | null
          const risk = (record.risk ?? null) as Record<string, unknown> | null
          if (!profile || !risk) return null
          const criticality = profile.criticality ?? null
          const priority = risk.context_index ?? null
          if (criticality === null || priority === null) return null
          return {
            key: `${explanation.assessment_id}/${explanation.finding_id}`,
            assessmentId: explanation.assessment_id,
            asset: (record.asset_id ?? profile.asset_id ?? '—') as string,
            priority: String(priority),
            criticality: String(criticality),
            missionImpact: (profile.mission_impact ?? null) as string | null,
            technicalRisk: (risk.technical_risk ?? null) as number | null,
            contextualRisk: (risk.contextualized_risk ?? null) as number | null,
            reason: (record.reason ?? null) as string | null,
          }
        })
        .filter((row): row is NonNullable<typeof row> => row !== null),
    [explanations],
  )

  return (
    <Panel title="Asset priority" subtitle="backend mission context · never inferred by Sentinel">
      {rows.length === 0 ? (
        <EmptyState
          title="Not configured"
          icon="filter"
          description="No mission context is attached to the findings in this store, so no asset priority is available. Sentinel does not assign one: priority is a mission decision, and inventing it here would be indistinguishable from a real one."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="data-table min-w-[420px]">
            <thead>
              <tr>
                {['Asset', 'Priority', 'Criticality', 'Impact', 'Risk', 'Reason', 'Record'].map((heading) => (
                  <th key={heading} scope="col">
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key}>
                  <td className="text-sm text-ink">{row.asset}</td>
                  <td className="text-sm font-medium text-ink-dim">{row.priority}</td>
                  <td className="text-sm text-ink-faint">{declaredValueLabel(row.criticality)}</td>
                  <td className="text-sm text-ink-faint">
                    {row.missionImpact ? declaredValueLabel(row.missionImpact) : NOT_OBSERVABLE}
                  </td>
                  <td className="mono tnum text-xs text-ink-faint">
                    {row.technicalRisk === null
                      ? NOT_OBSERVABLE
                      : `${row.technicalRisk} → ${row.contextualRisk}`}
                  </td>
                  <td className="text-sm text-ink-faint">{row.reason ?? NOT_OBSERVABLE}</td>
                  <td className="px-3 py-2">
                    <ProvenanceDetails title="Record ids">
                      <IdRow label="Assessment id" value={row.assessmentId} title={row.assessmentId} />
                      <IdRow label="Criticality" value={row.criticality} title={row.criticality} />
                      {row.missionImpact && (
                        <IdRow label="Mission impact" value={row.missionImpact} title={row.missionImpact} />
                      )}
                    </ProvenanceDetails>
                    <Link
                      to={`/assessments/${encodeURIComponent(row.assessmentId)}`}
                      className="mt-0.5 block text-xs text-sentinel hover:underline"
                    >
                      open assessment →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

/* --------------------------------------------------- selected asset context */

/**
 * Mission context for one *selected* asset, asked of the backend.
 *
 * `AssetPriorityPanel` above is a projection: it can only show the asset the
 * store was started with, because that is the only asset the custody
 * explanation reports. This panel is the other half of the same feature — it
 * asks the backend about whichever asset is chosen in the selector.
 *
 * Two things are deliberately not done here:
 *
 * 1. The asset list is never written down in the browser. It comes from
 *    `GET /api/v1/assets`, which reports the profiles an operator actually
 *    declared. A hardcoded `gw-a`/`gw-b` list would offer assets this
 *    deployment never declared and hide the ones it did.
 * 2. The criticality is never written down either. Selecting an asset sends its
 *    id and the panel renders what came back, so a change to the profile file
 *    changes this screen. Pairing an asset with a criticality client-side would
 *    make the panel look right while disagreeing with the backend, which is the
 *    one thing this console must never do.
 *
 * `status` is the field that matters when reading the result. `not_configured`
 * means no profile is declared for the selected asset, and in that case there is
 * no profile, no risk and no criticality to show — the panel says so rather than
 * rendering a blank that could read as "low".
 */
export function AssetContextPanel() {
  const assets = useResource((signal) => getAssets(signal))
  const [selected, setSelected] = useState('')
  const [applied, setApplied] = useState<string | null>(null)

  const declared = assets.data?.assets ?? []

  // Default to the asset this store was bound to, falling back to the first
  // declared one. Both come from the backend, so the selector can never offer an
  // asset the deployment does not have.
  useEffect(() => {
    if (declared.length === 0 || selected !== '') return
    const bound = assets.data?.store_asset_id
    setSelected(
      bound && declared.includes(bound) ? bound : (declared[0] ?? ''),
    )
  }, [declared, selected, assets.data])

  // Explicitly applied rather than fetched on change: the point of the control
  // is to show a request being made for the chosen asset.
  const context = useResource(
    (signal) => getAssetContext(applied as string, {}, signal),
    { enabled: applied !== null, deps: [applied] },
  )

  const mission = context.data?.mission_context ?? null
  const profile = mission?.profile ?? null
  const risk = mission?.risk ?? null
  const configured = mission?.status === 'configured' && profile !== null && risk !== null

  return (
    <Panel
      title="Asset context"
      subtitle="what an operator declared about this asset, and what was measured on it"
      action={
        <StatusPill
          status={mission?.status ?? 'not_applied'}
          tone={configured ? 'good' : 'neutral'}
          label={configured ? 'CONFIGURED' : 'NO CONTEXT'}
        />
      }
    >
      {assets.loading ? (
        <LoadingPanel label="Loading declared assets" rows={2} />
      ) : assets.error ? (
        <div className="p-3">
          <ErrorState error={assets.error} onRetry={assets.reload} compact />
        </div>
      ) : declared.length === 0 ? (
        <EmptyState
          title="No assets declared"
          icon="filter"
          description={
            assets.data?.reason ??
            'This store was started without a mission profile file, so no asset is declared. Assets are declared explicitly by an operator and are never inferred from traffic.'
          }
        />
      ) : (
        <div className="space-y-3 p-3.5">
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex flex-col gap-1">
              <span className="label text-ink-faint">Asset</span>
              <select
                className="rounded-md border border-edge bg-panel px-2 py-1 text-sm text-ink focus:border-sentinel focus:ring-2 focus:ring-sentinel/15 focus:outline-none"
                value={selected}
                onChange={(event) => setSelected(event.target.value)}
              >
                {declared.map((assetId) => (
                  <option key={assetId} value={assetId}>
                    {assetId}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="inline-flex items-center gap-1.5 rounded border border-sentinel/45 bg-sentinel/10 px-2.5 py-1 text-xs text-sentinel transition-colors hover:bg-sentinel/20 disabled:opacity-50"
              // Only the absence of a selection disables it. `useResource`
              // reports `loading: true` while it is disabled, so gating on
              // `context.loading` here would lock the control permanently.
              disabled={selected === '' || (applied === selected && context.loading)}
              onClick={() => setApplied(selected)}
            >
              {applied === selected && context.loading && <Spinner />}
              Assess asset
            </button>
          </div>

          {applied === null ? (
            <p className="text-xs leading-relaxed text-ink-faint">
              No asset assessed yet. Choosing an asset sends its id to the analytics service and
              renders the mission context the backend returns; the criticality below is never
              assumed in the browser.
            </p>
          ) : context.loading ? (
            <LoadingPanel label={`Assessing ${applied}`} rows={2} />
          ) : context.error ? (
            <ErrorState error={context.error} onRetry={context.reload} compact />
          ) : context.data && !configured ? (
            <div className="rounded border border-medium/30 bg-medium/[0.06] p-3">
              <p className="text-sm font-medium text-medium">
                No mission context for {context.data.asset_id}
              </p>
              <p className="mt-1 text-sm leading-relaxed text-ink-dim">
                {mission?.reason ?? 'The backend declared no profile for this asset.'}
              </p>
              <p className="mt-1.5 text-xs leading-relaxed text-ink-faint">
                This is deliberately not shown as a low criticality. An absent declaration and a
                benign declaration are different facts, and only the second one supports a claim
                about the asset.
              </p>
            </div>
          ) : context.data && profile && risk ? (
            <div className="asset-context-result space-y-4">
              {/* The asset is the subject of this panel, so it is named rather
                  than listed as one metric among four. */}
              <div>
                <p className="label text-ink-faint">Asset</p>
                <p className="mt-0.5 font-mono text-lg leading-none text-ink">
                  {profile.asset_id}
                </p>
              </div>

              {/* Criticality, priority, impact and role are operator
                  declarations. They are grouped and named as such, because
                  reading them next to observed findings without that
                  distinction would imply Sentinel inferred them from traffic,
                  which it does not do. */}
              <section
                aria-label="Operator-declared context"
                className="rounded border border-edge-soft bg-panel-2/40 p-3"
              >
                <p className="label mb-2.5">Operator-declared context</p>
                <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <Metric label="Criticality" value={declaredValueLabel(asString(profile.criticality))} />
                  <Metric label="Priority" value={risk.context_index} />
                  <Metric label="Mission impact" value={declaredValueLabel(asString(profile.mission_impact))} />
                  <Metric label="Role" value={declaredValueLabel(asString(profile.role))} />
                </dl>
                <p className="mt-2.5 text-xs leading-relaxed text-ink-faint">
                  Declared by an operator in mission configuration, not inferred by Sentinel from
                  observed traffic. It tells the risk engine how much this asset matters; it is not
                  a measurement of the asset.
                </p>
              </section>

              {/* What was actually observed, kept as a separate claim so the
                  two are never read as one. */}
              <section
                aria-label="Observed evidence"
                className="rounded border border-edge-soft p-3"
              >
                <p className="label mb-2">Observed evidence</p>
                <p className="text-sm leading-relaxed text-ink-dim">
                  {context.data.technical_risk_source.replace(/_/g, ' ')} measured{' '}
                  <span className="tnum font-semibold text-ink">{context.data.technical_risk}</span>{' '}
                  <span style={{ color: severityHex(context.data.technical_severity) }}>
                    {context.data.technical_severity}
                  </span>{' '}
                  from the captured traffic
                  {context.data.assessment_id ? (
                    <>
                      {' '}in{' '}
                      <ProvenanceDetails title="Assessment record">
                        <IdRow
                          label="Assessment id"
                          value={context.data.assessment_id}
                          title={context.data.assessment_id}
                        />
                      </ProvenanceDetails>
                    </>
                  ) : null}
                  . This is the measurement; the context above is how much it counts for.
                </p>
              </section>

              {/* The contextualisation arithmetic is how the two combine. It is
                  real and it is load-bearing, but it is arithmetic rather than
                  a finding, so it sits behind the disclosure. */}
              <ProvenanceDetails title="How the context was applied">
                <div className="overflow-x-auto">
                  <table className="data-table min-w-[420px]">
                    <thead>
                      <tr>
                        {['Risk', 'Value', 'Context', 'Value'].map((heading, index) => (
                          <th key={index} scope="col">
                            {heading}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {[
                        ['Score', risk.technical_risk, 'Contextualized', risk.contextualized_risk],
                        ['Severity', risk.technical_severity, 'Contextualized', risk.contextualized_severity],
                        ['Index', risk.context_index, 'Multiplier', risk.multiplier_bp],
                        ['Criticality weight', risk.criticality_weight, 'Impact weight', risk.mission_impact_weight],
                        ['Score cap', risk.score_cap, 'Inferred', String(risk.inferred_from_traffic)],
                      ].map((row) => (
                        <tr key={row[0] as string}>
                          <th scope="row" className="text-left text-xs font-normal text-ink-faint">
                            {row[0] as string}
                          </th>
                          <td className="tnum text-xs text-ink">{row[1] as string}</td>
                          <th scope="row" className="text-left text-xs font-normal text-ink-faint">
                            {row[2] as string}
                          </th>
                          <td className="tnum text-xs text-ink">{row[3] as string}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-ink-faint">
                  The declared profile came from {mission?.context_source ?? 'no source'}
                  {mission?.context_source_path ? ` (${mission.context_source_path})` : ''}, model{' '}
                  {mission?.model_version}. Selecting an asset is a read: it does not rebind this
                  store, so the custody chain still reports{' '}
                  {assets.data?.store_asset_id ?? 'no bound asset'}.
                </p>
              </ProvenanceDetails>
            </div>
          ) : null}
        </div>
      )}
    </Panel>
  )
}

/* ---------------------------------------------------------- threat matrix */

type MatrixAxis = 'severity' | 'posture'

const THREAT_AXES: { key: MatrixAxis; label: string; buckets: string[] }[] = [
  {
    key: 'severity',
    label: 'Severity',
    buckets: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
  },
  {
    key: 'posture',
    label: 'Planner posture',
    buckets: ['STRONG', 'GOOD', 'MEDIUM', 'WEAK', 'WORST'],
  },
]

/**
 * Severity against planner-declared posture.
 *
 * Both axes are backend-produced. The matrix is a cross-tabulation of two
 * recorded facts, not a score: nothing is weighted or ranked here, because
 * that judgement already exists in the risk engine and duplicating it would
 * create a second, weaker source of truth.
 */
export function ThreatMatrix({ headers }: { headers: AssessmentHeader[] }) {
  const [axis, setAxis] = useState<MatrixAxis>('severity')

  const active = THREAT_AXES.find((entry) => entry.key === axis)!

  const cells = useMemo(() => {
    const grid = new Map<string, AssessmentHeader[]>()
    for (const header of headers) {
      const value =
        axis === 'severity' ? header.severity.toUpperCase() : (header.security_posture || 'UNSPECIFIED').toUpperCase()
      const bucket = grid.get(value) ?? []
      bucket.push(header)
      grid.set(value, bucket)
    }
    return grid
  }, [headers, axis])

  const max = useMemo(
    () => Math.max(1, ...[...cells.values()].map((bucket) => bucket.length)),
    [cells],
  )

  return (
    <Panel
      title="Threat matrix"
      subtitle="assessments cross-tabulated by two backend-recorded axes"
      action={
        <div className="flex gap-1">
          {THREAT_AXES.map((entry) => (
            <button
              key={entry.key}
              type="button"
              onClick={() => setAxis(entry.key)}
              className={`rounded border px-2 py-1 text-xs transition-colors ${
                axis === entry.key
                  ? 'border-sentinel/45 bg-sentinel/12 text-sentinel'
                  : 'border-edge bg-panel-2 text-ink-faint hover:text-ink-dim'
              }`}
            >
              {entry.label}
            </button>
          ))}
        </div>
      }
    >
      {headers.length === 0 ? (
        <EmptyState title="No assessments to cross-tabulate" />
      ) : (
        <div className="space-y-2 p-3.5">
          <div className="grid gap-1.5" style={{ gridTemplateColumns: `repeat(${active.buckets.length}, minmax(0, 1fr))` }}>
            {active.buckets.map((bucket) => {
              const bucketRows = cells.get(bucket) ?? []
              return (
                <div
                  key={bucket}
                  className="rounded-md border border-edge bg-panel-2 p-2 text-center"
                  style={{ minHeight: `${48 + (bucketRows.length / max) * 64}px` }}
                >
                  <p className="mono tnum text-lg font-semibold leading-none text-ink">
                    {bucketRows.length}
                  </p>
                  <p className="mt-1 label text-ink-faint">
                    {bucket}
                  </p>
                </div>
              )
            })}
          </div>
          <p className="text-xs leading-relaxed text-ink-faint">
            Counts only. Sentinel does not derive a threat level from this grid: severity comes
            from the risk engine and posture is what the planner declared, and neither is
            re-weighted here.
          </p>
        </div>
      )}
    </Panel>
  )
}

/* --------------------------------------------------------------- reports */

const REPORT_KINDS: { kind: ReportKind; label: string; description: string }[] = [
  {
    kind: 'assessment',
    label: 'Assessment report',
    description: 'The full risk, comparison and evidence record for one assessment.',
  },
  {
    kind: 'incident',
    label: 'Incident summary',
    description: 'A grouped view of the findings raised across the store.',
  },
  {
    kind: 'evidence-log',
    label: 'Evidence log',
    description: 'Every recorded artifact with its digest and verification status.',
  },
]

/**
 * Report controls.
 *
 * The analytics plane is read-only and exposes no report endpoint, so these
 * return the reason rather than a document. The controls are shown anyway: an
 * analyst should be able to see that the capability is absent and why, rather
 * than infer it from a missing button.
 */
export function ReportsPanel({ runId }: { runId: string | null }) {
  const [busy, setBusy] = useState<ReportKind | null>(null)
  const [result, setResult] = useState<ReportResult | null>(null)

  const generate = async (kind: ReportKind) => {
    setBusy(kind)
    try {
      setResult(await generateReport({ kind, entityId: runId ?? 'store' }))
    } finally {
      setBusy(null)
    }
  }

  return (
    <Panel title="Reports" subtitle="read-only store · no report endpoint is exposed">
      <div className="space-y-2.5 p-3.5">
        <div className="grid gap-2 sm:grid-cols-3">
          {REPORT_KINDS.map((entry) => (
            <div key={entry.kind} className="rounded-md border border-edge bg-panel-2 p-2.5">
              <p className="text-sm font-medium text-ink">{entry.label}</p>
              <p className="mt-0.5 text-xs leading-relaxed text-ink-faint">
                {entry.description}
              </p>
              <button
                type="button"
                onClick={() => generate(entry.kind)}
                disabled={busy !== null}
                className="mt-2 inline-flex items-center gap-1.5 rounded border border-edge bg-panel-2 px-2.5 py-1 text-xs text-ink-dim transition-colors hover:text-ink disabled:opacity-50"
              >
                {busy === entry.kind && <Spinner />}
                Generate
              </button>
            </div>
          ))}
        </div>
        {result && (
          <div className="rounded-md border border-edge bg-panel p-3">
            <p className="text-sm font-medium text-ink-dim">
              No {result.kind} report was produced
            </p>
            <p className="mt-1 text-sm leading-relaxed text-ink-faint">{result.reason}</p>
          </div>
        )}
        <p className="text-xs leading-relaxed text-ink-faint">
          Sentinel does not compose a report in the browser. A document assembled client-side
          would carry no authority, and presenting it beside server-produced records would invite
          exactly the confusion the rest of this console is built to prevent.
        </p>
      </div>
    </Panel>
  )
}

/* -------------------------------------------------------------- statistics */

export function StatisticsPanel({
  overview,
  headers,
  findings,
}: {
  overview: StoreOverview | null
  headers: AssessmentHeader[]
  findings: Finding[]
}) {
  const [axis, setAxis] = useState<'severity' | 'posture'>('severity')

  const bySeverity = useMemo(() => {
    const counts = new Map<string, number>()
    for (const header of headers) {
      const key = header.severity.toUpperCase()
      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    return [...counts.entries()].map(([severity, count]) => ({ bucket: severity, count }))
  }, [headers])

  const byPosture = useMemo(() => {
    const counts = new Map<string, number>()
    for (const header of headers) {
      const key = (header.security_posture || 'UNSPECIFIED').toUpperCase()
      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    return [...counts.entries()].map(([bucket, count]) => ({ bucket, count }))
  }, [headers])

  const data = axis === 'posture' ? byPosture : bySeverity

  const findingSeverity = useMemo(() => {
    const counts = new Map<string, number>()
    for (const finding of findings) {
      const key = finding.severity.toUpperCase()
      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    return [...counts.entries()].map(([bucket, count]) => ({ bucket, count }))
  }, [findings])

  return (
    <Panel
      title="Statistics"
      subtitle="counts read directly from the store overview and headers"
      action={
        <div className="flex gap-1">
          {(['severity', 'posture'] as const).map((entry) => (
            <button
              key={entry}
              type="button"
              onClick={() => setAxis(entry)}
              className={`rounded border px-2 py-1 text-xs transition-colors ${
                axis === entry
                  ? 'border-sentinel/45 bg-sentinel/12 text-sentinel'
                  : 'border-edge bg-panel-2 text-ink-faint hover:text-ink-dim'
              }`}
            >
              {entry}
            </button>
          ))}        </div>
      }
    >
      <div className="grid gap-4 p-3.5 lg:grid-cols-2">
        <div>
          <p className="mb-1 label text-ink-faint">
            assessments by {axis}
          </p>
          <div className="h-[150px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 4, right: 12, bottom: 0, left: -20 }}>
                <XAxis
                  dataKey="bucket"
                  tick={{ fill: CHART_AXIS, fontSize: 9 }}
                  axisLine={{ stroke: CHART_GRID }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: CHART_AXIS, fontSize: 9 }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                  width={36}
                />
                <Tooltip content={<TooltipBox />} cursor={{ fill: 'rgba(34,211,238,0.05)' }} />
                <Bar dataKey="count" radius={[3, 3, 0, 0]} maxBarSize={30}>
                  {data.map((entry) => (
                    <Cell
                      key={entry.bucket}
                      fill={severityHex(axis === 'posture' ? entry.bucket : entry.bucket)}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="mb-1 mt-3 label text-ink-faint">
            findings by severity
          </p>
          <ul className="flex flex-wrap gap-1.5">
            {findingSeverity.map((entry) => (
              <li
                key={entry.bucket}
                className="flex items-center gap-1.5 rounded-md border border-edge bg-panel-2 px-2 py-1"
              >
                <span
                  className="h-2 w-2 rounded-sm"
                  style={{ background: severityHex(entry.bucket) }}
                  aria-hidden="true"
                />
                <span className="text-xs text-ink-faint">{entry.bucket}</span>
                <span className="mono tnum text-xs text-ink-dim">{entry.count}</span>
              </li>
            ))}
            {findingSeverity.length === 0 && (
              <li className="text-xs text-ink-faint">No findings recorded.</li>
            )}
          </ul>
        </div>
        <dl className="grid grid-cols-2 gap-3">
          <Metric label="Assessments" value={formatNumber(overview?.total_assessments ?? null)} />
          <Metric label="Findings" value={formatNumber(overview?.findings_total ?? null)} />
          <Metric label="Unknown obs." value={formatNumber(overview?.unknown_observations ?? null)} />
          <Metric label="ML anomalies" value={formatNumber(overview?.ml_anomalies ?? null)} />
          <Metric
            label="ML disagreements"
            value={formatNumber(overview?.ml_classification_disagreements ?? null)}
          />
          <Metric label="Highest risk" value={formatNumber(overview?.highest_risk ?? null)} />
        </dl>
      </div>
    </Panel>
  )
}

export { Kpi }
