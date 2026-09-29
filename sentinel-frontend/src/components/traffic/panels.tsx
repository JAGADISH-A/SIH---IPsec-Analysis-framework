import { useMemo, useState } from 'react'
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
import { getDriftBaselines, getDriftSummary } from '@/api/analytics'
import { generateReport } from '@/api/reports'
import { useResource } from '@/hooks/useResource'
import { EmptyState, ErrorState, LoadingPanel, Spinner } from '@/components/states'
import { Panel, StatusPill } from '@/components/ui'
import { ProvenanceChip, NotObservable } from '@/components/traffic/parts'
import { NOT_OBSERVABLE, formatNumber, severityHex } from '@/lib/format'
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

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="label text-ink-faint">{label}</dt>
      <dd className="mono tnum text-lg leading-tight text-ink">{value}</dd>
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
          const priority = record.priority ?? record.asset_priority ?? null
          if (priority === null || priority === undefined) return null
          return {
            key: `${explanation.assessment_id}/${explanation.finding_id}`,
            assessmentId: explanation.assessment_id,
            asset: (record.asset ?? record.asset_id ?? record.host ?? '—') as string,
            priority: String(priority),
            criticality: (record.criticality ?? null) as string | null,
            reason: (record.reason ?? record.rationale ?? null) as string | null,
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
                {['Asset', 'Priority', 'Criticality', 'Reason', 'Assessment'].map((heading) => (
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
                  <td className="text-sm text-ink-faint">{row.criticality ?? NOT_OBSERVABLE}</td>
                  <td className="text-sm text-ink-faint">{row.reason ?? NOT_OBSERVABLE}</td>
                  <td className="px-3 py-2">
                    <Link
                      to={`/assessments/${encodeURIComponent(row.assessmentId)}`}
                      className="mono text-xs text-sentinel hover:underline"
                    >
                      {row.assessmentId}
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
