import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { Button, Panel, SeverityBadge, StatusPill, Tag, HashChip, Prose, Metric } from '@/components/ui'
import { ComparisonTable } from './ComparisonTable'
import { FindingsList } from './FindingsList'
import { EvidencePanel } from './EvidencePanel'
import { XaiPanel } from './XaiPanel'
import { MlPanel } from './MlPanel'
import { ObservedPanel } from './ObservedPanel'
import { AssessmentDriftBlock } from '@/components/packet/AssessmentDriftBlock'
import { getAssessmentDrift } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { ErrorState, LoadingPanel } from '@/components/states'
import { IdRow, ProvenanceDetails } from '@/components/kit'
import {
  formatBytes,
  formatDateTime,
  formatNumber,
  formatPercent,
  humanize,
  severityStyle,
} from '@/lib/format'
import { acronymLabel, statusLabel } from '@/lib/labels'
import type { AssessmentBundle, Severity } from '@/types'

export type DetailTab = 'overview' | 'findings' | 'evidence' | 'xai' | 'ml'

const TABS: { id: DetailTab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'findings', label: 'Findings' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'xai', label: 'Explanation' },
  { id: 'ml', label: 'Model signals' },
]

/** Compact risk dial: the score plus the band the backend assigned it. */
function RiskGauge({ score, severity }: { score: number; severity: string }) {
  const style = severityStyle(severity)
  // The store's highest observed score bounds the bar; the value shown is
  // always the backend score, never a rescaled impression of it.
  const max = 100
  const pct = Math.max(2, Math.min(100, (score / max) * 100))
  return (
    <div className="flex items-end gap-3">
      <span className={`mono tnum text-[40px] font-semibold leading-none ${style.text}`}>
        {score}
      </span>
      <div className="flex-1 pb-1.5">
        <div className="h-1.5 overflow-hidden rounded-full bg-panel-2">
          <div
            className={`h-full rounded-full ${style.bar}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <p className="mt-1 text-xs text-ink-faint">
          risk score out of {max} · {humanize(severity)}
        </p>
      </div>
    </div>
  )
}

/**
 * What this assessment was and what it was run against.
 *
 * The scenario, slot, sequence and observation window are what an analyst
 * actually compares; the assessment, experiment, dataset-run and configuration
 * ids are store keys with no meaning outside the database, so they are one
 * disclosure away rather than the largest type on the page.
 */
export function AssessmentIdentity({ bundle }: { bundle: AssessmentBundle }) {
  const { expected, identity } = bundle
  return (
    <Panel title="This assessment" subtitle="the run this result came from">
      <dl className="grid grid-cols-2 gap-x-5 gap-y-4 p-4 md:grid-cols-3 xl:grid-cols-4">
        <div className="col-span-2 md:col-span-3 xl:col-span-4">
          <dt className="label text-ink-faint">
            Scenario
          </dt>
          <dd className="mt-0.5 text-base leading-relaxed text-ink">{bundle.scenario}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">
            Slot
          </dt>
          <dd className="mt-0.5 text-sm text-ink">{bundle.slot}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">
            Sequence
          </dt>
          <dd className="tnum mt-0.5 text-sm text-ink">{identity.sequence}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">
            Attempt
          </dt>
          <dd className="tnum mt-0.5 text-sm text-ink">{identity.attempt_number}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">
            Window
          </dt>
          <dd className="tnum mt-0.5 text-sm text-ink-dim">
            {identity.window_index ?? '—'}
          </dd>
        </div>
        <div className="col-span-2">
          <dt className="label text-ink-faint">
            Window span
          </dt>
          <dd className="mt-0.5 text-sm text-ink-dim">
            {formatDateTime(identity.window_start_ns)}
            {identity.window_end_ns !== null && (
              <span className="block text-ink-faint">→ {formatDateTime(identity.window_end_ns)}</span>
            )}
          </dd>
        </div>
      </dl>

      <div className="flex flex-wrap items-center gap-2 border-t border-edge px-4 py-3">
        {expected.mode && <Tag>{expected.mode} mode</Tag>}
        {expected.address_family && <Tag>{expected.address_family}</Tag>}
        {expected.security_posture && (
          <Tag className="border-medium/30 bg-medium/5 text-medium">
            posture {acronymLabel(expected.security_posture)}
          </Tag>
        )}
        <StatusPill
          status={statusLabel(bundle.correlation?.status ?? 'UNKNOWN')}
          tone={
            bundle.correlation?.status === 'MISMATCH'
              ? 'bad'
              : bundle.correlation?.status === 'MATCH'
                ? 'good'
                : 'neutral'
          }
        />
        <span className="ml-auto" />
      </div>
    </Panel>
  )
}

export function RiskSummary({ bundle }: { bundle: AssessmentBundle }) {
  const risk = bundle.risk
  const detail = risk.score_detail

  /* The score breakdown records ids, not titles. The findings the same
     response carries do have titles, so the breakdown is labelled with them
     rather than with keys. */
  const findingTitleById = useMemo(
    () => new Map((risk.findings ?? []).map((finding) => [finding.finding_id, finding.title])),
    [risk.findings],
  )

  const categoryTotals = useMemo(() => {
    const counts = new Map<string, number>()
    for (const finding of risk.findings ?? []) {
      counts.set(finding.category, (counts.get(finding.category) ?? 0) + 1)
    }
    return [...counts.entries()].map(([category, count]) => ({ category, count }))
  }, [risk.findings])

  return (
    <Panel
      title="Risk Summary"
      subtitle={`${risk.risk_policy_version} · engine ${risk.risk_engine_version}`}
      action={
        <Link
          to={`/findings?assessment=${encodeURIComponent(bundle.assessment_id)}`}
          className="text-sm text-ink-faint transition-colors hover:text-sentinel"
        >
          All findings →
        </Link>
      }
    >
      <div className="space-y-4 p-4">
        <RiskGauge score={risk.overall_score} severity={risk.severity} />

        <div className="grid grid-cols-3 gap-4 border-t border-edge pt-4">
          <Metric label="Severity" value={<SeverityBadge severity={risk.severity as Severity} size="sm" />} />
          <Metric label="Findings" value={formatNumber(risk.findings?.length ?? 0)} />
          <Metric
            label="Evidence refs"
            value={formatNumber(risk.evidence_refs?.length ?? 0)}
          />
        </div>

        {categoryTotals.length > 0 && (
          <div className="border-t border-edge pt-3">
            <p className="mb-2 label text-ink-faint">
              Categories
            </p>
            <ul className="flex flex-wrap gap-1.5">
              {categoryTotals.map((entry) => (
                <li key={entry.category}>
                  <Tag>
                    {humanize(entry.category)}{' '}
                    <span className="mono tnum text-ink-dim">{entry.count}</span>
                  </Tag>
                </li>
              ))}
            </ul>
          </div>
        )}

        {detail && detail.contributions?.length > 0 && (
          <div className="border-t border-edge pt-3">
            <p className="mb-2 label text-ink-faint">
              Score contributions
            </p>
            <ul className="space-y-1.5">
              {detail.contributions.map((contribution) => {
                const style = severityStyle(contribution.severity)
                const share = risk.overall_score
                  ? (contribution.added / risk.overall_score) * 100
                  : 0
                return (
                  <li key={contribution.finding_id} className="text-sm">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <Link
                          to={`/findings/${encodeURIComponent(bundle.assessment_id)}/${encodeURIComponent(contribution.finding_id)}`}
                          className="block truncate text-ink transition-colors hover:text-sentinel"
                        >
                          {findingTitleById.get(contribution.finding_id) ?? contribution.finding_id}
                        </Link>
                        <ProvenanceDetails title="Finding record">
                          <IdRow
                            label="Finding id"
                            value={contribution.finding_id}
                            title={contribution.finding_id}
                          />
                          {contribution.rule_id && (
                            <IdRow label="Rule id" value={contribution.rule_id} title={contribution.rule_id} />
                          )}
                        </ProvenanceDetails>
                      </div>
                      <span className={`mono tnum shrink-0 text-sm ${style.text}`}>
                        +{contribution.added}
                      </span>
                    </div>
                    <div className="mt-1 h-1 overflow-hidden rounded-full bg-panel-2">
                      <div
                        className={`h-full rounded-full ${style.bar}`}
                        style={{ width: `${Math.min(100, share)}%` }}
                      />
                    </div>
                  </li>
                )
              })}
            </ul>
          </div>
        )}

        {detail?.explanation && (
          <div className="border-t border-edge pt-3">
            <Prose>{detail.explanation}</Prose>
          </div>
        )}
      </div>
    </Panel>
  )
}

export function ExpectedStatePanel({ bundle }: { bundle: AssessmentBundle }) {
  const expected = bundle.expected
  return (
    <Panel
      title="Expected"
      subtitle="what the configuration says should happen"
      className="border-sentinel/25"
      bodyClassName="border-t border-sentinel/20"
    >
      <div className="flex items-start gap-2.5 border-b border-sentinel/20 bg-sentinel/[0.04] px-4 py-2.5">
        <span
          className="mt-[3px] h-1.5 w-1.5 shrink-0 rounded-full bg-sentinel"
          aria-hidden="true"
        />
        <p className="text-xs leading-relaxed text-ink-dim">
          Planner-supplied intent from the materialized Phase-3 plan. This is{' '}
          <span className="text-sentinel">not</span> captured traffic.
        </p>
      </div>
      <dl className="grid grid-cols-2 gap-x-5 gap-y-3.5 p-4 md:grid-cols-3">
        <div>
          <dt className="label text-ink-faint">Mode</dt>
          <dd className="mono mt-0.5 text-sm text-ink">{expected.mode ?? '—'}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">Address family</dt>
          <dd className="mono mt-0.5 text-sm text-ink">{expected.address_family ?? '—'}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">Security posture</dt>
          <dd className="mono mt-0.5 text-sm text-ink">
            {expected.security_posture ?? '—'}
          </dd>
        </div>
        <div>
          <dt className="label text-ink-faint">IKE version</dt>
          <dd className="mono mt-0.5 text-sm text-ink">
            {expected.ike?.version !== undefined ? `IKEv${expected.ike.version}` : '—'}
          </dd>
        </div>
        <div>
          <dt className="label text-ink-faint">IKE encryption</dt>
          <dd className="mono mt-0.5 text-sm text-ink">{expected.ike?.encryption ?? '—'}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">IKE integrity</dt>
          <dd className="mono mt-0.5 text-sm text-ink">
            {expected.ike?.integrity ?? <span className="text-ink-faint">none</span>}
          </dd>
        </div>
        <div>
          <dt className="label text-ink-faint">IKE DH group</dt>
          <dd className="mono mt-0.5 text-sm text-ink">{expected.ike?.dh_group ?? '—'}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">ESP encryption</dt>
          <dd className="mono mt-0.5 text-sm text-ink">{expected.esp?.encryption ?? '—'}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">ESP integrity</dt>
          <dd className="mono mt-0.5 text-sm text-ink">
            {expected.esp?.integrity ?? <span className="text-ink-faint">none</span>}
          </dd>
        </div>
        <div>
          <dt className="label text-ink-faint">ESP DH / PFS group</dt>
          <dd className="mono mt-0.5 text-sm text-ink">{expected.esp?.dh_group ?? '—'}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">PFS</dt>
          <dd className="mono mt-0.5 text-sm text-ink">
            {expected.esp?.pfs === undefined ? (
              '—'
            ) : expected.esp.pfs ? (
              <span className="text-good">enabled</span>
            ) : (
              <span className="text-medium">disabled</span>
            )}
          </dd>
        </div>
        <div>
          <dt className="label text-ink-faint">Traffic profile</dt>
          <dd className="mono mt-0.5 text-sm text-ink">
            {expected.traffic?.profile ?? '—'}
            {expected.traffic?.duration !== undefined && (
              <span className="text-ink-faint"> · {expected.traffic.duration}s</span>
            )}
          </dd>
        </div>
        <div className="col-span-2 md:col-span-3">
          <dt className="label text-ink-faint">
            Capture filter
          </dt>
          <dd className="mono mt-0.5 break-all text-xs text-ink-dim">
            {expected.capture_filter ?? '—'}
          </dd>
        </div>
      </dl>
    </Panel>
  )
}

export function ArtifactSources({ bundle }: { bundle: AssessmentBundle }) {
  const sources = bundle.sources ?? []
  if (sources.length === 0) return null
  return (
    <Panel
      title="Bundle Artifacts"
      subtitle={`${sources.length} recorded source file${sources.length === 1 ? '' : 's'}`}
      bodyClassName="overflow-x-auto"
    >
      <table className="data-table min-w-[720px]">
        <thead>
          <tr>
            {['Path', 'Type', 'Records', 'Size', 'Digest'].map((heading) => (
              <th key={heading} scope="col">
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sources.map((source, index) => (
            <tr key={`${source.path}-${index}`} className="border-b border-edge-soft last:border-0">
              <td className="px-4 py-2.5">
                <span className="mono block max-w-[320px] truncate text-xs text-ink-dim" title={source.path}>
                  {source.path}
                </span>
                {source.endpoints && (
                  <span className="mono text-xs text-ink-faint">
                    {source.endpoints.a} ↔ {source.endpoints.b}
                  </span>
                )}
              </td>
              <td className="px-4 py-2.5">
                <span className="text-sm text-ink-dim">
                  {source.feature_schema_version ?? 'observation'}
                </span>
              </td>
              <td className="px-4 py-2.5">
                <span className="mono tnum text-sm text-ink-dim">
                  {formatNumber(source.record_count ?? 0)}
                </span>
              </td>
              <td className="px-4 py-2.5">
                <span className="mono text-sm text-ink-dim">
                  {formatBytes(source.byte_size)}
                </span>
              </td>
              <td className="px-4 py-2.5">
                <HashChip hash={source.artifact_sha256} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  )
}

/**
 * The assessment's longitudinal comparison against the validated baseline.
 *
 * This is a separate read-only request from the bundle because the comparison
 * is a distinct resource with its own honest states: an assessment can exist
 * with no comparison at all (`not_configured`), and that is shown rather than
 * hidden. While an experiment is still running no comparison exists yet, so
 * this renders the same `not_configured` the API returns — it never shows a
 * provisional or invented verdict, and Refresh re-reads the comparison once
 * the run has completed and been persisted.
 */
function AssessmentDriftPanel({ assessmentId }: { assessmentId: string }) {
  const resource = useResource(
    (signal) => getAssessmentDrift(assessmentId, signal),
    { enabled: assessmentId !== '', deps: [assessmentId] },
  )

  return (
    <Panel
      title="Configuration drift"
      subtitle="this assessment against the validated baseline"
      action={
        <Button variant="secondary" onClick={resource.reload} disabled={resource.loading}>
          {resource.refreshing ? 'Refreshing\u2026' : 'Refresh'}
        </Button>
      }
    >
      {resource.loading ? (
        <LoadingPanel label="Loading drift comparison" rows={2} />
      ) : resource.error ? (
        <ErrorState error={resource.error} onRetry={resource.reload} compact />
      ) : (
        <div className="p-3.5">
          <AssessmentDriftBlock drift={resource.data} />
        </div>
      )}
    </Panel>
  )
}

export function AssessmentDetailBody({
  bundle,
  tab,
}: {
  bundle: AssessmentBundle
  tab: DetailTab
}) {
  if (tab === 'overview') {
    return (
      <div className="space-y-4">
        <div className="grid gap-4 xl:grid-cols-3">
          <div className="space-y-4 xl:col-span-2">
            <AssessmentIdentity bundle={bundle} />
            <ExpectedStatePanel bundle={bundle} />
            <ObservedPanel bundle={bundle} />
            <ComparisonTable bundle={bundle} />
            <AssessmentDriftPanel assessmentId={bundle.assessment_id} />
          </div>
          <div className="space-y-4">
            <RiskSummary bundle={bundle} />
            <FindingsList
              bundle={bundle}
              limit={5}
              title="Top Findings"
              action={
                <Link
                  to={`/findings?assessment=${encodeURIComponent(bundle.assessment_id)}`}
                  className="text-sm text-ink-faint transition-colors hover:text-sentinel"
                >
                  View all →
                </Link>
              }
            />
          </div>
        </div>
        <ArtifactSources bundle={bundle} />
      </div>
    )
  }

  if (tab === 'findings') {
    return (
      <div className="space-y-4">
        <FindingsList bundle={bundle} title="Findings" />
        <div className="panel p-4">
          <p className="label text-ink-faint">
            Score derivation
          </p>
          <p className="mt-1 text-sm leading-relaxed text-ink-faint">
            The deterministic risk engine is the authority for every finding on this page.
            The explainability layer below only describes them; it cannot add, re-score or
            suppress a finding.
          </p>
        </div>
      </div>
    )
  }

  if (tab === 'evidence') return <EvidencePanel bundle={bundle} />
  if (tab === 'xai') return <XaiPanel bundle={bundle} />
  return <MlPanel bundle={bundle} />
}

export { TABS as DETAIL_TABS }

/** Confidence badge used by the ML panel. */
export function ConfidenceBadge({ value }: { value: number | null | undefined }) {
  if (value === null || value === undefined) {
    return <span className="text-ink-faint">—</span>
  }
  return (
    <span className="mono tnum text-sm text-ink">{formatPercent(value)}</span>
  )
}
