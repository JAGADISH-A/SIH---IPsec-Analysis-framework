import { Fragment, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { getAssessments } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { EmptyState, ErrorState, LoadingPanel } from '@/components/states'
import { Panel, Prose, SeverityBadge, StatusPill, Tag } from '@/components/ui'
import { PageHeader } from '@/layouts/AppLayout'
import { formatNumber, humanize, severityRank } from '@/lib/format'
import type { Severity } from '@/types'

/**
 * Cross-assessment XAI overview.
 *
 * The per-assessment narrative lives in `XaiPanel`; this page gives the fleet
 * view — the engine's own framing of what it can and cannot say, plus the
 * severity mix of every explanation in the store. Findings themselves stay on
 * the Findings page, because the risk engine is their authority.
 */
export function XaiPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const resource = useResource((signal) => getAssessments({ limit: 200 }, signal))
  const [expanded, setExpanded] = useState<string | null>(null)

  const headers = useMemo(() => resource.data?.headers ?? [], [resource.data])
  const overview = resource.data?.overview ?? null
  const posture = searchParams.get('posture') ?? 'ALL'

  const postures = useMemo(
    () => [...new Set(headers.map((header) => header.security_posture))].filter(Boolean).sort(),
    [headers],
  )

  const rows = useMemo(() => {
    const filtered =
      posture === 'ALL' ? headers : headers.filter((header) => header.security_posture === posture)
    return [...filtered].sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) || (b.risk_score ?? 0) - (a.risk_score ?? 0),
    )
  }, [headers, posture])

  const withXai = rows.filter((row) => (row.finding_count ?? 0) > 0)

  return (
    <div className="space-y-4">
      <PageHeader
        title="Explainability"
        description="Why does the engine say what it says? Provenance for every decision, with the engine as the sole authority."
      />

      {/* Authority statement */}
      <div className="panel border-sentinel/25 bg-sentinel/[0.04] p-4">
        <div className="flex items-start gap-2.5">
          <span
            className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-sentinel/40 text-sentinel"
            aria-hidden="true"
          >
            <svg viewBox="0 0 16 16" className="h-3 w-3" fill="none">
              <circle cx="8" cy="8" r="6.2" stroke="currentColor" strokeWidth="1.3" />
              <path d="M8 7.2v4M8 4.9h.01" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </span>
          <div>
            <h2 className="text-sm font-semibold text-sentinel">
              The deterministic security engine is the authority
            </h2>
            <p className="mt-1 text-sm leading-relaxed text-ink-dim">
              Findings, severities and scores are produced by the backend risk engine and are
              exposed read-only. The explainability layer renders those decisions with
              provenance: it derives no new vulnerability, changes no score, and cannot
              override an authoritative result. Model verdicts are labelled as inference, and
              evidence gaps stay UNKNOWN rather than being reported as vulnerabilities.
            </p>
            {overview && (
              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                <StatusPill
                  status="read-only"
                  tone="info"
                  label="findings are read-only on this API"
                />
                <Tag>policy {overview.risk_policy_version}</Tag>
                <Tag>xai {overview.xai_available ? 'available' : 'unavailable'}</Tag>
              </div>
            )}
          </div>
        </div>
      </div>

      {resource.error && <ErrorState error={resource.error} onRetry={resource.reload} />}
      {resource.loading && <LoadingPanel label="Loading assessments" rows={6} />}

      {overview && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          {[
            { label: 'Assessments', value: overview.total_assessments, tone: 'text-ink' },
            { label: 'Explanations available', value: overview.xai_available ? 'yes' : 'no', tone: 'text-good' },
            { label: 'Findings explained', value: overview.findings_total, tone: 'text-sentinel' },
            { label: 'Unknown observations', value: overview.unknown_observations, tone: 'text-ink-dim' },
            {
              label: 'ML disagreements',
              value: overview.ml_classification_disagreements,
              tone: 'text-medium',
            },
          ].map((card) => (
            <div key={card.label} className="panel p-3.5">
              <p className="label text-ink-faint">{card.label}</p>
              <p className={`mono tnum mt-1 text-2xl leading-none ${card.tone}`}>
                {formatNumber(Number(card.value))}
              </p>
            </div>
          ))}
        </div>
      )}

      {overview?.source && (
        <Panel title="Engine Provenance" subtitle="what the store was built from">
          <div className="p-4">
            <Prose>{overview.source}</Prose>
          </div>
        </Panel>
      )}

      <Panel
        title="Explanations by Assessment"
        subtitle="select a row to open that assessment's XAI tab"
        action={
          <select
            value={posture}
            onChange={(event) => {
              const next = new URLSearchParams(searchParams)
              if (event.target.value === 'ALL') next.delete('posture')
              else next.set('posture', event.target.value)
              setSearchParams(next, { replace: true })
            }}
            className="rounded-md border border-edge bg-panel px-2 py-1 text-sm text-ink focus:border-sentinel focus:ring-2 focus:ring-sentinel/15 focus:outline-none"
          >
            <option value="ALL">All postures</option>
            {postures.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        }
        bodyClassName="overflow-x-auto"
      >
        {rows.length === 0 ? (
          <EmptyState title="No assessments" icon="inbox" />
        ) : (
          <table className="data-table min-w-[860px]">
            <thead>
              <tr className="border-b border-edge text-left">
                {['Assessment', 'Severity', 'Risk', 'Findings', 'Explanation', ''].map((heading, index) => (
                  <th
                    key={heading || index}
                    className="px-4 py-2.5 label text-ink-faint"
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const hasFindings = (row.finding_count ?? 0) > 0
                const isOpen = expanded === row.assessment_id
                return (
                  <Fragment key={row.assessment_id}>
                    <tr className="row-hover border-b border-edge-soft last:border-0">
                      <td className="px-4 py-2.5">
                        <span className="mono block text-sm text-ink">{row.slot}</span>
                        <span className="mono block max-w-[260px] truncate text-xs text-ink-faint">
                          {row.assessment_id}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <SeverityBadge severity={row.severity as Severity} size="sm" />
                      </td>
                      <td className="mono tnum text-sm text-ink-dim">
                        {row.risk_score}
                      </td>
                      <td className="mono tnum text-sm text-ink-dim">
                        {row.finding_count}
                      </td>
                      <td className="px-4 py-2.5">
                        {hasFindings ? (
                          <button
                            type="button"
                            onClick={() => setExpanded(isOpen ? null : row.assessment_id)}
                            className="text-sm text-sentinel transition-colors hover:underline"
                          >
                            {isOpen ? 'hide' : 'preview'}
                          </button>
                        ) : (
                          <span className="text-xs text-ink-faint">
                            no finding to explain
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2.5">
                        <Link
                          to={`/assessments/${encodeURIComponent(row.assessment_id)}?tab=xai`}
                          className="text-sm text-ink-faint transition-colors hover:text-sentinel"
                        >
                          Open XAI →
                        </Link>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="border-b border-edge-soft">
                        <td colSpan={6} className="bg-panel-2 px-4 py-3">
                          <p className="text-sm leading-relaxed text-ink-dim">
                            {row.scenario}
                          </p>
                          <Link
                            to={`/findings?assessment=${encodeURIComponent(row.assessment_id)}`}
                            className="mt-2 inline-block text-sm text-sentinel hover:underline"
                          >
                            Read the full chain of custody →
                          </Link>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        )}
      </Panel>

      {overview?.sources && overview.sources.length > 0 && (
        <Panel
          title="Evidence Sources"
          subtitle="artifacts the explainability layer may cite"
          bodyClassName="divide-y divide-edge/60"
        >
          {overview.sources.map((source, index) => (
            <div key={`${source.path}-${index}`} className="flex flex-wrap items-start gap-3 px-4 py-2.5">
              <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-sentinel/70" aria-hidden="true" />
              <div className="min-w-0 flex-1">
                <p className="mono text-xs text-ink-dim">{source.path}</p>
                <p className="text-xs text-ink-faint">{source.role}</p>
                {source.reason && (
                  <p className="mt-0.5 text-xs text-medium/80">{source.reason}</p>
                )}
              </div>
              <div className="flex shrink-0 gap-2">
                {source.artifact_sha256 && (
                  <span className="mono text-xs text-sentinel" title={source.artifact_sha256}>
                    {source.artifact_sha256.slice(0, 10)}…
                  </span>
                )}
                {source.byte_size !== undefined && (
                  <span className="mono text-xs text-ink-faint">
                    {formatNumber(source.byte_size)} B
                  </span>
                )}
              </div>
            </div>
          ))}
        </Panel>
      )}

      <p className="px-1 text-xs leading-relaxed text-ink-faint">
        {withXai.length} of {rows.length} assessments in view carry at least one explained
        finding. The remainder need no explanation because the risk engine raised nothing for
        them{posture !== 'ALL' ? ` under posture ${humanize(posture)}` : ''}.
      </p>
    </div>
  )
}
