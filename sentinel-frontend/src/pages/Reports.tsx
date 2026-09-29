import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { getAssessments } from '@/api/analytics'
import { generateReport } from '@/api/reports'
import { useResource } from '@/hooks/useResource'
import { LoadingPanel, ErrorState } from '@/components/states'
import { MetricStrip, ReportSection, SeverityPieChart, type SeverityCount } from '@/components/kit'
import { Button, Tag } from '@/components/ui'
import { Spinner } from '@/components/states'
import { PageHeader } from '@/layouts/AppLayout'
import { formatNumber } from '@/lib/format'
import { SEVERITY_ORDER } from '@/types'
import type { ReportKind, ReportResult, Severity } from '@/types'

/**
 * Reports — one read-only summary of the whole assessment store.
 *
 * The analytics plane exposes no report endpoint, so this page composes
 * nothing: the figures below are the store's own overview fields, and the
 * generate control states honestly that no document can be produced. The
 * severity distribution is drawn from the backend's counts only — no score is
 * recomputed in the browser.
 */

const REPORT_KINDS: { kind: ReportKind; label: string; description: string }[] = [
  { kind: 'assessment', label: 'Run summary', description: 'Totals, severity mix and dataset identity.' },
  { kind: 'incident', label: 'Incident summary', description: 'Findings grouped across the store.' },
  { kind: 'evidence-log', label: 'Evidence log', description: 'Every artifact with its digest and status.' },
]

function countOf(counts: Record<string, number>, severity: Severity): number {
  const entry = Object.entries(counts).find(([key]) => key.toUpperCase() === severity)
  return entry ? Number(entry[1]) || 0 : 0
}

export function Reports() {
  const resource = useResource((signal) => getAssessments({ limit: 500 }, signal))
  const overview = resource.data?.overview ?? null

  const severityCounts: SeverityCount[] = useMemo(
    () =>
      SEVERITY_ORDER.map((severity) => ({
        severity,
        count: overview ? countOf(overview.severity_counts, severity) : 0,
      })),
    [overview],
  )

  const categories = useMemo(
    () =>
      Object.entries(overview?.category_counts ?? {})
        .map(([name, count]) => ({ name, count: Number(count) || 0 }))
        .sort((a, b) => b.count - a.count),
    [overview],
  )

  const [busy, setBusy] = useState<ReportKind | null>(null)
  const [result, setResult] = useState<ReportResult | null>(null)
  const generate = async (kind: ReportKind) => {
    setBusy(kind)
    try {
      setResult(await generateReport({ kind, entityId: overview?.dataset_run_id ?? 'store' }))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title="Reports"
        description="A read-only summary of the assessment store. Every figure is the backend's own count; deep detail opens the assessment it came from."
        actions={
          <Button variant="secondary" onClick={resource.reload} disabled={resource.loading}>
            {resource.refreshing ? 'Refreshing…' : 'Refresh'}
          </Button>
        }
      />

      {resource.error ? (
        <ErrorState error={resource.error} onRetry={resource.reload} />
      ) : resource.loading ? (
        <LoadingPanel label="Loading report" rows={4} />
      ) : (
        <>
          <MetricStrip
            ariaLabel="Store summary"
            items={[
              { label: 'Assessments', value: formatNumber(overview?.total_assessments ?? 0) },
              { label: 'Findings', value: formatNumber(overview?.findings_total ?? 0) },
              {
                label: 'Highest severity',
                value: overview?.highest_severity ? String(overview.highest_severity) : '—',
                tone: 'neutral',
              },
              { label: 'ML anomalies', value: formatNumber(overview?.ml_anomalies ?? 0) },
              {
                label: 'Unknown observations',
                value: formatNumber(overview?.unknown_observations ?? 0),
              },
            ]}
          />

          <ReportSection
            title="Severity distribution"
            description="The store's own severity counts, not a recomputed score."
          >
            <SeverityPieChart counts={severityCounts} title="Assessments by severity" />
          </ReportSection>

          <ReportSection
            title="Findings by category"
            description="How the raised findings group across the store."
            action={
              <Link className="text-sm text-sentinel transition-colors hover:text-ink" to="/findings">
                Open findings →
              </Link>
            }
          >
            {categories.length === 0 ? (
              <p className="text-sm text-ink-faint">No findings are recorded in this store.</p>
            ) : (
              <ul className="divide-y divide-edge-soft">
                {categories.map((entry) => (
                  <li key={entry.name} className="flex items-center justify-between gap-4 py-2">
                    <span className="text-sm text-ink-dim">{entry.name}</span>
                    <span className="tnum text-sm font-semibold text-ink">{formatNumber(entry.count)}</span>
                  </li>
                ))}
              </ul>
            )}
          </ReportSection>

          <ReportSection
            title="Dataset"
            description="The run this report summarises."
          >
            <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-2">
              {[
                ['Dataset run', overview?.dataset_run_id ?? '—'],
                ['Risk policy', overview?.risk_policy_version ?? '—'],
                ['Store version', overview?.store_version ?? '—'],
                ['Explainability', overview?.xai_available ? 'available' : 'not available'],
              ].map(([label, value]) => (
                <div key={label} className="flex items-center justify-between gap-4 border-b border-edge-soft py-1.5">
                  <dt className="text-sm text-ink-faint">{label}</dt>
                  <dd className="mono text-sm text-ink">{value}</dd>
                </div>
              ))}
            </dl>
            {(overview?.sources ?? []).length > 0 && (
              <div className="mt-3">
                <p className="label mb-1.5">Sources</p>
                <ul className="space-y-1">
                  {overview!.sources!.map((source) => (
                    <li key={source.path} className="flex flex-wrap items-center justify-between gap-2 text-sm">
                      <span className="mono truncate text-ink-dim" title={source.path}>
                        {source.path}
                      </span>
                      <span className="flex items-center gap-2 text-ink-faint">
                        <Tag>{source.role}</Tag>
                        {source.record_count !== undefined && (
                          <span className="tnum">{formatNumber(source.record_count)} records</span>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </ReportSection>

          <ReportSection
            title="Generate report"
            description="The analytics plane is read-only and exposes no report endpoint."
          >
            <div className="grid gap-3 sm:grid-cols-3">
              {REPORT_KINDS.map((entry) => (
                <div key={entry.kind} className="panel flex flex-col gap-2 p-3">
                  <p className="text-sm font-medium text-ink">{entry.label}</p>
                  <p className="text-xs leading-relaxed text-ink-faint">{entry.description}</p>
                  <Button
                    variant="secondary"
                    onClick={() => generate(entry.kind)}
                    disabled={busy !== null}
                    className="self-start"
                  >
                    {busy === entry.kind && <Spinner />}
                    Generate
                  </Button>
                </div>
              ))}
            </div>
            {result && (
              <div className="mt-3 rounded-md border border-edge bg-panel-2 p-3">
                <p className="text-sm font-medium text-ink-dim">No {result.kind} report was produced</p>
                <p className="mt-1 text-sm leading-relaxed text-ink-faint">{result.reason}</p>
              </div>
            )}
          </ReportSection>
        </>
      )}
    </div>
  )
}
