import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Search } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { ConfidenceTag, SeverityTag } from '../../components/common/Evidence.tsx'
import { Field } from '../../components/common/Field.tsx'
import { Select } from '../../components/common/Select.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { Toolbar } from '../../components/common/Data.tsx'
import { PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { DonutChart } from '../../components/charts/Charts.tsx'
import { Panel, PanelHeader } from '../../components/common/Panel.tsx'
import { useFindingSummary, useFindings } from '../../hooks/queries'
import { FINDING_CATEGORIES, FINDING_CATEGORY_LABEL, FINDING_STATUS_LABEL } from '../../types/analysis'
import type { FindingQuery, SecurityFinding } from '../../types/analysis'
import { SEVERITIES, SEVERITY_LABEL, type Severity } from '../../types/evidence'

/**
 * Findings register.
 *
 * Findings are produced by the analysis backend; this page only lists, filters
 * and annotates them. Severity is never editable here — triage status is.
 */
export function FindingsPage() {
  const [params, setParams] = useSearchParams()
  const [searchDraft, setSearchDraft] = useState(params.get('search') ?? '')

  const query = useMemo<FindingQuery>(() => {
    const list = (key: string): string[] => {
      const raw = params.get(key)
      return raw ? raw.split(',').filter(Boolean) : []
    }
    return {
      search: params.get('search') ?? undefined,
      severities: list('severity') as Severity[],
      categories: list('category') as FindingQuery['categories'],
      statuses: list('status') as FindingQuery['statuses'],
      sessionId: params.get('session') ?? undefined,
      minConfidence: params.get('minConfidence') ? Number(params.get('minConfidence')) : undefined,
    }
  }, [params])

  const findings = useFindings(query)
  const summary = useFindingSummary(query)

  const setParam = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    if (value === null || value === '') next.delete(key)
    else next.set(key, value)
    setParams(next, { replace: true })
  }

  const rows = findings.data ?? []

  const columns = useMemo<ColumnDef<SecurityFinding>[]>(
    () => [
      {
        id: 'severity',
        header: 'Severity',
        width: '7.5rem',
        render: (row) => <SeverityTag severity={row.severity} />,
      },
      {
        id: 'title',
        header: 'Finding',
        render: (row) => (
          <div className="min-w-0">
            <Link to={`/findings/${row.id}`} className="block truncate font-medium text-mist hover:text-accent-300">
              {row.title}
            </Link>
            <span className="truncate text-[11px] text-mist-faint">{row.summary}</span>
          </div>
        ),
      },
      {
        id: 'category',
        header: 'Category',
        width: '10rem',
        render: (row) => <span className="text-xs text-mist-dim">{FINDING_CATEGORY_LABEL[row.category]}</span>,
      },
      {
        id: 'risk',
        header: 'Risk',
        width: '5rem',
        align: 'right',
        render: (row) => <span className="font-mono text-xs text-mist-dim">{row.riskScore}</span>,
      },
      {
        id: 'sessions',
        header: 'Sessions',
        width: '6rem',
        align: 'right',
        render: (row) => (
          <span className="font-mono text-xs text-mist-dim" title={row.sessionIds.join(', ')}>
            {row.sessionCount}
          </span>
        ),
      },
      {
        id: 'confidence',
        header: 'Confidence',
        width: '7rem',
        render: (row) => <ConfidenceTag confidence={row.confidence} />,
      },
      {
        id: 'status',
        header: 'Status',
        width: '8rem',
        render: (row) => (
          <Badge tone={row.status === 'open' ? 'warning' : row.status === 'resolved' ? 'success' : 'muted'}>
            {FINDING_STATUS_LABEL[row.status]}
          </Badge>
        ),
      },
      {
        id: 'detected',
        header: 'Detected',
        width: '10rem',
        align: 'right',
        render: (row) => (
          <span className="font-mono text-[11px] text-mist-faint">{new Date(row.detectedAt).toLocaleString()}</span>
        ),
      },
    ],
    [],
  )

  const activeFilters = (
    params.get('severity') ? 1 : 0
  ) + (params.get('category') ? 1 : 0) + (params.get('status') ? 1 : 0) + (params.get('search') ? 1 : 0) + (params.get('session') ? 1 : 0)

  return (
    <PageScroll>
      <PageHeader
        title="Findings"
        description="Every conclusion the platform draws, with the evidence and reasoning behind it."
        meta={
          <>
            <span className="font-mono">{summary.data?.total ?? rows.length} finding(s)</span>
            <span className="font-mono">{summary.data?.open ?? 0} open</span>
            {summary.data?.averageConfidence != null ? (
              <span>Average confidence {Math.round(summary.data.averageConfidence * 100)}%</span>
            ) : (
              <span>Average confidence unknown</span>
            )}
            {query.sessionId ? <span className="font-mono">Filtered to session {query.sessionId}</span> : null}
          </>
        }
        actions={
          activeFilters > 0 ? (
            <button type="button" className="btn" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
              Clear {activeFilters} filter{activeFilters === 1 ? '' : 's'}
            </button>
          ) : null
        }
      />

      <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,18rem)] lg:p-6">
        <div className="flex min-w-0 flex-col gap-4">
          <Panel flush>
            <Toolbar>
              <form
                className="flex items-end gap-2"
                onSubmit={(event) => {
                  event.preventDefault()
                  setParam('search', searchDraft.trim() || null)
                }}
              >
                <Field
                  label="Search"
                  placeholder="Title, behaviour, category…"
                  value={searchDraft}
                  onChange={(event) => setSearchDraft(event.target.value)}
                  leading={<Search className="size-3.5" aria-hidden />}
                  className="w-56"
                />
                <button type="submit" className="btn h-[34px]">
                  Search
                </button>
              </form>

              <Select
                label="Severity"
                value={params.get('severity') ?? ''}
                onChange={(event) => setParam('severity', event.target.value || null)}
                className="w-40"
              >
                <option value="">All severities</option>
                {SEVERITIES.map((severity) => (
                  <option key={severity} value={severity}>
                    {SEVERITY_LABEL[severity]}
                  </option>
                ))}
              </Select>

              <Select
                label="Category"
                value={params.get('category') ?? ''}
                onChange={(event) => setParam('category', event.target.value || null)}
                className="w-48"
              >
                <option value="">All categories</option>
                {FINDING_CATEGORIES.map((category) => (
                  <option key={category} value={category}>
                    {FINDING_CATEGORY_LABEL[category]}
                  </option>
                ))}
              </Select>

              <Select
                label="Status"
                value={params.get('status') ?? ''}
                onChange={(event) => setParam('status', event.target.value || null)}
                className="w-36"
              >
                <option value="">All statuses</option>
                {Object.entries(FINDING_STATUS_LABEL).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>

              <Select
                label="Min confidence"
                value={params.get('minConfidence') ?? ''}
                onChange={(event) => setParam('minConfidence', event.target.value || null)}
                className="w-32"
              >
                <option value="">Any</option>
                <option value="0.9">90%+</option>
                <option value="0.75">75%+</option>
                <option value="0.5">50%+</option>
              </Select>
            </Toolbar>

            <QueryBoundary
              isLoading={findings.isLoading}
              isError={findings.isError}
              error={findings.error}
              onRetry={() => void findings.refetch()}
              isEmpty={rows.length === 0}
              emptyTitle="No findings match these filters"
              emptyDescription="Try a broader severity or category, or clear the search box."
            >
              <DataTable columns={columns} rows={rows} rowKey={(row) => row.id} />
            </QueryBoundary>
          </Panel>
        </div>

        <div className="flex flex-col gap-4">
          <Panel flush>
            <PanelHeader title="Severity mix" subtitle="Current filtered set" />
            <div className="p-4">
              <DonutChart
                label="Findings by severity"
                centerLabel="Findings"
                data={SEVERITIES.map((severity) => ({
                  label: SEVERITY_LABEL[severity],
                  value: summary.data?.bySeverity[severity] ?? 0,
                  tone:
                    severity === 'critical'
                      ? ('critical' as const)
                      : severity === 'high'
                        ? ('danger' as const)
                        : severity === 'medium'
                          ? ('warning' as const)
                          : severity === 'low'
                            ? ('info' as const)
                            : ('success' as const),
                }))}
              />
            </div>
          </Panel>

          <Panel flush>
            <PanelHeader title="Triage" subtitle="Operator annotations" />
            <dl className="grid grid-cols-2 gap-2 p-4 text-[11px]">
              {[
                ['Open', summary.data?.open ?? 0],
                ['Acknowledged', summary.data?.acknowledged ?? 0],
                ['Resolved', summary.data?.resolved ?? 0],
                ['False positive', summary.data?.falsePositive ?? 0],
                ['Suppressed', summary.data?.suppressed ?? 0],
                ['Last evaluated', summary.data ? new Date(summary.data.lastEvaluated).toLocaleTimeString() : '—'],
              ].map(([label, value]) => (
                <div key={String(label)} className="rounded-md border border-edge bg-night-900 px-2.5 py-1.5">
                  <dt className="text-mist-faint">{label}</dt>
                  <dd className="font-mono text-sm text-mist">{value}</dd>
                </div>
              ))}
            </dl>
            <p className="border-t border-edge px-3 py-2 text-[10px] leading-relaxed text-mist-faint">
              Triage status is an operator annotation. It never changes the severity, the evidence or the rationale
              recorded by the analysis engine.
            </p>
          </Panel>
        </div>
      </div>
    </PageScroll>
  )
}
