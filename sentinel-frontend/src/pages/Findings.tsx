import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { getFindings } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { EmptyState, ErrorState, LoadingPanel } from '@/components/states'
import { Button, Panel, SeverityBadge, Tag } from '@/components/ui'
import { IdRow, ProvenanceDetails } from '@/components/kit'
import { PageHeader } from '@/layouts/AppLayout'
import {
  compareValues,
  formatValue,
  humanize,
  severityRank,
  severityStyle,
  truncate,
} from '@/lib/format'
import { acronymLabel, assessmentLabel, configTermLabel } from '@/lib/labels'
import type { Finding, Severity } from '@/types'

type SortKey = 'severity' | 'category' | 'finding_id' | 'assessment_id' | 'title'

const PAGE_SIZE = 20

export function Findings() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const resource = useResource((signal) => getFindings({ limit: 1000 }, signal))

  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState(searchParams.get('severity') ?? 'ALL')
  const [category, setCategory] = useState(searchParams.get('category') ?? 'ALL')
  const [assessment, setAssessment] = useState(searchParams.get('assessment') ?? 'ALL')
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [page, setPage] = useState(0)

  const findings = useMemo(() => resource.data?.findings ?? [], [resource.data])

  const severityOptions = useMemo(() => {
    const counts = new Map<string, number>()
    for (const finding of findings) {
      const key = finding.severity.toUpperCase()
      counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    return [...counts.entries()]
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => severityRank(a.name) - severityRank(b.name))
  }, [findings])

  const categoryOptions = useMemo(
    () => [...new Set(findings.map((finding) => finding.category))].sort(),
    [findings],
  )

  /* Every finding carries the scenario of the assessment it belongs to, so the
     store's assessment ids can be shown as the scenario the analyst recognises
     without a second request. The id stays the option value. */
  const assessmentLabelById = useMemo(() => {
    const map = new Map<string, string>()
    for (const finding of findings) {
      if (finding.assessment_id && !map.has(finding.assessment_id)) {
        map.set(
          finding.assessment_id,
          assessmentLabel({ assessment_id: finding.assessment_id, scenario: finding.scenario }),
        )
      }
    }
    return map
  }, [findings])

  const assessmentOptions = useMemo(
    () =>
      [...assessmentLabelById.entries()]
        .sort((a, b) => a[1].localeCompare(b[1]))
        .map(([id, label]) => ({ id, label })),
    [assessmentLabelById],
  )

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const rows = findings.filter((finding: Finding) => {
      if (severity !== 'ALL' && finding.severity?.toUpperCase() !== severity) return false
      if (category !== 'ALL' && finding.category !== category) return false
      if (assessment !== 'ALL' && finding.assessment_id !== assessment) return false
      if (needle === '') return true
      return (
        finding.finding_id?.toLowerCase().includes(needle) ||
        finding.title?.toLowerCase().includes(needle) ||
        finding.description?.toLowerCase().includes(needle) ||
        finding.rule_id?.toLowerCase().includes(needle) ||
        finding.related_variable?.toLowerCase().includes(needle) ||
        finding.assessment_id?.toLowerCase().includes(needle)
      )
    })

    return [...rows].sort((a, b) => {
      let result: number
      if (sortKey === 'severity') {
        result = severityRank(a.severity) - severityRank(b.severity)
        if (result === 0) result = a.finding_id.localeCompare(b.finding_id)
      } else {
        result = compareValues(a[sortKey], b[sortKey])
      }
      return sortDir === 'asc' ? result : -result
    })
  }, [findings, query, severity, category, assessment, sortKey, sortDir])

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const safePage = Math.min(page, pageCount - 1)
  const pageRows = filtered.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE)

  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(searchParams)
    if (value && value !== 'ALL') next.set(key, value)
    else next.delete(key)
    setSearchParams(next, { replace: true })
    setPage(0)
  }

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setSortDir((dir) => (dir === 'asc' ? 'desc' : 'asc'))
    else {
      setSortKey(key)
      setSortDir(key === 'severity' ? 'asc' : 'desc')
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title="Findings"
        description={
          resource.loading
            ? 'Loading findings…'
            : `${filtered.length} of ${findings.length} findings across ${assessmentOptions.length} assessments`
        }
        actions={
          <Button variant="secondary" onClick={resource.reload} disabled={resource.loading}>
            {resource.refreshing ? 'Refreshing…' : 'Refresh'}
          </Button>
        }
      />
      <p className="-mt-3 text-sm text-ink-faint">
        Read-only. The risk engine is the sole authority on what is a finding.
      </p>

      <div className="panel flex flex-wrap items-end gap-3 p-3">
        <label className="flex min-w-[220px] flex-1 flex-col gap-1">
          <span className="label text-ink-faint">
            Search
          </span>
          <span className="relative">
            <svg
              viewBox="0 0 16 16"
              className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-faint"
              fill="none"
              aria-hidden="true"
            >
              <circle cx="7" cy="7" r="4.2" stroke="currentColor" strokeWidth="1.4" />
              <path d="m10.2 10.2 3.3 3.3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            </svg>
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value)
                setPage(0)
              }}
              placeholder="finding id, rule, title, variable…"
              className="w-full rounded-md border border-edge bg-panel py-1.5 pl-8 pr-3 text-sm text-ink placeholder:text-ink-faint/70 focus:border-sentinel focus:ring-2 focus:ring-sentinel/15 focus:outline-none"
            />
          </span>
        </label>

        <label className="flex flex-col gap-1">
          <span className="label text-ink-faint">
            Severity
          </span>
          <select
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value)
              setFilter('severity', event.target.value)
            }}
            className="w-full rounded-md border border-edge bg-panel px-2.5 py-1.5 text-base text-ink transition-colors hover:border-ink-faint focus:border-sentinel focus:outline-none focus:ring-2 focus:ring-sentinel/15"
          >
            <option value="ALL">All</option>
            {severityOptions.map((option) => (
              <option key={option.name} value={option.name}>
                {option.name} ({option.count})
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="label text-ink-faint">
            Category
          </span>
          <select
            value={category}
            onChange={(event) => {
              setCategory(event.target.value)
              setFilter('category', event.target.value)
            }}
            className="w-full rounded-md border border-edge bg-panel px-2.5 py-1.5 text-base text-ink transition-colors hover:border-ink-faint focus:border-sentinel focus:outline-none focus:ring-2 focus:ring-sentinel/15"
          >
            <option value="ALL">All categories</option>
            {categoryOptions.map((option) => (
              <option key={option} value={option}>
                {humanize(option)}
              </option>
            ))}
          </select>
        </label>

        <label className="flex min-w-[220px] flex-col gap-1">
          <span className="label text-ink-faint">
            Assessment
          </span>
          <select
            value={assessment}
            onChange={(event) => {
              setAssessment(event.target.value)
              setFilter('assessment', event.target.value)
            }}
            className="w-full rounded-md border border-edge bg-panel px-2.5 py-1.5 text-base text-ink transition-colors hover:border-ink-faint focus:border-sentinel focus:outline-none focus:ring-2 focus:ring-sentinel/15"
          >
            <option value="ALL">All assessments</option>
            {assessmentOptions.map((option) => (
              <option key={option.id} value={option.id}>
                {option.label}
              </option>
            ))}
          </select>
        </label>

        {(query || severity !== 'ALL' || category !== 'ALL' || assessment !== 'ALL') && (
          <button
            type="button"
            onClick={() => {
              setQuery('')
              setSeverity('ALL')
              setCategory('ALL')
              setAssessment('ALL')
              setSearchParams(new URLSearchParams(), { replace: true })
              setPage(0)
            }}
            className="rounded-md px-2.5 py-1.5 text-sm text-ink-faint transition-colors hover:bg-panel-2 hover:text-ink"
          >
            Clear
          </button>
        )}
      </div>

      <Panel
        title="Findings"
        subtitle="Select a finding to open its evidence and explanation"
        bodyClassName="overflow-x-auto"
      >
        {resource.error ? (
          <div className="p-4">
            <ErrorState error={resource.error} onRetry={resource.reload} />
          </div>
        ) : resource.loading ? (
          <div className="p-4">
            <LoadingPanel label="Loading findings" rows={6} />
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            title={
              findings.length === 0 ? 'No findings in the store' : 'No findings match'
            }
            description={
              findings.length === 0
                ? 'The analytics API is reachable and the risk engine raised no finding across every assessment.'
                : 'Try clearing the filters or widening the search.'
            }
            icon={findings.length === 0 ? 'check' : 'filter'}
          />
        ) : (
          <table className="data-table min-w-[1020px]">
            <thead>
              <tr>
                {(
                  [
                    ['severity', 'Severity'],
                    ['title', 'Finding'],
                    ['category', 'Category'],
                    ['assessment_id', 'Assessment'],
                    ['finding_id', 'Record ids'],
                  ] as [SortKey, string][]
                ).map(([key, label]) => (
                  <th key={key} scope="col">
                    <button
                      type="button"
                      onClick={() => toggleSort(key)}
                      className="flex items-center gap-1 label text-ink-faint transition-colors hover:text-ink"
                    >
                      {label}
                      {sortKey === key && (
                        <span className="text-sentinel" aria-hidden="true">
                          {sortDir === 'asc' ? '▲' : '▼'}
                        </span>
                      )}
                    </button>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pageRows.map((finding) => {
                const style = severityStyle(finding.severity)
                const mismatch =
                  finding.expected_value !== undefined &&
                  finding.observed_value !== undefined &&
                  formatValue(finding.expected_value) !==
                    formatValue(finding.observed_value)
                return (
                  <tr
                    key={`${finding.assessment_id}-${finding.finding_id}-${finding.sequence}`}
                    onClick={() =>
                      navigate(
                        `/findings/${encodeURIComponent(finding.assessment_id)}/${encodeURIComponent(finding.finding_id)}`,
                      )
                    }
                    tabIndex={0}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') {
                        navigate(
                          `/findings/${encodeURIComponent(finding.assessment_id)}/${encodeURIComponent(finding.finding_id)}`,
                        )
                      }
                    }}
                    className="cursor-pointer"
                  >
                    <td>
                      <SeverityBadge severity={finding.severity as Severity} size="sm" />
                    </td>
                    <td>
                      <span className="block text-base font-medium leading-snug text-ink">
                        {finding.title}
                      </span>
                      <span className="mt-0.5 block text-sm leading-snug text-ink-faint">
                        {truncate(finding.description, 110)}
                      </span>
                      {mismatch && (
                        <span className="mt-1 block text-xs">
                          <span className="text-ink-faint">
                            {configTermLabel(finding.related_variable)}:{' '}
                          </span>
                          <span className="text-sentinel">
                            {truncate(formatValue(finding.expected_value), 24)}
                          </span>
                          <span className="text-ink-faint"> → </span>
                          <span className={style.text}>
                            {truncate(formatValue(finding.observed_value), 24)}
                          </span>
                        </span>
                      )}
                    </td>
                    <td>
                      <Tag>{acronymLabel(finding.category)}</Tag>
                    </td>
                    <td>
                      <span className="block text-sm text-ink-dim">
                        {assessmentLabelById.get(finding.assessment_id) ?? finding.assessment_id}
                      </span>
                      {/* Evidence availability is reported, never assumed: the
                          store states how many references exist, and a finding
                          with none says so rather than looking unbacked. */}
                      <span className="block text-xs text-ink-faint">
                        {finding.evidence_refs && finding.evidence_refs.length > 0
                          ? `${finding.evidence_refs.length} evidence ref${finding.evidence_refs.length === 1 ? '' : 's'}`
                          : 'no evidence attached'}
                      </span>
                    </td>
                    <td>
                      <ProvenanceDetails title="Record ids">
                        <IdRow label="Finding id" value={finding.finding_id} title={finding.finding_id} />
                        {finding.rule_id && (
                          <IdRow label="Rule id" value={finding.rule_id} title={finding.rule_id} />
                        )}
                        <IdRow label="Assessment id" value={finding.assessment_id} title={finding.assessment_id} />
                        {finding.dataset_run_id && (
                          <IdRow label="Dataset run id" value={finding.dataset_run_id} title={finding.dataset_run_id} />
                        )}
                      </ProvenanceDetails>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Panel>

      {filtered.length > PAGE_SIZE && (
        <div className="flex items-center justify-between gap-3 text-sm text-ink-faint">
          <span>
            Page {safePage + 1} of {pageCount} · showing {pageRows.length} rows
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={safePage === 0}
              onClick={() => setPage((value) => Math.max(0, value - 1))}
              className="rounded-md border border-edge bg-panel px-3 py-1.5 text-sm text-ink-dim transition-colors hover:bg-panel-2 hover:text-ink disabled:pointer-events-none disabled:opacity-40"
            >
              Previous
            </button>
            <button
              type="button"
              disabled={safePage >= pageCount - 1}
              onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}
              className="rounded-md border border-edge bg-panel px-3 py-1.5 text-sm text-ink-dim transition-colors hover:bg-panel-2 hover:text-ink disabled:pointer-events-none disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {resource.data?.note && (
        <p className="px-1 text-sm text-ink-faint">{resource.data.note}</p>
      )}
    </div>
  )
}
