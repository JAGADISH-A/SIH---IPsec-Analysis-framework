import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { getAssessments } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { EmptyState, ErrorState, LoadingPanel } from '@/components/states'
import { Button, Panel, SeverityBadge, Tag } from '@/components/ui'
import { MetricStrip, severityCounts } from '@/components/kit'
import { PageHeader } from '@/layouts/AppLayout'
import {
  compareValues,
  formatDateTime,
  formatNumber,
  severityRank,
  severityStyle,
} from '@/lib/format'
import type { AssessmentHeader, Severity } from '@/types'

type SortKey =
  | 'sequence'
  | 'slot'
  | 'mode'
  | 'address_family'
  | 'configuration_id'
  | 'risk_score'
  | 'finding_count'
  | 'severity'

const COLUMNS: { key: SortKey; label: string; className?: string }[] = [
  { key: 'sequence', label: 'Assessment', className: 'min-w-[220px]' },
  { key: 'mode', label: 'Assessed' },
  { key: 'configuration_id', label: 'Configuration', className: 'min-w-[260px]' },
  { key: 'risk_score', label: 'Score' },
  { key: 'finding_count', label: 'Findings' },
  { key: 'severity', label: 'Severity' },
]

const PAGE_SIZE = 15

export function Assessments() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  const resource = useResource((signal) => getAssessments({ limit: 500 }, signal))
  const headers = useMemo(() => resource.data?.headers ?? [], [resource.data])

  const [query, setQuery] = useState(searchParams.get('q') ?? '')
  const [severity, setSeverity] = useState(searchParams.get('severity') ?? 'ALL')
  const [mode, setMode] = useState(searchParams.get('mode') ?? 'ALL')
  const [sortKey, setSortKey] = useState<SortKey>('risk_score')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [page, setPage] = useState(0)

  const severityOptions = useMemo(() => {
    const counts = resource.data?.overview.severity_counts ?? {}
    return Object.entries(counts)
      .map(([name, count]) => ({ name: name.toUpperCase(), count }))
      .sort((a, b) => severityRank(a.name) - severityRank(b.name))
  }, [resource.data])

  const modeOptions = useMemo(
    () => [...new Set(headers.map((header) => header.mode).filter(Boolean))].sort(),
    [headers],
  )

  const severityMix = useMemo(
    () => severityCounts(headers, (header) => header.severity),
    [headers],
  )

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const rows = headers.filter((header: AssessmentHeader) => {
      if (severity !== 'ALL' && header.severity?.toUpperCase() !== severity) return false
      if (mode !== 'ALL' && header.mode !== mode) return false
      if (needle === '') return true
      return (
        header.assessment_id?.toLowerCase().includes(needle) ||
        header.slot?.toLowerCase().includes(needle) ||
        header.configuration_id?.toLowerCase().includes(needle) ||
        header.scenario?.toLowerCase().includes(needle) ||
        header.traffic_profile?.toLowerCase().includes(needle) ||
        header.security_posture?.toLowerCase().includes(needle) ||
        header.dataset_run_id?.toLowerCase().includes(needle) ||
        String(header.sequence ?? '').includes(needle)
      )
    })

    const severityAware = (key: SortKey) => (a: AssessmentHeader, b: AssessmentHeader) => {
      if (key === 'severity') {
        const rank = severityRank(a.severity) - severityRank(b.severity)
        if (rank !== 0) return rank
      }
      return compareValues(a[key], b[key])
    }

    return [...rows].sort((a, b) => {
      const result = severityAware(sortKey)(a, b)
      return sortDir === 'asc' ? result : -result
    })
  }, [headers, query, severity, mode, sortKey, sortDir])

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const safePage = Math.min(page, pageCount - 1)
  const pageRows = filtered.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE)

  const updateFilter = (key: string, value: string) => {
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
      setSortDir(key === 'risk_score' || key === 'finding_count' ? 'desc' : 'asc')
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title="Assessments"
        description={
          resource.loading
            ? 'Loading assessments…'
            : resource.data?.overview.dataset_run_id
              ? `${filtered.length} of ${headers.length} assessments in run ${resource.data.overview.dataset_run_id}`
              : `${filtered.length} of ${headers.length} assessments`
        }
        actions={
          <Button variant="secondary" onClick={resource.reload} disabled={resource.loading}>
            {resource.refreshing ? 'Refreshing…' : 'Refresh'}
          </Button>
        }
      />

      <MetricStrip
        ariaLabel="Assessment store"
        items={[
          { label: 'Assessments', value: formatNumber(headers.length) },
          ...severityMix.map((entry) => ({
            label: entry.severity,
            value: formatNumber(entry.count),
            tone: entry.severity,
          })),
        ]}
      />

      {/* Filter bar */}
      <div className="panel flex flex-wrap items-end gap-3 p-3">
        <label className="flex min-w-[240px] flex-1 flex-col gap-1">
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
              placeholder="id, slot, configuration, scenario…"
              className="w-full rounded-md border border-edge bg-panel py-1.5 pl-8 pr-3 text-base text-ink placeholder:text-ink-faint/70 transition-colors hover:border-ink-faint focus:border-sentinel focus:outline-none focus:ring-2 focus:ring-sentinel/15"
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
              updateFilter('severity', event.target.value)
            }}
            className="rounded-md border border-edge bg-panel px-2.5 py-1.5 text-base text-ink transition-colors hover:border-ink-faint focus:border-sentinel focus:outline-none focus:ring-2 focus:ring-sentinel/15"
          >
            <option value="ALL">All severities</option>
            {severityOptions.map((option) => (
              <option key={option.name} value={option.name}>
                {option.name} ({option.count})
              </option>
            ))}
          </select>
        </label>

        <label className="flex flex-col gap-1">
          <span className="label text-ink-faint">
            IPsec mode
          </span>
          <select
            value={mode}
            onChange={(event) => {
              setMode(event.target.value)
              updateFilter('mode', event.target.value)
            }}
            className="rounded-md border border-edge bg-panel px-2.5 py-1.5 text-base text-ink transition-colors hover:border-ink-faint focus:border-sentinel focus:outline-none focus:ring-2 focus:ring-sentinel/15"
          >
            <option value="ALL">All modes</option>
            {modeOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        {(query || severity !== 'ALL' || mode !== 'ALL') && (
          <button
            type="button"
            onClick={() => {
              setQuery('')
              setSeverity('ALL')
              setMode('ALL')
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
        title="Assessment index"
        subtitle="Select a row to open the full assessment"
        bodyClassName="overflow-x-auto"
      >
        {resource.error ? (
          <div className="p-4">
            <ErrorState error={resource.error} onRetry={resource.reload} />
          </div>
        ) : resource.loading ? (
          <div className="p-4">
            <LoadingPanel label="Loading assessments" rows={6} />
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            title={headers.length === 0 ? 'No assessments in the store' : 'No assessments match'}
            description={
              headers.length === 0
                ? 'The analytics API is reachable but the assessment store is empty. Run an experiment to populate it.'
                : 'Try clearing the search box or choosing a different severity / mode.'
            }
            icon={headers.length === 0 ? 'inbox' : 'filter'}
          />
        ) : (
          <table className="data-table min-w-[960px]">
            <thead>
              <tr>
                {COLUMNS.map((column) => (
                  <th key={column.key} scope="col" className={column.className ?? ''}>
                    <button
                      type="button"
                      onClick={() => toggleSort(column.key)}
                      className="flex items-center gap-1 label text-ink-faint transition-colors hover:text-ink"
                    >
                      {column.label}
                      {sortKey === column.key && (
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
              {pageRows.map((header) => {
                const style = severityStyle(header.severity)
                return (
                  <tr
                    key={header.assessment_id}
                    onClick={() =>
                      navigate(`/assessments/${encodeURIComponent(header.assessment_id)}`)
                    }
                    tabIndex={0}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') {
                        navigate(`/assessments/${encodeURIComponent(header.assessment_id)}`)
                      }
                    }}
                    className="cursor-pointer"
                  >
                    <td>
                      <span className="block truncate text-base text-ink">{header.slot}</span>
                      <span
                        className="mono block max-w-[260px] truncate text-xs text-ink-faint"
                        title={header.assessment_id}
                      >
                        {header.assessment_id}
                      </span>
                    </td>
                    <td className="whitespace-nowrap">
                      <span className="block text-sm text-ink-dim">
                        {formatDateTime(header.window_end_ns ?? header.window_start_ns)}
                      </span>
                      <span className="mt-1 flex items-center gap-1">
                        <Tag>{header.mode}</Tag>
                        <Tag>{header.address_family}</Tag>
                      </span>
                    </td>
                    <td>
                      <span
                        className="mono block max-w-[280px] truncate text-sm text-ink-dim"
                        title={header.configuration_id}
                      >
                        {header.configuration_id}
                      </span>
                      <span className="text-xs text-ink-faint">
                        ESP {header.esp_encryption} · IKEv{header.ike_version} ·{' '}
                        {header.traffic_profile}
                      </span>
                    </td>
                    <td>
                      <span className={`tnum text-base font-semibold ${style.text}`}>
                        {header.risk_score}
                      </span>
                    </td>
                    <td>
                      <span className="tnum text-sm text-ink-dim">{header.finding_count}</span>
                    </td>
                    <td>
                      <SeverityBadge severity={header.severity as Severity} size="sm" />
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
    </div>
  )
}
