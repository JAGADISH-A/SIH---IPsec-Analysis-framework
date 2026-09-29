import { useMemo, useState } from 'react'
import { Panel, Tag } from '@/components/ui'
import { EmptyState } from '@/components/states'
import { comparisonStyle, formatValue, humanize } from '@/lib/format'
import type { AssessmentBundle, ComparisonStatus } from '@/types'

const STATUS_ORDER: ComparisonStatus[] = ['MISMATCH', 'MATCH', 'UNKNOWN', 'NOT_APPLICABLE']

function StatusPip({ status }: { status: ComparisonStatus }) {
  const style = comparisonStyle(status)
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs font-medium capitalize ${style.border} ${style.bg} ${style.text}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
      {status.replace('_', ' ')}
    </span>
  )
}

/**
 * The variable-by-variable comparison. This is the page's central artifact: it
 * puts planned intent and the authoritative observation side by side, one row
 * per variable the comparison engine evaluated.
 */
export function ComparisonTable({ bundle }: { bundle: AssessmentBundle }) {
  const rows = bundle.correlation?.rows ?? []
  const [filter, setFilter] = useState<ComparisonStatus | 'ALL'>('ALL')

  const counts = useMemo(() => {
    const map = new Map<string, number>()
    for (const row of rows) map.set(row.status, (map.get(row.status) ?? 0) + 1)
    return map
  }, [rows])

  const visible = useMemo(
    () =>
      filter === 'ALL'
        ? rows
        : rows.filter((row) => row.status === filter),
    [rows, filter],
  )

  return (
    <Panel
      title="Expected vs Observed"
      subtitle={`${rows.length} variables evaluated by the comparison engine · ${bundle.correlation?.status ?? 'UNKNOWN'}`}
      bodyClassName="overflow-x-auto"
      action={
        <div className="flex flex-wrap items-center gap-1">
          <button
            type="button"
            onClick={() => setFilter('ALL')}
            className={`rounded px-1.5 py-0.5 text-xs transition-colors ${
              filter === 'ALL' ? 'bg-sentinel/15 text-sentinel' : 'text-ink-faint hover:text-ink'
            }`}
          >
            all {rows.length}
          </button>
          {STATUS_ORDER.filter((status) => counts.has(status)).map((status) => (
            <button
              key={status}
              type="button"
              onClick={() => setFilter(status)}
              className={`rounded px-1.5 py-0.5 text-xs transition-colors ${
                filter === status
                  ? 'bg-sentinel/15 text-sentinel'
                  : 'text-ink-faint hover:text-ink'
              }`}
            >
              {status.replace('_', ' ').toLowerCase()} {counts.get(status)}
            </button>
          ))}
        </div>
      }
    >
      {rows.length === 0 ? (
        <EmptyState title="No comparison rows" description="The comparison engine produced no rows." />
      ) : visible.length === 0 ? (
        <EmptyState title="No rows in this state" icon="filter" />
      ) : (
        <table className="data-table min-w-[760px]">
          <thead>
            <tr className="border-b border-edge text-left">
              <th className="label text-ink-faint">
                Variable
              </th>
              <th className="w-[152px] px-4 py-2.5 label text-ink-faint">
                Expected
              </th>
              <th className="w-[152px] px-4 py-2.5 label text-ink-faint">
                Observed
              </th>
              <th className="w-[124px] px-4 py-2.5 label text-ink-faint">
                Status
              </th>
              <th className="label text-ink-faint">
                Reason
              </th>
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => {
              const style = comparisonStyle(row.status)
              return (
                <tr
                  key={row.variable}
                  className="row-hover border-b border-edge-soft align-top last:border-0"
                >
                  <td className="px-4 py-2.5">
                    <span className="mono block text-sm text-ink">{row.variable}</span>
                    <span className="mono text-xs text-ink-faint">{row.comparison_rule}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="mono block max-w-[140px] truncate text-sm text-ink-dim" title={formatValue(row.expected_value)}>
                      {formatValue(row.expected_value)}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`mono block max-w-[140px] truncate text-sm ${
                        row.status === 'MISMATCH' ? style.text : 'text-ink'
                      }`}
                      title={formatValue(row.observed_value)}
                    >
                      {formatValue(row.observed_value)}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <StatusPip status={row.status} />
                    {row.evidence_refs && row.evidence_refs.length > 0 && (
                      <span className="mono mt-1 block text-xs text-ink-faint">
                        {row.evidence_refs.length} ref
                        {row.evidence_refs.length === 1 ? '' : 's'}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="block text-xs leading-snug text-ink-faint">
                      {humanize(row.reason)}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
      <div className="flex items-center gap-2 border-t border-edge px-4 py-2.5 text-xs text-ink-faint">
        <Tag>UNKNOWN is an evidence gap, not a vulnerability</Tag>
        <span className="hidden sm:inline">
          Variables the capture could not resolve stay UNKNOWN rather than being reported as
          mismatches.
        </span>
      </div>
    </Panel>
  )
}
