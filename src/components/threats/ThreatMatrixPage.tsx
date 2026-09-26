import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Badge } from '../../components/common/Badge.tsx'
import { SeverityTag } from '../../components/common/Evidence.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { Panel } from '../../components/common/Panel.tsx'
import { ThreatMatrix } from '../../components/charts/ThreatMatrix.tsx'
import { useThreatMatrix } from '../../hooks/queries'
import type { Threat } from '../../types/analysis'
import { SEVERITY_RANK, SEVERITY_LABEL, type Severity } from '../../types/evidence'

/**
 * Threat matrix: likelihood against impact.
 *
 * Threats are derived from the current findings, so the matrix is a view of the
 * evidence rather than a separate opinion. Opacity carries confidence, and a
 * threat with no estimate is drawn hollow.
 */
export function ThreatMatrixPage() {
  const matrix = useThreatMatrix()
  const [selected, setSelected] = useState<Threat | null>(null)
  const threats = matrix.data?.threats ?? []

  const ordered = [...threats].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.impact * b.likelihood - a.impact * a.likelihood,
  )

  const columns: ColumnDef<Threat>[] = [
    {
      id: 'threat',
      header: 'Threat',
      render: (row) => (
        <div className="min-w-0">
          <button
            type="button"
            onClick={() => setSelected(row)}
            className="block truncate text-left font-medium text-mist hover:text-accent-300"
          >
            {row.name}
          </button>
          <span className="truncate text-[11px] text-mist-faint">{row.description}</span>
        </div>
      ),
    },
    {
      id: 'severity',
      header: 'Severity',
      width: '7.5rem',
      render: (row) => <SeverityTag severity={row.severity} />,
    },
    {
      id: 'likelihood',
      header: 'Likelihood',
      width: '6rem',
      align: 'right',
      render: (row) => <span className="font-mono text-xs text-mist-dim">{row.likelihood}/5</span>,
    },
    {
      id: 'impact',
      header: 'Impact',
      width: '6rem',
      align: 'right',
      render: (row) => <span className="font-mono text-xs text-mist-dim">{row.impact}/5</span>,
    },
    {
      id: 'exposure',
      header: 'Exposure',
      width: '8rem',
      align: 'right',
      render: (row) => (
        <span className="font-mono text-xs text-mist-dim">
          {row.affectedSessions} session(s)
        </span>
      ),
    },
    {
      id: 'confidence',
      header: 'Confidence',
      width: '7rem',
      render: (row) => (
        <span className="font-mono text-[11px] text-mist-dim">
          {row.confidence === null ? 'Unknown' : `${Math.round(row.confidence * 100)}%`}
        </span>
      ),
    },
    {
      id: 'findings',
      header: 'Evidence',
      width: '7rem',
      align: 'right',
      render: (row) =>
        row.relatedFindingIds.length > 0 ? (
          <Link to="/findings" className="font-mono text-[11px] text-mist-dim hover:text-accent-300">
            {row.relatedFindingIds.length} finding(s)
          </Link>
        ) : (
          <span className="text-[11px] text-mist-faint">None</span>
        ),
    },
  ]

  return (
    <PageScroll>
      <PageHeader
        title="Threat Matrix"
        description="Each threat is positioned by how often it is expected and how badly it would end. Both axes come from the findings register."
        meta={
          matrix.data ? (
            <>
              <span className="font-mono">{threats.length} threat(s)</span>
              <span className="font-mono">
                {threats.filter((threat) => threat.severity === 'critical' || threat.severity === 'high').length} rated
                high or critical
              </span>
              <span>Generated {new Date(matrix.data.generatedAt).toLocaleString()}</span>
            </>
          ) : null
        }
      />

      <QueryBoundary
        isLoading={matrix.isLoading}
        isError={matrix.isError}
        error={matrix.error}
        onRetry={() => void matrix.refetch()}
        isEmpty={!matrix.data}
        emptyTitle="No threats could be derived"
        emptyDescription="The matrix is built from the current findings. Analyse more sessions to populate it."
        loadingRows={8}
      >
        {matrix.data ? (
          <PageBody>
            <Panel padded>
              <ThreatMatrix threats={threats} selectedId={selected?.id ?? null} onSelect={setSelected} />
            </Panel>

            {selected ? (
              <Panel padded>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityTag severity={selected.severity} />
                  <span className="text-[13px] font-semibold text-mist">{selected.name}</span>
                  <Badge tone="muted">{selected.category}</Badge>
                </div>
                <p className="mt-2 text-[12.5px] leading-relaxed text-mist-dim">{selected.description}</p>
                {selected.relatedFindingIds.length > 0 ? (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {selected.relatedFindingIds.map((id) => (
                      <Link key={id} to={`/findings/${id}`} className="btn btn-sm">
                        {id}
                      </Link>
                    ))}
                  </div>
                ) : null}
              </Panel>
            ) : null}

            <section className="flex flex-col gap-3">
              <div>
                <h2 className="text-[13px] font-semibold tracking-wide text-mist">Threat register</h2>
                <p className="mt-0.5 text-[11px] text-mist-faint">Sorted by severity, then by exposure.</p>
              </div>
              <Panel flush>
                <DataTable columns={columns} rows={ordered} rowKey={(row) => row.id} />
              </Panel>
            </section>

            <p className="text-[11px] leading-relaxed text-mist-faint">
              Likelihood and impact are platform assessments, each carrying its own confidence. A threat with no
              confidence estimate is drawn hollow and reported as Unknown in the table above — it is not treated as
              certain. Severity ladder: {(Object.keys(SEVERITY_RANK) as Severity[]).map((severity) => SEVERITY_LABEL[severity]).join(' → ')}.
            </p>
          </PageBody>
        ) : null}
      </QueryBoundary>
    </PageScroll>
  )
}
