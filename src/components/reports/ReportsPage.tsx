import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Download, FilePlus2, FileText, Trash2 } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { Button } from '../../components/common/Button.tsx'
import { KeyValueList } from '../../components/common/Data.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { Panel } from '../../components/common/Panel.tsx'
import { StatusDot } from '../../components/common/StatusDot.tsx'
import { useDeleteReport, useReport, useReportPreview, useReports } from '../../hooks/queries'
import { services } from '../../services'
import { formatBytes } from '../sessions/SessionDetailPage.tsx'
import {
  REPORT_DETAIL_LABEL,
  REPORT_FORMAT_LABEL,
  REPORT_TYPE_LABEL,
  type Report,
  type ReportFormat,
  type ReportStatus,
} from '../../types/report'

/**
 * Report register.
 *
 * Reports are generated artefacts with a status, not a button that opens a
 * print dialog. Generation is asynchronous, so the table shows progress and
 * refuses to offer a download until the service says the document is ready.
 */
export function ReportsPage() {
  const reports = useReports()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const remove = useDeleteReport()
  const items = reports.data ?? []

  const columns: ColumnDef<Report>[] = [
    {
      id: 'name',
      header: 'Report',
      render: (row) => (
        <div className="min-w-0">
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation()
              setSelectedId(row.id)
            }}
            className="block truncate text-left font-medium text-mist hover:text-accent-300"
          >
            {row.name}
          </button>
          <span className="block truncate font-mono text-[10.5px] text-mist-faint">
            {row.id} · {REPORT_TYPE_LABEL[row.type]}
          </span>
        </div>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      width: '9rem',
      render: (row) => <StatusCell report={row} />,
    },
    {
      id: 'detail',
      header: 'Detail',
      width: '6.5rem',
      render: (row) => <Badge tone="muted">{REPORT_DETAIL_LABEL[row.detailLevel]}</Badge>,
    },
    {
      id: 'formats',
      header: 'Formats',
      width: '7rem',
      render: (row) => (
        <span className="font-mono text-[10.5px] text-mist-faint">
          {row.formats.map((format) => REPORT_FORMAT_LABEL[format]).join(' ')}
        </span>
      ),
    },
    {
      id: 'scope',
      header: 'Scope',
      width: '9rem',
      render: (row) => (
        <span className="font-mono text-[10.5px] text-mist-faint">
          {row.sessionCount} session(s) · {row.findingCount} finding(s)
        </span>
      ),
    },
    {
      id: 'score',
      header: 'Score',
      width: '6rem',
      align: 'right',
      render: (row) => (
        <span className="font-mono text-[11px] text-mist-dim">
          {row.securityScore === null ? 'Unknown' : `${Math.round(row.securityScore * 100)}`}
        </span>
      ),
    },
    {
      id: 'size',
      header: 'Size',
      width: '6.5rem',
      align: 'right',
      render: (row) => (
        <span className="font-mono text-[11px] text-mist-dim">
          {row.sizeBytes === null ? '—' : formatBytes(row.sizeBytes)}
        </span>
      ),
    },
    {
      id: 'created',
      header: 'Created',
      width: '9rem',
      render: (row) => (
        <span className="text-[11px] text-mist-faint">{new Date(row.createdAt).toLocaleString()}</span>
      ),
    },
    {
      id: 'actions',
      header: '',
      width: '5rem',
      render: (row) => (
        <div className="flex items-center justify-end gap-1" onClick={(event) => event.stopPropagation()}>
          <DownloadMenu report={row} />
          <Button
            size="icon-sm"
            variant="danger"
            aria-label={`Delete report ${row.name}`}
            onClick={() => remove.mutate(row.id)}
            disabled={remove.isPending}
          >
            <Trash2 className="size-3.5" aria-hidden />
          </Button>
        </div>
      ),
    },
  ]

  return (
    <PageScroll>
      <PageHeader
        title="Reports"
        description="Generated assessments. Each report records the scope it covered, the formats it was rendered in, and the provenance of its figures."
        meta={reports.data ? <span className="font-mono">{reports.data.length} report(s)</span> : null}
        actions={
          <Link to="/reports/new" className="btn btn-primary">
            <FilePlus2 className="size-3.5" aria-hidden />
            New report
          </Link>
        }
      />

      <PageBody>
        <QueryBoundary
          isLoading={reports.isLoading}
          isError={reports.isError}
          error={reports.error}
          onRetry={() => void reports.refetch()}
          isEmpty={items.length === 0}
          emptyTitle="No reports yet"
          emptyDescription="Generate one from the current sessions, findings or experiments."
          emptyAction={
            <Link to="/reports/new" className="btn btn-primary">
              New report
            </Link>
          }
          loadingRows={8}
        >
          <Panel flush>
            <DataTable
              columns={columns}
              rows={items}
              rowKey={(row) => row.id}
              selectedKey={selectedId ?? undefined}
              onRowClick={(row) => setSelectedId(row.id === selectedId ? null : row.id)}
            />
          </Panel>
        </QueryBoundary>

        {selectedId ? <ReportDetail id={selectedId} onClose={() => setSelectedId(null)} /> : null}

        <p className="text-[11px] leading-relaxed text-mist-faint">
          A report reproduces evidence; it does not create new claims. If a figure in a report cannot be traced to a
          session and its captures, the report is wrong and the pipeline should be fixed rather than the document
          edited.
        </p>
      </PageBody>
    </PageScroll>
  )
}

function StatusCell({ report }: { report: Report }) {
  if (report.status === 'failed') {
    return (
      <span className="flex items-center gap-1.5">
        <StatusDot tone="danger" />
        <span className="text-[12px] text-danger">Failed</span>
      </span>
    )
  }
  if (report.status === 'ready') {
    return (
      <span className="flex items-center gap-1.5">
        <StatusDot tone="success" />
        <span className="text-[12px] text-mist-dim">Ready</span>
      </span>
    )
  }
  return (
    <span className="flex items-center gap-1.5">
      <StatusDot tone="accent" pulse />
      <span className="text-[12px] text-mist-dim">
        {REPORT_STATUS_LABEL[report.status]} {report.progressPercent}%
      </span>
    </span>
  )
}

const REPORT_STATUS_LABEL: Record<ReportStatus, string> = {
  queued: 'Queued',
  generating: 'Generating',
  ready: 'Ready',
  failed: 'Failed',
}

function DownloadMenu({ report }: { report: Report }) {
  const [error, setError] = useState<string | null>(null)
  const disabled = report.status !== 'ready'

  return (
    <span className="relative inline-flex">
      <Button
        size="icon-sm"
        aria-label={`Download report ${report.name}`}
        disabled={disabled}
        title={disabled ? 'The report is not ready yet' : undefined}
        onClick={async () => {
          const format = report.formats[0] ?? 'json'
          try {
            const url = await services.reports.getDownloadUrl(report.id, format)
            setError(null)
            window.open(url, '_blank', 'noopener')
          } catch (cause) {
            setError(cause instanceof Error ? cause.message : 'Download failed')
          }
        }}
      >
        <Download className="size-3.5" aria-hidden />
      </Button>
      {error ? (
        <span role="alert" className="absolute right-0 top-full z-10 mt-1 w-52 rounded-md border border-danger bg-night-900 p-1.5 text-[10.5px] text-danger">
          {error}
        </span>
      ) : null}
    </span>
  )
}

function ReportDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const preview = useReportPreview(id)
  // The report record itself is polled so the panel can show generation
  // progress; the preview only resolves once the document exists.
  const record = useReport(id)

  return (
    <Panel flush>
      <div className="flex items-center justify-between gap-3 border-b border-edge px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <FileText className="size-4 shrink-0 text-mist-faint" aria-hidden />
          <span className="truncate text-[13px] font-medium text-mist">
            {record.data?.name ?? 'Report'}
          </span>
          {record.data ? <Badge tone="muted">{REPORT_TYPE_LABEL[record.data.type]}</Badge> : null}
          {record.data ? <StatusCell report={record.data} /> : null}
        </div>
        <Button size="sm" onClick={onClose}>
          Close
        </Button>
      </div>

      {record.data && record.data.status !== 'ready' ? (
        <div className="flex items-center gap-3 border-b border-edge px-4 py-2.5">
          <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-night-800">
            <span
              className="block h-full rounded-full bg-accent-400"
              style={{ width: `${record.data.progressPercent}%` }}
            />
          </span>
          <span className="font-mono text-[11px] text-mist-faint">{record.data.progressPercent}%</span>
        </div>
      ) : null}

      {record.data?.error ? (
        <p role="alert" className="border-b border-edge bg-danger-dim px-4 py-2 text-[11.5px] text-danger">
          {record.data.error}
        </p>
      ) : null}

      {preview.isLoading ? (
        <p className="px-4 py-6 text-center text-xs text-mist-faint">Rendering preview…</p>
      ) : preview.isError ? (
        <p className="px-4 py-6 text-center text-xs text-danger">{preview.error.message}</p>
      ) : preview.data ? (
        <div className="flex flex-col gap-4 p-4">
          <div>
            <h2 className="text-[15px] font-semibold text-mist">{preview.data.title}</h2>
            <p className="text-[12px] text-mist-dim">{preview.data.subtitle}</p>
          </div>

          <KeyValueList
            columns={2}
            items={[
              { label: 'Detail level', value: REPORT_DETAIL_LABEL[preview.data.detailLevel] },
              { label: 'Generated', value: new Date(preview.data.generatedAt).toLocaleString() },
              { label: 'Sessions', value: String(preview.data.scope.sessionIds.length || 'All') },
              { label: 'Experiments', value: String(preview.data.scope.experimentIds.length || 'All') },
            ]}
          />

          {preview.data.sections.map((section) => (
            <section key={section.id} className="flex flex-col gap-2">
              <h3 className="text-[12.5px] font-semibold text-mist">{section.title}</h3>
              <p className="text-[12px] leading-relaxed text-mist-dim">{section.summary}</p>
              <dl className="divide-y divide-edge/60 rounded-md border border-edge">
                {section.rows.map((row) => (
                  <div key={row.label} className="flex items-baseline justify-between gap-3 px-2.5 py-1.5">
                    <dt className="text-[11.5px] text-mist-faint">{row.label}</dt>
                    <dd className="text-right font-mono text-[11.5px] text-mist-dim">
                      {row.value}
                      {row.note ? <span className="ml-1.5 font-sans text-[10.5px] text-mist-faint">{row.note}</span> : null}
                    </dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}

          <p className="rounded-md border border-edge bg-night-800 px-2.5 py-2 text-[10.5px] leading-relaxed text-mist-faint">
            {preview.data.provenance}
          </p>
        </div>
      ) : null}
    </Panel>
  )
}

export type { ReportFormat }
