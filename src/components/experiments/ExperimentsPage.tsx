import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { FlaskConical, Play, Search, Square, Trash2 } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { Button } from '../../components/common/Button.tsx'
import { ConfidenceTag } from '../../components/common/Evidence.tsx'
import { Field } from '../../components/common/Field.tsx'
import { Select } from '../../components/common/Select.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { Pagination, Toolbar } from '../../components/common/Data.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { Panel } from '../../components/common/Panel.tsx'
import { StatusDot } from '../../components/common/StatusDot.tsx'
import {
  useCancelExperiment,
  useDeleteExperiment,
  useExperimentSelection,
  useExperiments,
} from '../../hooks/queries'
import { ExperimentCompare } from './ExperimentCompare.tsx'
import { NewExperimentForm } from './NewExperimentForm.tsx'
import {
  EXPERIMENT_STATUSES,
  EXPERIMENT_STATUS_LABEL,
  type Experiment,
  type ExperimentStatus,
} from '../../types/experiment'

/** Runs that can still be stopped. */
const ACTIVE_STATUSES: ExperimentStatus[] = ['created', 'running', 'capturing', 'analyzing']
/** Runs whose record is worth keeping. */
const TERMINAL_STATUSES: ExperimentStatus[] = ['completed', 'failed', 'cancelled']
/** Upper bound on the comparison grid, chosen to stay readable. */
const MAX_COMPARISON = 4

/**
 * Experiment register.
 *
 * Every experiment here is a controlled run with a declared configuration, so
 * the list leads with the hypothesis rather than with a score.
 */
export function ExperimentsPage() {
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState<ExperimentStatus | 'all'>('all')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [creating, setCreating] = useState(false)

  const navigate = useNavigate()
  const cancel = useCancelExperiment()
  const remove = useDeleteExperiment()
  const { selection, setSelection } = useExperimentSelection()

  // The list already polls every 10s, so a run that starts in this session
  // walks through its lifecycle in the table without any extra wiring.
  const query = useExperiments({
    search: search.trim() || undefined,
    statuses: status === 'all' ? undefined : [status],
    page,
    pageSize,
  })
  const items = query.data?.items ?? []

  const columns: ColumnDef<Experiment>[] = [
    {
      id: 'name',
      header: 'Experiment',
      render: (row) => (
        <div className="min-w-0">
          <Link
            to={`/experiments/${row.id}`}
            onClick={(event) => event.stopPropagation()}
            className="block truncate font-medium text-mist hover:text-accent-300"
          >
            {row.name}
          </Link>
          <span className="block truncate text-[11px] text-mist-faint">{row.hypothesis}</span>
        </div>
      ),
    },
    {
      id: 'status',
      header: 'Status',
      width: '8rem',
      render: (row) => (
        <span className="flex items-center gap-1.5">
          <StatusDot
            tone={
              row.status === 'completed'
                ? 'success'
                : row.status === 'failed'
                  ? 'danger'
                  : row.status === 'running'
                    ? 'accent'
                    : 'info'
            }
            pulse={row.status === 'running'}
          />
          <span className="text-[12px] text-mist-dim">{EXPERIMENT_STATUS_LABEL[row.status]}</span>
        </span>
      ),
    },
    {
      id: 'config',
      header: 'Configuration',
      width: '16rem',
      render: (row) => (
        <div className="font-mono text-[10.5px] leading-relaxed text-mist-faint">
          <div>
            {row.ikeVersion} · {row.vpnMode} · {row.trafficProfile}
          </div>
          <div>
            {row.encryption} / {row.integrity} · {row.dhGroup}
          </div>
        </div>
      ),
    },
    {
      id: 'risk',
      header: 'Risk',
      width: '8rem',
      align: 'right',
      render: (row) => (
        <span className="font-mono text-xs text-mist-dim">
          {row.riskScore} <span className="text-mist-faint">{row.riskBand}</span>
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
      id: 'findings',
      header: 'Findings',
      width: '6rem',
      align: 'right',
      render: (row) => <span className="font-mono text-xs text-mist-dim">{row.findingCount}</span>,
    },
    {
      id: 'duration',
      header: 'Duration',
      width: '7rem',
      align: 'right',
      render: (row) => (
        <span className="font-mono text-[11px] text-mist-faint">
          {row.durationMs === null ? '—' : `${Math.round(row.durationMs / 1000)}s`}
        </span>
      ),
    },
    {
      id: 'started',
      header: 'Started',
      width: '9rem',
      render: (row) => (
        <span className="text-[11px] text-mist-faint">
          {row.startedAt ? new Date(row.startedAt).toLocaleString() : 'Not started'}
        </span>
      ),
    },
    {
      id: 'progress',
      header: 'Progress',
      width: '7rem',
      render: (row) =>
        ACTIVE_STATUSES.includes(row.status) ? (
          <div className="flex items-center gap-1.5">
            <span className="h-1.5 w-14 overflow-hidden rounded-full bg-night-800">
              <span
                className="block h-full rounded-full bg-accent-400"
                style={{ width: `${row.progressPercent}%` }}
              />
            </span>
            <span className="font-mono text-[10.5px] text-mist-faint">{row.progressPercent}%</span>
          </div>
        ) : (
          <span className="text-[10.5px] text-mist-faint">—</span>
        ),
    },
    {
      id: 'pin',
      header: 'Compare',
      width: '4.5rem',
      render: (row) => {
        const pinned = selection.includes(row.id)
        const disabled = !pinned && selection.length >= MAX_COMPARISON
        return (
          <input
            type="checkbox"
            checked={pinned}
            disabled={disabled}
            aria-label={`Pin ${row.name} for comparison`}
            title={disabled ? `At most ${MAX_COMPARISON} experiments can be compared` : 'Pin for comparison'}
            onClick={(event) => event.stopPropagation()}
            onChange={() =>
              setSelection(
                pinned ? selection.filter((id) => id !== row.id) : [...selection, row.id].slice(-MAX_COMPARISON),
              )
            }
            className="accent-accent-500"
          />
        )
      },
    },
    {
      id: 'actions',
      header: '',
      width: '6rem',
      render: (row) => (
        <div className="flex items-center justify-end gap-1" onClick={(event) => event.stopPropagation()}>
          {ACTIVE_STATUSES.includes(row.status) ? (
            <Button
              size="icon-sm"
              aria-label={`Cancel run ${row.name}`}
              title="Cancel this run"
              disabled={cancel.isPending}
              onClick={() => cancel.mutate(row.id)}
            >
              <Square className="size-3.5" aria-hidden />
            </Button>
          ) : (
            <Button
              size="icon-sm"
              aria-label={`Open run ${row.name}`}
              title="Open run"
              onClick={() => navigate(`/experiments/${row.id}`)}
            >
              <Play className="size-3.5" aria-hidden />
            </Button>
          )}
          <Button
            size="icon-sm"
            variant="danger"
            aria-label={`Delete run ${row.name}`}
            title={
              TERMINAL_STATUSES.includes(row.status)
                ? 'Delete this run and its record'
                : 'Cancel the run before deleting it'
            }
            disabled={!TERMINAL_STATUSES.includes(row.status) || remove.isPending}
            onClick={() => remove.mutate(row.id)}
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
        title="Experiments"
        description="Controlled runs of the testbed against a declared configuration, kept so the platform's judgement can be audited against what was actually configured."
        meta={query.data ? <span className="font-mono">{query.data.total} experiment(s)</span> : null}
        actions={
          <Button variant="primary" onClick={() => setCreating((value) => !value)} aria-expanded={creating}>
            <FlaskConical className="size-3.5" aria-hidden />
            New experiment
          </Button>
        }
      />

      <PageBody>
        {creating ? (
          <NewExperimentForm
            onClose={() => setCreating(false)}
            onCreated={(experiment) => {
              setCreating(false)
              navigate(`/experiments/${experiment.id}`)
            }}
          />
        ) : null}

        {selection.length > 0 ? (
          <ExperimentCompare ids={selection} onClear={() => setSelection([])} />
        ) : null}

        <Panel padded>
          <Toolbar>
            <Field
              label="Search"
              leading={<Search className="size-3.5" aria-hidden />}
              value={search}
              onChange={(event) => {
                setSearch(event.target.value)
                setPage(1)
              }}
              placeholder="Name, hypothesis or testbed"
            />
            <Select
              label="Status"
              value={status}
              onChange={(event) => {
                setStatus(event.target.value as ExperimentStatus | 'all')
                setPage(1)
              }}
            >
              <option value="all">All statuses</option>
              {EXPERIMENT_STATUSES.map((value) => (
                <option key={value} value={value}>
                  {EXPERIMENT_STATUS_LABEL[value]}
                </option>
              ))}
            </Select>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setSearch('')
                setStatus('all')
                setPage(1)
              }}
            >
              Reset
            </button>
          </Toolbar>
        </Panel>

        <QueryBoundary
          isLoading={query.isLoading}
          isError={query.isError}
          error={query.error}
          onRetry={() => void query.refetch()}
          isEmpty={items.length === 0}
          emptyTitle="No experiments match these filters"
          emptyDescription="Clear the filters, or register a new run against the testbed."
          loadingRows={10}
        >
          <Panel flush>
            <DataTable
              columns={columns}
              rows={items}
              rowKey={(row) => row.id}
              onRowClick={(row) => {
                window.location.assign(`/experiments/${row.id}`)
              }}
              empty="No experiments on this page."
            />
          </Panel>

          {query.data ? (
            <Panel flush>
              <Pagination
                page={query.data.page}
                pageSize={query.data.pageSize}
                total={query.data.total}
                label="experiments"
                onPageChange={setPage}
                onPageSizeChange={(value) => {
                  setPageSize(value)
                  setPage(1)
                }}
              />
            </Panel>
          ) : null}
        </QueryBoundary>

        {cancel.isError || remove.isError ? (
          <p role="alert" className="rounded-lg border border-danger bg-danger-dim px-3 py-2 text-[12px] text-danger">
            {(cancel.error ?? remove.error)?.message}
          </p>
        ) : null}

        <p className="flex flex-wrap items-center gap-2 text-[11px] text-mist-faint">
          <FlaskConical className="size-3.5" aria-hidden />
          Experiments are the only place where the platform states what it expected. Outside this register, every
          assertion must be justified by evidence. Pin up to {MAX_COMPARISON} runs to diff them side by side.
          <Badge tone="muted">testbed integration pending</Badge>
        </p>
      </PageBody>
    </PageScroll>
  )
}
