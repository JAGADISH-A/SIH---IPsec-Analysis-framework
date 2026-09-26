import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Check, FileText } from 'lucide-react'
import { Field } from '../../components/common/Field.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { Panel, PanelHeader } from '../../components/common/Panel.tsx'
import { Button } from '../../components/common/Button.tsx'
import { useCreateReport, useExperiments, useSessions } from '../../hooks/queries'
import { cx } from '../../lib/cx'
import {
  REPORT_DETAIL_DESCRIPTION,
  REPORT_DETAIL_LABEL,
  REPORT_TYPE_DESCRIPTION,
  REPORT_TYPE_LABEL,
  type ReportDetailLevel,
  type ReportFormat,
  type ReportType,
} from '../../types/report'
import { SEVERITY_LABEL, type Severity } from '../../types/evidence'

const TYPES: ReportType[] = ['executive', 'technical', 'compliance', 'comparison']
const DETAIL_LEVELS: ReportDetailLevel[] = ['summary', 'standard', 'forensic']
const FORMATS: ReportFormat[] = ['pdf', 'json', 'csv']

/**
 * Report builder.
 *
 * The form is deliberately explicit: type, detail level, formats and scope are
 * all visible before submission, because a report is a claim about the evidence
 * and the reader needs to know exactly what was included.
 */
export function NewReportPage() {
  const navigate = useNavigate()
  const create = useCreateReport()
  const sessions = useSessions({ page: 1, pageSize: 100 })
  const experiments = useExperiments({ page: 1, pageSize: 100 })

  const [name, setName] = useState('')
  const [type, setType] = useState<ReportType>('technical')
  const [detailLevel, setDetailLevel] = useState<ReportDetailLevel>('standard')
  const [formats, setFormats] = useState<ReportFormat[]>(['pdf'])
  const [sessionIds, setSessionIds] = useState<string[]>([])
  const [experimentIds, setExperimentIds] = useState<string[]>([])
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')

  const sessionOptions = sessions.data?.items ?? []
  const experimentOptions = experiments.data?.items ?? []

  const scopeSummary = useMemo(() => {
    const parts: string[] = []
    if (sessionIds.length > 0) parts.push(`${sessionIds.length} session(s)`)
    if (experimentIds.length > 0) parts.push(`${experimentIds.length} experiment(s)`)
    if (from || to) parts.push('date range')
    return parts.length > 0 ? parts.join(', ') : 'entire dataset'
  }, [sessionIds, experimentIds, from, to])

  const invalid = name.trim().length === 0 || formats.length === 0

  const toggle = <T extends string>(list: T[], setList: (value: T[]) => void, id: T) =>
    setList(list.includes(id) ? list.filter((entry) => entry !== id) : [...list, id])

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (invalid) return
    create.mutate(
      {
        name: name.trim(),
        type,
        detailLevel,
        formats,
        scope: {
          sessionIds,
          experimentIds,
          from: from || new Date(Date.now() - 7 * 86_400_000).toISOString(),
          to: to || new Date().toISOString(),
        },
      },
      { onSuccess: (report) => navigate(`/reports?report=${report.id}`) },
    )
  }

  return (
    <PageScroll>
      <PageHeader
        breadcrumb={[{ label: 'Reports', to: '/reports' }, { label: 'New report' }]}
        title="New Report"
        description="A report is a claim about the evidence. Choose what it covers and how much of the evidence to reproduce."
      />

      <PageBody>
        <form onSubmit={submit} className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
          <div className="flex flex-col gap-4">
            <Panel padded>
              <h2 className="text-[13px] font-semibold tracking-wide text-mist">Report</h2>
              <div className="mt-3 flex flex-col gap-3">
                <Field
                  label="Name"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="e.g. IKEv2 rekey regression, week 12"
                  required
                />
                <fieldset>
                  <legend className="label">Type</legend>
                  <div className="mt-1 grid gap-2 sm:grid-cols-2">
                    {TYPES.map((value) => (
                      <ChoiceCard
                        key={value}
                        name="report-type"
                        checked={type === value}
                        onChange={() => setType(value)}
                        title={REPORT_TYPE_LABEL[value]}
                        description={REPORT_TYPE_DESCRIPTION[value]}
                      />
                    ))}
                  </div>
                </fieldset>
                <fieldset>
                  <legend className="label">Detail level</legend>
                  <div className="mt-1 grid gap-2 sm:grid-cols-3">
                    {DETAIL_LEVELS.map((value) => (
                      <ChoiceCard
                        key={value}
                        name="report-detail"
                        checked={detailLevel === value}
                        onChange={() => setDetailLevel(value)}
                        title={REPORT_DETAIL_LABEL[value]}
                        description={REPORT_DETAIL_DESCRIPTION[value]}
                        compact
                      />
                    ))}
                  </div>
                </fieldset>
                <fieldset>
                  <legend className="label">Formats</legend>
                  <div className="mt-1 flex flex-wrap gap-3">
                    {FORMATS.map((value) => (
                      <label key={value} className="flex items-center gap-1.5 text-[12px] text-mist-dim">
                        <input
                          type="checkbox"
                          checked={formats.includes(value)}
                          onChange={() => toggle(formats, setFormats, value)}
                          className="accent-accent-500"
                        />
                        {value.toUpperCase()}
                      </label>
                    ))}
                  </div>
                  {formats.length === 0 ? (
                    <p className="mt-1 text-[11px] text-danger">Choose at least one output format.</p>
                  ) : null}
                </fieldset>
              </div>
            </Panel>

            <Panel padded>
              <h2 className="text-[13px] font-semibold tracking-wide text-mist">Scope</h2>
              <p className="mt-0.5 text-[11px] text-mist-faint">
                Leave everything empty to cover the entire dataset ({sessionOptions.length} sessions,{' '}
                {experimentOptions.length} experiments are currently loaded).
              </p>

              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <Field label="From" type="date" value={from} onChange={(event) => setFrom(event.target.value)} />
                <Field label="To" type="date" value={to} onChange={(event) => setTo(event.target.value)} />
              </div>

              <div className="mt-3 grid gap-3 lg:grid-cols-2">
                <CheckList
                  title="Sessions"
                  empty={sessions.isLoading ? 'Loading sessions…' : 'No sessions available.'}
                  options={sessionOptions.map((session) => ({
                    id: session.id,
                    label: session.id,
                    hint: `${session.configuration.ikeVersion.value} · ${session.configuration.vpnMode.value} · ${session.status}`,
                  }))}
                  selected={sessionIds}
                  onToggle={(id) => toggle(sessionIds, setSessionIds, id)}
                />
                <CheckList
                  title="Experiments"
                  empty={experiments.isLoading ? 'Loading experiments…' : 'No experiments available.'}
                  options={experimentOptions.map((experiment) => ({
                    id: experiment.id,
                    label: experiment.name,
                    hint: `${experiment.ikeVersion} · ${experiment.trafficProfile}`,
                  }))}
                  selected={experimentIds}
                  onToggle={(id) => toggle(experimentIds, setExperimentIds, id)}
                />
              </div>
            </Panel>
          </div>

          <div className="flex flex-col gap-4">
            <Panel flush>
              <PanelHeader title="Summary" subtitle="What will be generated" />
              <dl className="flex flex-col gap-2 p-4 text-[12px]">
                <Row label="Name" value={name.trim() || 'Untitled report'} />
                <Row label="Type" value={REPORT_TYPE_LABEL[type]} />
                <Row label="Detail" value={REPORT_DETAIL_LABEL[detailLevel]} />
                <Row label="Formats" value={formats.map((value) => value.toUpperCase()).join(', ') || 'None'} />
                <Row label="Scope" value={scopeSummary} />
                <Row
                  label="Sessions in scope"
                  value={sessionIds.length === 0 ? 'All loaded' : String(sessionIds.length)}
                />
              </dl>
            </Panel>

            <Panel padded>
              <h2 className="text-[13px] font-semibold tracking-wide text-mist">Severity ladder in this report</h2>
              <ul className="mt-2 flex flex-col gap-1 text-[11.5px] text-mist-dim">
                {(Object.keys(SEVERITY_LABEL) as Severity[]).map((severity) => (
                  <li key={severity} className="flex items-center gap-2">
                    <span className="font-mono text-mist-faint">{severity}</span>
                    <span>{SEVERITY_LABEL[severity]}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-[10.5px] leading-relaxed text-mist-faint">
                Severity is assigned by the analysis engine. A report presents it; it does not reassess it.
              </p>
            </Panel>

            {create.isError ? (
              <p role="alert" className="rounded-lg border border-danger bg-danger-dim px-3 py-2 text-[12px] text-danger">
                {create.error.message}
              </p>
            ) : null}

            <div className="flex items-center gap-2">
              <Button type="submit" variant="primary" disabled={invalid || create.isPending}>
                <FileText className="size-3.5" aria-hidden />
                {create.isPending ? 'Queuing…' : 'Generate report'}
              </Button>
              <Button type="button" onClick={() => navigate('/reports')}>
                Cancel
              </Button>
            </div>

            <p className="text-[10.5px] leading-relaxed text-mist-faint">
              Generation is asynchronous: the report is queued, then rendered, then made available for download. In
              this build the report service is local, and every document is stamped with its provenance.
            </p>
          </div>
        </form>
      </PageBody>
    </PageScroll>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="text-mist-faint">{label}</dt>
      <dd className="text-right text-mist">{value}</dd>
    </div>
  )
}

function ChoiceCard({
  name,
  checked,
  onChange,
  title,
  description,
  compact = false,
}: {
  name: string
  checked: boolean
  onChange: () => void
  title: string
  description: string
  compact?: boolean
}) {
  return (
    <label
      className={cx(
        'flex cursor-pointer items-start gap-2 rounded-lg border bg-night-900 p-2.5',
        checked ? 'border-accent-500 bg-accent-dim' : 'border-edge',
      )}
    >
      <input type="radio" name={name} checked={checked} onChange={onChange} className="mt-0.5 accent-accent-500" />
      <span className="min-w-0">
        <span className="block text-[12.5px] font-medium text-mist">{title}</span>
        {!compact ? (
          <span className="mt-0.5 block text-[11px] leading-relaxed text-mist-faint">{description}</span>
        ) : null}
      </span>
    </label>
  )
}

function CheckList({
  title,
  options,
  selected,
  onToggle,
  empty,
}: {
  title: string
  options: { id: string; label: string; hint: string }[]
  selected: string[]
  onToggle: (id: string) => void
  empty: string
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between">
        <span className="label">{title}</span>
        <span className="font-mono text-[11px] text-mist-faint">{selected.length} selected</span>
      </div>
      <div className="max-h-48 overflow-y-auto rounded-md border border-edge">
        {options.length === 0 ? (
          <p className="px-2.5 py-3 text-[11.5px] text-mist-faint">{empty}</p>
        ) : (
          <ul className="divide-y divide-edge/60">
            {options.map((option) => (
              <li key={option.id}>
                <label className="flex cursor-pointer items-center gap-2 px-2.5 py-1.5 text-[12px] text-mist-dim hover:bg-night-800">
                  <input
                    type="checkbox"
                    checked={selected.includes(option.id)}
                    onChange={() => onToggle(option.id)}
                    className="accent-accent-500"
                  />
                  <span className="min-w-0 flex-1 truncate">
                    {option.label}
                    <span className="ml-1.5 font-mono text-[10.5px] text-mist-faint">{option.hint}</span>
                  </span>
                  {selected.includes(option.id) ? <Check className="size-3 text-accent-400" aria-hidden /> : null}
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
