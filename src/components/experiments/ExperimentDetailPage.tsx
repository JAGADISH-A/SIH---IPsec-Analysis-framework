import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, CheckCircle2, XCircle, HelpCircle, Square, Trash2 } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { ConfidenceTag, SeverityTag } from '../../components/common/Evidence.tsx'
import { KeyValueList } from '../../components/common/Data.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { Panel } from '../../components/common/Panel.tsx'
import { ScoreDial } from '../../components/charts/ScoreDial.tsx'
import { DonutChart } from '../../components/charts/Charts.tsx'
import { Button } from '../../components/common/Button.tsx'
import { useCancelExperiment, useDeleteExperiment, useExperimentDetail } from '../../hooks/queries'
import { cx } from '../../lib/cx'
import {
  EXPERIMENT_STATUS_LABEL,
  TRAFFIC_PROFILE_LABEL,
  type Experiment,
  type ExperimentDetail,
  type ExperimentStatus,
} from '../../types/experiment'

/** Statuses during which a run can still be stopped. */
const ACTIVE_STATUSES: ExperimentStatus[] = ['created', 'running', 'capturing', 'analyzing']
import { formatBytes } from '../sessions/SessionDetailPage.tsx'

/**
 * Experiment detail: declared intent versus observed reality.
 *
 * The ground truth table is the point of the page. Every observation is marked
 * as agreeing, disagreeing, or not determinable, and disagreement is not treated
 * as a finding on its own.
 */
export function ExperimentDetailPage() {
  const { experimentId } = useParams<{ experimentId: string }>()
  const detail = useExperimentDetail(experimentId)
  const navigate = useNavigate()
  const cancel = useCancelExperiment()
  const remove = useDeleteExperiment()

  const experiment = detail.data?.experiment
  const isActive = experiment ? ACTIVE_STATUSES.includes(experiment.status) : false

  return (
    <PageScroll>
      <PageHeader
        breadcrumb={[{ label: 'Experiments', to: '/experiments' }, { label: experimentId ?? '' }]}
        title={detail.data?.experiment.name ?? experimentId ?? 'Experiment'}
        description={detail.data?.experiment.hypothesis}
        meta={
          detail.data ? (
            <>
              <span className="font-mono">{detail.data.experiment.id}</span>
              <span className="font-mono">{detail.data.experiment.testbed}</span>
              <span>
                {detail.data.experiment.status === 'running'
                  ? `${detail.data.experiment.progressPercent}% complete`
                  : EXPERIMENT_STATUS_LABEL[detail.data.experiment.status as ExperimentStatus]}
              </span>
              {detail.data.experiment.operator ? <span>Operator {detail.data.experiment.operator}</span> : null}
            </>
          ) : null
        }
        actions={
          <>
            {isActive ? (
              <Button
                onClick={() => experiment && cancel.mutate(experiment.id)}
                disabled={cancel.isPending}
                title="Stop this run and keep its record"
              >
                <Square className="size-3.5" aria-hidden />
                {cancel.isPending ? 'Cancelling…' : 'Cancel run'}
              </Button>
            ) : null}
            {!isActive ? (
              <Button
                variant="danger"
                disabled={!experiment || remove.isPending}
                onClick={() => {
                  if (!experiment) return
                  remove.mutate(experiment.id, { onSuccess: () => navigate('/experiments') })
                }}
              >
                <Trash2 className="size-3.5" aria-hidden />
                Delete run
              </Button>
            ) : null}
            <Link to="/experiments" className="btn">
              <ArrowLeft className="size-3.5" aria-hidden />
              All experiments
            </Link>
          </>
        }
      />

      <QueryBoundary
        isLoading={detail.isLoading}
        isError={detail.isError}
        error={detail.error}
        onRetry={() => void detail.refetch()}
        isEmpty={!detail.isLoading && !detail.data}
        emptyTitle="Experiment not found"
        emptyDescription="No experiment with this id exists in the register."
        loadingRows={10}
      >
        {detail.data ? (
          <PageBody>
            {cancel.isError || remove.isError ? (
              <p role="alert" className="rounded-lg border border-danger bg-danger-dim px-3 py-2 text-[12px] text-danger">
                {(cancel.error ?? remove.error)?.message}
              </p>
            ) : null}

            <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
              <div className="flex flex-col gap-4">
                <ComparisonTable detail={detail.data} />
                <ModelOutputs detail={detail.data} />
                <CorrelationPanel detail={detail.data} />
                <TrafficPanel detail={detail.data} />
                <TimelinePanel detail={detail.data} />
              </div>

              <div className="flex flex-col gap-4">
                <PosturePanel detail={detail.data} />
                <GroundTruthPanel detail={detail.data} />
                <FindingsPanel detail={detail.data} />
                <ArtefactsPanel detail={detail.data} />
              </div>
            </div>
          </PageBody>
        ) : null}
      </QueryBoundary>
    </PageScroll>
  )
}

function AgreementMark({ agrees }: { agrees: boolean | null }) {
  if (agrees === true)
    return (
      <span className="flex items-center gap-1 text-[11px] text-success">
        <CheckCircle2 className="size-3.5" aria-hidden /> Agrees
      </span>
    )
  if (agrees === false)
    return (
      <span className="flex items-center gap-1 text-[11px] text-danger">
        <XCircle className="size-3.5" aria-hidden /> Disagrees
      </span>
    )
  return (
    <span className="flex items-center gap-1 text-[11px] text-mist-faint">
      <HelpCircle className="size-3.5" aria-hidden /> Not determinable
    </span>
  )
}

function ComparisonTable({ detail }: { detail: ExperimentDetail }) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Ground truth versus observation</h2>
        <p className="mt-0.5 text-[11px] text-mist-faint">
          What the testbed was configured to do, next to what the platform saw on the wire.
        </p>
      </div>
      <Panel flush>
        <table className="w-full text-left text-[12px]">
          <thead className="border-b border-edge text-[10.5px] uppercase tracking-wide text-mist-faint">
            <tr>
              <th scope="col" className="px-3 py-2 font-medium">Field</th>
              <th scope="col" className="px-3 py-2 font-medium">Configured</th>
              <th scope="col" className="px-3 py-2 font-medium">Observed</th>
              <th scope="col" className="px-3 py-2 font-medium">Verdict</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-edge/60">
            {detail.observations.map((row) => (
              <tr key={row.field} className={cx(row.agrees === false && 'bg-danger-dim/20')}>
                <th scope="row" className="px-3 py-2 font-mono text-[11px] font-normal text-mist-faint">
                  {row.field}
                </th>
                <td className="px-3 py-2 font-mono text-[11px] text-mist-dim">{row.groundTruth}</td>
                <td className="px-3 py-2 font-mono text-[11px] text-mist">{row.observed}</td>
                <td className="px-3 py-2">
                  <AgreementMark agrees={row.agrees} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </section>
  )
}

function ModelOutputs({ detail }: { detail: ExperimentDetail }) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Model outputs</h2>
        <p className="mt-0.5 text-[11px] text-mist-faint">Each model states its own confidence.</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        {detail.modelOutputs.map((model) => (
          <Panel key={model.id} padded>
            <div className="flex items-center justify-between gap-2">
              <span className="text-[12.5px] font-medium text-mist">{model.name}</span>
              <span className="font-mono text-[10.5px] text-mist-faint">{model.version}</span>
            </div>
            <p className="mt-1.5 text-[12px] leading-relaxed text-mist-dim">{model.output}</p>
            <div className="mt-2 flex items-center gap-2">
              <ConfidenceTag confidence={model.confidence} showLabel />
              {model.agrees === null ? (
                <span className="text-[10.5px] text-mist-faint">not comparable to ground truth</span>
              ) : (
                <AgreementMark agrees={model.agrees} />
              )}
            </div>
          </Panel>
        ))}
      </div>
    </section>
  )
}

function CorrelationPanel({ detail }: { detail: ExperimentDetail }) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Cross-engine correlation</h2>
      </div>
      <Panel padded>
        <div className="flex flex-wrap items-baseline gap-2">
          <span className="text-[13px] font-medium text-mist">{detail.correlation.engine}</span>
          <span className="font-mono text-xl font-semibold text-mist">{detail.correlation.score}</span>
          <Badge tone={detail.correlation.score >= 80 ? 'success' : detail.correlation.score >= 60 ? 'warning' : 'danger'}>
            {detail.correlation.posture}
          </Badge>
        </div>
        <p className="mt-2 text-[12px] leading-relaxed text-mist-dim">{detail.correlation.narrative}</p>
      </Panel>
    </section>
  )
}

function TrafficPanel({ detail }: { detail: ExperimentDetail }) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Observed traffic</h2>
        <p className="mt-0.5 font-mono text-[11px] text-mist-faint">
          {detail.traffic.packets.toLocaleString()} packets · {formatBytes(detail.traffic.bytes)} ·{' '}
          {detail.traffic.averagePacketSize === null ? 'mean size unknown' : `${detail.traffic.averagePacketSize} B mean`}
        </p>
      </div>
      <Panel padded>
        <DonutChart
          label="Traffic class share"
          centerLabel="Bytes"
          data={detail.traffic.classes.map((entry, index) => ({
            label: entry.label,
            value: entry.value,
            tone: (['accent', 'info', 'success', 'warning', 'danger', 'critical', 'muted'] as const)[index % 7],
          }))}
        />
      </Panel>
    </section>
  )
}

function TimelinePanel({ detail }: { detail: ExperimentDetail }) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Run timeline</h2>
      </div>
      <Panel flush>
        <ol className="divide-y divide-edge/60">
          {detail.timeline.map((entry) => (
            <li key={entry.id} className="flex items-start gap-3 px-3 py-2">
              <span className="w-20 shrink-0 text-right font-mono text-[10.5px] text-mist-faint">
                {new Date(entry.timestamp).toLocaleTimeString()}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-[12.5px] text-mist">{entry.description}</p>
                <p className="font-mono text-[10.5px] text-mist-faint">
                  {entry.type} · {entry.source}
                </p>
              </div>
            </li>
          ))}
        </ol>
      </Panel>
    </section>
  )
}

function PosturePanel({ detail }: { detail: ExperimentDetail }) {
  const experiment = detail.experiment
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Run posture</h2>
      </div>
      <Panel padded className="flex items-center gap-4">
        <ScoreDial
          posture={{
            score: experiment.riskScore,
            grade: null,
            posture:
              experiment.riskBand === 'critical'
                ? 'critical'
                : experiment.riskBand === 'high'
                  ? 'weak'
                  : experiment.riskBand === 'medium'
                    ? 'needs-review'
                    : 'acceptable',
            affectedSessions: experiment.sessionIds.length,
            lastAssessmentAt: experiment.startedAt ?? new Date(0).toISOString(),
            method: `Risk score recorded for experiment ${experiment.id} at run time.`,
          }}
          size={96}
        />
        <div className="min-w-0 flex-1">
          <KeyValueList
            items={[
              { label: 'Status', value: EXPERIMENT_STATUS_LABEL[experiment.status] },
              { label: 'Risk band', value: experiment.riskBand },
              { label: 'Profile', value: TRAFFIC_PROFILE_LABEL[experiment.trafficProfile] },
              {
                label: 'Duration',
                value: experiment.durationMs === null ? 'Unknown' : `${Math.round(experiment.durationMs / 1000)}s`,
              },
            ]}
          />
          {experiment.status === 'running' ? (
            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-night-800" role="progressbar" aria-valuenow={experiment.progressPercent} aria-valuemin={0} aria-valuemax={100}>
              <span className="block h-full rounded-full bg-accent-400" style={{ width: `${experiment.progressPercent}%` }} />
            </div>
          ) : null}
        </div>
      </Panel>
    </section>
  )
}

function GroundTruthPanel({ detail }: { detail: ExperimentDetail }) {
  const truth = detail.experiment.groundTruth
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Declared ground truth</h2>
        <p className="mt-0.5 text-[11px] text-mist-faint">As declared before the run.</p>
      </div>
      <Panel padded>
        <KeyValueList
          items={[
            { label: 'IKE version', value: `IKEv${truth.ikeVersion}`, mono: true },
            { label: 'VPN mode', value: truth.vpnMode, mono: true },
            { label: 'Encryption', value: truth.encryption, mono: true },
            { label: 'Integrity', value: truth.integrity, mono: true },
            { label: 'DH group', value: truth.dhGroup, mono: true },
            { label: 'PFS', value: truth.perfectForwardSecrecy ? 'Required' : 'Not required' },
            { label: 'IP version', value: truth.ipVersion, mono: true },
            { label: 'Key lifetime', value: `${truth.keyLifetimeSeconds}s`, mono: true },
          ]}
        />
        {truth.expectedFindings.length > 0 ? (
          <div className="mt-3">
            <div className="text-[10.5px] uppercase tracking-wide text-mist-faint">Expected findings</div>
            <ul className="mt-1 flex flex-col gap-0.5 text-[11.5px] text-mist-dim">
              {truth.expectedFindings.map((finding) => (
                <li key={finding}>• {finding}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {truth.notes ? <p className="mt-3 text-[11.5px] leading-relaxed text-mist-dim">{truth.notes}</p> : null}
      </Panel>
    </section>
  )
}

function FindingsPanel({ detail }: { detail: ExperimentDetail }) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Findings raised by this run</h2>
      </div>
      <Panel flush>
        {detail.findings.length === 0 ? (
          <p className="px-4 py-6 text-center text-xs text-mist-faint">No findings were raised by this run.</p>
        ) : (
          <ul className="divide-y divide-edge/60">
            {detail.findings.map((finding) => (
              <li key={finding.id} className="flex flex-col gap-1 px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityTag severity={finding.severity} />
                  <Badge tone="muted">{finding.status}</Badge>
                  <ConfidenceTag confidence={finding.confidence} />
                </div>
                <Link to={`/findings/${finding.id}`} className="text-[12.5px] text-mist hover:text-accent-300">
                  {finding.title}
                </Link>
                <span className="font-mono text-[10.5px] text-mist-faint">{finding.id}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </section>
  )
}

function ArtefactsPanel({ detail }: { detail: ExperimentDetail }) {
  const experiment: Experiment = detail.experiment
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Artefacts</h2>
      </div>
      <Panel padded>
        <KeyValueList
          items={[
            {
              label: 'Sessions',
              value:
                experiment.sessionIds.length === 0 ? (
                  'None'
                ) : (
                  <span className="flex flex-col gap-0.5">
                    {experiment.sessionIds.map((id) => (
                      <Link key={id} to={`/vpn-sessions/${id}`} className="font-mono text-[11px] text-mist-dim hover:text-accent-300">
                        {id}
                      </Link>
                    ))}
                  </span>
                ),
            },
            {
              label: 'Captures',
              value:
                experiment.captureIds.length === 0 ? (
                  'None'
                ) : (
                  <span className="font-mono text-[11px] text-mist-dim">{experiment.captureIds.join(', ')}</span>
                ),
            },
            { label: 'Configuration source', value: <ConfigurationValues values={detail.configuration} /> },
          ]}
        />
        <div className="mt-3">
          <details>
            <summary className="cursor-pointer text-[11px] text-mist-dim">Raw experiment record</summary>
            <pre className="json mt-2 max-h-64 overflow-auto text-[10.5px]">{JSON.stringify(detail.raw, null, 2)}</pre>
          </details>
        </div>
      </Panel>
    </section>
  )
}

function ConfigurationValues({ values }: { values: ExperimentDetail['configuration'] }) {
  if (values.length === 0) return <span className="text-mist-faint">No configuration was parsed from the capture.</span>
  return (
    <ul className="flex flex-col gap-0.5">
      {values.map((entry) => (
        <li key={entry.label} className="flex items-baseline gap-2">
          <span className="font-mono text-[10.5px] text-mist-faint">{entry.label}</span>
          <span className="font-mono text-[11px] text-mist-dim">{entry.value.value}</span>
        </li>
      ))}
    </ul>
  )
}
