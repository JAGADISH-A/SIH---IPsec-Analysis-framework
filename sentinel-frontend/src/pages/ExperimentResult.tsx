import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { getExperiment } from '@/api/control'
import { useJobPolling, useResource } from '@/hooks/useResource'
import { ErrorState, LoadingPanel } from '@/components/states'
import { Button, LinkButton, Panel, StatusPill, Tag } from '@/components/ui'
import { acronymLabel, declaredValueLabel, statusLabel } from '@/lib/labels'
import { Breadcrumbs, PageHeader } from '@/layouts/AppLayout'
import { IdRow, ProvenanceDetails } from '@/components/kit'
import { EXPERIMENT_POLL_MS } from '@/config'
import { formatNumber, humanize } from '@/lib/format'
import { STAGE_SEQUENCE } from './RunAssessment'
import type { ExperimentJob, ExperimentResultPayload } from '@/types'

/** The payload `controller.executor.run_experiment` returns. */
type ResultShape = ExperimentResultPayload

/**
 * The run's progress, as the stages an analyst thinks in.
 *
 * The control plane reports a `stage` token; `STAGE_SEQUENCE` maps each token
 * to a human step, so the two never drift apart. The current step is marked with
 * a check for what is done, a filled marker for what is happening now, and an
 * empty marker for what has not started.
 */
function StageTracker({ stage, done }: { stage: string; done: boolean }) {
  const index = STAGE_SEQUENCE.findIndex((entry) => entry.key === stage)
  const activeIndex = index === -1 ? (done ? STAGE_SEQUENCE.length - 1 : 0) : index

  return (
    <ol className="p-4">
      {STAGE_SEQUENCE.map((step, position) => {
        const complete = position < activeIndex || (done && position <= activeIndex)
        const current = position === activeIndex && !done
        return (
          <li key={step.key} className="relative flex gap-3 pb-4 last:pb-0">
            {position < STAGE_SEQUENCE.length - 1 && (
              <span
                className={`absolute left-[11px] top-6 h-full w-px ${
                  complete ? 'bg-sentinel/30' : 'bg-edge'
                }`}
                aria-hidden="true"
              />
            )}
            <span
              className={`relative z-10 flex h-[23px] w-[23px] shrink-0 items-center justify-center rounded-full border text-xs ${
                complete
                  ? 'border-sentinel/30 bg-sentinel/10 text-sentinel'
                  : current
                    ? 'border-sentinel bg-sentinel/15 text-sentinel'
                    : 'border-edge bg-panel text-ink-faint'
              }`}
            >
              {complete ? (
                <svg viewBox="0 0 12 12" className="h-3 w-3" fill="none">
                  <path
                    d="m2.5 6.2 2.3 2.3 4.7-5"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              ) : (
                position + 1
              )}
            </span>
            <span className="min-w-0 pt-0.5">
              <span
                className={`block text-base ${
                  current
                    ? 'font-medium text-ink'
                    : complete
                      ? 'text-ink-dim'
                      : 'text-ink-faint'
                }`}
              >
                {step.label}
              </span>
              <span className="block text-sm text-ink-faint">{step.detail}</span>
            </span>
          </li>
        )
      })}
    </ol>
  )
}

function ResultValue({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="text-ink-faint">—</span>
  if (typeof value === 'boolean') {
    return <span className={value ? 'text-good' : 'text-ink-dim'}>{value ? 'yes' : 'no'}</span>
  }
  if (typeof value === 'number') return <span className="mono tnum">{formatNumber(value)}</span>
  if (typeof value === 'object') {
    return (
      <pre className="code-block max-h-48 overflow-auto whitespace-pre-wrap break-all p-2">
        {JSON.stringify(value, null, 2)}
      </pre>
    )
  }
  return <span className="mono text-sm">{String(value)}</span>
}

function ResultTable({ title, data }: { title: string; data: Record<string, unknown> }) {
  const entries = Object.entries(data)
  if (entries.length === 0) return null
  return (
    <div>
      <p className="label mb-2">{title}</p>
      <dl className="space-y-1.5">
        {entries.map(([key, value]) => (
          <div
            key={key}
            className="flex flex-wrap items-baseline gap-x-3 border-b border-edge-soft pb-1.5"
          >
            <dt className="mono w-40 shrink-0 text-xs text-ink-faint">{key}</dt>
            <dd className="min-w-0 flex-1 text-sm">
              <ResultValue value={value} />
            </dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

/**
 * The result of one run.
 *
 * Polls the job until it is terminal, then reports what the control plane
 * actually returned. A lab result (connectivity, SA verification) is a different
 * artifact from a security assessment (risk, findings, evidence), so the hand-off
 * between them is explicit rather than implied — Sentinel does not present a
 * passing tunnel as a passing assessment.
 */
export function ExperimentResult() {
  const { jobId = '' } = useParams()
  const [live, setLive] = useState<ExperimentJob | null>(null)

  const resource = useResource(
    (signal) => getExperiment(jobId, signal),
    { enabled: jobId !== '', deps: [jobId] },
  )

  useJobPolling(jobId || null, (job) => setLive(job), EXPERIMENT_POLL_MS)

  useEffect(() => {
    if (resource.data) setLive((current) => current ?? resource.data)
  }, [resource.data])

  const job = live ?? resource.data
  const running = job?.status === 'QUEUED' || job?.status === 'RUNNING'
  const failed = job?.status === 'FAILED'
  const completed = job?.status === 'COMPLETED'
  const result = (job?.result ?? null) as ResultShape | null

  return (
    <div className="space-y-5">
      <Breadcrumbs
        trail={[
          { to: '/run', label: 'Run Assessment' },
          { label: jobId || 'unknown run' },
        ]}
      />

      {resource.loading && <LoadingPanel label="Loading run status" rows={5} />}

      {resource.error && !job && (
        <div className="space-y-3">
          <ErrorState error={resource.error} onRetry={resource.reload} />
          <LinkButton to="/run" variant="secondary">
            ← Back to Run Assessment
          </LinkButton>
        </div>
      )}

      {job && (
        <>
          <PageHeader
            title={
              completed
                ? 'Assessment run complete'
                : failed
                  ? 'Assessment run failed'
                  : 'Assessment in progress'
            }
            description={
              completed
                ? 'The lab finished and reported its result. The scored assessment is a separate artifact in the analytics store.'
                : failed
                  ? 'The run stopped before completing. The stage below shows where.'
                  : 'This page updates itself as the run advances; no refresh needed.'
            }
            actions={
              running ? undefined : (
                <LinkButton to="/run" variant="secondary">
                  Run another assessment
                </LinkButton>
              )
            }
          />

          <div className="flex flex-wrap items-center gap-2">
            <StatusPill
              status={job.status}
              // The headline state is a human state; the control-plane token
              // stays available in the run provenance disclosure.
              label={statusLabel(job.status.toLowerCase())}
              tone={completed ? 'good' : failed ? 'bad' : running ? 'info' : 'neutral'}
            />
            <span className="mono text-xs text-ink-faint">{job.job_id}</span>
            {running && (
              <span className="flex items-center gap-1.5 text-xs text-ink-faint">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-sentinel" />
                checking every {EXPERIMENT_POLL_MS / 1000}s
              </span>
            )}
            {result && (
              <>
                <StatusPill
                  status={result.status ?? 'unknown'}
                  tone={
                    result.status === 'PASS' ? 'good' : result.status === 'FAIL' ? 'bad' : 'neutral'
                  }
                  label={`lab result ${result.status ?? 'unknown'}`}
                />
                {result.mode && <Tag>{declaredValueLabel(result.mode)} mode</Tag>}
                {result.address_family && <Tag>{acronymLabel(result.address_family)}</Tag>}
              </>
            )}
          </div>

          {failed && job.error && (
            <div className="panel border-critical/25 p-4">
              <p className="text-sm font-semibold text-critical">Run error</p>
              <p className="mt-1 text-sm leading-relaxed text-ink-dim">{job.error}</p>
            </div>
          )}

          <div className="grid gap-5 lg:grid-cols-3">
            <div className="space-y-5 lg:col-span-2">
              {result ? (
                <Panel title="Lab result" subtitle="Reported by the testbed runner">
                  <div className="space-y-5 p-4">
                    {result.ipsec && (
                      <div>
                        <p className="label mb-2">Observed security association</p>
                        <dl className="grid grid-cols-2 gap-x-5 gap-y-3 sm:grid-cols-3">
                          {(
                            [
                              ['IKE SA', result.ipsec.ike_sa, 'text-good'],
                              ['Child SA', result.ipsec.child_sa, 'text-good'],
                              ['Mode', result.ipsec.mode, 'text-ink'],
                            ] as const
                          ).map(([label, value, tone]) => (
                            <div key={label}>
                              <dt className="label">{label}</dt>
                              <dd className={`mono mt-0.5 text-sm ${tone}`}>{value ?? '—'}</dd>
                            </div>
                          ))}
                        </dl>
                      </div>
                    )}

                    {result.connectivity && (
                      <div>
                        <p className="label mb-2">Connectivity</p>
                        <div className="flex flex-wrap items-center gap-4">
                          <StatusPill
                            status={result.connectivity.status ?? 'unknown'}
                            label={`Connectivity ${result.connectivity.status ?? 'unknown'}`}
                            tone={result.connectivity.status === 'PASS' ? 'good' : 'bad'}
                          />
                          <span className="tnum text-sm text-ink-dim">
                            packet loss{' '}
                            {result.connectivity.packet_loss !== undefined
                              ? `${result.connectivity.packet_loss}%`
                              : '—'}
                          </span>
                        </div>
                      </div>
                    )}

                    <div className="grid gap-5 border-t border-edge-soft pt-4 md:grid-cols-2">
                      {result.ike && <ResultTable title="IKE configuration" data={result.ike} />}
                      {result.esp && <ResultTable title="ESP configuration" data={result.esp} />}
                    </div>

                    {result.traffic && (
                      <div className="border-t border-edge-soft pt-4">
                        <ResultTable
                          title="Traffic generation"
                          data={result.traffic as Record<string, unknown>}
                        />
                      </div>
                    )}

                    <details className="group border-t border-edge-soft pt-4">
                      <summary className="cursor-pointer list-none text-sm font-medium text-ink-dim transition-colors hover:text-ink">
                        <span className="group-open:hidden">Show raw result</span>
                        <span className="hidden group-open:inline">Hide raw result</span>
                      </summary>
                      <pre className="code-block mt-2 max-h-64 overflow-auto p-3">
                        {JSON.stringify(result, null, 2)}
                      </pre>
                    </details>
                  </div>
                </Panel>
              ) : running ? (
                <Panel title="Waiting for the testbed">
                  <p className="p-4 text-sm leading-relaxed text-ink-dim">
                    The run is at the {humanize(job.stage).toLowerCase()} stage. The control
                    plane reports progress as the topology is deployed, the IPsec
                    configuration is loaded, the security association is verified, and
                    traffic is generated.
                  </p>
                </Panel>
              ) : null}

              <Panel
                title="Next: review the assessment"
                subtitle="A passing tunnel is not a passing assessment — risk, findings and evidence are scored separately"
              >
                <div className="space-y-3 p-4">
                  <p className="text-sm leading-relaxed text-ink-dim">
                    {completed
                      ? 'The run finished and its capture is scored by the deterministic pipeline. The resulting assessment carries the risk score, findings, evidence and explanation.'
                      : 'Once the run completes, its capture is analysed and appears in the assessment store.'}
                  </p>
                  <div className="flex flex-wrap items-center gap-2">
                    <LinkButton to="/assessments" variant="primary">
                      View Assessments
                    </LinkButton>
                    <LinkButton to="/findings" variant="secondary">
                      Browse findings
                    </LinkButton>
                    <LinkButton to="/evidence" variant="ghost">
                      Evidence library
                    </LinkButton>
                    <LinkButton to="/explainability" variant="ghost">
                      Explanations
                    </LinkButton>
                  </div>
                </div>
              </Panel>
            </div>

            <div className="space-y-5">
              <Panel title="Progress" subtitle={running ? 'live' : job.status.toLowerCase()}>
                <StageTracker stage={job.stage} done={completed} />
              </Panel>

              <Panel title="Run details">
                <dl className="space-y-2 p-4 text-sm">
                  <div className="flex items-center justify-between gap-2">
                    <dt className="text-ink-faint">Status</dt>
                    <dd className="text-ink">
                      {failed ? 'Failed' : completed ? 'Completed' : humanize(job.status)}
                    </dd>
                  </div>
                  <div className="flex items-baseline justify-between gap-2">
                    <dt className="text-ink-faint">Stage</dt>
                    <dd className="text-right text-ink">
                      {STAGE_SEQUENCE.find((entry) => entry.key === job.stage)?.label ??
                        humanize(job.stage)}
                    </dd>
                  </div>
                </dl>
                <div className="border-t border-edge-soft p-3">
                  <ProvenanceDetails title="Run provenance">
                    <IdRow label="Run id" value={job.job_id} title={job.job_id} />
                    <IdRow label="Status token" value={job.status} title={job.status} />
                    <IdRow label="Stage token" value={job.stage} title={job.stage} />
                  </ProvenanceDetails>
                </div>
                <div className="border-t border-edge-soft p-3">
                  <Button variant="secondary" className="w-full" onClick={resource.reload}>
                    {resource.refreshing ? 'Refreshing…' : 'Refresh now'}
                  </Button>
                </div>
              </Panel>

              <Panel>
                <p className="label px-4 pt-4">Note</p>
                <p className="px-4 pb-4 pt-1.5 text-sm leading-relaxed text-ink-faint">
                  Run state is held in the control plane&apos;s memory. Restarting that
                  service clears it; the assessment store is unaffected because it is built
                  from recorded artifacts.
                </p>
              </Panel>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
