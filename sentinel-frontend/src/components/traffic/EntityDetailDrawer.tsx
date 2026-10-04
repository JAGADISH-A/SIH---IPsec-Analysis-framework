import { useMemo, useState } from 'react'
import { getAssessment, getAssessmentDrift, getFindingExplanation, getEvidenceIntegrity } from '@/api/analytics'
import { generateReport } from '@/api/reports'
import { AiExplainer } from '@/components/packet/AiExplainer'
import { useResource } from '@/hooks/useResource'
import { EmptyState, ErrorState, LoadingPanel, Spinner } from '@/components/states'
import { Panel, SeverityBadge, StatusPill, Tag } from '@/components/ui'
import {
  CustodySteps,
  DetailLink,
  EvidenceList,
  NotObservable,
  ProvenanceChip,
  ProvenanceValue,
  RiskBand,
} from './parts'
import { comparisonStyle, formatNumber, formatUtc, humanize } from '@/lib/format'
import type { TrafficRow } from '@/lib/traffic'
import type { EvidenceIntegrity, EvidenceRef, ReportKind, ReportResult } from '@/types'

type Tab = 'security' | 'ml' | 'evidence' | 'custody' | 'drift'

const TABS: { id: Tab; label: string }[] = [
  { id: 'security', label: 'Security' },
  { id: 'ml', label: 'ML' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'custody', label: 'Custody' },
  { id: 'drift', label: 'Drift' },
]

/* ------------------------------------------------------------- AI boundary */

/**
 * The AI control in the traffic drawer.
 *
 * The same `AiExplainer` the packet investigation surface uses, so an analyst
 * who has learned to read the four origin chips in one place meets the same
 * four in the other. Only the report control remains local to this drawer.
 */
function AiBoundary({
  assessmentId,
  experimentId,
  severity,
  hasEvidence,
}: {
  assessmentId: string
  /** From the fetched bundle; absent rather than guessed when not known. */
  experimentId: string | null
  severity: string | null
  hasEvidence: boolean
}) {
  const [report, setReport] = useState<ReportResult | null>(null)
  const [busy, setBusy] = useState(false)

  const makeReport = async (kind: ReportKind) => {
    setBusy(true)
    try {
      setReport(await generateReport({ kind, entityId: assessmentId }))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-3">
      <AiExplainer
        assessmentId={assessmentId}
        experimentId={experimentId}
        severity={severity}
        hasEvidence={hasEvidence}
        compact
      />

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => makeReport('assessment')}
          disabled={busy}
          className="inline-flex items-center gap-2 rounded-md border border-edge bg-panel-2 px-3 py-1.5 text-sm text-ink-dim transition-colors hover:text-ink disabled:opacity-50"
        >
          Generate report
        </button>
      </div>

      {report ? (
        <div className="rounded-md border border-edge bg-panel p-3">
          <p className="text-sm font-medium text-ink-dim">
            No {report.kind} report was produced
          </p>
          <p className="mt-1.5 text-sm leading-relaxed text-ink-faint">{report.reason}</p>
        </div>
      ) : null}
    </div>
  )
}

/* ----------------------------------------------------------------- drawer */

type Props = {
  row: TrafficRow | null
  frozen: boolean
  /**
   * True when the row is no longer in the live buffer and the drawer is
   * showing the snapshot taken at selection time. Stated in the UI rather
   * than left to look live.
   */
  held?: boolean
  onClose: () => void
}

export function EntityDetailDrawer({ row, frozen, held = false, onClose }: Props) {
  const [tab, setTab] = useState<Tab>('security')
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRef | null>(null)
  const [showAi, setShowAi] = useState(false)

  const assessmentId = row?.assessment?.assessment_id ?? null
  const bundle = useResource(
    (signal) => getAssessment(assessmentId as string, signal),
    { enabled: assessmentId !== null, deps: [assessmentId] },
  )
  const drift = useResource(
    (signal) => getAssessmentDrift(assessmentId as string, signal),
    { enabled: assessmentId !== null, deps: [assessmentId] },
  )

  // The custody chain is addressed by (assessment, finding); the first finding
  // is the one the assessment's own risk engine raised first.
  const firstFinding = row?.findings[0] ?? null
  const custody = useResource(
    (signal) =>
      getFindingExplanation(assessmentId as string, firstFinding!.finding_id, signal),
    {
      enabled: assessmentId !== null && firstFinding !== null,
      deps: [assessmentId, firstFinding?.finding_id],
    },
  )

  const evidenceId = selectedEvidence?.evidence_id ?? null
  const integrity = useResource(
    (signal) => getEvidenceIntegrity(evidenceId as string, signal),
    { enabled: evidenceId !== null, deps: [evidenceId] },
  )

  const sections = useMemo(() => {
    const data = bundle.data
    if (!data) return null
    const expected = data.expected
    const observed = data.observed
    const comparison = data.correlation
    return { data, expected, observed, comparison }
  }, [bundle.data])

  if (!row) {
    return (
      <Panel title="Entity Detail" subtitle="no selection" className="h-full">
        <EmptyState
          title="Select an event to inspect it"
          icon="search"
          description="Pick any row in the live monitor. The drawer opens against the assessment that event belongs to, and shows the security, ML, evidence, custody and drift state the backend actually recorded for it."
        />
      </Panel>
    )
  }

  const { event, assessment } = row

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <Panel
        title={
          <span className="flex items-center gap-2">
            <span className="mono truncate">{assessment ? `#${assessment.sequence} ${assessment.slot}` : 'unmatched event'}</span>
            {row.inherited.severity && (
              <SeverityBadge severity={row.inherited.severity} size="sm" />
            )}
          </span>
        }
        subtitle={
          assessment
            ? `${assessment.configuration_id} · ${assessment.mode} · ${assessment.address_family}`
            : 'This event does not match an assessment in the store'
        }
        action={
          <div className="flex items-center gap-1.5">
            {held && <Tag tone="neutral">held</Tag>}
            {frozen && <Tag tone="neutral">frozen</Tag>}
            <button
              type="button"
              onClick={onClose}
              className="rounded border border-edge bg-panel-2 px-2 py-1 text-xs text-ink-dim transition-colors hover:text-ink"
              aria-label="Close detail"
            >
              Close
            </button>
          </div>
        }
      >
        <div className="space-y-3 p-3.5">
          {held && (
            <p className="rounded-md border border-edge bg-panel-2 px-3 py-2 text-sm text-ink-dim">
              This event has scrolled out of the live buffer. The panel is showing the copy
              captured when you selected it; the assessment, findings and evidence below are
              still fetched live.
            </p>
          )}
          {/* What was selected, and by whom — always stated, never inferred. */}
          <div className="rounded-md border border-edge bg-panel-2 p-2.5">
            <p className="label text-ink-faint">
              Selected audit event
            </p>
            <dl className="mono mt-1.5 grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
              <div className="flex gap-1.5">
                <dt className="text-ink-faint">event</dt>
                <dd className="truncate text-ink-dim" title={event.event_id}>{event.event_id}</dd>
              </div>
              <div className="flex gap-1.5">
                <dt className="text-ink-faint">type</dt>
                <dd className="truncate text-ink-dim">{event.event_type}</dd>
              </div>
              <div className="flex gap-1.5">
                <dt className="text-ink-faint">recorded by</dt>
                <dd className="truncate text-ink-dim">{event.source}</dd>
              </div>
              <div className="flex gap-1.5">
                <dt className="text-ink-faint">at</dt>
                <dd className="truncate text-ink-dim">{formatUtc(event.recorded_at)}</dd>
              </div>
              <div className="flex gap-1.5">
                <dt className="text-ink-faint">window</dt>
                <dd className="truncate text-ink-dim">
                  {event.window_index ?? '—'} · {formatUtc(event.window_start_ns)}
                </dd>
              </div>
              <div className="flex gap-1.5">
                <dt className="text-ink-faint">authority</dt>
                <dd className={event.authoritative ? 'text-good' : 'text-ink-faint'}>
                  {event.authoritative ? 'authoritative' : 'derived, not authoritative'}
                </dd>
              </div>
            </dl>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={() => setShowAi((value) => !value)}
              className="rounded border border-edge bg-panel-2 px-2 py-1 text-xs text-ink-dim transition-colors hover:text-ink"
            >
              {showAi ? 'Hide' : 'Show'} AI explanation
            </button>
            {assessment && (
              <DetailLink to={`/assessments/${encodeURIComponent(assessment.assessment_id)}`}>
                Open full assessment →
              </DetailLink>
            )}
          </div>

          {showAi && assessmentId ? (
            <AiBoundary
              assessmentId={assessmentId}
              experimentId={bundle.data?.identity.experiment_id ?? null}
              severity={
                bundle.data?.risk.severity ?? row?.assessment?.severity ?? null
              }
              hasEvidence={
                (bundle.data?.evidence?.total_refs ?? 0) > 0 ||
                (row?.assessment?.finding_count ?? 0) > 0
              }
            />
          ) : null}
        </div>
      </Panel>

      <div className="flex shrink-0 gap-1 border-b border-edge">
        {TABS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            onClick={() => setTab(entry.id)}
            className={`-mb-px border-b-2 px-2.5 py-1.5 text-sm transition-colors ${
              tab === entry.id
                ? 'border-sentinel text-sentinel'
                : 'border-transparent text-ink-faint hover:text-ink-dim'
            }`}
          >
            {entry.label}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto pr-1">
        {bundle.loading ? (
          <LoadingPanel label="Loading assessment" rows={4} />
        ) : bundle.error ? (
          <ErrorState error={bundle.error} onRetry={bundle.reload} />
        ) : !sections ? (
          <EmptyState title="No assessment bundle" />
        ) : tab === 'security' ? (
          <div className="space-y-3">
            <Panel title="Risk" subtitle="read verbatim from the backend risk engine">
              <div className="p-3.5">
                <RiskBand
                  score={sections.data.risk.overall_score}
                  severity={sections.data.risk.severity}
                  policyVersion={sections.data.risk.risk_policy_version}
                  contributions={sections.data.risk.score_detail?.contributions?.map((c) => ({
                    severity: c.severity,
                    weight: c.weight,
                    added: c.added,
                    finding_id: c.finding_id,
                  }))}
                />
              </div>
            </Panel>

            <Panel title="Expected vs observed" subtitle="configuration intent against what the capture recorded">
              <div className="overflow-x-auto">
                <table className="data-table min-w-[420px]">
                  <thead>
                    <tr className="bg-panel-2 text-left">
                      {['Variable', 'Expected', 'Observed', 'Status'].map((heading) => (
                        <th
                          key={heading}
                          className="px-2.5 py-1.5 label text-ink-faint"
                        >
                          {heading}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sections.comparison.rows.map((row2) => {
                      const style = comparisonStyle(row2.status)
                      return (
                        <tr key={row2.variable} className="border-t border-edge-soft align-top">
                          <td className="mono px-2.5 py-1.5 text-xs text-ink-dim">
                            {row2.variable}
                          </td>
                          <td className="px-2.5 py-1.5 text-xs text-ink-faint">
                            {formatValueCell(row2.expected_value)}
                          </td>
                          <td className="px-2.5 py-1.5 text-xs text-ink-dim">
                            {formatValueCell(row2.observed_value)}
                          </td>
                          <td className={`px-2.5 py-1.5 text-xs ${style.text}`}>
                            {humanize(row2.status)}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </Panel>

            <Panel title="IPsec state" subtitle="observed association and SA metadata">
              <div className="grid grid-cols-2 gap-3 p-3.5">
                <ProvenanceValue provenance="OBSERVED" label="IKE seen">
                  {sections.observed.ike_seen === undefined ? 'Not observable' : String(sections.observed.ike_seen)}
                </ProvenanceValue>
                <ProvenanceValue provenance="OBSERVED" label="ESP seen">
                  {sections.observed.esp_seen === undefined ? 'Not observable' : String(sections.observed.esp_seen)}
                </ProvenanceValue>
                <ProvenanceValue provenance="OBSERVED" label="Packets observed">
                  {formatNumber(sections.observed.packets_seen ?? null)}
                </ProvenanceValue>
                <ProvenanceValue provenance="OBSERVED" label="Active associations">
                  {formatNumber(sections.observed.spis?.length ?? null)}
                </ProvenanceValue>
              </div>
              {sections.observed.spis && sections.observed.spis.length > 0 && (
                <div className="overflow-x-auto border-t border-edge">
                  <table className="data-table min-w-[520px]">
                    <thead>
                      <tr className="bg-panel-2 text-left">
                        {['SPI', 'Direction', 'Active', 'Packets', 'First seen', 'Last seen'].map((heading) => (
                          <th
                            key={heading}
                            className="px-2.5 py-1.5 label text-ink-faint"
                          >
                            {heading}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {sections.observed.spis.map((spi) => (
                        <tr key={spi.spi} className="border-t border-edge-soft">
                          <td className="mono px-2.5 py-1.5 text-xs text-ink-dim">{spi.spi}</td>
                          <td className="px-2.5 py-1.5 text-xs text-ink-faint">{spi.direction}</td>
                          <td className="px-2.5 py-1.5 text-xs text-ink-dim">{String(spi.active)}</td>
                          <td className="mono tnum px-2.5 py-1.5 text-xs text-ink-dim">
                            {formatNumber(spi.packet_count)}
                          </td>
                          <td className="mono px-2.5 py-1.5 text-xs text-ink-faint">
                            {formatUtc(spi.first_seen_ns)}
                          </td>
                          <td className="mono px-2.5 py-1.5 text-xs text-ink-faint">
                            {formatUtc(spi.last_seen_ns)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
          </div>
        ) : tab === 'ml' ? (
          <Panel
            title="ML classification"
            subtitle="flow and window scoped — never a per-packet verdict"
            className="h-full"
          >
            <div className="space-y-3 p-3.5">
              <div className="rounded border border-medium/30 bg-medium/[0.06] p-2.5 text-xs leading-relaxed text-ink-dim">
                This classification applies to the <strong>flow and analysis window</strong>, not
                to any individual encrypted packet. There is no per-packet ML label in this
                system, and none is implied.
              </div>
              <div className="grid grid-cols-2 gap-3">
                <ProvenanceValue provenance="MODEL-DERIVED" label="Model version">
                  {sections.data.ml.model_version ?? 'Not observable'}
                </ProvenanceValue>
                <ProvenanceValue provenance="MODEL-DERIVED" label="Traffic class">
                  {sections.data.ml.traffic_class ?? 'Not observable'}
                </ProvenanceValue>
                <ProvenanceValue provenance="MODEL-DERIVED" label="Anomaly">
                  {sections.data.ml.anomaly === null ? 'Not observable' : String(sections.data.ml.anomaly)}
                </ProvenanceValue>
                <ProvenanceValue provenance="MODEL-DERIVED" label="Anomaly score">
                  {sections.data.ml.anomaly_score === null ? 'Not observable' : sections.data.ml.anomaly_score}
                </ProvenanceValue>
                <ProvenanceValue provenance="MODEL-DERIVED" label="Classification confidence">
                  {sections.data.ml.classification_confidence === null
                    ? 'Not observable'
                    : sections.data.ml.classification_confidence}
                </ProvenanceValue>
                <ProvenanceValue provenance="OBSERVED" label="ML present">
                  {String(sections.data.ml.present)}
                </ProvenanceValue>
              </div>
              {sections.data.ml.reason && (
                <p className="text-sm leading-relaxed text-ink-faint">
                  {sections.data.ml.reason}
                </p>
              )}
              {sections.data.xai.ml_explanations.length > 0 && (
                <div className="space-y-2">
                  <p className="label text-ink-faint">
                    Model explanation
                  </p>
                  {sections.data.xai.ml_explanations.map((explanation, index) => (
                    <div key={index} className="rounded-md border border-edge bg-panel-2 p-2.5">
                      <p className="text-sm leading-relaxed text-ink-dim">{explanation.explanation}</p>
                      {explanation.limitations.length > 0 && (
                        <ul className="mt-1.5 space-y-0.5 text-xs text-ink-faint">
                          {explanation.limitations.map((limitation, i) => (
                            <li key={i}>— {limitation}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Panel>
        ) : tab === 'evidence' ? (
          <div className="space-y-3">
            <Panel title="Evidence references" subtitle="recorded artifacts backing this assessment">
              <div className="p-3.5">
                <EvidenceList
                  refs={sections.data.evidence.refs}
                  onSelect={setSelectedEvidence}
                  selectedId={selectedEvidence?.evidence_id ?? null}
                />
                {sections.data.evidence.sources && sections.data.evidence.sources.length > 0 && (
                  <p className="mono mt-2 text-xs text-ink-faint">
                    sources: {sections.data.evidence.sources.join(', ')}
                  </p>
                )}
              </div>
            </Panel>
            <Panel title="Integrity" subtitle="read-only; digests are never recomputed in the browser">
              <div className="space-y-2.5 p-3.5">
                {integrity.loading ? (
                  <Spinner />
                ) : integrity.error?.isNotFound ? (
                  // A reference on a finding and an artifact the registry can
                  // serve are different things. This is a normal state, not a
                  // failure, and it must not read as a verification problem.
                  <div className="rounded-md border border-edge bg-panel-2 p-2.5">
                    <p className="flex items-center gap-1.5 text-sm font-medium text-ink-dim">
                      <ProvenanceChip provenance="REPORTED" />
                      Artifact not available
                    </p>
                    <p className="mt-1.5 text-sm leading-relaxed text-ink-faint">
                      {integrity.error.detail} This finding records a reference to it, but the
                      evidence registry cannot serve the bytes, so its contents and digest cannot
                      be verified here. That is a statement about availability, not about
                      integrity.
                    </p>
                  </div>
                ) : integrity.error ? (
                  <ErrorState error={integrity.error} onRetry={integrity.reload} compact />
                ) : integrity.data ? (
                  <IntegrityRecord record={integrity.data as EvidenceIntegrity} />
                ) : selectedEvidence ? (
                  <p className="text-sm text-ink-faint">
                    This reference carries no evidence id, so the read-only integrity endpoint cannot
                    address it. The artifact digest shown above is the one recorded with the
                    finding.
                  </p>
                ) : (
                  <NotObservable what="no artifact has been selected for verification" />
                )}
              </div>
            </Panel>
          </div>
        ) : tab === 'custody' ? (
          <Panel title="Chain of custody" subtitle="how this finding was reached, in recorded order">
            <div className="space-y-3 p-3.5">
              {custody.loading ? (
                <LoadingPanel label="Loading custody chain" rows={3} />
              ) : custody.error ? (
                <ErrorState error={custody.error} onRetry={custody.reload} />
              ) : custody.data ? (
                <>
                  <div>
                    <p className="text-sm leading-relaxed text-ink">{custody.data.summary}</p>
                    {custody.data.finding_digest && (
                      <p className="mono mt-1.5 text-xs text-ink-faint">
                        digest {custody.data.finding_digest}
                      </p>
                    )}
                  </div>
                  <CustodySteps steps={custody.data.steps} />
                  {custody.data.integrity.length > 0 && (
                    <div>
                      <p className="mb-1.5 label text-ink-faint">
                        Integrity checks
                      </p>
                      <ul className="space-y-1">
                        {custody.data.integrity.map((check) => (
                          <li
                            key={check.check_id}
                            className="flex items-start gap-2 text-xs"
                          >
                            <span
                              className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${
                                check.passed ? 'bg-good' : 'bg-critical'
                              }`}
                              aria-hidden="true"
                            />
                            <span className="min-w-0">
                              <span className="text-ink-dim">{check.description}</span>
                              <span className="block text-ink-faint">{check.detail}</span>
                            </span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {custody.data.limitations.length > 0 && (
                    <div>
                      <p className="mb-1 label text-ink-faint">
                        Limitations
                      </p>
                      <ul className="space-y-0.5 text-xs text-ink-faint">
                        {custody.data.limitations.map((limitation, i) => (
                          <li key={i}>— {limitation}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              ) : (
                <NotObservable what="this assessment raised no finding, so there is no custody chain to show. Custody is recorded per finding, not per assessment." />
              )}
            </div>
          </Panel>
        ) : (
          <Panel title="Drift" subtitle="longitudinal comparison against a validated baseline">
            <div className="space-y-3 p-3.5">
              {drift.loading ? (
                <LoadingPanel label="Loading drift" rows={2} />
              ) : drift.error ? (
                <ErrorState error={drift.error} onRetry={drift.reload} />
              ) : drift.data ? (
                drift.data.status === 'not_configured' ? (
                  <div className="rounded border border-medium/30 bg-medium/[0.06] p-3">
                    <p className="text-sm font-medium text-medium">Not configured</p>
                    <p className="mt-1 text-sm leading-relaxed text-ink-dim">
                      {drift.data.reason}
                    </p>
                    <p className="mt-1.5 text-xs text-ink-faint">
                      This is not a finding of &ldquo;no drift&rdquo;. No comparison was made,
                      because a baseline must be established explicitly and is never inferred from
                      the most recent observation.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <StatusPill
                        status={drift.data.status}
                        tone={drift.data.drift_detected ? 'warn' : 'good'}
                        label={drift.data.drift_detected ? 'DRIFT DETECTED' : 'NO DRIFT'}
                      />
                    </div>
                    {drift.data.changed_fields.length > 0 && (
                      <ul className="space-y-1">
                        {drift.data.changed_fields.map((field, index) => (
                          <li key={index} className="rounded-md border border-edge bg-panel-2 p-2 text-xs">
                            <span className="mono text-ink-dim">{field.variable}</span>
                            <span className="block text-ink-faint">
                              {formatValueCell(field.baseline_value)} → {formatValueCell(field.current_value)}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )
              ) : (
                <NotObservable what="no drift record was returned" />
              )}
            </div>
          </Panel>
        )}
      </div>
    </div>
  )
}

function formatValueCell(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function IntegrityRecord({ record }: { record: EvidenceIntegrity }) {
  const verified = record.verification_status === 'verified' || record.verifiable === true
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <StatusPill
          status={record.verification_status ?? 'unknown'}
          tone={verified ? 'good' : record.verification_status === 'mismatch' ? 'bad' : 'neutral'}
          label={(record.verification_status ?? 'UNKNOWN').toUpperCase()}
        />
        {record.artifact_present === false && (
          <Tag className="text-medium">artifact bytes not present</Tag>
        )}
      </div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-xs">
        <div>
          <dt className="label text-ink-faint">Evidence id</dt>
          <dd className="mono truncate text-ink-dim">{record.evidence_id}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">Type</dt>
          <dd className="text-ink-dim">{record.artifact_type ?? 'Not observable'}</dd>
        </div>
        <div>
          <dt className="label text-ink-faint">Recorded digest</dt>
          <dd className="mono truncate text-ink-dim">
            {record.artifact_sha256 ? record.artifact_sha256.slice(0, 20) : 'Not observable'}
          </dd>
        </div>
        <div>
          <dt className="label text-ink-faint">Recomputed digest</dt>
          <dd className="mono truncate text-ink-dim">
            {record.actual_sha256 ? record.actual_sha256.slice(0, 20) : 'Not observable'}
          </dd>
        </div>
      </dl>
      {record.verification_detail && (
        <p className="text-sm leading-relaxed text-ink-faint">{record.verification_detail}</p>
      )}
      <p className="text-xs leading-relaxed text-ink-faint">
        Verification is performed by the backend over the stored artifact. Sentinel never hashes a
        file in the browser, and never marks an artifact verified on its own authority.
      </p>
    </div>
  )
}
