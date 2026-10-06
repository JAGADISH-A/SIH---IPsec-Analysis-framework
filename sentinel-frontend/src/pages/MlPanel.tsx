import { Panel, Tag, Prose } from '@/components/ui'
import { EmptyState } from '@/components/states'
import { formatPercent } from '@/lib/format'
import { trafficLabel } from '@/lib/labels'
import { IdRow, ProvenanceDetails } from '@/components/kit'
import type { AssessmentBundle } from '@/types'

/**
 * ML analysis, rendered strictly from what `bundle.ml` actually contains.
 *
 * The ML result is model-derived inference. The backend is explicit that it is
 * never an authoritative protocol observation, so this panel repeats that
 * rather than presenting a classification as a measured fact. Fields the
 * backend did not return are omitted rather than filled in.
 */
export function MlPanel({ bundle }: { bundle: AssessmentBundle }) {
  const ml = bundle.ml
  const present = ml?.present === true
  const explanation = bundle.xai?.ml_explanations?.[0]
  const relatedFindings = (bundle.risk?.findings ?? []).filter(
    (finding) => finding.source === 'ML' || finding.category.includes('ML_'),
  )

  return (
    <div className="space-y-4">
      {!present ? (
        <Panel title="ML Analysis" subtitle="traffic classification result">
          <EmptyState
            title="No ML result for this assessment"
            description={
              ml?.reason ??
              'The backend reports that ML was not executed for this assessment, so no classification, confidence or feature data exists.'
            }
            icon="inbox"
          />
        </Panel>
      ) : (
        <>
          <Panel
            title="Traffic Classification"
            subtitle="what the model inferred about this traffic"
          >
            <div className="grid grid-cols-2 gap-x-5 gap-y-5 p-4 md:grid-cols-3">
              <div>
                <p className="label text-ink-faint">Prediction</p>
                <p className="mt-1 text-2xl leading-none text-low">
                  {ml.traffic_class ? trafficLabel(ml.traffic_class) : '—'}
                </p>
              </div>
              <div>
                <p className="label text-ink-faint">
                  Confidence
                </p>
                <p className="mono tnum mt-1 text-2xl leading-none text-ink">
                  {ml.classification_confidence !== null &&
                  ml.classification_confidence !== undefined
                    ? formatPercent(ml.classification_confidence)
                    : '—'}
                </p>
                {ml.classification_confidence !== null &&
                  ml.classification_confidence !== undefined && (
                    <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-panel-2">
                      <div
                        className="h-full rounded-full bg-low"
                        style={{
                          width: `${Math.max(2, Math.min(100, ml.classification_confidence * 100))}%`,
                        }}
                      />
                    </div>
                  )}
              </div>
              <div>
                <p className="label text-ink-faint">Anomaly</p>
                <p className="mono mt-1 text-2xl leading-none text-ink">
                  {ml.anomaly === null || ml.anomaly === undefined
                    ? '—'
                    : ml.anomaly
                      ? 'true'
                      : 'false'}
                </p>
                <p className="mt-1 text-xs text-ink-faint">
                  score{' '}
                  {ml.anomaly_score !== null && ml.anomaly_score !== undefined
                    ? ml.anomaly_score
                    : 'not reported'}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 border-t border-edge px-4 py-3">
              <Tag className="border-low/30 bg-low/5 text-low">model-derived</Tag>
              <span className="text-xs text-ink-faint">
                A classification is inference about traffic, not a measured protocol fact.
              </span>
              {ml.model_version && (
                <ProvenanceDetails title="Model provenance">
                  <IdRow label="Model version" value={ml.model_version} title={ml.model_version} />
                </ProvenanceDetails>
              )}
            </div>
          </Panel>

          <Panel
            title="Expected Profile"
            subtitle="what the traffic generator was configured to produce"
          >
            <div className="grid grid-cols-2 gap-x-5 gap-y-4 p-4">
              <div>
                <p className="label text-ink-faint">
                  Planned profile
                </p>
                <p className="mt-0.5 text-base text-ink">
                  {bundle.expected?.traffic?.profile
                    ? trafficLabel(bundle.expected.traffic.profile)
                    : '—'}
                </p>
              </div>
              <div>
                <p className="label text-ink-faint">
                  Classified as
                </p>
                <p className="mono mt-0.5 text-base text-low">
                  {ml.traffic_class ? trafficLabel(ml.traffic_class) : '—'}
                </p>
              </div>
            </div>
            {bundle.expected?.traffic?.profile && ml.traffic_class &&
              bundle.expected.traffic.profile !== ml.traffic_class && (
                <p className="border-t border-edge bg-low/[0.04] px-4 py-2.5 text-sm text-ink-dim">
                  The model verdict disagrees with the planned profile. The risk engine may
                  raise a low-severity finding; the disagreement itself is not a
                  vulnerability.
                </p>
              )}
          </Panel>

          {explanation && (
            <Panel
              title="Model Explanation"
              subtitle={`${explanation.provenance} · ${explanation.explanation_kind}`}
            >
              <div className="space-y-3 p-4">
                <Prose>{explanation.explanation}</Prose>
                {explanation.evidence_refs && explanation.evidence_refs.length > 0 && (
                  <div className="border-t border-edge pt-3">
                    <p className="mb-1.5 label text-ink-faint">
                      Evidence
                    </p>
                    <ul className="space-y-1">
                      {explanation.evidence_refs.map((ref, index) => (
                        <li key={ref.evidence_id ?? index} className="text-xs text-ink-dim">
                          <ProvenanceDetails title="Evidence record">
                            <IdRow
                              label="Evidence id"
                              value={ref.evidence_id ?? '—'}
                              title={ref.evidence_id ?? undefined}
                            />
                            {ref.pcap_path && (
                              <IdRow label="Capture path" value={ref.pcap_path} title={ref.pcap_path} />
                            )}
                          </ProvenanceDetails>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {explanation.limitations && explanation.limitations.length > 0 && (
                  <div className="rounded-md border border-medium/25 bg-medium/[0.05] p-2.5">
                    <p className="label text-medium/80">
                      Limitations
                    </p>
                    <ul className="mt-1 space-y-1">
                      {explanation.limitations.map((limitation) => (
                        <li key={limitation} className="text-xs leading-snug text-ink-dim">
                          {limitation}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </Panel>
          )}

          {relatedFindings.length > 0 && (
            <Panel
              title="Findings Derived From ML"
              subtitle="low-weight, informational by policy"
            >
              <ul className="divide-y divide-edge/60">
                {relatedFindings.map((finding) => (
                  <li key={finding.finding_id} className="px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="mono text-xs text-ink-faint">
                        {finding.finding_id}
                      </span>
                      <Tag>{finding.severity}</Tag>
                    </div>
                    <p className="mt-1 text-sm text-ink">{finding.title}</p>
                    <p className="mt-1 text-sm leading-relaxed text-ink-faint">
                      {finding.reason}
                    </p>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </>
      )}
    </div>
  )
}
