import { IdRow, ProvenanceDetails } from '@/components/kit'
import { formatNumber, formatValue, severityHex } from '@/lib/format'
import { configTermLabel, statusLabel } from '@/lib/labels'
import type { AssessmentDriftResponse } from '@/types'

/**
 * The assessment's drift comparison vs a validated baseline, shared by the
 * Overview explanation and the XAI panel so both render the same honest
 * states: baseline configured + drifted (baseline → current per field),
 * baseline configured + clean, or "not_configured" — which is never
 * presented as "no drift" (a baseline must be established explicitly and is
 * never inferred).
 *
 * Every value shown here is read from the response: the status, the changed
 * fields with their baseline/current values, the finding ids and severities,
 * and the provenance of both sides. Nothing is inferred client-side and no
 * variable, value, severity or finding id is known to this component, so an
 * assessment compared against any baseline renders truthfully.
 */
export function AssessmentDriftBlock({ drift }: { drift: AssessmentDriftResponse | null }) {
  return (
    <div>
      <h4 className="pw-subhead">Configuration drift</h4>
      {drift ? (
        drift.status === 'not_configured' ? (
          <p className="pw-faint-text">
            {drift.reason ?? 'No baseline is configured; no comparison was made.'} This is not a
            finding of &ldquo;no drift&rdquo; — a baseline must be established explicitly and is
            never inferred.
          </p>
        ) : drift.drift_detected ? (
          <>
            <div className="pw-kv">
              <dt>Status</dt>
              <dd>
                <span style={{ color: severityHex(drift.risk?.severity ?? 'HIGH') }}>
                  DRIFT DETECTED
                </span>
                <span className="pw-dim">
                  {' '}
                  · {formatNumber(drift.changed_fields.length)} changed field
                  {drift.changed_fields.length === 1 ? '' : 's'} · {statusLabel(drift.status)}
                  {drift.risk?.severity ? ` · ${statusLabel(drift.risk.severity)}` : ''}
                </span>
              </dd>
            </div>
            {drift.changed_fields.map((field, index) => (
              <dl className="pw-kv" key={`${field.variable ?? index}`}>
                <dt>{field.label ?? (field.variable ? configTermLabel(field.variable) : 'field')}</dt>
                <dd>
                  <span className="pw-ink">{formatValue(field.current_value)}</span>
                  <span className="pw-faint-text">
                    {' '}
                    (baseline {formatValue(field.baseline_value)})
                  </span>
                  {field.severity && <span className="pw-dim"> · {statusLabel(field.severity)}</span>}
                  {(field.variable || field.comparison_rule || field.drift_category || field.finding_id) && (
                    <ProvenanceDetails title="Drift record" className="mt-1">
                      {field.variable && <IdRow label="Variable" value={field.variable} title={field.variable} />}
                      {field.comparison_rule && (
                        <IdRow label="Comparison rule" value={field.comparison_rule} title={field.comparison_rule} />
                      )}
                      {field.drift_category && (
                        <IdRow label="Drift category" value={field.drift_category} title={field.drift_category} />
                      )}
                      {field.finding_id && (
                        <IdRow label="Finding id" value={String(field.finding_id)} title={String(field.finding_id)} />
                      )}
                    </ProvenanceDetails>
                  )}
                </dd>
              </dl>
            ))}
            {drift.risk?.findings && drift.risk.findings.length > 0 && (
              <dl className="pw-kv">
                <dt>Findings</dt>
                <dd className="pw-ink">
                  {drift.risk.findings.map((finding, index) => (
                    <span key={`${finding.finding_id ?? index}`}>
                      {index > 0 && <span className="pw-dim">, </span>}
                      {finding.severity ? statusLabel(finding.severity) : 'finding'}
                      {finding.severity ? ' · ' : ''}
                      <ProvenanceDetails title="Finding record">
                        <IdRow
                          label="Finding id"
                          value={finding.finding_id ?? '—'}
                          title={finding.finding_id ?? undefined}
                        />
                      </ProvenanceDetails>
                    </span>
                  ))}
                </dd>
              </dl>
            )}
            <DriftProvenance drift={drift} />
          </>
        ) : drift.status === 'no_drift' ? (
          <>
            <p className="pw-faint-text">
              No drift detected. Baseline {drift.baseline ? 'recorded' : '—'} compared against the
              current configuration.
            </p>
            <DriftProvenance drift={drift} />
          </>
        ) : (
          /* `indeterminate` (the current observation carried no usable evidence)
             and any future non-clean status must never be rendered as "no drift":
             the API deliberately serves them with drift_detected=false while
             claiming neither drift nor agreement. */
          <p className="pw-faint-text">
            {drift.reason ?? 'The comparison claimed neither drift nor agreement.'} This is not a
            finding of &ldquo;no drift&rdquo; — a comparison that could not read the current
            configuration did not find it clean.
          </p>
        )
      ) : (
        <p className="pw-faint-text">No drift record was returned for this assessment.</p>
      )}
    </div>
  )
}

/**
 * Which run each side of the comparison came from. This is what ties an
 * assessment opened by id back to the experiment that produced it, so it is
 * shown verbatim rather than reconstructed.
 */
function DriftProvenance({ drift }: { drift: AssessmentDriftResponse }) {
  const baseline = drift.baseline
  const current = drift.current
  if (!baseline && !current) return null
  return (
    <ProvenanceDetails title="Comparison record" className="mt-2">
      {baseline?.baseline_id && <IdRow label="Baseline id" value={baseline.baseline_id} title={baseline.baseline_id} />}
      {baseline?.validated_by && <IdRow label="Validated by" value={baseline.validated_by} />}
      {baseline?.validated_at && <IdRow label="Validated at" value={baseline.validated_at} />}
      {current?.run_id && <IdRow label="Run id" value={current.run_id} title={current.run_id} />}
      {current?.sequence != null && <IdRow label="Sequence" value={String(current.sequence)} />}
      {(drift.unknown_variables?.length ?? 0) > 0 && (
        <IdRow label="Not established" value={drift.unknown_variables?.join(', ')} />
      )}
    </ProvenanceDetails>
  )
}