import { formatNumber, formatValue, humanize, severityHex } from '@/lib/format'
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
                  {drift.changed_fields.length === 1 ? '' : 's'} · {drift.status}
                  {drift.risk?.severity ? ` · ${humanize(String(drift.risk.severity))}` : ''}
                </span>
              </dd>
            </div>
            {drift.changed_fields.map((field, index) => (
              <dl className="pw-kv" key={`${field.variable ?? index}`}>
                <dt>{field.label ?? field.variable ?? 'field'}</dt>
                <dd className="pw-mono">
                  {formatValue(field.baseline_value)} <span className="pw-dim">→</span> {formatValue(field.current_value)}
                  {field.severity && <span className="pw-dim"> · {humanize(String(field.severity))}</span>}
                  {field.finding_id && (
                    <span className="pw-dim"> · {String(field.finding_id)}</span>
                  )}
                </dd>
                {(field.comparison_rule || field.drift_category) && (
                  <dd className="pw-dim">
                    {[field.comparison_rule, field.drift_category].filter(Boolean).join(' · ')}
                  </dd>
                )}
              </dl>
            ))}
            {drift.risk?.findings && drift.risk.findings.length > 0 && (
              <dl className="pw-kv">
                <dt>Findings</dt>
                <dd>
                  {drift.risk.findings.map((finding, index) => (
                    <span key={`${finding.finding_id ?? index}`} className="pw-mono">
                      {index > 0 && <span className="pw-dim">, </span>}
                      {finding.finding_id ?? 'finding'}
                      {finding.severity ? ` (${humanize(String(finding.severity))})` : ''}
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
    <dl className="pw-kv">
      <dt>Provenance</dt>
      <dd className="pw-mono pw-dim">
        {[
          baseline?.baseline_id ? `baseline ${baseline.baseline_id}` : null,
          baseline?.validated_by ? `validated by ${baseline.validated_by}` : null,
          baseline?.validated_at ? `at ${baseline.validated_at}` : null,
          current?.run_id ? `run ${current.run_id}` : null,
          current?.sequence != null ? `sequence ${current.sequence}` : null,
        ]
          .filter(Boolean)
          .join(' · ')}
      </dd>
      {(drift.unknown_variables?.length ?? 0) > 0 && (
        <dd className="pw-dim">
          not established: {drift.unknown_variables?.join(', ')}
        </dd>
      )}
    </dl>
  )
}