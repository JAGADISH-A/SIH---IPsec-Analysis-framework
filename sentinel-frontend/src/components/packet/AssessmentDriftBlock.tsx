import { formatNumber, formatValue, humanize, severityHex } from '@/lib/format'
import type { AssessmentDriftResponse } from '@/types'

/**
 * The assessment's drift comparison vs a validated baseline, shared by the
 * Overview explanation and the XAI panel so both render the same honest
 * states: baseline configured + drifted (baseline → current per field),
 * baseline configured + clean, or "not_configured" — which is never
 * presented as "no drift" (a baseline must be established explicitly and is
 * never inferred).
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
                <span style={{ color: severityHex('CRITICAL') }}>DRIFT DETECTED</span>
                <span className="pw-dim">
                  {' '}
                  · {formatNumber(drift.changed_fields.length)} changed field
                  {drift.changed_fields.length === 1 ? '' : 's'} · {drift.status}
                </span>
              </dd>
            </div>
            {drift.changed_fields.map((field, index) => (
              <dl className="pw-kv" key={`${field.variable ?? index}`}>
                <dt>{field.variable ?? 'field'}</dt>
                <dd className="pw-mono">
                  {formatValue(field.baseline_value)} <span className="pw-dim">→</span> {formatValue(field.current_value)}
                  {field.severity && <span className="pw-dim"> · {humanize(String(field.severity))}</span>}
                </dd>
              </dl>
            ))}
          </>
        ) : (
          <p className="pw-faint-text">
            No drift detected. Baseline {drift.baseline ? 'recorded' : '—'} compared against the
            current configuration.
          </p>
        )
      ) : (
        <p className="pw-faint-text">No drift record was returned for this assessment.</p>
      )}
    </div>
  )
}