import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { getAssessments } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { LoadingPanel, ErrorState } from '@/components/states'
import { formatNumber } from '@/lib/format'
import { acronymLabel, statusLabel } from '@/lib/labels'

/**
 * IPsec Configuration — the tunnel parameters every assessment on record was
 * configured with.
 *
 * This is a CONFIGURED view and nothing else. The analytics plane performs no
 * runtime observation of any IPsec cryptographic parameter, so there is no
 * observed counterpart to show here; a row the store did not publish reads
 * "Not available" rather than being inferred from the plan.
 */
export function ConfigurationIndex() {
  const assessments = useResource((signal) => getAssessments({ limit: 200 }, signal))

  const headers = useMemo(() => assessments.data?.headers ?? [], [assessments.data])

  return (
    <div className="ls-page">
      <header className="ls-page-head">
        <h1 className="ls-title">IPsec Configuration</h1>
        <p className="ls-subtitle">
          Configured tunnel parameters for every assessment on record
        </p>
        <span className="ls-state ls-state-configured">configured</span>
      </header>

      {assessments.loading ? <LoadingPanel label="Loading assessments…" /> : null}
      {assessments.error ? <ErrorState error={assessments.error} onRetry={assessments.reload} /> : null}

      {headers.length > 0 ? (
        <div className="ls-table-wrap">
          <table className="ls-table">
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Mode</th>
                <th>Address Family</th>
                <th>IKE Version</th>
                <th>ESP Encryption</th>
                <th>Security Posture</th>
                <th className="ls-th-num">Findings</th>
                <th className="ls-th-num">Risk</th>
              </tr>
            </thead>
            <tbody>
              {headers.map((row) => (
                <tr key={row.assessment_id}>
                  <td>
                    <Link
                      className="ls-link"
                      to={`/assessments/${encodeURIComponent(row.assessment_id)}`}
                    >
                      {row.scenario ?? row.assessment_id}
                    </Link>
                  </td>
                  <td>{row.mode ? statusLabel(row.mode) : <span className="ls-na">Not available</span>}</td>
                  <td>
                    {row.address_family ? (
                      acronymLabel(row.address_family)
                    ) : (
                      <span className="ls-na">Not available</span>
                    )}
                  </td>
                  <td className="ls-mono">
                    {typeof row.ike_version === 'number' ? `IKEv${row.ike_version}` : '—'}
                  </td>
                  <td className="ls-mono">{row.esp_encryption ?? '—'}</td>
                  <td>{row.security_posture ?? '—'}</td>
                  <td className="ls-th-num ls-mono">{formatNumber(row.finding_count ?? 0)}</td>
                  <td>
                    <span className="ls-risk" data-risk={row.severity ?? 'UNASSESSED'}>
                      {typeof row.risk_score === 'number' ? formatNumber(row.risk_score) : '—'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  )
}