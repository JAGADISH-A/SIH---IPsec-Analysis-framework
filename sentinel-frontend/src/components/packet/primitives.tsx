import type { ReactNode } from 'react'
import { comparisonStyle, formatBytes, formatValue, humanize, severityHex } from '@/lib/format'
import type { PacketDirection, PacketRiskLabel } from '@/lib/packetRows'
import type { ComparisonRow, EvidenceIntegrity, ExpectedState } from '@/types'

/**
 * Shared presentational primitives for the Packet Investigation surface.
 *
 * These are the two sentences of evidence style in this product:
 *
 *  - every value carries its provenance (configured / observed / not provided
 *    by backend), and
 *  - severity / comparison verdicts always use the same chips, so the "Security
 *    status" strip, the finding lists and the assessment explanation cannot
 *    drift into different visual languages.
 *
 * Centring them here (rather than copying them per tab) is what keeps evidence
 * style single-sourced.
 */

export function Prov({ kind, children }: { kind: 'conf' | 'obs' | 'miss'; children?: ReactNode }) {
  const cls =
    kind === 'conf' ? 'pw-prov pw-prov-conf' : kind === 'obs' ? 'pw-prov pw-prov-obs' : 'pw-prov pw-prov-miss'
  const text = kind === 'conf' ? 'configured' : kind === 'obs' ? 'observed' : 'not provided by backend'
  return (
    <span className={cls} title={text}>
      {children ?? text}
    </span>
  )
}

/**
 * Compact severity badge for one observed packet in the live stream.
 *
 * The word is the backend's own severity for that packet (a projection of the
 * assessment store by the SPI the store actually observed), and nothing else:
 * no score is appended, because a score in a dense scrolling column reads as a
 * value of its own. Provenance lives in the title. `UNASSESSED` is rendered as
 * its own state rather than a dash, so a missing classification is visible as
 * "no risk for this packet" and never confused with a low one.
 */
export function PacketRiskBadge({
  label,
  score,
  present,
  spi,
  assessments,
}: {
  label: PacketRiskLabel
  score: number | null
  present: boolean
  spi: number | null
  assessments: { assessment_id: string; severity: string | null; risk_score: number | null }[]
}) {
  if (!present) {
    return (
      <span
        className="pw-badge pw-badge-none"
        data-risk="UNASSESSED"
        title={
          spi === null
            ? 'This packet carries no SPI, so no assessment could have been correlated to it. The backend reports no risk classification for it.'
            : `No assessment in the store observed SPI 0x${spi.toString(16)}, so there is no risk classification for this packet. UNASSESSED is the honest value — no severity is assumed.`
        }
      >
        UNASSESSED
      </span>
    )
  }
  const hex = severityHex(label)
  return (
    <span
      className="pw-badge"
      data-risk={label}
      style={{ color: hex, borderColor: `${hex}55`, background: `${hex}1f` }}
      title={
        `${label} · risk score ${score ?? '—'} · ` +
        `${assessments.length} assessment${assessments.length === 1 ? '' : 's'} observed this packet's SPI` +
        (spi === null ? '' : ` (0x${spi.toString(16)})`) +
        ` · highest of: ${assessments
          .map((a) => `${a.assessment_id} ${a.severity ?? '—'}`)
          .join(', ')}`
      }
    >
      {label}
    </span>
  )
}

/**
 * Compact direction badge for one observed packet. `UNKNOWN` means the gateway
 * observation context did not report a direction for it; the capture side is not
 * inferred from the addresses.
 */
export function PacketDirectionBadge({ direction }: { direction: PacketDirection }) {
  const known = direction !== 'UNKNOWN'
  return (
    <span
      className={`pw-badge pw-dir${known ? '' : ' pw-badge-none'}`}
      data-direction={direction}
      title={
        known
          ? `${direction === 'INCOMING' ? 'Arrived at' : 'Left'} the captured gateway interface, as reported by the capture adapter.`
          : 'The capture adapter reported no direction for this packet. The capture side is not configured, so the addresses are not used to guess one.'
      }
    >
      {direction}
    </span>
  )
}

export function RiskChip({ severity, score }: { severity: string | null; score: number | null }) {
  if (!severity) return <span className="pw-dim">—</span>
  const hex = severityHex(severity)
  return (
    <span
      className="pw-risk"
      style={{ color: hex, borderColor: `${hex}55`, background: `${hex}1f` }}
      title={`${severity.toUpperCase()}${score === null ? '' : ` · score ${score}`} · from the assessment store by observed SPI`}
    >
      {severity.toUpperCase()}
      {score === null ? '' : ` · ${score}`}
    </span>
  )
}

/**
 * One labelled verdict for a comparison row. Only the engine's own status word
 * is used (`humanize`), so `UNKNOWN` can never be promoted to a mismatch.
 */
export function ComparisonVerdict({ status }: { status?: ComparisonRow | null }) {
  if (!status) return <span className="pw-val-muted">—</span>
  const style = comparisonStyle(status.status)
  return (
    <span style={{ color: style.hex }}>
      {humanize(status.status)}
      {status.status === 'MISMATCH' && ' · mismatch'}
    </span>
  )
}

/**
 * One chip for an artifact's verification state. Only the server's own words
 * are used: a digest the backend verified reads VERIFIED · INTACT, a digest it
 * found altered reads ALTERED · INTEGRITY FAILURE, and everything else stays
 * unverified rather than being promoted to a verdict.
 */
export function VerdictChip({
  status,
  present,
  verifiable,
}: {
  status?: string | null
  present?: boolean | null
  verifiable?: boolean | null
}) {
  const normalized = (status ?? '').toLowerCase()
  const green = '0px solid #34d399'
  const red = '0px solid #f87171'
  const neutral = '0px solid var(--pw-border)'
  let text = (status ?? 'state unavailable').toUpperCase()
  let color = neutral
  if (normalized === 'verified' || verifiable === true) {
    text = 'VERIFIED · INTACT'
    color = green
  } else if (normalized === 'mismatch') {
    text = 'ALTERED · INTEGRITY FAILURE'
    color = red
  }
  return (
    <span
      className="pw-verdict"
      style={{ borderColor: color, color: color === green ? '#34d399' : color === red ? '#f87171' : 'var(--pw-faint)' }}
    >
      {present === false && normalized !== 'mismatch' ? 'artifact bytes not present · ' : ''}
      {text}
    </span>
  )
}

export function IntegrityVerdict({ record }: { record: EvidenceIntegrity }) {
  const { evidence_id: id, artifact_type: type, artifact_sha256: sha } = record
  const mismatch = sha && record.actual_sha256 && sha !== record.actual_sha256
  return (
    <div className="pw-finding">
      <div className="pw-finding-head">
        <VerdictChip
          status={record.verification_status}
          present={record.artifact_present}
          verifiable={record.verifiable}
        />
        {mismatch && <span style={{ color: severityHex('CRITICAL') }}>digest mismatch</span>}
      </div>
      <dl className="pw-kv">
        <dt>Evidence id</dt>
        <dd className="pw-mono">{id}</dd>
      </dl>
      <dl className="pw-kv">
        <dt>Artifact</dt>
        <dd className="pw-mono">
          {type ?? '—'} · {formatBytes(record.byte_size)}
        </dd>
      </dl>
      <dl className="pw-kv">
        <dt>Recorded digest</dt>
        <dd className="pw-mono" title={sha ?? ''}>
          {sha ? sha.slice(0, 24) : '—'}
        </dd>
      </dl>
      <dl className="pw-kv">
        <dt>Actual digest</dt>
        <dd className="pw-mono" title={record.actual_sha256 ?? ''}>
          {record.actual_sha256 ? record.actual_sha256.slice(0, 24) : '—'}
        </dd>
      </dl>
      {record.verification_detail && <p className="pw-faint-text">{record.verification_detail}</p>}
    </div>
  )
}

export type ConfigRow = { term: string; variable: string; value: unknown }

/**
 * The one table of configuration intent the analytics plane exposes: the
 * expected (configured) state, projected into display rows. Both the Gateway
 * Config tab and the assessment explanation surface build from this so a
 * parameter can never render differently in the two places.
 */
export function expectedConfigRows(expected: ExpectedState): ConfigRow[] {
  return [
    { term: 'IKE version', variable: 'ike.version', value: expected.ike?.version },
    { term: 'IKE encryption', variable: 'ike.encryption', value: expected.ike?.encryption },
    { term: 'IKE integrity', variable: 'ike.integrity', value: expected.ike?.integrity },
    { term: 'IKE DH group', variable: 'ike.dh_group', value: expected.ike?.dh_group },
    { term: 'ESP encryption', variable: 'esp.encryption', value: expected.esp?.encryption },
    { term: 'ESP integrity', variable: 'esp.integrity', value: expected.esp?.integrity },
    { term: 'ESP DH group', variable: 'esp.dh_group', value: expected.esp?.dh_group },
    { term: 'PFS enabled', variable: 'esp.pfs', value: expected.esp?.pfs },
    { term: 'Mode', variable: 'mode', value: expected.mode },
    { term: 'Address family', variable: 'address_family', value: expected.address_family },
    { term: 'Traffic profile', variable: 'traffic.profile', value: expected.traffic?.profile },
    { term: 'Capture filter', variable: 'capture_filter', value: expected.capture_filter },
    { term: 'Security posture', variable: 'security_posture', value: expected.security_posture },
  ].filter((row) => row.value !== undefined && row.value !== null)
}

/**
 * The Configured / Observed / Status grid shared by the Gateway Config tab and
 * the "Relevant configuration" view inside the assessment explanation. Rows a
 * finding pinned via `related_variable` are marked flagged.
 */
export function ConfigCompareGrid({
  rows,
  correlationMap,
  flaggedVariables = new Set<string>(),
}: {
  rows: ConfigRow[]
  correlationMap: Map<string, ComparisonRow>
  flaggedVariables?: Set<string>
}) {
  return (
    <div>
      <div className="pw-colheads">
        <span>Parameter</span>
        <span>Configured</span>
        <span>Observed</span>
        <span>Status</span>
      </div>
      {rows.map((row) => {
        const status = correlationMap.get(row.variable) ?? null
        const flagged = flaggedVariables.has(row.variable)
        return (
          <div className="pw-row3" key={row.variable}>
            <span className="pw-term">
              {row.term}
              {flagged && <span className="pw-warn"> · flagged</span>}
            </span>
            <span className="pw-val">
              {formatValue(row.value)} <Prov kind="conf">configured</Prov>
            </span>
            <span className="pw-val">
              {status?.observed_value === undefined || status?.observed_value === null ? (
                <span className="pw-val-muted">
                  not provided by backend <Prov kind="miss">not provided</Prov>
                </span>
              ) : (
                <>
                  {formatValue(status.observed_value)} <Prov kind="obs">observed</Prov>
                </>
              )}
            </span>
            <ComparisonVerdict status={status} />
          </div>
        )
      })}
    </div>
  )
}