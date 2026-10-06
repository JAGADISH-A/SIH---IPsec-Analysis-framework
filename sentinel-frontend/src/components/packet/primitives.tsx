import type { ReactNode } from 'react'
import { IdRow, ProvenanceDetails } from '@/components/kit'
import { comparisonStyle, formatBytes, formatValue, humanize, severityHex } from '@/lib/format'
import { acronymLabel, configTermLabel } from '@/lib/labels'
import type { PacketRiskLabel } from '@/lib/packetRows'
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
 * One labelled verdict for a comparison row.
 *
 * Only the engine's own status word is used (`humanize`), so `UNKNOWN` can never
 * be promoted to a mismatch and `MATCH` can never be softened. The word appears
 * once: the status is the whole answer, and repeating it adds nothing. A row
 * the backend did not publish is reported as unavailable rather than as an
 * em dash, which would read as an empty-but-valid result.
 */
export function ComparisonVerdict({ status }: { status?: ComparisonRow | null }) {
  if (!status) return <span className="pw-na">Not available</span>
  const style = comparisonStyle(status.status)
  return <span style={{ color: style.hex }}>{humanize(status.status)}</span>
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

/**
 * One artifact's integrity card.
 *
 * The verdict leads because it is the decision. The recorded and actual digests
 * are the evidence *for* that verdict and stay visible side by side, because an
 * analyst reconciling against the store needs both. Only the evidence id — a
 * store key with no meaning outside the database — is pushed behind a
 * disclosure.
 */
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
        <dt>Artifact</dt>
        <dd className="pw-ink">
          {acronymLabel(type)}
          <span className="pw-dim"> · {formatBytes(record.byte_size)}</span>
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
      <ProvenanceDetails title="Evidence record" className="mt-1.5">
        <IdRow label="Evidence id" value={id} title={id} />
      </ProvenanceDetails>
    </div>
  )
}

export type ConfigRow = { term: string; variable: string; value: unknown }

/**
 * Every configuration parameter the analytics plane projects, in the order the
 * Gateway Config grid has always shown them.
 */
const CONFIG_VARIABLES = [
  'ike.version',
  'ike.encryption',
  'ike.integrity',
  'ike.dh_group',
  'esp.encryption',
  'esp.integrity',
  'esp.dh_group',
  'esp.pfs',
  'mode',
  'address_family',
  'traffic.profile',
  'capture_filter',
  'security_posture',
]

function variableValue(expected: ExpectedState, variable: string): unknown {
  switch (variable) {
    case 'ike.version':
      return expected.ike?.version
    case 'ike.encryption':
      return expected.ike?.encryption
    case 'ike.integrity':
      return expected.ike?.integrity
    case 'ike.dh_group':
      return expected.ike?.dh_group
    case 'esp.encryption':
      return expected.esp?.encryption
    case 'esp.integrity':
      return expected.esp?.integrity
    case 'esp.dh_group':
      return expected.esp?.dh_group
    case 'esp.pfs':
      return expected.esp?.pfs
    case 'mode':
      return expected.mode
    case 'address_family':
      return expected.address_family
    case 'traffic.profile':
      return expected.traffic?.profile
    case 'capture_filter':
      return expected.capture_filter
    case 'security_posture':
      return expected.security_posture
    default:
      return undefined
  }
}

/**
 * The one table of configuration intent the analytics plane exposes: the
 * expected (configured) state, projected into display rows. Both the Gateway
 * Config tab and the assessment explanation surface build from this so a
 * parameter can never render differently in the two places. The `term` for each
 * variable comes from the product's single `CONFIG_TERM_LABELS` map.
 */
export function expectedConfigRows(expected: ExpectedState): ConfigRow[] {
  return CONFIG_VARIABLES.map((variable) => ({
    term: configTermLabel(variable),
    variable,
    value: variableValue(expected, variable),
  })).filter((row) => row.value !== undefined && row.value !== null)
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