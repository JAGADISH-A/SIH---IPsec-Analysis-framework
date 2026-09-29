import { useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  selectPrimaryFinding,
  useFindingCustody,
  usePacketInvestigation,
} from '@/hooks/usePacketInvestigation'
import { ErrorState, Spinner } from '@/components/states'
import { formatBytes } from '@/lib/format'
import type { CaptureRow } from '@/lib/packetRows'
import { AssessmentExplanation } from './AssessmentExplanation'
import { RiskChip } from './primitives'

/**
 * The one identity strip at the top of the investigation: the packet itself,
 * its browser-local capture time (full local time + zone and UTC in the
 * tooltip), the protocol geometry and the security status. Everything here is
 * a field the capture feed actually carried.
 */
function ContextStrip({ model }: { model: CaptureRow }) {
  const packet = model.packet
  const { source_port: sourcePort, destination_port: destinationPort, classification } = packet.packet
  const ports = sourcePort || destinationPort ? `${sourcePort || '—'} → ${destinationPort || '—'}` : '—'
  const items: [string, ReactNode, boolean?][] = [
    ['No.', model.sequence.toString(), true],
    [
      'Captured',
      <span title={model.timeTitle} key="t">
        {model.time}
      </span>,
      true,
    ],
    ['Source', <span className="pw-ink" key="s">{model.source}</span>, true],
    ['Destination', <span className="pw-ink" key="d">{model.destination}</span>, true],
    ['Protocol', model.protocol],
    ['Length', `${formatBytes(model.length)} (${model.length})`, true],
    ['SPI', packet.spi === null ? '—' : `0x${packet.spi.toString(16).padStart(8, '0')}`, true],
    ['Sequence', String(packet.packet.sequence), true],
    ['Ports', ports, true],
    // Same resolved vocabulary as the live stream column (INCOMING / OUTGOING /
    // UNKNOWN), so the two views of one packet cannot disagree.
    ['Direction', model.directionLabel],
    ['Detection', classification],
    ['Security status', <RiskChip severity={model.severity} score={model.riskScore} key="r" />],
  ]
  return (
    <div className="pw-strip">
      {items.map(([label, value, mono]) => (
        <div key={label}>
          <div className="pw-strip-label">{label}</div>
          <div className={`pw-strip-value ${mono ? 'pw-mono' : ''}`}>{value}</div>
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------- investigation */

/**
 * The in-workspace packet investigation. One panel answers the analyst's
 * questions from the assessment store — what was detected, why, what is
 * configured vs observed, was there drift, and is the evidence intact — as a
 * single ordered scroll whose deep evidence sits behind collapsible sections.
 * Every value carries its provenance (configured / observed / not provided by
 * backend).
 */
export function PacketInvestigation({
  model,
  held,
  focusFindingId = null,
}: {
  model: CaptureRow | null
  held: boolean
  /**
   * The finding the analyst arrived with (clicked in the findings strip). It
   * selects which finding the explanation follows; the assessment-level facts
   * never change with it.
   */
  focusFindingId?: string | null
}) {
  const assessmentId =
    model?.packet.risk.present === true ? (model.packet.risk.assessments[0]?.assessment_id ?? null) : null
  const inv = usePacketInvestigation(assessmentId)
  const [focusedId, setFocusedId] = useState<string | null>(null)

  // The focused finding follows the row the analyst clicked. A selection that
  // does not belong to this assessment is ignored, so the explanation can never
  // describe a finding from another packet.
  useEffect(() => {
    setFocusedId(focusFindingId)
  }, [focusFindingId, model?.key])

  const focusedFinding = inv.findings.find((finding) => finding.finding_id === focusedId) ?? null
  /**
   * The finding this investigation explains. An analyst selection always wins;
   * with no selection the highest-severity finding is the default, and it is
   * labelled as such rather than passed off as an analyst choice.
   */
  const explained = focusedFinding ?? selectPrimaryFinding(inv.findings)
  const explanationIsDefault = focusedFinding === null
  // Finding scope: the custody chain and integrity follow the EXPLAINED
  // finding — never a convenient one, and never requested without a finding.
  const custody = useFindingCustody(assessmentId, explained?.finding_id ?? null)

  const correlationMap = new Map(
    (inv.bundle?.correlation.rows ?? []).map((row) => [row.variable, row] as const),
  )

  return (
    <div className="pw-invest" aria-label="Packet investigation">
      <div className="pw-invest-head">
        <h3 className="pw-invest-title">Packet Investigation</h3>
        {model && inv.assessmentId && (
          <Link className="pw-link" to={`/assessments/${encodeURIComponent(inv.assessmentId)}`}>
            open assessment →
          </Link>
        )}
        <span className="pw-invest-spacer" />
        {held &&
          (model?.key.startsWith('finding:') ? (
            <span className="pw-warn">
              opened from the findings · no current live packet is in the capture buffer
            </span>
          ) : (
            <span className="pw-warn">evicted row · shown from a snapshot, not from the live buffer</span>
          ))}
      </div>

      {!model ? (
        <div className="pw-empty">
          <span>Select a live packet from the stream to open its investigation.</span>
        </div>
      ) : (
        <>
          <ContextStrip model={model} />

          {!assessmentId ? (
            <div className="pw-empty" style={{ minHeight: 0 }}>
              <span className="pw-ink-strong">No security finding associated with this packet/flow.</span>
              <p className="pw-empty-note">
                The assessment store observed SPI {model.spi === null ? '—' : `0x${model.spi.toString(16)}`}{' '}
                with no risk attached, so nothing is inferred from the packet itself.
              </p>
            </div>
          ) : inv.loading ? (
            <div className="pw-empty" style={{ minHeight: 0 }}>
              <Spinner />
              <span>Loading assessment {inv.assessmentId}…</span>
            </div>
          ) : inv.error ? (
            <ErrorState error={inv.error} onRetry={inv.reload} />
          ) : inv.bundle ? (
            <AssessmentExplanation
              model={model}
              bundle={inv.bundle}
              drift={inv.drift}
              findings={inv.findings}
              custody={custody}
              explanationIsDefault={explanationIsDefault}
              correlationMap={correlationMap}
              focusedFinding={focusedFinding}
              onExplain={setFocusedId}
            />
          ) : null}
        </>
      )}
    </div>
  )
}
