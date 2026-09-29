import type { CapturePacket, FeedPacket, Severity } from '@/types'
import { formatLocalClock, formatLocalFull, formatUtcFull } from '@/lib/timeZone'

/**
 * The packet list is now built from the actual capture feed
 * (`/api/v1/capture/events`), which serves the xdp_monitor packet journal
 * normalized by the streaming adapter. Every column maps to a field the feed
 * genuinely carries; the feed itself computes protocol labels and the Info
 * string so the UI never re-parses a packet. Risk comes at that level too: a
 * per-packet projection of the assessment store by observed SPI, present only
 * when an assessment actually observed the SPI.
 */
export type CaptureRow = {
  /** Position in the displayed list, newest first, starting at 1. */
  sequence: number
  key: string
  packet: CapturePacket
  /** Browser-local time of the capture, `HH:MM:SS.mmm`. */
  time: string
  /** Full browser-local + UTC evidence timestamp for a tooltip / inspector. */
  timeTitle: string
  source: string
  destination: string
  /** Wireshark-style protocol label computed by the feed. */
  protocol: string
  length: number
  /** Feed-computed Info string (SPI/seq for IPsec, ports otherwise). */
  info: string
  spi: number | null
    classification: string
    direction: string | null
    /** Direction resolved for display: INCOMING / OUTGOING / UNKNOWN. */
    directionLabel: PacketDirection
    severity: Severity | string | null
    /** Per-packet risk word for display; UNASSESSED when the store has none. */
    riskLabel: PacketRiskLabel
    riskScore: number | null
    riskPresent: boolean
    assessmentIds: string[]
}

/**
 * Direction as the *gateway observation context* reports it.
 *
 * The streaming adapter only produces a direction when the service knows which
 * side of the tunnel it sits on (`capture_ip`, or configured endpoints); it then
 * emits `inbound` / `outbound`. With no capture side configured the journal
 * carries no direction at all, and that is shown as UNKNOWN — it is never
 * guessed from which source address happens to appear first.
 */
export type PacketDirection = 'INCOMING' | 'OUTGOING' | 'UNKNOWN'

export function packetDirection(direction: string | null | undefined): PacketDirection {
  const value = (direction ?? '').trim().toLowerCase()
  if (value === 'inbound' || value === 'incoming') return 'INCOMING'
  if (value === 'outbound' || value === 'outgoing') return 'OUTGOING'
  return 'UNKNOWN'
}

/**
 * Per-packet risk, verbatim from the feed's own SPI projection of the
 * assessment store. `UNASSESSED` is a real, distinct state: the store never
 * observed this packet's SPI, so there is genuinely no risk classification for
 * it. A severity word is never invented, defaulted or promoted to HIGH.
 */
export type PacketRiskLabel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'UNASSESSED'

const SEVERITIES: readonly PacketRiskLabel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export function packetRiskLabel(severity: string | null | undefined, present: boolean): PacketRiskLabel {
  if (!present) return 'UNASSESSED'
  const value = (severity ?? '').trim().toUpperCase()
  return (SEVERITIES as readonly string[]).includes(value) ? (value as PacketRiskLabel) : 'UNASSESSED'
}

export function formatSpi(spi: number | null): string {
  if (spi === null || spi === undefined) return '—'
  return `0x${spi.toString(16).padStart(8, '0')}`
}

export function toCaptureRow(packet: FeedPacket, sequence: number): CaptureRow {
  const risk = packet.risk.present === true ? packet.risk : null
  return {
    sequence,
    key: packet.id,
    packet,
    time: formatLocalClock(packet.timestamp_ns),
    timeTitle: `${formatLocalFull(packet.timestamp_ns)} · ${formatUtcFull(
      packet.timestamp_ns,
    )} · ${packet.source}`,
    source: packet.packet.source || '—',
    destination: packet.packet.destination || '—',
    protocol: packet.protocol_label,
    length: packet.packet.packet_length,
    info: packet.info,
    spi: packet.spi,
    classification: packet.packet.classification,
    direction: packet.direction,
    directionLabel: packetDirection(packet.direction),
    severity: risk ? risk.highest_severity : null,
    riskLabel: packetRiskLabel(risk?.highest_severity, risk !== null),
    riskScore: risk ? risk.highest_risk_score : null,
    riskPresent: risk !== null,
    assessmentIds: risk ? risk.assessments.map((a) => a.assessment_id) : [],
  }
}

/**
 * Build the displayed rows newest-first (row 1 = the most recently captured
 * packet). `packets` is already in capture order; it is reversed here so the
 * newest line sits at the top, mirroring how the journal views work.
 */
export function toCaptureRows(packets: FeedPacket[]): CaptureRow[] {
  return [...packets].reverse().map((packet, index) => toCaptureRow(packet, index + 1))
}