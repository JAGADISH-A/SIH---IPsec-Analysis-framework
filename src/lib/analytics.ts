import type { Packet, PacketProtocolName } from '../types/packet'
import type { RiskLevel } from '../types/security'
import type {
  ProtocolDistribution,
  ProtocolFamily,
  TrafficBin,
  TrafficStatistics,
  TrafficWindow,
} from '../types/analytics'

/* ------------------------------------------------------------------ */
/* Pure derive helpers for the Live Analyzer. Kept out of components   */
/* so the rendering layer stays thin and testable.                     */
/* ------------------------------------------------------------------ */

const IPSEC_PROTOCOLS: ReadonlySet<PacketProtocolName> = new Set(['IKEv2', 'ESP', 'AH'])

export function isIpsecProtocol(protocol: PacketProtocolName): boolean {
  return IPSEC_PROTOCOLS.has(protocol)
}

const SEVERITY_ORDER: Record<RiskLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

/** Most severe finding on a packet, or null when it is clean. */
export function worstSeverity(packet: Packet): RiskLevel | null {
  if (packet.findings.length === 0) return null
  return packet.findings.reduce<RiskLevel>((worst, finding) =>
    SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[worst] ? finding.severity : worst,
  packet.findings[0].severity)
}

export const TRAFFIC_WINDOW_MS = 20_000
export const TRAFFIC_STEPS = 20
const BIN_MS = TRAFFIC_WINDOW_MS / TRAFFIC_STEPS

/** Roll the packet list into ~20 one-second buckets over the last ~20s. */
export function computeTraffic(packets: Packet[]): TrafficWindow {
  const nowMs = packets[0]?.relativeTimeMs ?? 0
  const start = nowMs - TRAFFIC_WINDOW_MS
  const bins: TrafficBin[] = Array.from({ length: TRAFFIC_STEPS }, () => ({
    total: 0,
    ipsec: 0,
    other: 0,
  }))
  let windowPackets = 0
  for (const packet of packets) {
    const t = packet.relativeTimeMs
    if (t < start) continue
    windowPackets += 1
    const index = Math.min(TRAFFIC_STEPS - 1, Math.max(0, Math.floor((t - start) / BIN_MS)))
    const bin = bins[index]
    bin.total += packet.length
    if (isIpsecProtocol(packet.protocol)) bin.ipsec += packet.length
    else bin.other += packet.length
  }
  const windowBytes = bins.reduce((sum, bin) => sum + bin.total, 0)
  return {
    bins,
    windowBytes,
    windowPackets,
    bitsPerSecond: (windowBytes * 8) / (TRAFFIC_WINDOW_MS / 1000),
    packetsPerSecond: windowPackets / (TRAFFIC_WINDOW_MS / 1000),
    maxBytes: Math.max(1, ...bins.map((bin) => bin.total)),
  }
}

/** Aggregate security/volume stats across the buffered packet set. */
export function computeSummary(packets: Packet[]): TrafficStatistics {
  let byteCount = 0
  let ipsecCount = 0
  let high = 0
  let medium = 0
  let low = 0
  let alerts = 0
  for (const packet of packets) {
    byteCount += packet.length
    if (isIpsecProtocol(packet.protocol)) ipsecCount += 1
    const severity = worstSeverity(packet)
    if (severity === 'critical') alerts += 1
    else if (severity === 'high') high += 1
    else if (severity === 'medium') medium += 1
    else if (severity === 'low') low += 1
  }
  return {
    packetCount: packets.length,
    byteCount,
    ipsecCount,
    highCount: high,
    mediumCount: medium,
    lowCount: low,
    alertCount: alerts,
    rate: computeTraffic(packets),
  }
}

/** Per-protocol packet share, ordered largest first, Other last. */
export function computeDistribution(packets: Packet[]): ProtocolDistribution[] {
  const counts = new Map<PacketProtocolName, number>()
  let other = 0
  for (const packet of packets) {
    if (isIpsecProtocol(packet.protocol)) {
      counts.set(packet.protocol, (counts.get(packet.protocol) ?? 0) + 1)
    } else {
      other += 1
    }
  }
  const total = packets.length
  const slices: ProtocolDistribution[] = [...counts.entries()].map(([label, count]) => ({
    label: label as ProtocolFamily,
    count,
    pct: total ? (count / total) * 100 : 0,
  }))
  slices.push({ label: 'Other', count: other, pct: total ? (other / total) * 100 : 0 })
  return slices.sort((a, b) => b.count - a.count)
}