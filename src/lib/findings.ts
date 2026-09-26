import type { Packet } from '../types/packet'
import type { FindingCategory, RiskLevel, PacketFinding } from '../types/security'
import { RISK_LEVELS, riskSeverityIndex } from '../types/security'

/* ------------------------------------------------------------------ */
/* Pure derivations for the Findings and Reports workspaces. Kept out   */
/* of components so both pages stay thin and testable.                  */
/* ------------------------------------------------------------------ */

export interface AggregatedFinding {
  /** Stable key: the underlying rule plus the protocol it fired on. */
  key: string
  title: string
  severity: RiskLevel
  category: FindingCategory
  description: string
  recommendation?: string
  ruleId?: string
  references?: string[]
  /** Every packet in the buffer that raised this finding. */
  packets: Packet[]
  count: number
  /** Distinct source/destination pairs the finding was observed on. */
  endpoints: { source: string; destination: string }[]
}

export interface CategoryRollup {
  category: FindingCategory
  count: number
  severity: RiskLevel
}

export interface FindingsOverview {
  total: number
  bySeverity: Record<RiskLevel, number>
  affectedPackets: number
  criticalCategories: CategoryRollup[]
  findings: AggregatedFinding[]
}

/** Group every finding in the buffer by rule + protocol, newest packet first. */
export function aggregateFindings(packets: Packet[]): AggregatedFinding[] {
  const groups = new Map<string, PacketFinding[]>()
  const byKey = new Map<string, Packet[]>()

  for (const packet of packets) {
    for (const finding of packet.findings) {
      const key = `${finding.ruleId ?? finding.category}:${finding.id}`
      const bucket = groups.get(key)
      if (bucket) bucket.push(finding)
      else groups.set(key, [finding])
      const holders = byKey.get(key)
      if (holders) holders.push(packet)
      else byKey.set(key, [packet])
    }
  }

  const aggregated: AggregatedFinding[] = []
  for (const [key, findings] of groups) {
    const first = findings[0]
    const holders = byKey.get(key) ?? []
    const endpoints = new Map<string, { source: string; destination: string }>()
    for (const packet of holders) {
      const pairKey = `${packet.source}>${packet.destination}`
      if (!endpoints.has(pairKey)) {
        endpoints.set(pairKey, { source: packet.source, destination: packet.destination })
      }
    }
    aggregated.push({
      key,
      title: first.title,
      severity: first.severity,
      category: first.category,
      description: first.description,
      recommendation: first.recommendation,
      ruleId: first.ruleId,
      references: first.references,
      packets: holders,
      count: holders.length,
      endpoints: [...endpoints.values()].slice(0, 6),
    })
  }

  return aggregated.sort(
    (a, b) => riskSeverityIndex(a.severity) - riskSeverityIndex(b.severity) || b.count - a.count,
  )
}

/** Severity totals plus per-category rollup, both derived from the buffer. */
export function findingsOverview(packets: Packet[]): FindingsOverview {
  const findings = aggregateFindings(packets)
  const bySeverity = Object.fromEntries(RISK_LEVELS.map((level) => [level, 0])) as Record<
    RiskLevel,
    number
  >

  for (const packet of packets) {
    for (const finding of packet.findings) bySeverity[finding.severity] += 1
  }

  const categories = new Map<FindingCategory, { count: number; severity: RiskLevel }>()
  for (const finding of findings) {
    const current = categories.get(finding.category)
    if (!current) {
      categories.set(finding.category, { count: finding.count, severity: finding.severity })
    } else {
      current.count += finding.count
      if (riskSeverityIndex(finding.severity) < riskSeverityIndex(current.severity)) {
        current.severity = finding.severity
      }
    }
  }

  return {
    total: findings.reduce((sum, finding) => sum + finding.count, 0),
    bySeverity,
    affectedPackets: packets.filter((packet) => packet.findings.length > 0).length,
    criticalCategories: [...categories.entries()]
      .map(([category, value]) => ({ category, count: value.count, severity: value.severity }))
      .sort((a, b) => b.count - a.count),
    findings,
  }
}

/* ------------------------------------------------------------------ */
/* Reporting                                                           */
/* ------------------------------------------------------------------ */

export interface ReportRow {
  label: string
  value: string
  note?: string
  tone?: 'critical' | 'high' | 'medium' | 'accent'
}

export interface ReportSection {
  id: string
  title: string
  summary: string
  rows: ReportRow[]
}

/** Letter grade + risk score derived from the observed findings. */
export function postureScore(overview: FindingsOverview, packetCount: number): {
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  label: string
} {
  if (packetCount === 0) return { score: 0, grade: 'A', label: 'No traffic observed' }

  const weighted =
    overview.bySeverity.critical * 12 +
    overview.bySeverity.high * 6 +
    overview.bySeverity.medium * 2 +
    overview.bySeverity.low * 0.4 +
    overview.bySeverity.info * 0.1
  const ratio = weighted / Math.max(1, packetCount)
  const score = Math.max(0, Math.min(100, Math.round(ratio * 4)))

  const grade = score >= 60 ? 'F' : score >= 40 ? 'D' : score >= 22 ? 'C' : score >= 10 ? 'B' : 'A'
  const label =
    grade === 'A'
      ? 'Strong posture'
      : grade === 'B'
        ? 'Acceptable posture'
        : grade === 'C'
          ? 'Needs review'
          : grade === 'D'
            ? 'Weak posture'
            : 'Critical posture'

  return { score, grade, label }
}

/** RFC references surfaced alongside the report, kept in one place. */
export const RFC_REFERENCES = [
  { id: 'RFC 7296', title: 'Internet Key Exchange Protocol Version 2 (IKEv2)' },
  { id: 'RFC 4303', title: 'Encapsulating Security Payload Protocol (ESP)' },
  { id: 'RFC 4302', title: 'IP Authentication Header Protocol (AH)' },
  { id: 'RFC 8247', title: 'Cryptographic Algorithms for IPsec' },
  { id: 'RFC 8221', title: 'ESP/AH Additional Algorithm Requirements' },
] as const
