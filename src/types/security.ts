import type { Nullable } from './common'

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type FindingCategory =
  | 'encryption'
  | 'authentication'
  | 'integrity'
  | 'configuration'
  | 'protocol'
  | 'anomaly'
  | 'replay'
  | 'exposure'
  | 'performance'

/**
 * A single packet-level security observation.
 *
 * This is the *wire* finding raised against one frame by the dissection rule
 * engine. The platform-level, evidence-backed finding that analysts act on
 * lives in `types/analysis.ts` as `SecurityFinding`.
 */
export interface PacketFinding {
  id: string
  packetId: string
  category: FindingCategory
  title: string
  severity: RiskLevel
  description: string
  /** Names of the protocol fields involved, for highlighting. */
  affectedFields: string[]
  recommendation?: string
  references?: string[]
  /** Engine rule identifier, useful once a real backend exists. */
  ruleId?: string
}

export interface AssessmentScore {
  /** 0 (clean) .. 100 (critical) composite risk score. */
  riskScore: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
}

/** Full assessment produced for a single packet by the analysis engine. */
export interface SecurityAssessment {
  packetId: string
  score: AssessmentScore
  summary: string
  cleanCount: number
  findings: PacketFinding[]
}

/** Severity levels ordered from most to least severe. */
export const RISK_LEVELS: readonly RiskLevel[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as const

export function riskSeverityIndex(level: RiskLevel): number {
  switch (level) {
    case 'critical':
      return 0
    case 'high':
      return 1
    case 'medium':
      return 2
    case 'low':
      return 3
    case 'info':
      return 4
  }
}

/** Ranking helper used by mocks and (future) backend responses. */
export function severityLabel(level: Nullable<RiskLevel>): string {
  if (!level) return 'N/A'
  return level.toUpperCase()
}