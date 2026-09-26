import type { Severity, SeverityTally } from './analysis'
import type { ServiceStatus } from './health'
import type { TimeSeriesPoint } from './trafficIntelligence'
import type { VpnSession } from './session'

export type KpiTone = 'neutral' | 'positive' | 'warning' | 'danger' | 'accent'

export interface KpiMetric {
  id: string
  label: string
  value: number | string | null
  unit?: string
  /** Compact pre-formatted value, e.g. "1,204". */
  display: string
  /** Trend delta vs. the previous comparable window, or null. */
  delta: number | null
  deltaDirection: 'up' | 'down' | 'flat'
  tone: KpiTone
  hint: string
  /** True when the value could not be computed and must be shown as unknown. */
  unknown?: boolean
}

export type Posture = 'strong' | 'acceptable' | 'needs-review' | 'weak' | 'critical' | 'unknown'

export const POSTURE_LABEL: Record<Posture, string> = {
  strong: 'Strong',
  acceptable: 'Acceptable',
  'needs-review': 'Needs review',
  weak: 'Weak',
  critical: 'Critical',
  unknown: 'Unknown',
}

export interface SecurityPosture {
  /** 0 (best) – 100 (worst). Null when there is nothing to assess. */
  score: number | null
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | null
  posture: Posture
  affectedSessions: number
  lastAssessmentAt: string
  /** How the score was produced. */
  method: string
}

export interface DistributionDatum {
  label: string
  value: number
  share: number
}

export interface DashboardSummary {
  posture: SecurityPosture
  kpis: KpiMetric[]
  severityDistribution: DistributionDatum[]
  securityScoreTrend: TimeSeriesPoint[]
  findingsOverTime: TimeSeriesPoint[]
  sessionsByMode: DistributionDatum[]
  encryptionDistribution: DistributionDatum[]
  aiConfidenceDistribution: DistributionDatum[]
  activeSessions: VpnSession[]
  recentFindings: {
    id: string
    severity: Severity
    title: string
    sessionId: string | null
    confidence: number | null
    detectedAt: string
    status: string
  }[]
  findingTally: SeverityTally
  systemStatus: { label: string; status: ServiceStatus; detail: string }[]
  generatedAt: string
  /** Window the summary was computed over. */
  range: { from: string; to: string; label: string }
  /** True when part of the summary could not be produced. */
  partial: boolean
  partialReasons: string[]
}

export interface DashboardQuery {
  from?: string
  to?: string
  environment?: string
}
