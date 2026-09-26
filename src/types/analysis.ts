import type { DataSource, EvidenceReference, ProtocolValue, Severity } from './evidence'

/* ------------------------------------------------------------------ */
/* Security findings — the platform-level, evidence-backed record.    */
/* Findings are produced by the analysis backend; the frontend only     */
/* renders them. It never computes a finding.                          */
/* ------------------------------------------------------------------ */

export type FindingCategory =
  | 'cryptography'
  | 'key-exchange'
  | 'authentication'
  | 'security-association'
  | 'replay-protection'
  | 'perfect-forward-secrecy'
  | 'metadata-exposure'
  | 'traffic-anomaly'
  | 'protocol-behavior'
  | 'compliance'

export const FINDING_CATEGORIES: readonly FindingCategory[] = [
  'cryptography',
  'key-exchange',
  'authentication',
  'security-association',
  'replay-protection',
  'perfect-forward-secrecy',
  'metadata-exposure',
  'traffic-anomaly',
  'protocol-behavior',
  'compliance',
] as const

export const FINDING_CATEGORY_LABEL: Record<FindingCategory, string> = {
  cryptography: 'Cryptography',
  'key-exchange': 'Key Exchange',
  authentication: 'Authentication',
  'security-association': 'Security Association',
  'replay-protection': 'Replay Protection',
  'perfect-forward-secrecy': 'Perfect Forward Secrecy',
  'metadata-exposure': 'Metadata Exposure',
  'traffic-anomaly': 'Traffic Anomaly',
  'protocol-behavior': 'Protocol Behavior',
  compliance: 'Compliance',
}

export type FindingStatus =
  | 'open'
  | 'acknowledged'
  | 'resolved'
  | 'false-positive'
  | 'suppressed'

export const FINDING_STATUSES: readonly FindingStatus[] = [
  'open',
  'acknowledged',
  'resolved',
  'false-positive',
  'suppressed',
] as const

export const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  open: 'Open',
  acknowledged: 'Acknowledged',
  resolved: 'Resolved',
  'false-positive': 'False Positive',
  suppressed: 'Suppressed',
}

export interface SeverityTally {
  critical: number
  high: number
  medium: number
  low: number
  informational: number
  unknown: number
}

export interface SecurityFinding {
  id: string
  title: string
  /** One-line restatement of the conclusion. */
  summary: string
  severity: Severity
  category: FindingCategory
  /** 0 (harmless) – 100 (critical) composite risk contributed by this finding. */
  riskScore: number
  /** 0..1, or null when the analyser could not estimate it. */
  confidence: number | null
  status: FindingStatus
  /** What the capture actually showed. */
  observedBehavior: string
  /** What the assessed baseline requires. */
  expectedBehavior: string
  /** Consequence if the behaviour is not remediated. */
  impact: string
  /** Concrete remediation guidance. */
  recommendation: string
  /** Why the system believes this — the reasoning chain. */
  rationale: string
  /** Rule and/or model that produced the finding. */
  ruleId?: string
  model?: string
  source: DataSource
  sessionIds: string[]
  sessionCount: number
  relatedEventIds: string[]
  evidence: EvidenceReference[]
  references: string[]
  detectedAt: string
  updatedAt: string
}

export interface FindingSummary {
  total: number
  bySeverity: SeverityTally
  open: number
  resolved: number
  acknowledged: number
  falsePositive: number
  suppressed: number
  averageConfidence: number | null
  lastEvaluated: string
}

/** Query envelope for the findings register. */
export interface FindingQuery {
  search?: string
  severities?: Severity[]
  categories?: FindingCategory[]
  statuses?: FindingStatus[]
  sessionId?: string
  /** 0..1 lower bound applied to the confidence filter. */
  minConfidence?: number
  from?: string
  to?: string
}

/* ------------------------------------------------------------------ */
/* Threat matrix                                                        */
/* ------------------------------------------------------------------ */

export type ThreatId =
  | 'weak-cryptographic-algorithm'
  | 'weak-diffie-hellman-group'
  | 'pfs-disabled'
  | 'replay-window-anomaly'
  | 'excessive-sa-lifetime'
  | 'ike-version-downgrade'
  | 'repeated-negotiation-failure'
  | 'endpoint-metadata-exposure'
  | 'encrypted-traffic-anomaly'

export interface Threat {
  id: ThreatId
  name: string
  category: FindingCategory
  severity: Severity
  /** 1 (rare) – 5 (expected) */
  likelihood: number
  /** 1 (negligible) – 5 (severe) */
  impact: number
  description: string
  /** Sessions in which the threat was observed. */
  affectedSessions: number
  sessionIds: string[]
  /** 0..1, or null when unknown. Opacity on the matrix follows this. */
  confidence: number | null
  firstDetected: string
  lastObserved: string
  relatedFindingIds: string[]
  references: string[]
}

export interface ThreatMatrix {
  threats: Threat[]
  /** Axis labels so the visualisation stays data-driven. */
  axes: {
    x: { label: string; description: string }
    y: { label: string; description: string }
  }
  generatedAt: string
}

/** Compact shape used by the finding/session detail rails. */
export interface FindingReference {
  id: string
  title: string
  severity: Severity
  status: FindingStatus
  confidence: number | null
}

/** Re-exported for consumers that only import the analysis module. */
export type { EvidenceReference, ProtocolValue, Severity }
