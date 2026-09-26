export type ReportType = 'executive' | 'technical' | 'compliance' | 'comparison'
export type ReportFormat = 'pdf' | 'json' | 'csv'
export type ReportDetailLevel = 'summary' | 'standard' | 'forensic'
export type ReportStatus = 'queued' | 'generating' | 'ready' | 'failed'

export const REPORT_TYPE_LABEL: Record<ReportType, string> = {
  executive: 'Executive Report',
  technical: 'Technical Report',
  compliance: 'Compliance Report',
  comparison: 'Experiment Comparison Report',
}

export const REPORT_TYPE_DESCRIPTION: Record<ReportType, string> = {
  executive:
    'Posture, risk and remediation in plain language for non-specialist stakeholders. No packet-level detail.',
  technical:
    'Full protocol configuration, security associations, evidence records and per-finding rationale.',
  compliance:
    'Findings mapped to control references with evidence identifiers for audit trails.',
  comparison:
    'Side-by-side diff of two or more experiments: configured versus observed versus classified.',
}

export const REPORT_FORMAT_LABEL: Record<ReportFormat, string> = {
  pdf: 'PDF',
  json: 'JSON',
  csv: 'CSV',
}

export const REPORT_DETAIL_LABEL: Record<ReportDetailLevel, string> = {
  summary: 'Summary',
  standard: 'Standard',
  forensic: 'Forensic',
}

export const REPORT_DETAIL_DESCRIPTION: Record<ReportDetailLevel, string> = {
  summary: 'Headline metrics, severity counts and the remediation list.',
  standard: 'Adds protocol configuration, timeline and traffic classification.',
  forensic: 'Adds every evidence record, raw extracted values and model outputs.',
}

export interface ReportScope {
  sessionIds: string[]
  experimentIds: string[]
  from: string
  to: string
}

export interface Report {
  id: string
  name: string
  type: ReportType
  detailLevel: ReportDetailLevel
  status: ReportStatus
  scope: ReportScope
  formats: ReportFormat[]
  createdAt: string
  createdBy: string
  sizeBytes: number | null
  /** Number of findings covered by the report. */
  findingCount: number
  sessionCount: number
  /** 0..1 or null when the assessment has not been computed. */
  securityScore: number | null
  progressPercent: number
  error?: string
}

export interface ReportRequest {
  name: string
  type: ReportType
  detailLevel: ReportDetailLevel
  formats: ReportFormat[]
  scope: ReportScope
}

/** Rendered report payload, assembled by the (mock) report service. */
export interface ReportPreview {
  title: string
  subtitle: string
  type: ReportType
  detailLevel: ReportDetailLevel
  scope: ReportScope
  sections: ReportPreviewSection[]
  generatedAt: string
  /** Explicit note that the document was produced from mock data. */
  provenance: string
}

export interface ReportPreviewSection {
  id: string
  title: string
  summary: string
  rows: { label: string; value: string; note?: string }[]
}
