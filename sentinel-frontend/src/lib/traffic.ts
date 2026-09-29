import type {
  AssessmentHeader,
  AuditEventSummary,
  Finding,
  Severity,
} from '@/types'
import { severityRank } from './format'

/**
 * How a value on the traffic monitor reached the screen.
 *
 * The monitor is the one place where it is easiest to accidentally blur what
 * was measured and what was inherited, so the provenance of every column is
 * explicit and machine-checkable rather than a matter of column colour.
 */
export type Provenance = 'OBSERVED' | 'CONFIGURED' | 'INFERRED' | 'MODEL-DERIVED' | 'REPORTED'

/** The lifecycle stage an audit event sits at, in pipeline order. */
export const STAGE_ORDER = [
  'expected',
  'observed',
  'comparison',
  'ml',
  'risk',
  'explanation',
  'evidence',
  'response',
] as const

export type AuditStage = (typeof STAGE_ORDER)[number] | string

/**
 * One row of the live monitor.
 *
 * This is an *analysis event*, not a packet. The journal the analytics plane
 * serves records what the correlation pipeline recorded about a run; it holds
 * no frame bytes, no addresses and no payload. Every field below is therefore
 * either copied from the event itself, or inherited from the assessment that
 * event belongs to — and the `inherited` block records exactly that, so a row
 * can never imply a per-event measurement it does not have.
 */
export type TrafficRow = {
  /** The event's own content-addressed id. Unique, stable, server-assigned. */
  key: string
  event: AuditEventSummary
  stage: AuditStage
  recordedAtMs: number | null
  /**
   * The assessment this event belongs to, resolved by run + sequence. Rows
   * whose event does not map to a stored assessment keep `assessment: null`
   * rather than borrowing the nearest one.
   */
  assessment: AssessmentHeader | null
  findings: Finding[]
  /**
   * Risk and ML as they apply to the enclosing flow/window, never to a single
   * event. `scope` carries that qualifier into the UI so a score is never read
   * as a per-event measurement.
   */
  inherited: {
    scope: 'assessment' | 'none'
    riskScore: number | null
    severity: Severity | string | null
    anomaly: boolean | null
    /** Set when the event type is itself an ML stage record. */
    isMlStage: boolean
  }
}

export type TrafficFilters = {
  search: string
  stages: AuditStage[]
  onlyAuthoritative: boolean
  onlyAnomalies: boolean
  minRisk: number | null
  severities: string[]
}

/** The key that ties an audit event to its assessment. */
function assessmentKey(datasetRunId: string, sequence: number): string {
  return `${datasetRunId}#${sequence}`
}

export function indexAssessmentsByKey(
  headers: AssessmentHeader[],
): Map<string, AssessmentHeader> {
  const index = new Map<string, AssessmentHeader>()
  for (const header of headers) {
    index.set(assessmentKey(header.dataset_run_id, header.sequence), header)
  }
  return index
}

export function indexFindingsByAssessment(
  findings: Finding[],
): Map<string, Finding[]> {
  const index = new Map<string, Finding[]>()
  for (const finding of findings) {
    const bucket = index.get(finding.assessment_id)
    if (bucket) bucket.push(finding)
    else index.set(finding.assessment_id, [finding])
  }
  return index
}

/**
 * Turn one audit event into a display row.
 *
 * `recorded_at` is an ISO string (or null). An event with no recorded time is
 * ordered by the journal's own sequence rather than being given a fake
 * timestamp, and sorts after anything that has one.
 */
export function toTrafficRow(
  event: AuditEventSummary,
  assessments: Map<string, AssessmentHeader>,
  findingsByAssessment: Map<string, Finding[]>,
): TrafficRow {
  const assessment =
    assessments.get(assessmentKey(event.dataset_run_id, event.sequence)) ?? null
  const stage = event.stage ?? event.event_type
  const parsed = event.recorded_at ? new Date(event.recorded_at) : null
  const recordedAtMs = parsed && !Number.isNaN(parsed.getTime()) ? parsed.getTime() : null

  return {
    key: event.event_id,
    event,
    stage,
    recordedAtMs,
    assessment,
    findings: assessment ? (findingsByAssessment.get(assessment.assessment_id) ?? []) : [],
    inherited: {
      scope: assessment ? 'assessment' : 'none',
      riskScore: assessment ? assessment.risk_score : null,
      severity: assessment ? assessment.severity : null,
      anomaly: assessment ? assessment.ml_anomaly : null,
      isMlStage: stage === 'ml',
    },
  }
}

/** Newest first, with undated events last. Stable within equal keys. */
export function compareTrafficRows(a: TrafficRow, b: TrafficRow): number {
  if (a.recordedAtMs !== b.recordedAtMs) {
    if (a.recordedAtMs === null) return 1
    if (b.recordedAtMs === null) return -1
    return b.recordedAtMs - a.recordedAtMs
  }
  if (a.event.sequence !== b.event.sequence) return b.event.sequence - a.event.sequence
  return a.event.event_id.localeCompare(b.event.event_id)
}

function haystack(row: TrafficRow): string {
  const { event, assessment, stage } = row
  const parts = [
    stage,
    event.event_type,
    event.source,
    event.event_id,
    event.dataset_run_id,
    event.experiment_id,
    event.attempt_number,
    event.window_index,
    event.response_proposal_ref,
    assessment?.assessment_id,
    assessment?.slot,
    assessment?.scenario,
    assessment?.configuration_id,
    assessment?.security_posture,
    assessment?.esp_encryption,
    assessment?.ike_version,
    assessment?.mode,
    assessment?.address_family,
  ]
  return parts.filter((part) => part !== null && part !== undefined).join(' ').toLowerCase()
}

/**
 * Apply the analyst's filters.
 *
 * Risk and severity filters match the *inherited* flow-level values, so a
 * filter can drop events that belong to a low-risk flow. Because that value is
 * inherited, a row with no resolvable assessment is never matched by a risk
 * filter — filtering for "medium and above" must not quietly include events
 * whose risk is unknown.
 */
export function filterTrafficRows(rows: TrafficRow[], filters: TrafficFilters): TrafficRow[] {
  const search = filters.search.trim().toLowerCase()
  const severities = new Set(filters.severities.map((s) => s.toUpperCase()))
  const threshold = severities.size
    ? Math.min(...[...severities].map(severityRank))
    : null
  const stages = new Set(filters.stages)

  return rows.filter((row) => {
    if (search && !haystack(row).includes(search)) return false
    if (stages.size > 0 && !stages.has(row.stage)) return false
    if (filters.onlyAuthoritative && !row.event.authoritative) return false
    if (filters.onlyAnomalies && row.inherited.anomaly !== true) return false
    if (filters.minRisk !== null) {
      const score = row.inherited.riskScore
      if (score === null || score < filters.minRisk) return false
    }
    if (threshold !== null) {
      const severity = row.inherited.severity
      if (severity === null) return false
      // severityRank is ascending, so a lower rank is a more severe label.
      if (severityRank(severity) > threshold) return false
    }
    return true
  })
}

/**
 * The identity of the thing a row selected, for the detail drawer.
 *
 * Rows resolve to an assessment, which is the only entity that carries risk,
 * ML, evidence and custody together. An event with no matching assessment
 * still selects — it just selects the event, and the drawer says so.
 */
export type TrafficSelection = {
  rowKey: string
  assessmentId: string | null
  eventId: string
}

export function selectionForRow(row: TrafficRow): TrafficSelection {
  return {
    rowKey: row.key,
    assessmentId: row.assessment?.assessment_id ?? null,
    eventId: row.event.event_id,
  }
}
