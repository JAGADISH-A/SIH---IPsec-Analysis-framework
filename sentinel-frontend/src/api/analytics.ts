import { ANALYTICS_API_URL } from '@/config'
import { request } from './client'
import type {
  AnalyticsHealth,
  AnalyticsV1Health,
  AssessmentBundle,
  AssessmentDriftResponse,
  AssessmentsResponse,
  AssessmentsV1Response,
  AuditEventDetail,
  AuditEventsResponse,
  AuditRunsResponse,
  CaptureEventsResponse,
  CustodyExplanation,
  DriftBaselinesResponse,
  DriftSummary,
  EvidenceIntegrity,
  FindingsResponse,
  RunAuditTrailResponse,
} from '@/types'

/**
 * Server A — the read-only analytics plane (127.0.0.1:8081).
 *
 * This module is the only place that knows analytics paths. Pages import the
 * named functions below; none of them build a URL.
 */

const BASE = ANALYTICS_API_URL

export function getAnalyticsHealth(signal?: AbortSignal): Promise<AnalyticsHealth> {
  return request<AnalyticsHealth>('analytics', BASE, '/api/health', {
    signal,
    title: 'Unable to reach the analytics API',
    fallback: 'The analytics service did not answer the health check.',
  })
}

export function getAnalyticsV1Health(signal?: AbortSignal): Promise<AnalyticsV1Health> {
  return request<AnalyticsV1Health>('analytics', BASE, '/api/v1/health', {
    signal,
    title: 'Unable to read component health',
    fallback: 'The analytics service did not return its component health.',
  })
}

/** Phase-8 list: headers + the store overview used for dashboard KPIs. */
export function getAssessments(
  params: { limit?: number; offset?: number } = {},
  signal?: AbortSignal,
): Promise<AssessmentsResponse> {
  return request<AssessmentsResponse>('analytics', BASE, '/api/assessments', {
    signal,
    query: { limit: params.limit ?? 100, offset: params.offset ?? 0 },
    title: 'Unable to load assessments',
    fallback: 'The analytics service did not return the assessment index.',
  })
}

/** Phase-10 list: filterable + sortable rows (server-side filtering available). */
export function getAssessmentsV1(
  params: {
    limit?: number
    offset?: number
    severity?: string
    mode?: string
    address_family?: string
    security_posture?: string
    traffic_profile?: string
    sort?: string
    order?: string
  } = {},
  signal?: AbortSignal,
): Promise<AssessmentsV1Response> {
  return request<AssessmentsV1Response>('analytics', BASE, '/api/v1/assessments', {
    signal,
    query: { limit: params.limit ?? 100, offset: params.offset ?? 0, ...params },
    title: 'Unable to load assessments',
    fallback: 'The analytics service did not return the assessment index.',
  })
}

export function getAssessment(id: string, signal?: AbortSignal): Promise<AssessmentBundle> {
  return request<AssessmentBundle>(
    'analytics',
    BASE,
    `/api/assessments/${encodeURIComponent(id)}`,
    {
      signal,
      title: 'Unable to load assessment',
      fallback: 'The analytics service did not return the requested assessment.',
    },
  )
}

export function getFindings(
  params: {
    limit?: number
    offset?: number
    severity?: string
    category?: string
    assessment_id?: string
  } = {},
  signal?: AbortSignal,
): Promise<FindingsResponse> {
  return request<FindingsResponse>('analytics', BASE, '/api/v1/findings', {
    signal,
    query: { limit: params.limit ?? 100, offset: params.offset ?? 0, ...params },
    title: 'Unable to load findings',
    fallback: 'The analytics service did not return any findings.',
  })
}

export function getAssessmentFindings(
  assessmentId: string,
  signal?: AbortSignal,
): Promise<FindingsResponse> {
  return request<FindingsResponse>(
    'analytics',
    BASE,
    `/api/v1/assessments/${encodeURIComponent(assessmentId)}/findings`,
    {
      signal,
      title: 'Unable to load findings',
      fallback: 'The analytics service did not return findings for this assessment.',
    },
  )
}

/**
 * The chain-of-custody explanation for one finding inside one assessment.
 * A finding id repeats across assessments, so it is addressed by the pair.
 */
export function getFindingExplanation(
  assessmentId: string,
  findingId: string,
  signal?: AbortSignal,
): Promise<CustodyExplanation> {
  return request<CustodyExplanation>(
    'analytics',
    BASE,
    `/api/v1/assessments/${encodeURIComponent(assessmentId)}/findings/${encodeURIComponent(findingId)}/explanation`,
    {
      signal,
      title: 'Unable to load explanation',
      fallback:
        'The analytics service did not return a custody chain for this finding.',
    },
  )
}

/* ------------------------------------------------------------- capture */

/**
 * Read-only tail of the xdp_monitor packet journal — the capture / live-traffic
 * view. The server normalizes each raw XDP event through the streaming adapter
 * and never fabricates packets; with no journal it reports a structured
 * `present:false` waiting state (or a 503 `capture_feed_unavailable` when the
 * feed is not attached at all). `cursor` is a byte offset the server returns,
 * so consecutive polls resume exactly where the last left off.
 *
 * Every envelope also reports the backend's own `current` verdict: whether the
 * journal is being actively written. `current:false` means any rows present are
 * recorded history, not current live traffic — the UI must not render them as
 * live. Nothing here is approximated client-side.
 */
export function getCaptureEvents(
  params: { cursor?: number; limit?: number } = {},
  signal?: AbortSignal,
): Promise<CaptureEventsResponse> {
  return request<CaptureEventsResponse>('analytics', BASE, '/api/v1/capture/events', {
    signal,
    query: { cursor: params.cursor ?? 0, limit: params.limit ?? 200 },
    title: 'Unable to read the capture feed',
    fallback:
      'The analytics service did not return capture events. A feed with no packets reports a waiting state rather than inventing one.',
  })
}

/* ---------------------------------------------------------------- audit */

/**
 * The server accepts a repeated `event_type`/`source` or a comma-separated
 * list, so an array from a caller is flattened here rather than at each call
 * site.
 */
function joinFilter(value: string | string[] | undefined): string | undefined {
  if (value === undefined) return undefined
  return Array.isArray(value) ? value.join(',') : value
}

/**
 * Page through the analysis audit journal.
 *
 * This is the live-traffic source: the read-only projection of the append-only
 * analysis journal. It is deliberately *not* described as a packet stream — it
 * carries analysis-stage records, not decrypted frames — and the server caps
 * every response via `limit`, so a page never pulls an unbounded journal.
 */
export function getAuditEvents(
  params: {
    run_id?: string
    experiment_id?: string
    sequence?: number
    attempt_number?: number
    event_type?: string | string[]
    source?: string | string[]
    authoritative?: boolean
    window_index?: number
    window_from_ns?: number
    window_to_ns?: number
    event_id?: string | string[]
    limit?: number
    offset?: number
  } = {},
  signal?: AbortSignal,
): Promise<AuditEventsResponse> {
  return request<AuditEventsResponse>('analytics', BASE, '/api/v1/audit/events', {
    signal,
    query: {
      limit: params.limit ?? 200,
      offset: params.offset ?? 0,
      ...params,
      event_type: joinFilter(params.event_type),
      source: joinFilter(params.source),
      event_id: joinFilter(params.event_id),
    },
    title: 'Unable to read the audit journal',
    fallback:
      'The analytics service did not return any audit events. A store with no journal attached reports an empty result rather than inventing one.',
  })
}

/** One audit event exactly as persisted; its `event_id` is the authority. */
export function getAuditEvent(
  eventId: string,
  signal?: AbortSignal,
): Promise<AuditEventDetail> {
  return request<AuditEventDetail>(
    'analytics',
    BASE,
    `/api/v1/audit/events/${encodeURIComponent(eventId)}`,
    {
      signal,
      title: 'Unable to load this audit event',
      fallback: 'The analytics service did not return that audit event.',
    },
  )
}

/** Which runs in the journal actually have recorded evidence. */
export function getAuditRuns(signal?: AbortSignal): Promise<AuditRunsResponse> {
  return request<AuditRunsResponse>('analytics', BASE, '/api/v1/audit/runs', {
    signal,
    title: 'Unable to list audited runs',
    fallback: 'The analytics service did not return any audited runs.',
  })
}

/** The ordered per-window lifecycle trail for one run. */
export function getRunAuditTrail(
  runId: string,
  params: { limit?: number; offset?: number } = {},
  signal?: AbortSignal,
): Promise<RunAuditTrailResponse> {
  return request<RunAuditTrailResponse>(
    'analytics',
    BASE,
    `/api/v1/runs/${encodeURIComponent(runId)}/audit`,
    {
      signal,
      query: { limit: params.limit ?? 500, offset: params.offset ?? 0 },
      title: 'Unable to load the run audit trail',
      fallback: 'The analytics service did not return an audit trail for this run.',
    },
  )
}

/* ---------------------------------------------------------------- drift */

/**
 * Store-wide drift. `configured: false` means no validated baseline exists, so
 * no comparison was made — which is different from "no drift exists" and is
 * rendered as exactly that.
 */
export function getDriftSummary(signal?: AbortSignal): Promise<DriftSummary> {
  return request<DriftSummary>('analytics', BASE, '/api/v1/drift', {
    signal,
    title: 'Unable to load drift',
    fallback: 'The analytics service did not return a drift summary.',
  })
}

export function getDriftBaselines(signal?: AbortSignal): Promise<DriftBaselinesResponse> {
  return request<DriftBaselinesResponse>('analytics', BASE, '/api/v1/drift/baselines', {
    signal,
    title: 'Unable to load baselines',
    fallback: 'The analytics service did not return a baseline registry.',
  })
}

export function getAssessmentDrift(
  assessmentId: string,
  signal?: AbortSignal,
): Promise<AssessmentDriftResponse> {
  return request<AssessmentDriftResponse>(
    'analytics',
    BASE,
    `/api/v1/assessments/${encodeURIComponent(assessmentId)}/drift`,
    {
      signal,
      title: 'Unable to load drift for this assessment',
      fallback: 'The analytics service did not return a drift comparison.',
    },
  )
}

/* ------------------------------------------------------------- evidence */

/**
 * Read-only integrity status for one evidence artifact. The digest, size and
 * presence come from the server; a missing artifact is reported as missing and
 * is never re-hashed in the browser.
 */
export function getEvidenceIntegrity(
  evidenceId: string,
  signal?: AbortSignal,
): Promise<EvidenceIntegrity> {
  return request<EvidenceIntegrity>(
    'analytics',
    BASE,
    `/api/v1/evidence/${encodeURIComponent(evidenceId)}`,
    {
      signal,
      title: 'Unable to verify this artifact',
      fallback: 'The analytics service did not return an integrity record for this artifact.',
    },
  )
}
