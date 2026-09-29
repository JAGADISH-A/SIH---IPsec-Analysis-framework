import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getAssessment, getAssessmentDrift, getAssessments, getFindings } from '@/api/analytics'
import { ApiRequestError } from '@/api/client'
import { humanize } from '@/lib/format'
import { packetRiskLabel, type CaptureRow } from '@/lib/packetRows'
import type {
  AssessmentDriftResponse,
  AssessmentHeader,
  Finding,
  MlResult,
} from '@/types'

/**
 * Findings-scoped filters for the Packet Analysis workspace.
 *
 * The live packet table is deliberately NOT filtered — it keeps streaming every
 * observed packet. This hook narrows the *findings* a finding can see, using
 * nothing but the analytics store:
 *
 *  - Risk / criticality  -> `finding.severity` (the backend's own taxonomy).
 *  - Confidence          -> `finding.confidence` (null for deterministic rules;
 *                           the ML finding carries the classifier's probability).
 *  - Traffic             -> the assessment's configured `traffic_profile` plus,
 *                           when the flow ran ML, the inferred class.
 *  - Finding             -> the actual `finding_id` values present in the store.
 *  - Drift               -> the backend's per-assessment drift comparison.
 *
 * Every option list is derived here — nothing is hard-coded except the severity
 * taxonomy (which is the backend model's own) and the confidence thresholds the
 * requirement specifies.
 */

/** Exact backend severity taxonomy, most severe first (mirrors `severityRank`). */
export const RISK_OPTIONS: string[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

/** Confidence thresholds: "All" plus ≥90 / ≥80 / ≥70 / ≥50 percent. */
export const CONFIDENCE_OPTIONS: { value: 'ALL' | number; label: string }[] = [
  { value: 'ALL', label: 'All' },
  { value: 90, label: '≥90%' },
  { value: 80, label: '≥80%' },
  { value: 70, label: '≥70%' },
  { value: 50, label: '≥50%' },
]

export type FindingFilters = {
  risk: string | 'ALL'
  confidence: 'ALL' | number
  traffic: string | 'ALL'
  finding: string | 'ALL'
  drift: 'ALL' | 'with' | 'without'
}

export const DEFAULT_FILTERS: FindingFilters = {
  risk: 'ALL',
  confidence: 'ALL',
  traffic: 'ALL',
  finding: 'ALL',
  drift: 'ALL',
}

/** One store finding decorated with everything a filter row needs. */
export type FilteredFinding = {
  finding: Finding
  severity: string
  confidence: number | null
  trafficTags: string[]
  driftBucket: 'with' | 'without' | null
  driftStatus: string
  assessment: AssessmentHeader | null
}

export type FindingFilterStore = {
  findings: FilteredFinding[]
  /** Distinct finding_id values present in the store (the "Finding" options). */
  findingOptions: string[]
  /** Distinct traffic labels derived from the assessments + ML inference. */
  trafficOptions: string[]
  /** Severity buckets over the current filtered set, most severe first. */
  countBySeverity: { severity: string; count: number }[]
  totalFindings: number
  filteredFindings: number
  assessmentCount: number
  loading: boolean
  error: ApiRequestError | null
  reload: () => void
}

/** `finding.confidence` — the backend's own value; deterministic rules are null. */
export function findingConfidence(finding: Finding): number | null {
  return finding.confidence ?? null
}

function severityOf(finding: Finding): string {
  return (finding.severity ?? '').toUpperCase()
}

/** The real traffic labels a finding's flow carries (configured + inferred). */
function trafficTagsFor(assessment: AssessmentHeader | null, ml: MlResult | null): string[] {
  const tags: string[] = []
  if (assessment?.traffic_profile) tags.push(assessment.traffic_profile.toLowerCase())
  if (ml?.present && ml.traffic_class) tags.push(ml.traffic_class.toLowerCase())
  return [...new Set(tags)]
}

function driftFor(record: AssessmentDriftResponse | undefined): {
  bucket: 'with' | 'without' | null
  status: string
} {
  if (!record) return { bucket: null, status: 'no drift report' }
  if (record.drift_detected === true) return { bucket: 'with', status: 'drift' }
  if (record.status === 'not_configured') return { bucket: 'without', status: 'no baseline configured' }
  return { bucket: 'without', status: 'no drift' }
}

/** AND semantics across all five filters, all values from the store. */
export function matchesFilters(f: FilteredFinding, filters: FindingFilters): boolean {
  if (filters.risk !== 'ALL' && f.severity !== filters.risk) return false
  if (filters.confidence !== 'ALL') {
    const confidence = f.confidence
    if (confidence === null || confidence * 100 < filters.confidence) return false
  }
  if (filters.traffic !== 'ALL' && !f.trafficTags.includes(filters.traffic)) return false
  if (filters.finding !== 'ALL' && f.finding.finding_id !== filters.finding) return false
  if (filters.drift !== 'ALL' && f.driftBucket !== filters.drift) return false
  return true
}

export const RISK_BUCKET_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

/** A click target for a finding whose assessment has no buffered packet. */
export function anchorRowFor(f: FilteredFinding): CaptureRow {
  const assessmentId = f.finding.assessment_id
  const score = f.assessment?.risk_score ?? null
  // The assessment's OWN severity is the packet-level risk. A finding severity
  // must never leak into this slot: the two concepts are tracked separately
  // (assessment highest_severity vs finding.severity), and a HIGH assessment
  // may carry only MEDIUM (or lower) findings.
  const assessmentSeverity = f.assessment?.severity ?? f.severity
  const esp = f.assessment?.esp_encryption ? true : false
  const risk = {
    present: true as const,
    highest_severity: assessmentSeverity,
    highest_risk_score: score,
    assessments: [
      {
        assessment_id: assessmentId,
        severity: assessmentSeverity,
        risk_score: score,
        finding_count: f.assessment?.finding_count ?? 0,
      },
    ],
  }
  return {
    sequence: 0,
    key: `finding:${assessmentId}:${f.finding.finding_id}`,
    packet: {
      id: `finding:${assessmentId}`,
      source: 'assessment_store',
      offset: 0,
      timestamp_ns: 0,
      schema: 'xdp_event_v1',
      packet: {
        timestamp: 0,
        interface: '—',
        protocol: esp ? 50 : 0,
        source: '—',
        destination: '—',
        spi: null,
        sequence: 0,
        packet_length: 0,
        source_port: 0,
        destination_port: 0,
        classification: 'ESP',
        direction: null,
        sensor_type: 'xdp_monitor',
      },
      protocol_label: esp ? 'ESP' : '—',
      info: `assessment ${assessmentId}`,
      spi: null,
      direction: null,
      risk,
    },
    time: '—',
    timeTitle: 'Opened from the findings strip — no current live packet for this assessment is available',
    info: 'assessment flow',
    source: '—',
    destination: '—',
    protocol: esp ? 'ESP' : '—',
    length: 0,
    spi: null,
    classification: 'ESP',
    direction: null,
    directionLabel: 'UNKNOWN',
    severity: assessmentSeverity,
    riskLabel: packetRiskLabel(assessmentSeverity, true),
    riskScore: score,
    riskPresent: true,
    assessmentIds: [assessmentId],
  }
}

export function useFindingFilters(filters: FindingFilters): FindingFilterStore {
  const [base, setBase] = useState<{
    findings: Finding[]
    headers: Map<string, AssessmentHeader>
    drift: Map<string, AssessmentDriftResponse>
    ml: Map<string, MlResult>
  } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiRequestError | null>(null)
  const [nonce, setNonce] = useState(0)
  const activeRef = useRef(false)

  const reload = useCallback(() => setNonce((value) => value + 1), [])

  useEffect(() => {
    activeRef.current = false
    const controller = new AbortController()
    activeRef.current = true
    setLoading(true)
    setError(null)

    const run = async () => {
      try {
        // Phase A — the two index reads the filters are built from.
        const [findingsRes, assessmentsRes] = await Promise.all([
          getFindings({ limit: 500 }, controller.signal),
          getAssessments({ limit: 100 }, controller.signal),
        ])
        if (!activeRef.current) return

        const findings = findingsRes.findings ?? []
        const headers = new Map(assessmentsRes.headers.map((h) => [h.assessment_id, h]))

        // Phase B — supplemental (ml class, per-assessment drift). These never
        // fail the whole store: a missing value simply drops that finding from
        // the request-specific bucket, which is the honest degradation.
        const headersList = [...headers.values()]
        const mlIds = headersList.filter((h) => h.ml_present).map((h) => h.assessment_id)
        const [mlResult, driftResult] = await Promise.allSettled([
          Promise.allSettled(mlIds.map((id) => getAssessment(id, controller.signal))),
          Promise.allSettled(headersList.map((h) => getAssessmentDrift(h.assessment_id, controller.signal))),
        ])
        if (!activeRef.current) return

        const ml = new Map<string, MlResult>()
        if (mlResult.status === 'fulfilled') {
          for (const bundle of mlResult.value) {
            if (bundle.status === 'fulfilled') {
              ml.set(bundle.value.assessment_id, bundle.value.ml)
            }
          }
        }

        const drift = new Map<string, AssessmentDriftResponse>()
        if (driftResult.status === 'fulfilled') {
          for (const entry of driftResult.value) {
            if (entry.status === 'fulfilled') drift.set(entry.value.assessment_id, entry.value)
          }
        }

        setBase({ findings, headers, drift, ml })
        setLoading(false)
      } catch (cause) {
        if (!activeRef.current || controller.signal.aborted) return
        setLoading(false)
        if (cause instanceof ApiRequestError) setError(cause)
        else
          setError(
            new ApiRequestError({
              title: 'Unable to load findings',
              detail: 'The analytics service did not return the finding index.',
              status: 0,
              code: 'unexpected_error',
              service: 'analytics',
            }),
          )
      }
    }

    void run()

    return () => {
      activeRef.current = false
      controller.abort()
    }
  }, [nonce])

  const registry = useMemo<FilteredFinding[]>(() => {
    if (!base) return []
    return base.findings.map((finding) => {
      const assessment = base.headers.get(finding.assessment_id) ?? null
      const ml = base.ml.get(finding.assessment_id) ?? null
      const drift = driftFor(base.drift.get(finding.assessment_id))
      return {
        finding,
        severity: severityOf(finding),
        confidence: findingConfidence(finding),
        trafficTags: trafficTagsFor(assessment, ml),
        driftBucket: drift.bucket,
        driftStatus: drift.status,
        assessment,
      }
    })
  }, [base])

  const findingOptions = useMemo(
    () => [...new Set(registry.map((f) => f.finding.finding_id))].sort(),
    [registry],
  )

  const trafficOptions = useMemo(
    () =>
      [...new Set(registry.flatMap((f) => f.trafficTags))].sort((a, b) =>
        humanize(a).localeCompare(humanize(b)),
      ),
    [registry],
  )

  const filtered = useMemo(
    () => registry.filter((f) => matchesFilters(f, filters)),
    [registry, filters],
  )

  const countBySeverity = useMemo(() => {
    const counts = new Map<string, number>()
    for (const f of filtered) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1)
    return RISK_BUCKET_ORDER.filter((severity) => counts.get(severity) !== undefined).map(
      (severity) => ({ severity, count: counts.get(severity) as number }),
    )
  }, [filtered])

  return {
    findings: filtered,
    findingOptions,
    trafficOptions,
    countBySeverity,
    totalFindings: registry.length,
    filteredFindings: filtered.length,
    assessmentCount: base?.headers.size ?? 0,
    loading,
    error,
    reload,
  }
}

/** A short, human label for a traffic tag (voip -> VoIP, icmp -> ICMP). */
const ACRONYM_TRAFFIC: Record<string, string> = {
  icmp: 'ICMP',
  esp: 'ESP',
  ah: 'AH',
  ike: 'IKE',
  dns: 'DNS',
  tcp: 'TCP',
  udp: 'UDP',
  sip: 'SIP',
  rtp: 'RTP',
  voip: 'VoIP',
  dtls: 'DTLS',
  sctp: 'SCTP',
  bgp: 'BGP',
  ipsec: 'IPsec',
}

export function trafficLabel(tag: string): string {
  const lowered = tag.toLowerCase()
  return ACRONYM_TRAFFIC[lowered] ?? humanize(tag)
}