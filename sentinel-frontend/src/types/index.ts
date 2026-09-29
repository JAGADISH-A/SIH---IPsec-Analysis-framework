/**
 * Wire types for the two Sentinel backends.
 *
 * These mirror the JSON the servers actually emit (verified against a live
 * store). Fields that are frequently `null` upstream are typed as `T | null`,
 * and optional fields are optional — nothing is asserted to exist when the
 * backend may omit it. Anything the backend does not send is simply absent in
 * the UI, never invented.
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

/* ------------------------------------------------------------------ health */

export type AnalyticsHealth = {
  status: string
  service: string
  api_schema_version: string
  store_version: string
  total_assessments: number
  read_only: boolean
  note?: string
}

export type V1Component = {
  status: string
  detail?: string
  metrics?: Record<string, unknown>
}

export type AnalyticsV1Health = {
  status: string
  components: Record<string, V1Component>
  cors?: {
    allowed_origins?: string[]
    allow_credentials?: boolean
    allowed_methods?: string[]
    allowed_headers?: string[]
    exposed_headers?: string[]
    max_age_seconds?: number
    configured?: boolean
  }
}

/* -------------------------------------------------------------- assessments */

export type StoreOverview = {
  store_version?: string
  total_assessments: number
  severity_counts: Record<string, number>
  category_counts: Record<string, number>
  findings_total: number
  unknown_observations: number
  ml_anomalies: number
  ml_classification_disagreements: number
  risk_policy_version: string
  xai_available: boolean
  source?: string
  dataset_run_id?: string | null
  sources?: StoreSource[]
  highest_risk?: number | null
  highest_severity?: Severity | string | null
}

export type StoreSource = {
  path: string
  role: string
  artifact_sha256?: string
  byte_size?: number
  samples?: number
  record_count?: number
  reason?: string
}

export type AssessmentHeader = {
  assessment_id: string
  slot: string
  scenario: string
  dataset_run_id: string
  sequence: number
  experiment_id: string
  attempt_number: number
  window_index: number | null
  window_start_ns: number | null
  window_end_ns: number | null
  configuration_id: string
  traffic_profile: string
  security_posture: string
  mode: string
  address_family: string
  ike_version: number
  esp_encryption: string
  risk_score: number
  severity: Severity | string
  finding_count: number
  correlation_status: string
  ml_present: boolean
  ml_anomaly: boolean | null
}

export type AssessmentsResponse = {
  api: string
  overview: StoreOverview
  headers: AssessmentHeader[]
  count: number
  total: number
  limit: number
  offset: number
  has_more: boolean
}

export type AssessmentsV1Response = {
  api: string
  assessments: AssessmentHeader[]
  count: number
  total: number
  limit: number
  offset: number
  has_more: boolean
  read_only: boolean
  overview: StoreOverview
  severity_order: string[]
}

export type ExpectedState = {
  mode?: string
  address_family?: string
  ike?: {
    version?: number
    encryption?: string
    integrity?: string | null
    dh_group?: string
  }
  esp?: {
    encryption?: string
    integrity?: string | null
    dh_group?: string
    pfs?: boolean
  }
  traffic?: {
    profile?: string
    duration?: number
    port?: number
  }
  capture_filter?: string
  configuration_id?: string
  security_posture?: string
}

export type SpiEntry = {
  spi: string
  direction: string
  active: boolean
  first_seen_ns: number
  last_seen_ns: number
  packet_count: number
  first_sequence: number
  last_sequence: number
  highest_sequence: number
  sequence_delta: number
}

export type Transition = {
  name: string
  timestamp_ns: number
  details: Record<string, unknown>
}

export type ObservedState = {
  present: boolean
  timestamp_ns?: number | null
  endpoints?: { a?: string; b?: string } | null
  active?: boolean
  tunnel_seen?: boolean
  packets_seen?: number
  bytes_seen?: number
  packets_a_to_b?: number
  packets_b_to_a?: number
  bytes_a_to_b?: number
  bytes_b_to_a?: number
  ike_seen?: boolean
  ike_nat_t_seen?: boolean
  esp_seen?: boolean
  ah_seen?: boolean
  observed_ike_activity?: boolean
  last_ike_timestamp_ns?: number | null
  last_ike_nat_t_timestamp_ns?: number | null
  last_esp_timestamp_ns?: number | null
  last_ah_timestamp_ns?: number | null
  spis?: SpiEntry[]
  transitions?: Transition[]
}

export type ComparisonStatus = 'MATCH' | 'MISMATCH' | 'UNKNOWN' | 'NOT_APPLICABLE' | string

export type EvidenceRef = {
  pcap_path: string
  capture_sequence?: number
  audit_event_reference?: string | null
  source?: string
  timestamp?: string | null
  artifact_type?: string
  artifact_sha256?: string
  byte_size?: number
  run_id?: string
  experiment_id?: string | null
  sequence?: number
  window_index?: number | null
  capture_start_ns?: number | null
  capture_end_ns?: number | null
  packet_start?: number | null
  packet_end?: number | null
  evidence_id?: string
}

export type ComparisonRow = {
  variable: string
  status: ComparisonStatus
  expected_value: unknown
  observed_value: unknown
  comparison_rule: string
  reason: string
  evidence_refs?: EvidenceRef[]
}

export type Correlation = {
  status: string
  rows: ComparisonRow[]
  status_counts?: Record<string, number>
  metadata?: {
    comparison_engine_version?: string
    observation_completeness?: string
    ml_evaluated?: boolean
    rules_executed?: string[]
    spi_summary?: Record<string, unknown>
    [key: string]: unknown
  }
}

export type RiskContribution = {
  finding_id: string
  rule_id: string
  category: string
  severity: string
  weight: number
  added: number
}

export type RiskScoreDetail = {
  score: number
  severity: string
  severity_band: [string, number, number] | unknown
  raw_sum: number
  contributions: RiskContribution[]
  per_category_totals?: [string, number][]
  explanation?: string
  [key: string]: unknown
}

export type Finding = {
  finding_id: string
  rule_id: string
  category: string
  severity: Severity | string
  title: string
  description: string
  reason: string
  condition: string
  source: string
  evidence_type: string
  related_variable: string
  expected_value: unknown
  observed_value: unknown
  confidence: number | null
  model_version: string | null
  evidence_refs: EvidenceRef[]
  assessment_id: string
  dataset_run_id: string
  scenario?: string
  sequence?: number
  window_index?: number | null
  risk_policy_version?: string
  read_only?: boolean
}

export type Risk = {
  schema_version: string
  risk_engine_version: string
  risk_policy_version: string
  overall_score: number
  severity: Severity | string
  identity?: Record<string, unknown>
  findings: Finding[]
  evidence_refs?: EvidenceRef[]
  score_detail?: RiskScoreDetail
  metadata?: {
    posture_context?: {
      authoritative_posture?: string
      posture_provenance?: string
      posture_is_context_only?: boolean
      posture_not_recomputed?: boolean
    }
    [key: string]: unknown
  }
}

export type FindingExplanation = {
  provenance: string
  finding_id: string
  rule_id: string
  title: string
  severity: Severity | string
  category: string
  related_variable: string
  description: string
  why_it_was_flagged: string
  expected: unknown
  observed: unknown
  condition: string
  reason: string
  source: string
  evidence_type: string
  evidence_refs: EvidenceRef[]
  confidence: number | null
  model_version: string | null
  contributing_factors: string[]
  explanation_categories: string[]
  limitations: string[]
}

export type MlExplanation = {
  provenance: string
  explanation_kind: string
  model_version: string | null
  traffic_class: string | null
  classification_confidence: number | null
  anomaly: boolean | null
  anomaly_score: number | null
  explanation: string
  explanation_categories: string[]
  limitations: string[]
  evidence_refs: EvidenceRef[]
}

export type XaiVariableExplanation = {
  variable?: string
  provenance?: string
  status?: string
  expected_value?: unknown
  explanation?: string
  reason?: string
  explanation_categories?: string[]
  limitations?: string[]
  limitation?: string | null
  [key: string]: unknown
}

export type ScoreExplanation = {
  provenance: string
  score: number
  severity: string
  severity_band: unknown
  risk_policy_version: string
  raw_sum: number
  contributions: RiskContribution[]
  per_category_totals?: [string, number][]
  explanation: string
  [key: string]: unknown
}

export type Xai = {
  schema_version: string
  identity?: Record<string, unknown>
  summary: {
    overall_score?: number
    severity?: string
    risk_policy_version?: string
    finding_explanations?: number
    ml_explanations?: number
    unknown_explanations?: number
    not_applicable_explanations?: number
    evidence_refs?: number
    overall_explanation?: string
  }
  finding_explanations: FindingExplanation[]
  ml_explanations: MlExplanation[]
  unknown_explanations?: XaiVariableExplanation[]
  not_applicable_explanations?: XaiVariableExplanation[]
  evidence_summary?: {
    total_refs?: number
    refs?: EvidenceRef[]
    sources?: unknown[]
    source_counts?: Record<string, number>
    /** Present only when the backend could not enumerate the registry. */
    limitation?: string | null
    provenance?: string
    fabricated?: boolean
  }
  score_explanation?: ScoreExplanation
  metadata?: {
    explainability_engine_version?: string
    input_summary?: Record<string, unknown>
    explanation_categories_present?: string[]
    unknown_handling?: Record<string, boolean>
    evidence_policy?: Record<string, unknown>
    [key: string]: unknown
  }
}

export type EvidenceBlock = {
  total_refs: number
  refs: EvidenceRef[]
  /** Distinct capture sources behind the refs, e.g. ["live_xdp"]. */
  sources?: string[]
  limitation?: string | null
}

export type MlResult = {
  present: boolean
  reason?: string
  model_version: string | null
  traffic_class: string | null
  classification_confidence: number | null
  anomaly: boolean | null
  anomaly_score: number | null
}

export type BundleSource = {
  path: string
  role?: string
  artifact_sha256?: string
  byte_size?: number
  record_count?: number
  feature_schema_version?: string
  window_start_ns?: number | null
  window_end_ns?: number | null
  endpoints?: { a?: string; b?: string } | null
  packets_seen?: number
  esp_seen?: boolean
  ike_seen?: boolean
  ike_nat_t_seen?: boolean
  spi_count?: number
  observation_start_ns?: number | null
  last_packet_timestamp_ns?: number | null
  [key: string]: unknown
}

export type AssessmentBundle = {
  assessment_id: string
  slot: string
  scenario: string
  dataset_run_id: string
  identity: {
    dataset_run_id: string
    sequence: number
    experiment_id: string
    attempt_number: number
    window_index: number | null
    window_start_ns: number | null
    window_end_ns: number | null
  }
  expected: ExpectedState
  observed: ObservedState
  correlation: Correlation
  ml: MlResult
  risk: Risk
  xai: Xai
  evidence: EvidenceBlock
  ipsec_state: ObservedState
  sources: BundleSource[]
}

/* ----------------------------------------------------------------- findings */

export type FindingsResponse = {
  api: string
  findings: Finding[]
  count: number
  total: number
  limit: number
  offset: number
  has_more: boolean
  read_only: boolean
  severity_order?: string[]
  note?: string
}

/* ------------------------------------------------------- custody chain (XAI) */

export type CustodyFact = {
  fact_id: string
  category: string
  authority: string
  authoritative: boolean
  label: string
  value: unknown
  value_digest?: string
  source?: string
  detail?: string
  evidence_ids?: string[]
}

export type CustodyStep = {
  index: number
  stage: string
  component: string
  action: string
  authoritative: boolean
  inputs: string[]
  outcome: string
}

export type CustodyEvidence = {
  evidence_id: string
  artifact_type?: string
  artifact_sha256?: string
  byte_size?: number
  verifiable?: boolean
  verification_status?: string
  verification_detail?: string
  artifact_present?: boolean
  actual_sha256?: string
  attached_by?: string[]
}

export type CustodyIntegrityCheck = {
  check_id: string
  description: string
  status: string
  passed: boolean
  detail: string
  observed?: unknown
  expected?: unknown
  client_verifiable?: boolean
}

export type CustodyExplanation = {
  schema_version: string
  component: string
  component_version: string
  read_only: boolean
  assessment_id: string
  finding_id: string
  finding_digest: string
  title: string
  summary: string
  category: string
  severity: Severity | string
  risk_score: number
  risk_severity: Severity | string
  risk_policy_version: string
  risk_engine_version: string
  identity: Record<string, unknown>
  rule: {
    rule_id: string
    finding_id: string
    registered: boolean
    base_rule_id?: string
    source_variable?: string
    authoritative_source?: string
    condition?: string
    evidence_requirement?: string
    unknown_handling?: string
    dedup_behavior?: string
    severity?: string
    score_contribution?: number
    [key: string]: unknown
  }
  facts: CustodyFact[]
  steps: CustodyStep[]
  evidence: CustodyEvidence[]
  sources: {
    role: string
    public_path: string
    artifact_sha256?: string
    byte_size?: number
    record_count?: number
    detail?: Record<string, unknown>
  }[]
  integrity: CustodyIntegrityCheck[]
  recommendation?: {
    recommendation_id?: string
    action?: string
    priority?: string
    policy_version?: string
    reason?: string
    rationale?: string
    authorization_required?: boolean
    approval_required?: boolean
    required_roles?: string[]
    limitations?: string[]
    applied?: boolean
    derived_by?: string
  }
  audit_event_ids?: string[]
  audit_linkage_status?: string
  limitations: string[]
  determinism?: Record<string, unknown>
  mission_context?: Record<string, unknown> | null
  drift?: unknown
  verification?: { performed?: boolean; reason?: string }
}

/* --------------------------------------------------------- audit (analysis) */

/**
 * One analysis-stage audit event, as listed by `GET /api/v1/audit/events`.
 *
 * These are the *only* persisted analysis events the read-only analytics plane
 * exposes to a browser. They are not packets: the journal records what the
 * correlation pipeline recorded about a run, not decrypted frame contents.
 * `source` and `authoritative` are echoed verbatim by the server and are never
 * upgraded, so a `comparison-engine` event can never be read as an observation
 * and an `ml` event can never be read as authoritative.
 */
export type AuditEventSummary = {
  event_id: string
  event_type: string
  /** Lifecycle stage; `null` for an event type the server does not map. */
  stage: string | null
  source: string
  authoritative: boolean
  recorded_at: string | null
  dataset_run_id: string
  sequence: number
  experiment_id: string
  attempt_number: number
  window_index: number | null
  window_start_ns: number | null
  window_end_ns: number | null
  response_proposal_ref?: string | null
}

export type AuditEventsResponse = {
  api: string
  read_only: boolean
  source_of_truth?: string
  count: number
  total: number
  limit: number
  offset: number
  filters?: Record<string, unknown>
  stage_order?: string[]
  events: AuditEventSummary[]
}

/**
 * The complete persisted record for one audit event. Stage payloads are
 * optional by design — a run may legitimately stop after comparison — so an
 * absent field means "this stage produced no result", never a default.
 */
export type AuditEventDetail = {
  schema_version: string
  event_id: string
  event_type: string
  source: string
  authoritative: boolean
  recorded_at: string | null
  identity: {
    dataset_run_id: string
    sequence: number
    experiment_id: string
    attempt_number: number
    window_index: number | null
    window_start_ns: number | null
    window_end_ns: number | null
  }
  provenance?: Record<string, unknown>
  expected_ref?: Record<string, unknown> | null
  observed_ref?: Record<string, unknown> | null
  comparison?: Record<string, unknown> | null
  ml_ref?: Record<string, unknown> | null
  risk_ref?: Record<string, unknown> | null
  explanation_ref?: Record<string, unknown> | null
  decision?: Record<string, unknown> | null
  response_proposal_ref?: string | null
  evidence_refs?: EvidenceRef[]
}

export type AuditRunsResponse = {
  api: string
  read_only: boolean
  count: number
  total: number
  runs: {
    run_id: string
    event_count?: number
    window_count?: number
    stages_present?: string[]
    first_event_id?: string
    last_event_id?: string
    first_recorded_at?: string | null
    last_recorded_at?: string | null
    [key: string]: unknown
  }[]
}

export type RunAuditTrailResponse = {
  api: string
  read_only: boolean
  run_id: string
  window_count: number
  event_count: number
  returned_event_count?: number
  limit?: number
  offset?: number
  has_more?: boolean
  stage_order?: string[]
  stages_present?: string[]
  windows: {
    window_index: number | null
    window_start_ns: number | null
    window_end_ns: number | null
    stage_names: string[]
    stages: {
      stage: string
      present: boolean
      event_count: number
      events: AuditEventSummary[]
      response_lifecycle?: Record<string, unknown> | null
    }[]
  }[]
}

/* ------------------------------------------------------------------- drift */

export type DriftChangedField = {
  variable?: string
  category?: string
  baseline_value?: unknown
  current_value?: unknown
  change?: string
  severity?: string
  [key: string]: unknown
}

export type DriftSummary = {
  api?: string
  read_only?: boolean
  configured?: boolean
  status?: string
  reason?: string | null
  persistent?: boolean
  baseline_ids?: string[]
  baselines?: Record<string, unknown>[]
  canonicalization?: Record<string, unknown>
  assessment_count?: number
  compared_count?: number
  drift_detected_count?: number
  assessments?: Record<string, unknown>[]
  [key: string]: unknown
}

export type DriftBaselinesResponse = DriftSummary

export type AssessmentDriftResponse = {
  api: string
  read_only: boolean
  assessment_id: string
  status: string
  drift_detected: boolean
  reason?: string | null
  baseline: Record<string, unknown> | null
  current: Record<string, unknown> | null
  changed_fields: DriftChangedField[]
  unchanged_variables?: string[]
  unknown_variables?: string[]
  drift_categories?: string[]
  risk: Record<string, unknown> | null
}

/* ------------------------------------------------- evidence & integrity */

/**
 * Read-only integrity status for one evidence artifact. `verification_status`
 * distinguishes "verified", "mismatch" and "unavailable" — an artifact whose
 * bytes are absent is reported as unavailable, never as passing.
 */
export type EvidenceIntegrity = {
  api?: string
  read_only?: boolean
  evidence_id: string
  artifact_type?: string
  artifact_sha256?: string
  byte_size?: number
  artifact_present?: boolean
  actual_sha256?: string | null
  verifiable?: boolean
  verification_status?: string
  verification_detail?: string
  path?: string
  attached_by?: string[]
  [key: string]: unknown
}

/* ----------------------------------------- frontend capability boundaries */

/**
 * The status an integration reports before any work is attempted. Sentinel
 * refuses to render a partially-applied result, so every boundary is either
 * fully available or explicitly not connected.
 */
export type CapabilityStatus = 'available' | 'not_connected' | 'unavailable'

/**
 * Where a value came from.
 *
 * This is the distinction the whole feature rests on, so it is a closed set
 * rather than a free string: a renderer can rely on the four cases being
 * exhaustive and can therefore always label what it shows.
 *
 * - `observed_fact` — recorded by the tools: packets, configuration, drift.
 * - `deterministic_assessment` — produced by the risk engine: severity, score,
 *   findings. The security verdict, and never the assistant's to change.
 * - `ml_inference` — a model prediction about traffic shape. Not a judgement.
 * - `ai_explanation` — generated prose. Adds no new finding and no new number.
 */
export type AiOrigin = 'observed_fact' | 'deterministic_assessment' | 'ml_inference' | 'ai_explanation'

/** How a question was classified, so the UI can label the kind of answer. */
export type AiScopeIntent =
  | 'risk_explanation'
  | 'expected_vs_observed'
  | 'evidence'
  | 'terminology'
  | 'decision_request'
  | 'general_ipsec'
  | 'out_of_scope'

/**
 * What produced the text. `deterministic_template` is the important one: with
 * no model configured the service still answers, from recorded values, and the
 * answer is not generated. A UI that says "AI wrote this" for a template would
 * be lying about provenance.
 */
export type AiAnswerOrigin = 'llm' | 'deterministic_template' | 'glossary' | 'fixed_refusal' | 'unavailable'

export type AiGuardStatus = 'clean' | 'substituted' | 'refused'

export type AiCitation = {
  kind: string
  identifier: string
  origin: AiOrigin
}

/**
 * The backend's own verdict, carried beside the prose.
 *
 * The analyst reads severity and score from *this*, not from the explanation
 * text, which is what keeps the visual trust boundary honest: the number on
 * screen is the number the risk engine produced.
 */
export type AiAuthoritativeBlock = {
  read_only: true
  origin: AiOrigin
  source: string
  assessment_id: string | null
  finding_id: string | null
  severity: string | null
  risk_score: number | null
  risk_policy_version: string | null
  risk_engine_version: string | null
  finding?: Record<string, unknown> | null
  [key: string]: unknown
}

/**
 * The ML block.
 *
 * `assistant_confidence` is present and always null. It exists to make the
 * absence explicit: a model confidence is exactly the field an analyst would
 * otherwise assume exists and would over-trust.
 */
export type AiMlBlock = {
  origin: AiOrigin
  source: string
  present: boolean
  traffic_class: string | null
  classification_confidence: number | null
  model_version: string | null
  anomaly: boolean | null
  anomaly_score: number | null
  reason: string | null
  assistant_confidence: null
  note: string
}

export type AiExplainResponse = {
  api: string
  schema_version: string
  /** Always true. The service has no route that changes anything. */
  read_only: true
  /** Always false. Explanation is not a decision. */
  decision_made: false
  is_explanation: true
  label: string
  answer: string
  question: string
  origin: AiAnswerOrigin
  assessment_id: string | null
  finding_id: string | null
  model_version: string | null
  scope: {
    in_scope: boolean
    intent: AiScopeIntent
    reason: string
    matched_terms: string[]
  }
  guard: {
    status: AiGuardStatus
    violations: string[]
    detail: string | null
    clean: boolean
  }
  citations: AiCitation[]
  authoritative: AiAuthoritativeBlock
  ml: AiMlBlock
}

export type AiHealthResponse = {
  api: string
  read_only: true
  status: string
  role: string
  context: { available: boolean; source: string; reason: string | null }
  model: { configured: boolean; provider: string; model_version: string | null; reason: string | null }
  capabilities: Record<string, boolean>
}

export type AiAnalysisRequest = {
  entityId: string
  entityKind: 'assessment' | 'finding' | 'evidence'
  /**
   * The investigation summary the analysis is scoped to. This is selected
   * packet/assessment context assembled on the surface so a future backend
   * (and a future reader) knows exactly which observation a model would have
   * explained. It is never treated as a measurement.
   */
  context?: string
  /** The question. The follow-up field in the AI panel. */
  question?: string
  /** Narrows the answer to one finding of the assessment. */
  findingId?: string | null
  /** Prior turns about the same context, oldest first. */
  history?: { question: string; answer: string }[]
}

export type AiAnalysisResult = {
  status: CapabilityStatus
  /** True only when the service actually answered. */
  connected: boolean
  entityId: string
  /** Echoed verbatim; the boundary renders what a model would have seen. */
  context?: string
  /** Always populated: the reason when unavailable, the answer's summary when not. */
  reason: string
  /**
   * Present only when the service answered. Never synthesised in the browser:
   * a failed request yields no `analysis` at all rather than an empty object
   * that would render as an explanation of nothing.
   */
  analysis?: AiExplainResponse
  /** The service's own capability statement, for the "why not" affordance. */
  health?: AiHealthResponse
}

export type ReportKind = 'assessment' | 'incident' | 'evidence-log'

export type ReportRequest = {
  kind: ReportKind
  entityId: string
}

export type ReportResult = {
  status: CapabilityStatus
  connected: boolean
  kind: ReportKind
  entityId: string
  reason: string
  /** Present only when a real report service answers. Never synthesised. */
  document?: never
}

/* ----------------------------------------------------------------- control */

export type ExperimentConfigurations = {
  modes: string[]
  address_families: string[]
  ike: {
    version: number
    encryption: string[]
    integrity: string[]
    dh_groups: string[]
  }
  esp: {
    encryption: string[]
    integrity: string[]
    dh_groups: string[]
    pfs: boolean[]
  }
  traffic: {
    profiles: string[]
    duration: { min: number; max: number; default: number }
  }
}

export type ExperimentRequest = {
  mode: string
  address_family: string
  ike: { version: number; encryption: string; integrity: string; dh_group: string }
  esp: {
    encryption: string
    integrity: string | null
    dh_group: string
    pfs: boolean
  }
  traffic: { profile: string; duration: number }
}

export type ExperimentJob = {
  job_id: string
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | string
  /** QUEUED | RUNNING | DEPLOY | IPSEC | OBSERVATION | CONNECTIVITY | TRAFFIC | COMPLETED | CONFIGURATION | EXPERIMENT */
  stage: string
  result: ExperimentResultPayload | null
  error: string | null
}

/** The payload `run_experiment` returns; every field is server-produced. */
export type ExperimentResultPayload = {
  status: 'PASS' | 'FAIL' | string
  mode: string
  address_family: string
  ike: ExperimentRequest['ike']
  esp: ExperimentRequest['esp']
  connectivity: { status: string; packet_loss?: number; [key: string]: unknown }
  ipsec: { ike_sa?: string | null; child_sa?: string | null; mode?: string; [key: string]: unknown }
  traffic?: { status?: string; profile?: string; [key: string]: unknown }
}

export type ControlHealth = { status: string }

/* ------------------------------------------------------------- capture */

/**
 * One captured packet as served by /api/v1/capture/events. The `packet` block
 * is the streaming adapter's canonical normalization of the raw XDP event,
 * verbatim; `protocol_label` and `info` are computed server-side so the UI
 * never re-parses a packet. `risk` is a verbatim projection of the assessment
 * store by observed SPI — absent when no assessment observed the SPI.
 */
export type CapturePacket = {
  id: string
  source: string
  offset: number
  timestamp_ns: number
  schema: string
  packet: {
    timestamp: number
    interface: string
    protocol: number
    source: string
    destination: string
    spi: number | null
    sequence: number
    packet_length: number
    source_port: number
    destination_port: number
    classification: string
    direction: string | null
    sensor_type: string
  }
  protocol_label: string
  info: string
  spi: number | null
  direction: string | null
  risk:
    | {
        present: false
      }
    | {
        present: true
        highest_severity: Severity | string | null
        highest_risk_score: number | null
        assessments: {
          assessment_id: string
          severity: Severity | string | null
          risk_score: number | null
          finding_count: number
        }[]
      }
}

/**
 * A packet in the live buffer, stamped with the provenance the feed reported
 * for the page that delivered it.
 *
 * The verdict is the backend's, never the UI's: a page whose envelope carries
 * `current: true` was read from a journal that is *actively being written*, so
 * the packets it delivered are current traffic. Anything else — a `current:
 * false` page, or a server too old to answer the question at all — is recorded
 * history, and must never be presented as live.
 */
export type FeedPacket = CapturePacket & {
  /** True only when the delivering page reported an actively written journal. */
  live: boolean
}

export type CaptureEventsResponse = {
  api: string
  schema: string
  state: 'available' | 'waiting' | string
  read_only: boolean
  present: boolean
  reason: string | null
  source: string
  frame: string
  cursor: number
  start_cursor: number
  size: number
  total: number
  count: number
  limit: number
  has_more: boolean
  /**
   * Whether the journal is being actively appended to right now (server-side
   * verdict from write activity). `false` means the file exists but holds no
   * *current* traffic — its rows are recorded history and must never be
   * presented as live. Absent on old servers = treat as "authoritative
   * unknown", i.e. not assumed current.
   */
  current?: boolean
  /** The server's live-freshness window (a journal is current while writes
   *  stay inside it). */
  freshness_window_ms?: number
  /** Milliseconds since the journal was last written, when it exists. */
  last_write_age_ms?: number | null
  /** Wall-clock time of the journal's last modification. */
  journal_mtime_ms?: number | null
  /** Server time when the envelope was built. */
  server_time_ms?: number
  /** Wall-clock time of the newest complete line in the journal. */
  newest_observed_at_ms?: number | null
  events: CapturePacket[]
}
