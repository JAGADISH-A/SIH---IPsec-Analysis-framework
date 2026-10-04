/**
 * Temporary live data-contract smoke test (not part of the shipped app).
 *
 * Calls every API wrapper against the running backends and asserts that the
 * exact fields the UI reads are actually present. This is what catches a wrong
 * field name, which a typecheck cannot, because the wire types are hand-written.
 */
import {
  getAnalyticsHealth,
  getAnalyticsV1Health,
  getAssessment,
  getAssessmentDrift,
  getAssessmentFindings,
  getAssessments,
  getAssessmentsV1,
  getAssetContext,
  getAssets,
  getAuditEvent,
  getAuditEvents,
  getAuditRuns,
  getDriftBaselines,
  getDriftSummary,
  getEvidenceIntegrity,
  getFindingExplanation,
  getFindings,
  getRunAuditTrail,
} from '@/api/analytics'
import { getControlHealth, getExperimentConfigurations } from '@/api/control'
import { analyzeWithAI } from '@/api/ai'
import { generateReport } from '@/api/reports'
import { getCaptureEvents } from '@/api/analytics'

let failures = 0
function check(label: string, condition: boolean, detail = '') {
  if (condition) {
    console.log(`ok   ${label}`)
  } else {
    failures += 1
    console.error(`FAIL ${label} ${detail}`)
  }
}
function missing(source: object, keys: string[]): string[] {
  return keys.filter((key) => !(key in source))
}

async function main() {
  const health = await getAnalyticsHealth()
  check('analytics /api/health', health.status !== undefined, JSON.stringify(health).slice(0, 120))
  check(
    'analytics health fields read by SystemStatus',
    missing(health, [
      'status',
      'service',
      'api_schema_version',
      'store_version',
      'total_assessments',
      'read_only',
      'note',
    ]).length === 0,
    JSON.stringify(Object.keys(health)),
  )

  const v1 = await getAnalyticsV1Health()
  check('analytics /api/v1/health components', v1.components !== undefined)
  check('analytics v1 cors.allowed_origins', Array.isArray(v1.cors?.allowed_origins))

  const list = await getAssessments({ limit: 200 })
  check('assessments overview', Boolean(list.overview))
  check('assessments headers', list.headers.length > 0, `count=${list.headers.length}`)
  const headerMissing = missing(list.headers[0] as object, [
    'assessment_id',
    'slot',
    'severity',
    'risk_score',
    'finding_count',
    'security_posture',
    'traffic_profile',
    'ml_present',
    'ml_anomaly',
    'scenario',
  ])
  check('assessment header fields read by the UI', headerMissing.length === 0, headerMissing.join(','))
  check(
    'assessments envelope fields',
    missing(list, ['overview', 'headers', 'count', 'total', 'limit', 'offset']).length === 0,
    Object.keys(list).join(','),
  )
  check(
    'overview fields read by Overview/XAI/ML/Status',
    missing(list.overview as object, [
      'total_assessments',
      'findings_total',
    'severity_counts',
    'category_counts',
    'unknown_observations',
      'ml_anomalies',
      'ml_classification_disagreements',
      'xai_available',
      'risk_policy_version',
      'store_version',
      'highest_risk',
      'highest_severity',
      'dataset_run_id',
      'source',
      'sources',
    ]).length === 0,
    Object.keys(list.overview as object).join(','),
  )

  const v1list = await getAssessmentsV1({ limit: 200 })
  check('assessments v1 rows', (v1list.assessments ?? v1list.headers ?? []).length > 0, Object.keys(v1list).join(','))
  check('assessments v1 filters echo', v1list.total !== undefined)

// Pick an assessment that actually raised a finding, so the custody endpoint
// below is exercised against a real (assessment, finding) pair.
const withFindings = list.headers.find((h) => h.finding_count > 0)
check('store has an assessment with findings', Boolean(withFindings))

const first = withFindings ?? list.headers[0]
const bundle = await getAssessment(first.assessment_id)
  check('bundle assessment_id', bundle.assessment_id === first.assessment_id)
  const bundleMissing = missing(bundle, [
    'assessment_id',
    'expected',
    'observed',
    'correlation',
    'risk',
    'ml',
    'xai',
    'evidence',
    'ipsec_state',
    'sources',
  ])
  check('bundle sections', bundleMissing.length === 0, bundleMissing.join(','))

  const assessmentFindings = await getAssessmentFindings(bundle.assessment_id)
  check('per-assessment findings', Array.isArray(assessmentFindings.findings))

  const findings = await getFindings({ limit: 1000 })
  check('findings list', findings.findings.length > 0, `count=${findings.findings.length}`)
  const findingMissing = missing(findings.findings[0] as object, [
    'finding_id',
    'rule_id',
    'assessment_id',
    'dataset_run_id',
    'severity',
    'title',
    'description',
    'reason',
    'condition',
    'source',
    'evidence_type',
    'related_variable',
    'expected_value',
    'observed_value',
    'evidence_refs',
    'scenario',
    'sequence',
  ])
  check('finding fields read by Findings page', findingMissing.length === 0, findingMissing.join(','))
  check(
    'findings envelope fields',
    missing(findings, ['findings', 'total', 'limit', 'offset', 'count', 'has_more', 'read_only', 'note']).length ===
      0,
    Object.keys(findings).join(','),
  )

  const withRefs = findings.findings.find((f) => (f.evidence_refs ?? []).length > 0)
  if (withRefs) {
    const ref = withRefs.evidence_refs![0]
    const refMissing = missing(ref, [
      'artifact_sha256',
      'byte_size',
      'capture_start_ns',
      'timestamp',
      'pcap_path',
    ])
    check('evidence ref fields read by the Evidence browser', refMissing.length === 0, refMissing.join(','))
    console.log(`note evidence refs across store: ${findings.findings.reduce((n, f) => n + (f.evidence_refs?.length ?? 0), 0)}`)
  } else {
    console.log('note no finding carries evidence_refs')
  }

  // Custody is addressed by the (assessment, finding) pair, because a finding
  // id repeats across assessments.
  const target =
    findings.findings.find((f) => f.assessment_id === first.assessment_id) ?? findings.findings[0]
  const explanation = await getFindingExplanation(target.assessment_id, target.finding_id)
  const explanationMissing = missing(explanation, [
    'schema_version',
    'component',
    'assessment_id',
    'finding_id',
    'finding_digest',
    'title',
    'summary',
    'category',
    'severity',
    'risk_score',
    'risk_severity',
    'identity',
    'rule',
    'facts',
    'steps',
    'evidence',
    'sources',
    'integrity',
    'recommendation',
    'limitations',
    'determinism',
    'verification',
  ])
  check('custody explanation envelope', explanationMissing.length === 0, explanationMissing.join(','))
  check('custody facts carry authority', explanation.facts.every((f) => 'authoritative' in f && 'authority' in f))
  // Steps are 1-based and must be strictly increasing in stage order.
  check(
    'custody steps ordered',
    explanation.steps.every((s, i) => s.index === i + 1),
    explanation.steps.map((s) => s.index).join(','),
  )
  check('custody summary is prose', typeof explanation.summary === 'string' && explanation.summary.length > 0)
  check('determinism reported', typeof explanation.determinism?.deterministic === 'boolean')

  const controlHealth = await getControlHealth()
  check('control /health', controlHealth.status !== undefined, JSON.stringify(controlHealth).slice(0, 120))

  const configs = await getExperimentConfigurations()
  const configMissing = missing(configs, [
    'modes',
    'address_families',
    'ike',
    'esp',
    'traffic',
  ]).concat(
    missing(configs.ike, ['version', 'encryption', 'integrity', 'dh_groups']),
    missing(configs.esp, ['encryption', 'integrity', 'dh_groups', 'pfs']),
    missing(configs.traffic, ['profiles', 'duration']),
    missing(configs.traffic.duration, ['min', 'max', 'default']),
  )
  check('configuration fields read by the Run Assessment page', configMissing.length === 0, configMissing.join(','))
  check('config options are non-empty', [
    configs.modes.length,
    configs.address_families.length,
    configs.ike.encryption.length,
    configs.esp.encryption.length,
    configs.esp.pfs.length,
    configs.traffic.profiles.length,
  ].every((n) => n > 0))
  console.log(
    `note ${configs.modes.length} modes · ${configs.address_families.length} address families · ` +
      `${configs.traffic.profiles.length} traffic profiles · duration ${configs.traffic.duration.min}-${configs.traffic.duration.max}s`,
  )

  // ---------------------------------------------------------- live traffic
  //
  // The live monitor is the primary workspace, so the audit journal is the
  // surface most worth pinning down: a wrong field name here would render an
  // empty or misleading table rather than fail loudly.
  const audit = await getAuditEvents({ limit: 50 })
  check('audit events envelope', Array.isArray(audit.events), Object.keys(audit).join(','))
  check('audit read_only', audit.read_only === true)

  if (audit.events.length > 0) {
    const first = audit.events[0]
    const eventMissing = missing(first, [
      'event_id',
      'event_type',
      'stage',
      'source',
      'authoritative',
      'recorded_at',
      'dataset_run_id',
      'sequence',
      'experiment_id',
      'attempt_number',
      'window_index',
      'window_start_ns',
      'window_end_ns',
    ])
    check('audit event summary fields read by the monitor', eventMissing.length === 0, eventMissing.join(','))
    check('audit stage_order is published', Array.isArray(audit.stage_order))
    // The server echoes the active filters so a client can see what it asked.
    check('audit filters echoed', audit.filters !== undefined)

    const detail = await getAuditEvent(first.event_id)
    check('audit detail echoes the same event_id', detail.event_id === first.event_id)
    check(
      'audit detail identity fields',
      missing(detail.identity, [
        'dataset_run_id',
        'sequence',
        'experiment_id',
        'attempt_number',
        'window_index',
        'window_start_ns',
        'window_end_ns',
      ]).length === 0,
    )
    // Provenance must survive the round trip verbatim: a derived event must not
    // come back labelled authoritative.
    check(
      'audit authority preserved verbatim',
      detail.authoritative === first.authoritative && detail.source === first.source,
      `${detail.source}/${detail.authoritative}`,
    )
    check('audit schema_version present', typeof detail.schema_version === 'string')
  } else {
    console.log('note no audit journal attached: the monitor will render its unavailable state')
  }

  const auditRuns = await getAuditRuns()
  check('audit runs envelope', Array.isArray(auditRuns.runs), Object.keys(auditRuns).join(','))
  if (auditRuns.runs.length > 0) {
    const trail = await getRunAuditTrail(auditRuns.runs[0].run_id)
    check('run trail envelope', Array.isArray(trail.windows))
    // Windows list only the stages that actually recorded an event.
    check(
      'run trail stages are a subset of the published stage order',
      trail.windows.every((window) =>
        window.stages.every((stage) => (trail.stage_order ?? []).includes(stage.stage)),
      ),
    )
  }

  // ------------------------------------------------------------ capture view
  //
  // The first page is the packet-capture workspace, so the capture feed is the
  // surface most worth pinning down: a wrong field name here would render a
  // broken or misleading packet table rather than fail loudly. The feed is the
  // read-only tail of the gateway's xdp_monitor journal; a feed with no
  // packets reports its waiting state and is a valid, honest contract.
  const capture = await getCaptureEvents({ limit: 200 })
  check('capture read_only', capture.read_only === true)
  check('capture envelope', typeof capture.present === 'boolean' && Array.isArray(capture.events))
  check('capture cursor is a byte offset', typeof capture.cursor === 'number')
  check('capture source named', typeof capture.source === 'string' && capture.source.length > 0)
  // The backend decides currentness (a journal is current only while actively
  // written); the UI renders live rows solely on this verdict, so the verdict
  // must travel in the envelope, not be approximated client-side.
  check('capture liveness verdict is explicit', typeof capture.current === 'boolean', String(capture.current))
  check(
    'capture liveness window is serialized',
    typeof capture.freshness_window_ms === 'number' && capture.freshness_window_ms > 0,
    String(capture.freshness_window_ms),
  )
  check(
    'capture last-write age is numeric when the journal exists',
    capture.last_write_age_ms === null || typeof capture.last_write_age_ms === 'number',
  )
  check(
    'capture newest-observed time is numeric or absent',
    capture.newest_observed_at_ms === null || capture.newest_observed_at_ms === undefined || typeof capture.newest_observed_at_ms === 'number',
  )
  check(
    'a journal that is not being written is never reported current',
    !capture.present || capture.last_write_age_ms === null || capture.last_write_age_ms <= capture.freshness_window_ms + 500 || capture.current === false,
    `present=${capture.present} age=${capture.last_write_age_ms} window=${capture.freshness_window_ms} current=${capture.current}`,
  )

  if (capture.events.length > 0) {
    const first = capture.events[0]
    const packetMissing = missing(first, [
      'id',
      'source',
      'timestamp_ns',
      'schema',
      'protocol_label',
      'info',
      'spi',
    ]).concat(
      missing(first.packet, [
        'timestamp',
        'protocol',
        'source',
        'destination',
        'classification',
        'packet_length',
        'sequence',
        'spi',
        'source_port',
        'destination_port',
      ]),
    )
    check('capture packet fields read by the workspace', packetMissing.length === 0, packetMissing.join(','))
    check('capture risk is explicitly present/absent', typeof first.risk.present === 'boolean')
    // The capture adapter maps once, at ingest: the packet-level timestamp must
    // equal the envelope timestamp, and both must be a realtime epoch — printed
    // as an analyst-local time, never as sensor uptime. The 1.7e18 lower bound
    // is 2024-01-01Z; uptime/seconds values stay far below it by construction.
    check('envelope and packet timestamps agree', first.timestamp_ns === first.packet.timestamp, `${first.timestamp_ns} vs ${first.packet.timestamp}`)
    check(
      'capture timestamps are realtime epoch nanoseconds',
      first.timestamp_ns > 1.7e18 && first.timestamp_ns < Date.now() * 1e6 + 86400e9,
      String(first.timestamp_ns),
    )
    if (first.risk.present === true) {
      check(
        'capture risk carries the store verbatim',
        typeof first.risk.highest_severity === 'string' && Array.isArray(first.risk.assessments),
      )
    } else {
      console.log('note no assessment observed any captured SPI; risk renders as an em dash')
    }
  } else if (capture.present === false) {
    check('capture waiting state explains itself', typeof capture.reason === 'string' && capture.reason.length > 0)
  }

  // ------------------------------------------------------------------ drift
  const drift = await getDriftSummary()
  check('drift read_only', drift.read_only === true)
  check('drift reports configured state', typeof drift.configured === 'boolean')
  if (drift.configured === false) {
    // An unconfigured store must say why rather than look like "no drift".
    check('unconfigured drift explains itself', typeof drift.reason === 'string' && drift.reason.length > 0)
  }
  const baselines = await getDriftBaselines()
  check('baseline registry reports configured state', typeof baselines.configured === 'boolean')
  check('baseline ids is a list', Array.isArray(baselines.baseline_ids))

  const assessmentDrift = await getAssessmentDrift(first.assessment_id)
  check('assessment drift envelope', assessmentDrift.assessment_id === first.assessment_id)
  check(
    'assessment drift distinguishes unknown from clean',
    assessmentDrift.status === 'not_configured' || typeof assessmentDrift.drift_detected === 'boolean',
    assessmentDrift.status,
  )

  // --------------------------------------------------------------- evidence
  if (withRefs) {
    const evidenceId = withRefs.evidence_refs![0].evidence_id
    if (evidenceId) {
      // An evidence *reference* on a finding is not the same as an artifact the
      // registry can serve, so a 404 here is a real, expected outcome rather
      // than a broken contract. The UI has to render it, so assert on it.
      let integrity
      try {
        integrity = await getEvidenceIntegrity(evidenceId)
      } catch (cause) {
        integrity = null
        const err = cause as { status?: number; code?: string; detail?: string }
        check(
          'unresolvable evidence reports a structured 404',
          err.status === 404 && err.code === 'evidence_not_found',
          `${err.status} ${err.code}`,
        )
        check('unresolvable evidence explains itself', Boolean(err.detail && err.detail.length > 0))
      }
      if (integrity) {
        check('integrity echoes the evidence id', integrity.evidence_id === evidenceId)
        // An artifact that is not on disk must be reported absent, not verified.
        check(
          'integrity reports a real verification state',
          integrity.verification_status !== undefined || integrity.artifact_present === false,
          JSON.stringify(Object.keys(integrity)).slice(0, 160),
        )
      } else {
        console.log(`note evidence ${evidenceId} is referenced but not registered; drawer shows it as unavailable`)
      }
    } else {
      console.log('note evidence ref carries no evidence_id; integrity endpoint not addressable')
    }
  }

  // ------------------------------------------------------ mission (assets)
  const assets = await getAssets()
  check('asset list is read-only', assets.read_only === true)
  check('asset list reports configured state', typeof assets.configured === 'boolean')
  check('asset list carries an assets array', Array.isArray(assets.assets))
  check('asset count agrees with the list', assets.count === assets.assets.length)
  if (assets.configured === false) {
    // A store started without --mission-profiles declares nothing. That must be
    // stated, not rendered as a network with no assets, and the panel shows it
    // as an empty state.
    check(
      'unconfigured asset inventory explains itself',
      typeof assets.reason === 'string' && assets.reason.length > 0,
    )
    console.log('note no mission profile file is attached; asset context needs --asset-id --mission-profiles')
  } else {
    check(
      'asset inventory carries its provenance',
      typeof assets.source === 'string' && typeof assets.source_sha256 === 'string',
      JSON.stringify(Object.keys(assets)).slice(0, 160),
    )
    const declared = assets.assets[0]
    const context = await getAssetContext(declared)
    check('asset context is read-only', context.read_only === true)
    check('asset context echoes the requested asset', context.asset_id === declared)
    check(
      'asset context states how the technical risk was chosen',
      ['assessment_header', 'store_highest_risk'].includes(context.technical_risk_source),
      context.technical_risk_source,
    )
    check(
      'asset context fields read by the panel',
      missing(context, [
        'asset_id',
        'assessment_id',
        'technical_risk_source',
        'technical_risk',
        'technical_severity',
        'mission_context',
      ]).length === 0,
      JSON.stringify(Object.keys(context)),
    )
    check(
      'mission context reports status and configured together',
      typeof context.mission_context.status === 'string' &&
        context.mission_context.configured === (context.mission_context.status === 'configured'),
      context.mission_context.status,
    )
    if (context.mission_context.configured) {
      check(
        'configured mission context publishes a profile and a risk',
        missing(context.mission_context, ['profile', 'risk', 'context_source']).length === 0 &&
          context.mission_context.profile !== null &&
          context.mission_context.risk !== null,
      )
      check(
        'the profile fields the panel renders',
        missing(context.mission_context.profile as object, [
          'asset_id',
          'role',
          'criticality',
          'mission_impact',
        ]).length === 0,
        JSON.stringify(Object.keys(context.mission_context.profile ?? {})),
      )
      check(
        'the risk fields the panel renders',
        missing(context.mission_context.risk as object, [
          'technical_risk',
          'technical_severity',
          'contextualized_risk',
          'contextualized_severity',
          'context_index',
          'multiplier_bp',
          'criticality_weight',
          'mission_impact_weight',
          'score_cap',
          'inferred_from_traffic',
          'model_version',
        ]).length === 0,
        JSON.stringify(Object.keys(context.mission_context.risk ?? {})),
      )
      check(
        'context is never inferred from traffic',
        context.mission_context.risk?.inferred_from_traffic === false &&
          context.mission_context.derived_from_observation === false,
      )
    } else {
      // Absent context must carry no profile and no risk, so the panel cannot
      // mistake "nothing declared" for "nothing wrong".
      check(
        'unconfigured context publishes no profile and no risk',
        context.mission_context.profile === null &&
          context.mission_context.risk === null &&
          typeof context.mission_context.reason === 'string',
        JSON.stringify(context.mission_context).slice(0, 160),
      )
    }
  }

  // --------------------------------------------------------------- AI plane
  //
  // The explanation plane is optional, so this branch is written to hold in
  // both deployments. What must never be true in either is the interesting
  // part: content that the service did not produce.
  const ai = await analyzeWithAI({
    entityId: first.assessment_id,
    entityKind: 'assessment',
    question: `Why is this ${first.severity}?`,
  })

  if (ai.connected && ai.analysis) {
    const answer = ai.analysis
    check('AI answer declares itself read-only', answer.read_only === true)
    check('AI answer declares that it made no decision', answer.decision_made === false)
    check('AI answer is labelled as an explanation', answer.is_explanation === true)
    check('AI answer reports a guard status', typeof answer.guard.status === 'string')
    check(
      'AI answer carries a guard report with every violation',
      answer.guard.violations.length > 0 || answer.guard.clean === true,
    )
    check('AI answer names its scope intent', typeof answer.scope.intent === 'string')

    // The four origins must be distinguishable in the payload, because the UI
    // gives each one its own visual treatment and cannot do that from a blob.
    check(
      'AI authoritative block is attributed to the deterministic engine',
      answer.authoritative.origin === 'deterministic_assessment',
    )
    check(
      'AI authoritative block carries the backend severity unchanged',
      answer.authoritative.severity === first.severity,
    )
    check(
      'AI authoritative block carries the backend score unchanged',
      answer.authoritative.risk_score === first.risk_score,
    )
    check('AI ml block is attributed to ml_inference', answer.ml.origin === 'ml_inference')
    check(
      'AI reports no confidence of its own',
      answer.ml.assistant_confidence === null && answer.ml.classification_confidence !== undefined,
    )

    // Every citation must point at something that exists in the store, or say
    // plainly that it is a model prediction.
    check(
      'every AI citation is attributed to a known origin',
      answer.citations.every((c) =>
        ['observed_fact', 'deterministic_assessment', 'ml_inference', 'ai_explanation'].includes(
          c.origin,
        ),
      ),
    )

    // A follow-up about a term needs no assessment, and must still be answered
    // from the glossary rather than refused.
    const term = await analyzeWithAI({
      entityId: first.assessment_id,
      entityKind: 'assessment',
      question: 'What does PFS mean?',
    })
    check(
      'AI answers a definition question',
      term.connected && term.analysis?.scope.intent === 'terminology',
    )
    check(
      'definition answer is not presented as an assessment judgement',
      term.analysis !== undefined && term.analysis.authoritative.read_only === true,
    )

    // Out of scope must produce the fixed refusal and no prose.
    const offTopic = await analyzeWithAI({
      entityId: first.assessment_id,
      entityKind: 'assessment',
      question: 'What is the weather?',
    })
    check(
      'off-topic question is refused',
      offTopic.analysis !== undefined && offTopic.analysis.scope.in_scope === false,
    )
    check(
      'off-topic refusal is short and fixed',
      offTopic.analysis !== undefined &&
        offTopic.analysis.origin === 'fixed_refusal' &&
        offTopic.analysis.answer.length < 400,
    )
  } else {
    console.log('note AI explanation service is not running; asserting the disconnected contract')
    check('AI boundary reports not connected', ai.connected === false)
    check('AI boundary returns no analysis payload', ai.analysis === undefined)
    check('AI boundary explains itself', ai.reason.length > 0)
  }

  const report = await generateReport({ kind: 'assessment', entityId: first.assessment_id })
  check('report boundary reports unavailable', report.connected === false && report.status === 'unavailable')
  check('report boundary returns no document', report.document === undefined)
  check('report boundary explains itself', report.reason.length > 0)

  console.log(failures === 0 ? 'ALL API CONTRACTS OK' : `${failures} CONTRACT CHECK(S) FAILED`)
  if (failures > 0) process.exitCode = 1
}

main().catch((error) => {
  console.error('smoke run failed:', error)
  process.exitCode = 1
})
