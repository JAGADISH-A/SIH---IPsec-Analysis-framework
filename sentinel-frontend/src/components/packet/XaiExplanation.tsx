import { useState } from 'react'
import { formatPercent, formatValue, humanize, severityHex } from '@/lib/format'
import type { FindingCustody } from '@/hooks/usePacketInvestigation'
import type {
  AssessmentBundle,
  AssessmentDriftResponse,
  ComparisonRow,
  EvidenceRef,
  Finding,
} from '@/types'
import { ComparisonVerdict, ConfigCompareGrid, Prov, RiskChip } from './primitives'

/**
 * The XAI / explainability layer for a single finding, living inside the
 * Packet Investigation workflow (Overview tab). It does NOT add a second
 * analysis engine and it never invents reasoning.
 *
 * The panel is grounded in the backend's own explainability records:
 *   - `bundle.xai.finding_explanations[]`  (deterministic per-finding rationale:
 *     why_it_was_flagged, condition, reason, contributing_factors, limitations)
 *   - `bundle.xai.ml_explanations[]`        (model prose, confidence, limitations)
 *   - `bundle.risk.score_detail.contributions[]` (numeric score attribution)
 *   - `bundle.ml`                            (classification confidence)
 *   - `bundle.risk.severity` and `finding.severity` (assessment risk vs finding
 *     severity — two distinct concepts, never blended)
 *   - the custody chain (`explanation`) as expandable technical detail.
 *
 * Every missing capability renders an explicit honest state; no claim is shown
 * that cannot be traced to the data above.
 */
function severityOf(value: string | null | undefined): string {
  return String(value ?? '').toUpperCase()
}

export function XaiExplanation({
  bundle,
  finding,
  drift,
  correlationMap,
  custody,
  onShowEvidence,
}: {
  bundle: AssessmentBundle
  finding: Finding | null
  drift: AssessmentDriftResponse | null
  correlationMap: Map<string, ComparisonRow>
  /** Finding-scope custody for THIS finding; never another finding's. */
  custody: FindingCustody
  onShowEvidence: () => void
}) {
  const [open, setOpen] = useState(false)
  // Only render a chain that belongs to the finding on screen.
  const explanation =
    custody.explanation && custody.explanation.finding_id === finding?.finding_id
      ? custody.explanation
      : null

  if (!finding) {
    return (
      <div>
        <div className="pw-finding-head">
          <h4 className="pw-finding-title" style={{ margin: '0.5rem 0 0' }}>
            Explain this finding
          </h4>
        </div>
        <p className="pw-faint-text">
          No finding is recorded for this assessment, so there is nothing to explain.
        </p>
      </div>
    )
  }

  const risk = bundle.risk
  const xai = bundle.xai
  const ml = bundle.ml
  const scoreDetail = risk.score_detail
  const xaiFinding =
    xai?.finding_explanations.find((entry) => entry.finding_id === finding.finding_id) ?? null
  const mlExplanation = xai?.ml_explanations[0] ?? null
  const isMlFinding =
    finding.source === 'ML' || xaiFinding?.source === 'ML' || severityOf(finding.category).startsWith('ML')
  const contribution = scoreDetail?.contributions.find(
    (entry) => entry.finding_id === finding.finding_id,
  )
  const refs: EvidenceRef[] = finding.evidence_refs ?? []
  const firstRef = refs[0]
  const comparison = correlationMap.get(finding.related_variable) ?? null
  const contributingFactors = xaiFinding?.contributing_factors ?? []
  const explanationCategories = xaiFinding?.explanation_categories ?? []

  const confidenceText =
    ml.present && ml.classification_confidence !== null
      ? formatPercent(ml.classification_confidence)
      : finding.confidence !== null
        ? formatPercent(finding.confidence)
        : 'not recorded — deterministic rule'
  const confidenceSource =
    ml.present && ml.classification_confidence !== null
      ? `ML classification · ${ml.model_version ?? 'unknown model'}`
      : finding.confidence !== null
        ? 'recorded on the finding'
        : 'no statistical confidence — the rule is deterministic'

  const detectedText =
    xaiFinding?.why_it_was_flagged ||
    (isMlFinding && mlExplanation
      ? mlExplanation.explanation
      : xaiFinding?.description) ||
    finding.description ||
    finding.reason

  const flaggedVariables = new Set([finding.related_variable].filter(Boolean))
  const relevantRows = expectedConfigRowsFor(bundle, finding)
  const differs = risk.severity && severityOf(finding.severity) !== severityOf(risk.severity)

  return (
    <div className="pw-xai" data-xai-panel="true" aria-label="Explain this finding">
      <div className="pw-finding-head">
        <h4 className="pw-finding-title" style={{ margin: '0.5rem 0 0' }}>
          Explain this finding
        </h4>
        <button
          type="button"
          className="pw-btn"
          data-xai-toggle="true"
          onClick={() => setOpen((value) => !value)}
        >
          {open ? 'Hide explanation' : 'Explain this finding'}
        </button>
      </div>
      <p className="pw-faint-text" style={{ margin: '0.4rem 0 0' }}>
        How the backend decided this finding. Every factor below is the assessment, model or
        evidence&apos;s own record — nothing is invented, and missing data is shown as unavailable.
      </p>

      {open && (
        <div style={{ marginTop: '0.6rem' }}>
          {/* Trio: assessment risk / finding severity / confidence — three concepts. */}
          <div
            className="pw-finding"
            style={{ borderLeftColor: severityHex(finding.severity), borderLeftWidth: '3px' }}
            data-xai-finding-id={finding.finding_id}
          >
            <div className="pw-finding-head">
              <span className="pw-quiet">Why was this flagged?</span>
              <RiskChip severity={finding.severity} score={null} />
            </div>
            <p className="pw-ink" style={{ marginTop: '0.35rem' }}>
              {finding.title}
            </p>
            <dl className="pw-kv">
              <dt>
                Assessment risk <Prov kind="conf">assessment</Prov>
              </dt>
              <dd>
                <RiskChip severity={risk.severity} score={risk.overall_score} />
                <span className="pw-faint-text" data-xai-assessment-severity={String(risk.severity ?? '')}>
                  {' '}
                  the packet&apos;s assessment highest-severity
                </span>
              </dd>
            </dl>
            <dl className="pw-kv">
              <dt>
                Finding severity <Prov kind="obs">finding</Prov>
              </dt>
              <dd>
                <RiskChip severity={finding.severity} score={null} />
                <span className="pw-faint-text" data-xai-finding-severity={String(finding.severity ?? '')}>
                  {' '}
                  the severity of this individual finding
                </span>
              </dd>
            </dl>
            <dl className="pw-kv">
              <dt>Confidence</dt>
              <dd className="pw-ink">
                {confidenceText}
                <span className="pw-faint-text"> · {confidenceSource}</span>
              </dd>
            </dl>
            <dl className="pw-kv">
              <dt>Source</dt>
              <dd className="pw-ink">
                {isMlFinding ? (
                  <>
                    <span className="pw-chip pw-chip-ipsec">ML-derived</span>
                    {'  '}a model classification, evidence-only (never an authoritative protocol
                    observation)
                  </>
                ) : (
                  <>
                    <span className="pw-chip">deterministic rule</span>
                    {'  '}
                    <span className="pw-mono">{(xaiFinding?.rule_id ?? finding.rule_id)}</span>
                  </>
                )}
              </dd>
            </dl>
          </div>

          {/* What Sentinel detected — the backend's own rationale. */}
          <h4 className="pw-subhead">What Sentinel detected</h4>
          <p className="pw-ink">{detectedText}</p>
          {xaiFinding === null &&
            (isMlFinding && mlExplanation ? (
              <p className="pw-faint-text">
                The explainability engine recorded no deterministic rule record for this ML-derived
                finding; the ML explanation below is the backend&apos;s own model narrative.
              </p>
            ) : (
              <p className="pw-faint-text">
                No deterministic rule explanation is available for this finding; the panel falls
                back to the finding&apos;s own recorded description and reason.
              </p>
            ))}
          {xaiFinding?.reason ? (
            <p className="pw-faint-text">
              <span className="pw-mono">reason</span> {xaiFinding.reason}
            </p>
          ) : (
            <p className="pw-faint-text">Backend recorded no separate reason line for this rule.</p>
          )}

          {/* Key factors — traceable, evidence-tagged. */}
          <h4 className="pw-subhead">Key factors</h4>
          <ol className="pw-xai-factors" data-xai-factors="true">
            <li data-xai-factor="rule">
              <span className="pw-ink">Rule matched</span>
              <span className="pw-mono">
                {(xaiFinding?.rule_id ?? finding.rule_id)} — condition{' '}
                                {(xaiFinding?.condition ?? finding.condition) || 'not recorded'}
              </span>
              <span className="pw-faint-text" style={{ display: 'block' }}>
                evidence: {finding.evidence_type ? `finding is of type ${finding.evidence_type}` : 'evidence type not recorded'}
              </span>
            </li>
            {finding.related_variable && (
              <li data-xai-factor="parameter">
                <span className="pw-ink">Parameter · {humanize(finding.related_variable)}</span>
                <span className="pw-mono">
                  expected <span className="pw-ink">{formatValue(finding.expected_value)}</span>
                  {finding.observed_value !== null && finding.observed_value !== undefined && (
                    <>
                      <span className="pw-dim"> vs </span>
                      observed <span className="pw-ink">{formatValue(finding.observed_value)}</span>
                    </>
                  )}
                  {'  '}
                  <ComparisonVerdict status={comparison} />
                </span>
                <span className="pw-faint-text" style={{ display: 'block' }}>
                  evidence: the correlation engine&apos;s comparison row for this variable
                </span>
              </li>
            )}
            {contribution && (
              <li data-xai-factor="score">
                <span className="pw-ink">Score contribution +{contribution.added}</span>
                <span className="pw-mono">
                  {contribution.rule_id} · weight {contribution.weight} · {contribution.severity} ·{' '}
                  {humanize(contribution.category)}
                </span>
                <span className="pw-faint-text" style={{ display: 'block' }}>
                  evidence: risk engine score_detail (policy{' '}
                  <span className="pw-mono">{scoreDetail ? risk.risk_policy_version : '—'}</span>)
                </span>
              </li>
            )}
            {contributingFactors.length === 0 ? (
              <li data-xai-factor="none" className="pw-faint-text">
                No contributing factors were recorded by the backend.
              </li>
            ) : (
              contributingFactors.map((factor) => (
                <li key={factor} data-xai-factor="contributing">
                  <span className="pw-ink">{factor}</span>
                  <span className="pw-faint-text" style={{ display: 'block' }}>
                    evidence: {refs.length === 0 ? 'no artifact attached to this finding' : `${refs.length} evidence reference(s)`}
                  </span>
                </li>
              ))
            )}
          </ol>

          {/* Deterministic vs ML explanation. */}
          {isMlFinding || ml.present ? (
            <div className="pw-xai-ml" data-xai-ml="true">
              <h4 className="pw-subhead">ML context (evidence-only)</h4>
              {ml.present ? (
                <>
                  {!isMlFinding && (
                    <p className="pw-faint-text" data-xai-ml-not-source="true">
                      This finding came from a deterministic rule, not from the model. The model also
                      classified this assessment as {ml.traffic_class ?? '—'}; that result is carried
                      by its own finding.
                    </p>
                  )}
                  <dl className="pw-kv">
                    <dt>Model</dt>
                    <dd className="pw-mono">{ml.model_version ?? '—'}</dd>
                  </dl>
                  <dl className="pw-kv">
                    <dt>Classification</dt>
                    <dd className="pw-ink">
                      {ml.traffic_class ?? '—'}
                      {ml.classification_confidence !== null
                        ? ` · ${formatPercent(ml.classification_confidence)}`
                        : ''}
                    </dd>
                  </dl>
                  {mlExplanation?.explanation && (
                    <p className="pw-ink">{mlExplanation.explanation}</p>
                  )}
                  <p className="pw-faint-text">
                    Model feature attribution is not available for this assessment. The backend
                    returns the classification, its confidence and a model explanation, but no
                    per-feature importance.
                  </p>
                  {(mlExplanation?.limitations ?? []).length > 0 && (
                    <>
                      <h4 className="pw-subhead">ML limitations</h4>
                      {mlExplanation!.limitations.map((limitation, index) => (
                        <p className="pw-faint-text" key={index}>
                          — {limitation}
                        </p>
                      ))}
                    </>
                  )}
                </>
              ) : (
                <p className="pw-faint-text">ML was not executed for this assessment.</p>
              )}
            </div>
          ) : null}

          {/* Configuration impact. */}
          <h4 className="pw-subhead">Configuration impact</h4>
          {relevantRows.length === 0 ? (
            <p className="pw-faint-text">No configuration comparison is available for this finding.</p>
          ) : (
            <>
              {flavourNote(finding, comparison, explanationCategories)}
              <ConfigCompareGrid rows={relevantRows} correlationMap={correlationMap} flaggedVariables={flaggedVariables} />
            </>
          )}

          {/* Drift — honest even when unconfigured. */}
          <h4 className="pw-subhead">Drift</h4>
          {drift ? (
            drift.status === 'not_configured' ? (
              <p className="pw-faint-text">
                Drift analysis is not available for this assessment —{' '}
                {drift.reason ?? 'no validated baseline was configured.'} This is not a finding of
                &ldquo;no drift&rdquo;: no comparison was made.
              </p>
            ) : drift.drift_detected ? (
              <>
                <p className="pw-ink">Drift against baseline:</p>
                {drift.changed_fields.filter((field) => finding && field.finding_id === finding.finding_id).length > 0
                  ? drift.changed_fields
                      .filter((field) => finding && field.finding_id === finding.finding_id)
                      .map((field, index) => (
                        <dl className="pw-kv" key={`${field.variable ?? index}`}>
                          <dt>{field.variable ?? 'field'}</dt>
                          <dd className="pw-mono">
                            baseline {formatValue(field.baseline_value)} <span className="pw-dim">→</span> current{' '}
                            {formatValue(field.current_value)}
                          </dd>
                        </dl>
                      ))
                  : drift.changed_fields.map((field, index) => (
                      <dl className="pw-kv" key={`${field.variable ?? index}`}>
                        <dt>{field.variable ?? 'field'}</dt>
                        <dd className="pw-mono">
                          baseline {formatValue(field.baseline_value)} <span className="pw-dim">→</span> current{' '}
                          {formatValue(field.current_value)}
                        </dd>
                      </dl>
                    ))}
              </>
            ) : (
              <p className="pw-faint-text">No drift was detected for this assessment.</p>
            )
          ) : (
            <p className="pw-faint-text">No drift record was returned for this assessment.</p>
          )}

          {/* Evidence / provenance link — one evidence implementation, jump to the tab. */}
          <h4 className="pw-subhead">Evidence</h4>
          <p className="pw-faint-text" style={{ margin: '0 0 0.4rem' }}>
            This explanation is grounded in the finding and its recorded artifacts. Open the
            Evidence tab for the full integrity + provenance chain.
          </p>
          <dl className="pw-kv">
            <dt>
              Finding <Prov kind="obs">recorded</Prov>
            </dt>
            <dd className="pw-mono">
              {finding.finding_id}
              {firstRef?.evidence_id ? (
                <>
                  {' '}→ Evidence <span className="pw-mono">{firstRef.evidence_id}</span>
                </>
              ) : null}
              {firstRef?.source ? (
                <>
                  {' '}→ Provenance <span className="pw-mono">{firstRef.source}</span>
                </>
              ) : null}
            </dd>
          </dl>
          {firstRef?.pcap_path && (
            <dl className="pw-kv">
              <dt>Artifact</dt>
              <dd className="pw-mono">{firstRef.pcap_path}</dd>
            </dl>
          )}
          <div className="pw-kv" style={{ marginTop: '0.3rem' }}>
            <dt />
            <dd>
              <button type="button" className="pw-btn" data-xai-evidence="true" onClick={onShowEvidence}>
                View evidence →
              </button>
            </dd>
          </div>

          {/* Technical details — ids and engine provenance, expandable. */}
          <details className="pw-xai-details">
            <summary>Technical details</summary>
            <dl className="pw-kv">
              <dt>Finding id</dt>
              <dd className="pw-mono">{finding.finding_id}</dd>
            </dl>
            {xaiFinding?.rule_id && (
              <dl className="pw-kv">
                <dt>Rule id</dt>
                <dd className="pw-mono">{xaiFinding.rule_id}</dd>
              </dl>
            )}
            <dl className="pw-kv">
              <dt>Sources</dt>
              <dd className="pw-mono">
                {finding.source}
                {finding.model_version ? ` · model ${finding.model_version}` : ''}
              </dd>
            </dl>
            <dl className="pw-kv">
              <dt>Explanatory engine</dt>
              <dd className="pw-mono">
                {xai?.metadata?.explainability_engine_version ?? '—'}
                {xai?.schema_version ? ` · schema ${xai.schema_version}` : ''}
              </dd>
            </dl>
            <dl className="pw-kv">
              <dt>Risk policy</dt>
              <dd className="pw-mono">{risk.risk_policy_version}</dd>
            </dl>
            <p className="pw-faint-text">
              {differs
                ? `Assessment risk ${risk.severity} and finding severity ${finding.severity} are intentionally kept separate: the assessment is the packet-level triage state, the finding severity is this rule's own.`
                : `Assessment risk and this finding's severity are both ${finding.severity} here — one value, two meanings (the assessment's highest vs this finding's own).`}
            </p>
            {/* Evidence custody — whose chain this is, and its real state. */}
            <dl className="pw-kv" data-xai-custody={finding.finding_id}>
              <dt>Evidence custody</dt>
              <dd className="pw-mono">
                Finding {finding.finding_id} · Assessment{' '}
                {explanation?.assessment_id ?? bundle.assessment_id}
              </dd>
            </dl>
            {custody.loading && (
              <p className="pw-faint-text" data-xai-custody-loading={finding.finding_id}>
                Reading the custody chain for {finding.finding_id}…
              </p>
            )}
            {custody.error ? (
              <div data-xai-custody-error={finding.finding_id}>
                <p className="pw-faint-text">
                  The custody chain for {finding.finding_id} could not be read. Nothing from
                  another finding is shown in its place.
                </p>
                <button type="button" className="pw-btn" onClick={custody.reload}>
                  Retry custody chain →
                </button>
              </div>
            ) : explanation ? (
              <>
                <dl className="pw-kv">
                  <dt>Chain position</dt>
                  <dd className="pw-mono">
                    {explanation.steps.length} recorded step{explanation.steps.length === 1 ? '' : 's'} ·{' '}
                    {explanation.facts.length} fact{explanation.facts.length === 1 ? '' : 's'} ·{' '}
                    {explanation.integrity.length} integrity check
                    {explanation.integrity.length === 1 ? '' : 's'}
                  </dd>
                </dl>
                <dl className="pw-kv">
                  <dt>Hash</dt>
                  <dd className="pw-mono">{explanation.finding_digest}</dd>
                </dl>
                <dl className="pw-kv">
                  <dt>Provenance</dt>
                  <dd className="pw-mono">
                    {explanation.sources.length === 0
                      ? '—'
                      : explanation.sources
                          .map((source) => `${source.role} ${source.public_path}`)
                          .join(' · ')}
                  </dd>
                </dl>
                <dl className="pw-kv">
                  <dt>Verification</dt>
                  <dd className="pw-ink">
                    {custody.integrity
                      ? `${formatValue(custody.integrity.verification_status)} · artifact ${custody.integrity.evidence_id}`
                      : 'no artifact integrity record was returned for this finding’s evidence'}
                  </dd>
                </dl>
                <p className="pw-faint-text">
                  The custody chain below records the exact expected/observed facts, engine steps,
                  digest checks and recommendations for {finding.finding_id}.
                </p>
              </>
            ) : (
              !custody.loading && (
                <p className="pw-faint-text" data-xai-custody-absent={finding.finding_id}>
                  The backend did not return a custody chain for {finding.finding_id}; the technical
                  evidence above is all that is recorded.
                </p>
              )
            )}
          </details>

          <p className="pw-faint-text" style={{ marginTop: '0.6rem' }}>
            This explanation is the deterministic/evidence-grounded answer to &ldquo;why&rdquo;.
            Ask AI (below) is a separate conversational follow-up about this explanation — its
            output is labelled inferred and is never rendered as observation or evidence.
          </p>
        </div>
      )}
    </div>
  )
}

/** The config rows tied to this finding's parameter, when the backend has them. */
function expectedConfigRowsFor(bundle: AssessmentBundle, finding: Finding) {
  const rows: { term: string; variable: string; value: unknown }[] = []
  const expected = bundle.expected
  const valueFor: Record<string, unknown> = {
    'ike.version': expected.ike?.version,
    'ike.encryption': expected.ike?.encryption,
    'ike.integrity': expected.ike?.integrity,
    'ike.dh_group': expected.ike?.dh_group,
    'esp.encryption': expected.esp?.encryption,
    'esp.integrity': expected.esp?.integrity,
    'esp.dh_group': expected.esp?.dh_group,
    'esp.pfs': expected.esp?.pfs,
    mode: expected.mode,
    address_family: expected.address_family,
    'traffic.profile': expected.traffic?.profile,
    capture_filter: expected.capture_filter,
    security_posture: expected.security_posture,
  }
  const labels: Record<string, string> = {
    'ike.version': 'IKE version',
    'ike.encryption': 'IKE encryption',
    'ike.integrity': 'IKE integrity',
    'ike.dh_group': 'IKE DH group',
    'esp.encryption': 'ESP encryption',
    'esp.integrity': 'ESP integrity',
    'esp.dh_group': 'ESP DH group',
    'esp.pfs': 'ESP PFS',
    mode: 'Mode',
    address_family: 'Address family',
    'traffic.profile': 'Traffic profile',
    capture_filter: 'Capture filter',
    security_posture: 'Security posture',
  }
  const variable = finding.related_variable
  if (!variable) return rows
  if (variable in valueFor) {
    rows.push({ term: labels[variable] ?? humanize(variable), variable, value: valueFor[variable] })
  }
  return rows
}

/** One honest line tying the finding to the configuration that matters. */
function flavourNote(
  finding: Finding,
  comparison: ComparisonRow | null,
  explanationCategories: string[],
) {
  const source = (finding.source ?? '').toUpperCase()
  if (source === 'ML') {
    return (
      <p className="pw-faint-text" style={{ margin: '0 0 0.5rem' }}>
        The ML model flagged the flow&apos;s classification; the configuration grid below is for
        reference and was not the decision input.
      </p>
    )
  }
  if (source === 'EXPECTED_CONFIGURATION') {
    return (
      <p className="pw-faint-text" style={{ margin: '0 0 0.5rem' }}>
        This finding comes from the expected (configured) state itself — the rule rated{' '}
        <span className="pw-mono">{finding.related_variable}</span>
        {' = '}
        <span className="pw-mono">{formatValue(finding.expected_value)}</span> as weak, independent
        of any observed difference.
      </p>
    )
  }
  if (comparison) {
    return (
      <p className="pw-faint-text" style={{ margin: '0 0 0.5rem' }}>
        The comparison engine reports{' '}
        <span className="pw-mono">{finding.related_variable}</span> as{' '}
        <span className="pw-ink">{comparison.status}</span>
        {comparison.observed_value !== undefined && comparison.observed_value !== null ? (
          <>
            {' '}
            (observed <span className="pw-mono">{formatValue(comparison.observed_value)}</span>)
          </>
        ) : null}
        — the field associated with this finding.
      </p>
    )
  }
  if (explanationCategories.includes('CONFIGURATION_EXPLANATION')) {
    return (
      <p className="pw-faint-text" style={{ margin: '0 0 0.5rem' }}>
        The backend flagged this as configuration-related; its own categorisation is{' '}
        {explanationCategories.join(', ')}.
      </p>
    )
  }
  return (
    <p className="pw-faint-text" style={{ margin: '0 0 0.5rem' }}>
      The backend provided no comparison row or expected-config record for this finding&apos;s
      parameter.
    </p>
  )
}