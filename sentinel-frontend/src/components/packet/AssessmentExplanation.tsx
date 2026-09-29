import { useState } from 'react'
import { Link } from 'react-router-dom'
import { selectPrimaryFinding, type FindingCustody } from '@/hooks/usePacketInvestigation'
import { Spinner } from '@/components/states'
import { CollapsibleSection } from '@/components/kit'
import {
  formatBytes,
  formatNumber,
  formatPercent,
  formatValue,
  humanize,
  severityHex,
} from '@/lib/format'
import { formatLocalFull } from '@/lib/timeZone'
import type { CaptureRow } from '@/lib/packetRows'
import type {
  AssessmentBundle,
  AssessmentDriftResponse,
  ComparisonRow,
  CustodyExplanation,
  EvidenceIntegrity,
  EvidenceRef,
  Finding,
} from '@/types'
import {
  ComparisonVerdict,
  ConfigCompareGrid,
  IntegrityVerdict,
  Prov,
  RiskChip,
  VerdictChip,
  expectedConfigRows,
} from './primitives'
import { AssessmentDriftBlock } from './AssessmentDriftBlock'
import { XaiExplanation } from './XaiExplanation'
import { AiExplainer } from './AiExplainer'

/**
 * The packet investigation body.
 *
 * One scroll, one hierarchy: a compact headline, then a short, ordered set of
 * collapsible sections — Overview, Why this risk?, Configuration,
 * Allowed / expected combinations, Drift, Evidence, Chain of custody and
 * AI explanation. Every section renders the backend's own record with its
 * provenance (configured / observed / not provided by backend); deep evidence
 * sits behind its own disclosure so the analyst is never dropped into a wall
 * of prose. Nothing here is invented: a value the store did not provide stays
 * masked with the product's single "not provided by backend" marker.
 */

function severityBandText(severity: unknown): string | null {
  if (!Array.isArray(severity) || severity.length < 2) return null
  const [name, low, high] = severity as [string, number, number]
  return `${name} (${low}–${high})`
}

/* -------------------------------------------------------- shared blocks */

function ConfidenceSection({
  ml,
  primary,
  findingConfidenceText,
}: {
  ml: AssessmentBundle['ml']
  primary: Finding | null
  findingConfidenceText: string
}) {
  const mlConfidence =
    ml.present && ml.classification_confidence !== null
      ? formatPercent(ml.classification_confidence)
      : null
  // The scoring engine lives in the analytics plane. This attribute exposes the
  // exact backend score so a global or per-flow confidence filter can key on
  // the same field without Sentinel recomputing or inventing one.
  const backendConfidence = mlConfidence ?? (primary?.confidence ?? '')
  return (
    <div data-confidence={String(backendConfidence)}>
      <h4 className="pw-subhead">Confidence</h4>
      <dl className="pw-kv">
        <dt>
          Classification <Prov kind={ml.present ? 'obs' : 'miss'}>{ml.present ? 'model' : 'inferred'}</Prov>
        </dt>
        <dd className="pw-ink">
          {mlConfidence === null ? (
            '—'
          ) : (
            <>
              {mlConfidence}
              {ml.model_version ? ` · ${ml.model_version}` : ''}
            </>
          )}
        </dd>
      </dl>
      <dl className="pw-kv">
        <dt>
          This finding <Prov kind={primary && primary.confidence !== null ? 'obs' : 'miss'}>recorded</Prov>
        </dt>
        <dd className="pw-ink">{findingConfidenceText}</dd>
      </dl>
      {!mlConfidence && (!primary || primary.confidence === null) && (
        <p className="pw-faint-text">
          The analytics store returned no confidence score for this assessment. Deterministic rules
          record no statistical confidence, and ML was not executed here.
        </p>
      )}
      <p className="pw-faint-text">
        Confidence is the analytics plane&apos;s own score, rendered without recalculation. No
        calibration curve is provided by the backend, so none is shown.
      </p>
      {primary && primary.model_version && (
        <p className="pw-faint-text">
          <span className="pw-mono">{primary.model_version}</span> is the model version whose
          classification produced the finding.
        </p>
      )}
    </div>
  )
}

function WhyFlaggedBlock({
  finding,
  explanation,
  correlationMap,
}: {
  finding: Finding
  explanation: CustodyExplanation | null
  correlationMap: Map<string, ComparisonRow>
}) {
  const firstRef: EvidenceRef | undefined = finding.evidence_refs?.[0]
  const recommendation = explanation?.recommendation
  const comparison = correlationMap.get(finding.related_variable) ?? null
  return (
    <div
      className="pw-finding"
      style={{ borderLeftColor: severityHex(finding.severity), borderLeftWidth: '3px' }}
      aria-label="Why this packet is flagged"
    >
      <div className="pw-finding-head">
        <h4 className="pw-finding-title">{finding.title}</h4>
        <RiskChip severity={finding.severity} score={null} />
      </div>
      <dl className="pw-kv">
        <dt>Detected</dt>
        <dd className="pw-ink">{finding.condition}</dd>
      </dl>
      <dl className="pw-kv">
        <dt>Cause</dt>
        <dd className="pw-ink">{explanation?.summary ?? finding.reason}</dd>
      </dl>
      <dl className="pw-kv">
        <dt>
          Parameter · {humanize(finding.related_variable)} <Prov kind="conf">configured</Prov>
        </dt>
        <dd className="pw-mono">
          expected <span className="pw-ink">{formatValue(finding.expected_value)}</span>
          {finding.observed_value !== null && finding.observed_value !== undefined && (
            <>
              <span className="pw-dim"> vs </span>
              observed <span className="pw-ink">{formatValue(finding.observed_value)}</span>
            </>
          )}
          {'  '}
          <ComparisonVerdict status={comparison} />
        </dd>
      </dl>
      <dl className="pw-kv">
        <dt>Evidence</dt>
        <dd className="pw-mono">
          {finding.evidence_type}
          {firstRef?.pcap_path ? ` · ${firstRef.pcap_path}` : ''}
        </dd>
      </dl>
      <dl className="pw-kv">
        <dt>Impact</dt>
        <dd className="pw-ink">{finding.description}</dd>
      </dl>
      {recommendation?.reason && (
        <dl className="pw-kv">
          <dt>Recommended</dt>
          <dd className="pw-ink">{recommendation.reason}</dd>
        </dl>
      )}
    </div>
  )
}

function FactChip({ category }: { category: string }) {
  const cls =
    category === 'OBSERVED'
      ? 'pw-prov pw-prov-obs'
      : category === 'EXPECTED'
        ? 'pw-prov pw-prov-conf'
        : 'pw-prov pw-prov-miss'
  return <span className={cls}>{category.toUpperCase()}</span>
}

function ExplainFindingBlock({
  finding,
  custody,
  assessmentId,
  isDefault,
}: {
  finding: Finding | null
  custody: FindingCustody
  assessmentId: string | null
  /** True when this is the default highest-severity finding, not a choice. */
  isDefault: boolean
}) {
  const [open, setOpen] = useState(false)
  if (!finding) {
    return (
      <div>
        <h4 className="pw-subhead">Chain of custody · technical details</h4>
        <p className="pw-faint-text" data-custody-empty="true">
          No finding is recorded for this assessment, so there is no custody chain to explain — and
          none is requested.
        </p>
      </div>
    )
  }
  // The chain is only ever rendered when it belongs to the finding on screen.
  const explanation =
    custody.explanation && custody.explanation.finding_id === finding.finding_id
      ? custody.explanation
      : null
  const recommendation = explanation?.recommendation
  return (
    <div data-custody-for={finding.finding_id}>
      <div className="pw-finding-head">
        <h4 className="pw-finding-title" style={{ margin: '0.5rem 0 0' }}>
          Chain of custody · technical details
        </h4>
        <button
          type="button"
          className="pw-btn"
          data-custody-toggle={finding.finding_id}
          onClick={() => setOpen((value) => !value)}
        >
          {open ? 'Hide custody chain' : 'Show custody chain'}
        </button>
      </div>
      {/* Whose chain this is, stated before anything is expanded. */}
      <div className="pw-kv">
        <dt>
          Finding <Prov kind="obs">recorded</Prov>
        </dt>
        <dd className="pw-mono">
          {finding.finding_id} · {finding.title}
          <span className="pw-dim">
            {' '}
            · {isDefault ? 'default (highest-severity finding)' : 'selected by the analyst'}
          </span>
        </dd>
      </div>
      <div className="pw-kv">
        <dt>
          Assessment <Prov kind="obs">recorded</Prov>
        </dt>
        <dd className="pw-mono">{explanation?.assessment_id ?? assessmentId ?? '—'}</dd>
      </div>
      {custody.error ? (
        <div
          className="pw-empty"
          style={{ minHeight: 0, marginTop: '0.4rem' }}
          data-custody-error={finding.finding_id}
        >
          <span className="pw-ink-strong">The custody chain for {finding.finding_id} could not be read.</span>
          <p className="pw-empty-note">
            {custody.error.detail} Nothing from another finding is shown in its place.
          </p>
          <button type="button" className="pw-btn" data-custody-retry={finding.finding_id} onClick={custody.reload}>
            Retry custody chain →
          </button>
        </div>
      ) : custody.loading ? (
        <p className="pw-faint-text" data-custody-loading={finding.finding_id}>
          <Spinner /> reading the custody chain for {finding.finding_id}…
        </p>
      ) : (
        <p className="pw-faint-text" style={{ margin: '0.4rem 0 0' }}>
          {explanation?.summary ?? 'The backend did not return a custody chain for this finding.'}
        </p>
      )}
      {open && explanation && (
        <div style={{ marginTop: '0.5rem' }}>
          <h4 className="pw-subhead">Facts</h4>
          {explanation.facts.length === 0 && <p className="pw-faint-text">No facts were recorded.</p>}
          {explanation.facts.map((fact) => (
            <dl className="pw-kv" key={fact.fact_id ?? `${fact.category}-${fact.label}`}>
              <dt>
                <FactChip category={fact.category} /> {fact.label}
                {fact.authoritative && <span className="pw-warn"> · authoritative</span>}
              </dt>
              <dd className="pw-ink">{formatValue(fact.value)}</dd>
            </dl>
          ))}
          <h4 className="pw-subhead">Steps</h4>
          {explanation.steps.map((step) => (
            <dl className="pw-kv" key={`${step.index}-${step.component}`}>
              <dt>
                {step.index}. {humanize(step.stage)}
              </dt>
              <dd className="pw-ink">
                {step.component} — {step.action}
                {step.authoritative ? '' : <span className="pw-dim"> (derived)</span>}
              </dd>
            </dl>
          ))}
          {recommendation && (
            <>
              <h4 className="pw-subhead">Recommendation</h4>
              <dl className="pw-kv">
                <dt>Action</dt>
                <dd className="pw-ink">
                  {humanize(recommendation.action ?? '—')}
                  {recommendation.priority ? <span className="pw-dim"> · {recommendation.priority}</span> : ''}
                </dd>
              </dl>
              <dl className="pw-kv">
                <dt>Reason</dt>
                <dd className="pw-ink">{recommendation.reason ?? '—'}</dd>
              </dl>
              <dl className="pw-kv">
                <dt>Rationale</dt>
                <dd className="pw-ink">{recommendation.rationale ?? '—'}</dd>
              </dl>
              {(recommendation.required_roles ?? []).length > 0 && (
                <dl className="pw-kv">
                  <dt>Required roles</dt>
                  <dd className="pw-ink">{recommendation.required_roles!.join(', ')}</dd>
                </dl>
              )}
            </>
          )}
          <h4 className="pw-subhead">Limitations</h4>
          {explanation.limitations.length === 0 && <p className="pw-faint-text">None recorded.</p>}
          {explanation.limitations.map((limitation, index) => (
            <p className="pw-faint-text" key={index}>
              — {limitation}
            </p>
          ))}
        </div>
      )}
      {assessmentId && (
        <div className="pw-kv">
          <dt />
          <dd className="pw-mono">
            <span className="pw-dim">{finding.finding_id}</span>{' '}
            <Link
              className="pw-link"
              to={`/findings/${encodeURIComponent(assessmentId)}/${encodeURIComponent(finding.finding_id)}`}
            >
              open finding →
            </Link>
          </dd>
        </div>
      )}
    </div>
  )
}

function EvidenceBlock({
  primary,
  custody,
  onShowEvidence,
}: {
  primary: Finding | null
  custody: FindingCustody
  onShowEvidence: () => void
}) {
  const integrity = custody.integrity
  const refs: EvidenceRef[] = primary?.evidence_refs ?? []
  return (
    <div>
      <h4 className="pw-subhead">Evidence &amp; provenance</h4>
      {primary ? (
        <>
          <div className="pw-kv">
            <dt>
              Finding <Prov kind="obs">recorded</Prov>
            </dt>
            <dd className="pw-mono">
              {primary.finding_id} · {primary.source}
            </dd>
          </div>
          {refs.length === 0 ? (
            <div className="pw-empty" style={{ minHeight: 0 }}>
              <span className="pw-ink-strong">No evidence artifact is attached to this finding.</span>
              <p className="pw-empty-note">
                {primary.evidence_type
                  ? ` The finding records evidence type "${primary.evidence_type}" but no artifact digest is attached, so there is nothing to verify here.`
                  : ' Nothing is inferred from the packet itself.'}
              </p>
            </div>
          ) : (
            refs.map((ref) => (
              <dl className="pw-kv" key={ref.evidence_id ?? ref.pcap_path}>
                <dt>
                  {ref.artifact_type ?? 'artifact'} <Prov kind="obs">observed</Prov>
                </dt>
                <dd className="pw-mono">
                  {ref.pcap_path}
                  {ref.byte_size !== undefined ? ` · ${formatBytes(ref.byte_size)}` : ''}
                  {ref.artifact_sha256 ? ` · sha256 ${ref.artifact_sha256.slice(0, 16)}…` : ''}
                  {ref.source ? <span className="pw-dim"> · {ref.source}</span> : ''}
                </dd>
              </dl>
            ))
          )}
          <div className="pw-kv">
            <dt>
              Chain <Prov kind="obs">recorded</Prov>
            </dt>
            <dd className="pw-ink">
              Finding <span className="pw-mono">{primary.finding_id}</span>
              {refs[0]?.evidence_id ? (
                <>
                  {' '}
                  → Evidence <span className="pw-mono">{refs[0].evidence_id}</span>
                </>
              ) : null}
              {refs[0]?.source ? (
                <>
                  {' '}
                  → Provenance <span className="pw-mono">{refs[0].source}</span>
                </>
              ) : null}
            </dd>
          </div>
          {integrity && (
            <dl className="pw-kv">
              <dt>Integrity</dt>
              <dd>
                <span className="pw-mono">{integrity.evidence_id.slice(0, 12)}</span>{' '}
                <span className="pw-ink">{formatValue(integrity.verification_status)}</span>
                <span className="pw-dim">
                  {' '}
                  · digest {integrity.artifact_sha256 ? integrity.artifact_sha256.slice(0, 16) : '—'}…
                </span>
              </dd>
            </dl>
          )}
          {custody.loading && !integrity && (
            <p className="pw-faint-text" data-evidence-loading={primary.finding_id}>
              <Spinner /> verification state loading for {primary.finding_id}…
            </p>
          )}
          <div className="pw-kv" style={{ marginTop: '0.4rem' }}>
            <dt />
            <dd>
              <button type="button" className="pw-btn" onClick={onShowEvidence}>
                View evidence →
              </button>
            </dd>
          </div>
        </>
      ) : (
        <p className="pw-faint-text">
          No finding is recorded for this assessment, so there is no evidence chain to show.
        </p>
      )}
    </div>
  )
}

function EvidenceDetail({
  custody,
  finding,
  assessmentId,
}: {
  custody: FindingCustody
  finding: Finding | null
  assessmentId: string
}) {
  const { explanation, integrity } = custody
  const primary = finding
  const primaryRefs: EvidenceRef[] = primary?.evidence_refs ?? []
  const custodyEvidence = explanation?.evidence ?? []
  const integrityChecks = explanation?.integrity ?? []

  return (
    <div style={{ marginTop: '0.75rem' }}>
      {integrity ? (
        <>
          <h4 className="pw-subhead">Primary artifact integrity</h4>
          <IntegrityVerdict record={integrity} />
        </>
      ) : primaryRefs.length === 0 && custodyEvidence.length === 0 ? (
        <div className="pw-empty" style={{ minHeight: 0 }}>
          <span className="pw-ink-strong">No evidence artifact is attached to this finding.</span>
          <p className="pw-empty-note">
            {primary?.evidence_type
              ? ` The finding records evidence type "${primary.evidence_type}" but no artifact digest is attached, so there is nothing to verify here.`
              : ' Nothing is inferred from the packet itself.'}
          </p>
        </div>
      ) : (
        <p className="pw-faint-text">
          The findings reference {formatNumber(primaryRefs.length)} artifact
          {primaryRefs.length === 1 ? '' : 's'}; no integrity record was returned for the primary
          artifact, so verification state is unavailable rather than assumed.
        </p>
      )}

      {primaryRefs.length > 0 && (
        <>
          <h4 className="pw-subhead">Finding references</h4>
          {primaryRefs.map((ref, index) => (
            <dl className="pw-kv" key={ref.evidence_id ?? `${ref.pcap_path}-${index}`}>
              <dt>
                {ref.artifact_type ?? 'artifact'} <Prov kind="obs">observed</Prov>
              </dt>
              <dd className="pw-mono">
                {ref.pcap_path} · {formatBytes(ref.byte_size)}
                {ref.artifact_sha256 ? ` · sha256 ${ref.artifact_sha256.slice(0, 16)}…` : ''}
              </dd>
            </dl>
          ))}
        </>
      )}

      {custodyEvidence.length > 0 && (
        <>
          <h4 className="pw-subhead">Custody evidence</h4>
          {custodyEvidence.map((evidence) => (
            <dl className="pw-kv" key={evidence.evidence_id}>
              <dt>
                {evidence.evidence_id.slice(0, 12)} <Prov kind="obs">observed</Prov>
              </dt>
              <dd className="pw-mono">
                {evidence.artifact_type ?? 'artifact'}
                {evidence.artifact_sha256 ? ` · sha256 ${evidence.artifact_sha256.slice(0, 16)}…` : ''}
                {evidence.byte_size !== undefined ? ` · ${formatBytes(evidence.byte_size)}` : ''}
                {' · '}
                <VerdictChip
                  status={evidence.verification_status}
                  present={evidence.artifact_present}
                  verifiable={evidence.verifiable}
                />
              </dd>
            </dl>
          ))}
        </>
      )}

      {integrityChecks.length > 0 && (
        <>
          <h4 className="pw-subhead">Integrity checks</h4>
          {integrityChecks.map((check) => (
            <dl className="pw-kv" key={check.check_id}>
              <dt>{check.check_id}</dt>
              <dd>
                <span style={{ color: check.passed ? undefined : severityHex('CRITICAL') }}>
                  {check.passed ? 'passed' : 'FAILED'}
                </span>
                <span className="pw-dim"> · {check.description}</span>
                <span className="pw-faint-text"> {check.detail}</span>
              </dd>
            </dl>
          ))}
        </>
      )}

      <p className="pw-faint-text">
        Integrity is verified by the analytics backend over the stored artifact. Sentinel never
        hashes a file in the browser, and never marks an artifact verified on its own authority.
        Assessment <span className="pw-mono">{assessmentId}</span>.
      </p>
    </div>
  )
}

/* ------------------------------------------------- configuration / SA */

function SaRow({
  term,
  configured,
  observed,
  status,
  observedNote,
}: {
  term: string
  configured?: unknown
  observed?: unknown
  status?: ComparisonRow | null
  observedNote?: string
}) {
  return (
    <div className="pw-row3">
      <span className="pw-term">{term}</span>
      <span className="pw-val">
        {configured === undefined || configured === null ? (
          <span className="pw-val-muted">—</span>
        ) : (
          <>
            {formatValue(configured)} <Prov kind="conf">configured</Prov>
          </>
        )}
      </span>
      <span className="pw-val">
        {observed === undefined || observed === null ? (
          <span className="pw-val-muted">{observedNote ?? '—'}</span>
        ) : (
          <>
            {formatValue(observed)} <Prov kind="obs">observed</Prov>
          </>
        )}
      </span>
      <ComparisonVerdict status={status} />
    </div>
  )
}

function IkeSaBlock({
  model,
  bundle,
  correlationMap,
}: {
  model: CaptureRow
  bundle: AssessmentBundle
  correlationMap: Map<string, ComparisonRow>
}) {
  const expected = bundle.expected
  const observed = bundle.observed
  const variable = (name: string) => correlationMap.get(name) ?? null

  const rows: {
    term: string
    configured?: unknown
    observed?: unknown
    status?: ComparisonRow | null
    observedNote?: string
  }[] = [
    {
      term: 'IKE version',
      configured: expected.ike?.version,
      observed: observed.ike_seen === true ? 'handshake observed' : 'no IKE observed',
      status: variable('ike.version'),
    },
    {
      term: 'IKE encryption',
      configured: expected.ike?.encryption,
      status: variable('ike.encryption'),
      observedNote: 'not provided by backend',
    },
    {
      term: 'IKE integrity',
      configured: expected.ike?.integrity,
      status: variable('ike.integrity'),
      observedNote: 'not provided by backend',
    },
    {
      term: 'IKE DH group',
      configured: expected.ike?.dh_group,
      status: variable('ike.dh_group'),
      observedNote: 'not provided by backend',
    },
    {
      term: 'ESP encryption',
      configured: expected.esp?.encryption,
      status: variable('esp.encryption'),
      observedNote: 'not provided by backend',
    },
    {
      term: 'ESP integrity',
      configured: expected.esp?.integrity,
      status: variable('esp.integrity'),
      observedNote: 'not provided by backend',
    },
    {
      term: 'ESP DH group (PFS)',
      configured: expected.esp?.dh_group,
      status: variable('esp.dh_group'),
      observedNote: 'not provided by backend',
    },
    {
      term: 'PFS enabled',
      configured: expected.esp?.pfs,
      status: variable('esp.pfs'),
      observedNote: 'not provided by backend',
    },
    {
      term: 'SA lifetime / rekey',
      status: null,
      observedNote: 'not provided by backend',
    },
    {
      term: 'Negotiated proposals',
      status: null,
      observedNote: 'not provided by backend',
    },
  ]

  return (
    <div>
      <p className="pw-faint-text" style={{ marginBottom: '0.5rem' }}>
        The analytics plane records configuration intent and the *geometry* the capture observed
        (protocol activity, SPI list, sequence). It never decrypts negotiated payloads, so rows
        marked <Prov kind="miss">not provided&nbsp;by&nbsp;backend</Prov> are only available in the
        raw pcap evidence.
      </p>
      <p className="pw-subhead">Crypto</p>
      <div className="pw-colheads">
        <span>Parameter</span>
        <span>Configured</span>
        <span>Observed</span>
        <span>Comparison</span>
      </div>
      {rows.map((row) => (
        <SaRow key={row.term} {...row} />
      ))}

      <h4 className="pw-subhead">SPI / association</h4>
      <div className="pw-kv">
        <dt>
          This packet <Prov kind="obs">observed</Prov>
        </dt>
        <dd className="pw-mono">
          SPI 0x{model.packet.spi === null ? '…' : model.packet.spi.toString(16).padStart(8, '0')} · seq{' '}
          {model.packet.packet.sequence}
        </dd>
      </div>
      {(observed.spis ?? []).map((spi) => (
        <dl className="pw-kv" key={spi.spi}>
          <dt>
            SA {spi.spi} <Prov kind="obs">observed</Prov>
          </dt>
          <dd className="pw-mono">
            {spi.direction} · {spi.active ? 'active' : 'inactive'} · {formatNumber(spi.packet_count)} pkt · seq{' '}
            {formatNumber(spi.highest_sequence)} · {formatLocalFull(spi.first_seen_ns)} → {formatLocalFull(spi.last_seen_ns)}
          </dd>
        </dl>
      ))}
    </div>
  )
}

function ConfigBlock({
  bundle,
  correlationMap,
  findings,
  showAllConfig,
  onToggleAll,
}: {
  bundle: AssessmentBundle
  correlationMap: Map<string, ComparisonRow>
  findings: Finding[]
  showAllConfig: boolean
  onToggleAll: () => void
}) {
  const expected = bundle.expected
  const observed = bundle.observed
  const packet = bundle.observed
  const flaggedVariables = new Set(findings.map((finding) => finding.related_variable).filter(Boolean))
  const configRows = expectedConfigRows(expected)
  const relevantRows = configRows.filter((row) => flaggedVariables.has(row.variable))
  const shownRows = showAllConfig ? configRows : relevantRows.length > 0 ? relevantRows : configRows

  return (
    <div>
      <h4 className="pw-subhead">Relevant configuration</h4>
      <p className="pw-faint-text" style={{ margin: '0 0 0.4rem' }}>
        The parameters the findings flag, compared against the observed record. The full list is a
        click away.
      </p>
      {shownRows.length === 0 ? (
        <p className="pw-faint-text">The analytics plane recorded no configuration rows for this assessment.</p>
      ) : (
        <ConfigCompareGrid rows={shownRows} correlationMap={correlationMap} flaggedVariables={flaggedVariables} />
      )}
      {!showAllConfig && (
        <button type="button" className="pw-btn" style={{ marginTop: '0.5rem' }} onClick={onToggleAll}>
          Show all configuration →
        </button>
      )}
      {showAllConfig && (
        <button type="button" className="pw-btn" style={{ marginTop: '0.5rem' }} onClick={onToggleAll}>
          Show only flagged
        </button>
      )}
      {bundle.correlation.rows.length === 0 && (
        <p className="pw-faint-text">
          The analytics plane recorded no comparison rows for this assessment.
        </p>
      )}

      <h4 className="pw-subhead">Configuration comparison · Gateway A ↔ B</h4>
      <p className="pw-faint-text" style={{ margin: '0 0 0.4rem' }}>
        The backend records the tunnel&apos;s two endpoint addresses (observed) and one configured
        intent per assessment; it does not provide a separate per-gateway (A/B) configuration, so
        only one configured column exists.
      </p>
      <dl className="pw-kv">
        <dt>
          Gateway A <Prov kind="obs">observed</Prov>
        </dt>
        <dd className="pw-mono">
          {observed.endpoints?.a ?? '—'}
          {observed.packets_a_to_b !== undefined && (
            <span className="pw-dim"> → sends {formatNumber(observed.packets_a_to_b)} pkt</span>
          )}
          {observed.bytes_a_to_b !== undefined && (
            <span className="pw-dim"> ({formatBytes(observed.bytes_a_to_b)})</span>
          )}
        </dd>
      </dl>
      <dl className="pw-kv">
        <dt>
          Gateway B <Prov kind="obs">observed</Prov>
        </dt>
        <dd className="pw-mono">
          {observed.endpoints?.b ?? '—'}
          {observed.packets_b_to_a !== undefined && (
            <span className="pw-dim"> → sends {formatNumber(observed.packets_b_to_a)} pkt</span>
          )}
          {observed.bytes_b_to_a !== undefined && (
            <span className="pw-dim"> ({formatBytes(observed.bytes_b_to_a)})</span>
          )}
        </dd>
      </dl>
      <dl className="pw-kv">
        <dt>
          Configured intent <Prov kind="conf">configured</Prov>
        </dt>
        <dd className="pw-mono">
          {expected.configuration_id ?? '—'}
          {expected.security_posture ? <span className="pw-dim"> · posture {expected.security_posture}</span> : ''}
        </dd>
      </dl>

      <h4 className="pw-subhead">Observed SA</h4>
      <dl className="pw-kv">
        <dt>
          Handshake <Prov kind="obs">observed</Prov>
        </dt>
        <dd className="pw-ink">
          {observed.ike_seen === true ? 'IKE seen' : 'no IKE observed'}
          {observed.ike_nat_t_seen ? ' · NAT-T seen' : ''}
          {observed.esp_seen ? ' · ESP seen' : ''}
          {observed.ah_seen ? ' · AH seen' : ''}
        </dd>
      </dl>
      <dl className="pw-kv">
        <dt>
          Associations <Prov kind="obs">observed</Prov>
        </dt>
        <dd className="pw-mono">{formatNumber(observed.spis?.length ?? null)}</dd>
      </dl>
      <dl className="pw-kv">
        <dt>
          Packets <Prov kind="obs">observed</Prov>
        </dt>
        <dd className="pw-mono">
          {formatNumber(packet.packets_seen ?? null)}
          {packet.bytes_seen !== undefined && <span className="pw-dim"> ({formatBytes(packet.bytes_seen)})</span>}
        </dd>
      </dl>
      <dl className="pw-kv">
        <dt>
          Correlation engine <Prov kind={correlationMap.size ? 'obs' : 'miss'}>reported</Prov>
        </dt>
        <dd className="pw-ink">
          {bundle.correlation.status}
          {correlationMap.size > 0 &&
            ` · ${formatNumber(
              [...correlationMap.values()].filter((row) => row.status === 'MATCH').length,
            )} match, ${formatNumber(
              [...correlationMap.values()].filter((row) => row.status === 'MISMATCH').length,
            )} mismatch`}
        </dd>
      </dl>
    </div>
  )
}

/**
 * The AI explanation section.
 *
 * All this does is assemble the exact investigation context and hand it to
 * `AiExplainer`. The panel itself lives in its own file because the same
 * component is mounted in the traffic drawer, and one implementation is what
 * keeps the provenance labelling identical in both places.
 */
function AiSection({
  model,
  bundle,
  findings,
  drift,
  primary,
  integrity,
  assessmentId,
}: {
  model: CaptureRow
  bundle: AssessmentBundle
  findings: Finding[]
  drift: AssessmentDriftResponse | null
  primary: Finding | null
  integrity: EvidenceIntegrity | null
  assessmentId: string | null
}) {
  const build = (): string => {
    const packet = model.packet
    const risk = packet.risk
    const ml = bundle.ml
    const flaggedVariables = findings.map((finding) => finding.related_variable).filter(Boolean)
    const lines: string[] = [
      `Assessment ${assessmentId ?? '—'} (scenario ${bundle.scenario ?? '—'}, slot ${bundle.slot ?? '—'})`,
      `Packet: ${model.source} -> ${model.destination} · ${model.protocol} · len ${model.length} · SPI ${model.spi === null ? 'none' : `0x${model.spi.toString(16)}`} · seq ${packet.packet.sequence} · at ${model.time}`,
      `Security status: ${risk.present ? String(risk.highest_severity) : 'none'} · score ${risk.present ? risk.highest_risk_score : '—'} · ${risk.present ? risk.assessments.length : 0} assessment(s) (store by observed SPI)`,
      `Confidence: ml classification ${ml.present ? (ml.classification_confidence === null ? '—' : formatPercent(ml.classification_confidence)) : 'not executed'} (${ml.present ? ml.model_version ?? 'model' : 'no model'}) · this finding ${primary && primary.confidence !== null ? formatPercent(primary.confidence) : 'not recorded (deterministic rule)'}`,
      `Traffic: detected=${packet.packet.classification}${ml.present ? ` · inferred=${ml.traffic_class ?? '—'}` : ''} · configured profile=${bundle.expected.traffic?.profile ?? '—'}`,
      `Configured: IKEv${bundle.expected.ike?.version ?? '—'} · ESP ${bundle.expected.esp?.encryption ?? '—'} / ${bundle.expected.esp?.integrity ?? '—'} · dh ${bundle.expected.esp?.dh_group ?? '—'} · pfs ${bundle.expected.esp?.pfs ?? '—'} · mode ${bundle.expected.mode ?? '—'} ${bundle.expected.address_family ?? ''}`,
      `Observed: ${bundle.observed.endpoints?.a ?? '—'} -> ${bundle.observed.endpoints?.b ?? '—'} · IKE seen ${bundle.observed.ike_seen ?? '—'} · ESP seen ${bundle.observed.esp_seen ?? '—'} · ${bundle.observed.spis?.length ?? '—'} SA(s)`,
      `Correlation: ${bundle.correlation.status ?? '—'} (${bundle.correlation.rows.length ?? 0} rows)`,
      `Relevant configuration: ${flaggedVariables.length === 0 ? 'none flagged' : flaggedVariables.join(', ')}`,
      `Configuration combination: no combination analysis is available from the backend`,
      `Findings: ${findings.length === 0 ? 'none' : findings.map((f) => `${f.severity} ${f.title}`).join('; ')}`,
      `Evidence: ${primary ? primary.evidence_refs.map((r) => r.evidence_id).filter(Boolean).join(', ') || 'no references' : 'no finding'}${integrity ? ` · integrity ${integrity.verification_status}` : ''}`,
      `Drift: ${drift ? (drift.drift_detected ? `drift detected (${drift.changed_fields.length} fields)` : drift.status === 'not_configured' ? 'not configured (no baseline)' : 'no drift') : '—'}`,
    ]
    return lines.join('\n')
  }

  return (
    <AiExplainer
      assessmentId={assessmentId}
      findingId={primary?.finding_id ?? null}
      severity={primary?.severity ?? bundle.risk.severity ?? null}
      hasEvidence={
        primary
          ? primary.evidence_refs.length > 0
          : (bundle.evidence?.total_refs ?? 0) > 0
      }
      context={build()}
    />
  )
}

/* ------------------------------------------------------------- the body */

export function AssessmentExplanation({
  model,
  bundle,
  drift,
  findings,
  custody,
  explanationIsDefault,
  correlationMap,
  focusedFinding = null,
  onExplain,
}: {
  model: CaptureRow
  bundle: AssessmentBundle
  drift: AssessmentDriftResponse | null
  findings: Finding[]
  /** Finding-scope custody: the chain + integrity of the explained finding. */
  custody: FindingCustody
  /** True when the explained finding is the default, not an analyst choice. */
  explanationIsDefault: boolean
  correlationMap: Map<string, ComparisonRow>
  /**
   * The finding the analyst selected. The assessment-level facts stay
   * assessment-level; only the finding-specific explanation follows this
   * selection, so "explain this finding" always means the row actually chosen.
   */
  focusedFinding?: Finding | null
  /** Select a finding to explain; the assessment-level facts do not move. */
  onExplain?: (findingId: string) => void
}) {
  const [showAllConfig, setShowAllConfig] = useState(false)
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  const packet = model.packet
  const ml = bundle.ml
  const risk = bundle.risk
  const scoreDetail = risk.score_detail
  const primary = selectPrimaryFinding(findings)
  /** The finding being explained: the selection when there is one. */
  const explained = focusedFinding ?? primary
  const findingConfidenceText =
    explained && explained.confidence !== null
      ? formatPercent(explained.confidence)
      : 'not recorded — deterministic rule'
  const band = severityBandText(scoreDetail?.severity_band)
  const differs =
    !!explained &&
    String(risk.severity ?? '').toUpperCase() !== String(explained.severity ?? '').toUpperCase()
  const selectedIsPrimary = !!explained && explained.finding_id === primary?.finding_id
  const openEvidence = () => setEvidenceOpen(true)

  return (
    <div className="pw-invest-body" aria-label="Security assessment explanation">
      {/* Overview — the verdict, the findings and the backend's own confidence. */}
      <CollapsibleSection title="Overview" defaultOpen>
        <div className="pw-finding" style={{ borderLeftColor: severityHex(risk.severity), borderLeftWidth: '3px' }}>
          <div className="pw-finding-head">
            <h4 className="pw-finding-title">Security assessment</h4>
            <span className="pw-risk-col">
              <RiskChip severity={risk.severity} score={risk.overall_score} />
              <span className="pw-chip-caption" data-packet-risk="true">
                assessment / packet risk
              </span>
            </span>
          </div>
          {differs && (
            <dl className="pw-kv" data-risk-vs-severity="true">
              <dt>Risk vs severity</dt>
              <dd className="pw-ink">
                Assessment / packet risk is <span className="pw-mono">{String(risk.severity)}</span> — the
                assessment&apos;s highest scored severity.{' '}
                {selectedIsPrimary ? 'The primary finding' : 'The selected finding'}&apos;s own severity is{' '}
                <span className="pw-mono">{String(explained?.severity)}</span>. The two are distinct
                concepts: a HIGH assessment may carry only MEDIUM (or lower) findings.
              </dd>
            </dl>
          )}
          {band && (
            <dl className="pw-kv">
              <dt>Severity band</dt>
              <dd className="pw-mono">{band}</dd>
            </dl>
          )}
          <dl className="pw-kv">
            <dt>Overall score</dt>
            <dd className="pw-mono">
              {formatNumber(risk.overall_score)}
              {scoreDetail?.raw_sum !== undefined && (
                <span className="pw-dim"> · sum of contributions {formatNumber(scoreDetail.raw_sum)}</span>
              )}
              <span className="pw-dim"> · policy {risk.risk_policy_version}</span>
            </dd>
          </dl>
          <dl className="pw-kv">
            <dt>Findings raised</dt>
            <dd className="pw-ink">
              {formatNumber(findings.length)} finding{findings.length === 1 ? '' : 's'}
              {findings.length > 0 && primary && (
                <span className="pw-dim"> · highest finding severity {primary.severity}</span>
              )}
            </dd>
          </dl>
        </div>

        <h4 className="pw-subhead">Findings</h4>
        {findings.length === 0 ? (
          <div className="pw-empty" style={{ minHeight: 0 }}>
            <span className="pw-ink-strong">No security finding associated with this packet/flow.</span>
            <p className="pw-empty-note">
              The assessment recorded no finding; nothing is inferred from the packet itself.
            </p>
          </div>
        ) : (
          findings.map((finding) => (
            <div
              className="pw-finding"
              key={finding.finding_id}
              data-finding-id={finding.finding_id}
              data-explained={explained?.finding_id === finding.finding_id ? 'true' : undefined}
            >
              <div className="pw-finding-head">
                <h4 className="pw-finding-title">
                  <RiskChip severity={finding.severity} score={null} /> {finding.title}
                </h4>
              </div>
              <p className="pw-faint-text">
                {finding.rule_id} · {humanize(finding.category)}
                {finding.confidence === null ? '' : ` · confidence ${formatPercent(finding.confidence)}`}
                {explained?.finding_id === finding.finding_id && (
                  <span className="pw-chip-caption"> · explained below</span>
                )}
              </p>
              {onExplain && (
                <button
                  type="button"
                  className={
                    explained?.finding_id === finding.finding_id ? 'pw-btn pw-btn-primary' : 'pw-btn'
                  }
                  data-explain-finding={finding.finding_id}
                  onClick={() => onExplain(finding.finding_id)}
                >
                  {explained?.finding_id === finding.finding_id
                    ? 'Explained below'
                    : 'Explain this finding'}
                </button>
              )}
            </div>
          ))
        )}

        <ConfidenceSection ml={ml} primary={explained} findingConfidenceText={findingConfidenceText} />

        <h4 className="pw-subhead">Traffic type</h4>
        <dl className="pw-kv">
          <dt>
            Detected <Prov kind="obs">observed</Prov>
          </dt>
          <dd className="pw-ink">{packet.packet.classification}</dd>
        </dl>
        <dl className="pw-kv">
          <dt>
            Inferred <Prov kind={ml.present ? 'obs' : 'miss'}>model</Prov>
          </dt>
          <dd className="pw-ink">
            {ml.present
              ? `${ml.traffic_class ?? '—'}${ml.classification_confidence === null ? '' : ` · ${formatPercent(ml.classification_confidence)} confidence`}`
              : '—'}
          </dd>
        </dl>
        <dl className="pw-kv">
          <dt>
            Configured <Prov kind="conf">configured</Prov>
          </dt>
          <dd className="pw-ink">{bundle.expected.traffic?.profile ?? '—'}</dd>
        </dl>
        <p className="pw-faint-text">
          NOTE — ML classification applies to the flow and analysis window, not to a single encrypted
          packet. The per-packet label above is the capture adapter&apos;s protocol detection.
        </p>
      </CollapsibleSection>

      {/* Why this risk? — the evidence-grounded explanation, then the scheme. */}
      <CollapsibleSection title="Why this risk?" defaultOpen>
        <XaiExplanation
          bundle={bundle}
          finding={explained}
          drift={drift}
          correlationMap={correlationMap}
          custody={custody}
          onShowEvidence={openEvidence}
        />
        {explained && (
          <WhyFlaggedBlock
            finding={explained}
            explanation={custody.explanation}
            correlationMap={correlationMap}
          />
        )}
      </CollapsibleSection>

      {/* Configuration — the configured/observed comparison. */}
      <CollapsibleSection title="Configuration" defaultOpen>
        <ConfigBlock
          bundle={bundle}
          correlationMap={correlationMap}
          findings={findings}
          showAllConfig={showAllConfig}
          onToggleAll={() => setShowAllConfig((value) => !value)}
        />
      </CollapsibleSection>

      {/* Allowed / expected combinations — what the backend can and cannot say. */}
      <CollapsibleSection title="Allowed / expected combinations">
        <h4 className="pw-subhead">Configuration combination</h4>
        <p className="pw-faint-text">
          No configuration combination analysis is available for this finding. The analytics plane
          records per-variable comparison rows but no cross-parameter combination or co-occurrence
          analysis, so none is presented here.
        </p>
        <IkeSaBlock model={model} bundle={bundle} correlationMap={correlationMap} />
      </CollapsibleSection>

      {/* Drift vs baseline. */}
      <CollapsibleSection title="Drift">
        <AssessmentDriftBlock drift={drift} />
      </CollapsibleSection>

      {/* Evidence — integrity first, then the finding's artifacts. */}
      <CollapsibleSection
        title="Evidence"
        id="invest-evidence"
        open={evidenceOpen}
        onToggle={setEvidenceOpen}
      >
        <EvidenceBlock primary={explained} custody={custody} onShowEvidence={openEvidence} />
        <EvidenceDetail custody={custody} finding={explained} assessmentId={bundle.assessment_id} />
      </CollapsibleSection>

      {/* Chain of custody — the finding's derived chain, inline. */}
      <CollapsibleSection title="Chain of custody">
        <ExplainFindingBlock
          finding={explained}
          custody={custody}
          assessmentId={bundle.assessment_id}
          isDefault={explanationIsDefault}
        />
      </CollapsibleSection>

      {/* AI explanation — grounded context, honest not-connected state. */}
      <CollapsibleSection title="AI explanation">
        <AiSection
          model={model}
          bundle={bundle}
          findings={findings}
          drift={drift}
          primary={explained}
          integrity={custody.integrity}
          assessmentId={bundle.assessment_id}
        />
      </CollapsibleSection>

      {/* Assessment identity — the run the whole investigation belongs to. */}
      <p className="pw-faint-text" style={{ marginTop: '0.75rem' }}>
        Dataset <span className="pw-mono">{bundle.dataset_run_id}</span> · scenario{' '}
        <span className="pw-mono">{bundle.scenario}</span> · slot <span className="pw-mono">{bundle.slot}</span> ·
        correlation <span className="pw-mono">{bundle.correlation.status}</span> · assessment{' '}
        <span className="pw-mono">{bundle.assessment_id}</span>.
      </p>
      {scoreDetail?.contributions && scoreDetail.contributions.length > 0 && (
        <dl className="pw-kv">
          <dt>Contributions</dt>
          <dd className="pw-mono">{scoreDetail.contributions.map((c) => `${c.finding_id} +${c.added}`).join(' · ')}</dd>
        </dl>
      )}
      <Link className="pw-link" to={`/assessments/${encodeURIComponent(bundle.assessment_id)}`}>
        Open full assessment →
      </Link>
    </div>
  )
}
