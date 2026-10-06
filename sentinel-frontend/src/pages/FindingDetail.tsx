import { useNavigate, useParams } from 'react-router-dom'
import { getFindingExplanation } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { ErrorState, LoadingPanel } from '@/components/states'
import { Panel, Prose, SeverityBadge, StatusPill, Tag, LinkButton, HashChip } from '@/components/ui'
import { IdRow, ProvenanceDetails } from '@/components/kit'
import { Breadcrumbs } from '@/layouts/AppLayout'
import { ApiRequestError } from '@/api/client'
import { formatBytes, formatValue } from '@/lib/format'
import { acronymLabel, configTermLabel, statusLabel } from '@/lib/labels'
import type { CustodyExplanation, Severity } from '@/types'

/* ------------------------------------------------------------- primitives */

function AuthorityChip({ authoritative }: { authoritative: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-semibold tracking-wide ${
        authoritative
          ? 'border-good/35 bg-good/10 text-good'
          : 'border-medium/35 bg-medium/10 text-medium'
      }`}
    >
      {authoritative ? 'AUTHORITATIVE' : 'NON-AUTHORITATIVE'}
    </span>
  )
}

function ExpectedObserved({
  expected,
  observed,
  variable,
}: {
  expected: unknown
  observed: unknown
  variable?: string
}) {
  const expectedText = formatValue(expected)
  const observedText = formatValue(observed)
  const differs = expectedText !== observedText

  return (
    <div className="grid gap-3 md:grid-cols-2">
      <div className="rounded-md border border-sentinel/25 bg-sentinel/[0.04] p-3">
        <p className="label text-sentinel/80">
          Expected state
        </p>
        <p className="mono mt-1.5 break-all text-base text-sentinel">{expectedText}</p>
        {variable && (
          <p className="mt-1 text-xs text-ink-faint">
            parameter <span>{configTermLabel(variable)}</span>
          </p>
        )}
      </div>
      <div
        className={`rounded-md border p-3 ${
          differs ? 'border-critical/30 bg-critical/[0.05]' : 'border-good/25 bg-good/[0.04]'
        }`}
      >
        <p
          className={`label ${
            differs ? 'text-critical/80' : 'text-good/80'
          }`}
        >
          Observed evidence
        </p>
        <p
          className={`mono mt-1.5 break-all text-base ${
            differs ? 'text-critical' : 'text-good'
          }`}
        >
          {observedText}
        </p>
        <p className="mt-1 text-xs text-ink-faint">
          {differs ? 'contradicts the plan' : 'matches the plan'}
        </p>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ steps */

function CustodySteps({ steps }: { steps: CustodyExplanation['steps'] }) {
  return (
    <ol className="relative space-y-0 p-4">
      {steps.map((step, index) => (
        <li key={step.index} className="relative flex gap-3.5 pb-5 last:pb-0">
          {index < steps.length - 1 && (
            <span
              className="absolute left-[13px] top-7 h-full w-px bg-gradient-to-b from-edge to-edge/30"
              aria-hidden="true"
            />
          )}
          <span
            className={`relative z-10 flex h-[27px] w-[27px] shrink-0 items-center justify-center rounded-full border mono text-xs ${
              step.authoritative
                ? 'border-sentinel/45 bg-sentinel/10 text-sentinel'
                : 'border-medium/40 bg-medium/10 text-medium'
            }`}
          >
            {step.index}
          </span>
          <div className="min-w-0 flex-1 pt-0.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium capitalize text-ink">
                {step.stage.replace(/_/g, ' ')}
              </span>
              <AuthorityChip authoritative={step.authoritative} />
            </div>
            <p className="mono mt-0.5 text-xs text-ink-faint">{step.component}</p>
            <p className="mt-1 text-sm text-ink-dim">{step.action}</p>
            {step.inputs.length > 0 && (
              <div className="mt-1.5 flex flex-wrap gap-1">
                {step.inputs.map((input) => (
                  <span
                    key={input}
                    className="mono rounded-md border border-edge bg-panel px-1.5 py-0.5 text-xs text-ink-faint"
                  >
                    {input}
                  </span>
                ))}
              </div>
            )}
            <p className="mt-1.5 rounded-md border border-edge bg-panel-2 px-2.5 py-1.5 text-sm leading-snug text-ink-dim">
              {step.outcome}
            </p>
          </div>
        </li>
      ))}
    </ol>
  )
}

/* ------------------------------------------------------------------ facts */

function CustodyFacts({ facts }: { facts: CustodyExplanation['facts'] }) {
  const authoritative = facts.filter((fact) => fact.authoritative)
  const derived = facts.filter((fact) => !fact.authoritative)

  return (
    <div className="space-y-3 p-4">
      {authoritative.length > 0 && (
        <div>
          <p className="mb-2 label text-good/80">
            Authoritative facts
          </p>
          <ul className="space-y-2">
            {authoritative.map((fact) => (
              <li
                key={fact.fact_id}
                className="rounded-md border border-good/25 bg-good/[0.04] px-3 py-2"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm text-ink">{fact.label}</span>
                  <span className="mono ml-auto text-sm text-good">
                    {formatValue(fact.value)}
                  </span>
                </div>
                {fact.detail && (
                  <p className="mt-1 text-xs leading-snug text-ink-faint">{fact.detail}</p>
                )}
                <ProvenanceDetails title="Fact record" className="mt-1.5">
                  <IdRow label="Fact id" value={fact.fact_id ?? '—'} title={fact.fact_id ?? undefined} />
                  {fact.source && <IdRow label="Source" value={fact.source} title={fact.source} />}
                  {fact.evidence_ids && fact.evidence_ids.length > 0 && (
                    <IdRow
                      label={`Evidence id${fact.evidence_ids.length === 1 ? '' : 's'} (${fact.evidence_ids.length})`}
                      value={fact.evidence_ids.join(', ')}
                      title={fact.evidence_ids.join(', ')}
                    />
                  )}
                </ProvenanceDetails>
              </li>
            ))}
          </ul>
        </div>
      )}

      {derived.length > 0 && (
        <div>
          <p className="mb-2 label text-medium/80">
            Derived (non-authoritative)
          </p>
          <ul className="space-y-2">
            {derived.map((fact) => (
              <li
                key={fact.fact_id}
                className="rounded-md border border-edge bg-panel-2 px-3 py-2"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm text-ink-dim">{fact.label}</span>
                  <span className="mono ml-auto text-sm text-medium">
                    {formatValue(fact.value)}
                  </span>
                </div>
                {fact.detail && (
                  <p className="mt-1 text-xs leading-snug text-ink-faint">{fact.detail}</p>
                )}
                <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-ink-faint">
                  <span className="mono">{fact.fact_id}</span>
                  {fact.source && <span className="mono">from {fact.source}</span>}
                  {fact.value_digest && (
                    <span className="mono" title={fact.value_digest}>
                      digest {fact.value_digest.slice(0, 10)}…
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

/* ------------------------------------------------------------- integrity */

function IntegrityChecks({ checks }: { checks: CustodyExplanation['integrity'] }) {
  return (
    <ul className="divide-y divide-edge/60">
      {checks.map((check) => {
        const tone =
          check.status === 'pass'
            ? 'text-good'
            : check.status === 'fail'
              ? 'text-critical'
              : 'text-ink-faint'
        return (
          <li key={check.check_id} className="px-4 py-3">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs font-medium capitalize ${
                  check.status === 'pass'
                    ? 'border-good/30 bg-good/10'
                    : check.status === 'fail'
                      ? 'border-critical/35 bg-critical/10'
                      : 'border-edge'
                } ${tone}`}
              >
                {check.status}
              </span>
              <span className="mono text-xs text-ink">{check.check_id}</span>
              {check.client_verifiable && (
                <span className="text-xs text-ink-faint">client-verifiable</span>
              )}
            </div>
            <p className="mt-1 text-sm leading-snug text-ink-dim">{check.description}</p>
            <p className="mt-1 text-xs leading-snug text-ink-faint">{check.detail}</p>
          </li>
        )
      })}
    </ul>
  )
}

/* ------------------------------------------------------------------ page */

export function FindingDetail() {
  const { assessmentId = '', findingId = '' } = useParams()
  const navigate = useNavigate()

  const resource = useResource(
    (signal) => getFindingExplanation(assessmentId, findingId, signal),
    { enabled: assessmentId !== '' && findingId !== '', deps: [assessmentId, findingId] },
  )

  if (assessmentId === '' || findingId === '') {
    return (
      <ErrorState
        error={
          new ApiRequestError({
            title: 'No finding selected',
            detail: 'The route did not include an assessment id and a finding id.',
            status: 404,
            code: 'missing_finding_id',
            service: 'analytics',
          })
        }
        onRetry={() => navigate('/findings')}
      />
    )
  }

  const chain = resource.data

  return (
    <div>
      <Breadcrumbs
        trail={[
          { to: '/findings', label: 'Findings' },
          { to: `/assessments/${encodeURIComponent(assessmentId)}`, label: assessmentId },
          { label: findingId },
        ]}
      />

      {resource.loading && <LoadingPanel label="Loading chain of custody" rows={8} />}
      {resource.error && (
        <div className="space-y-3">
          <ErrorState error={resource.error} onRetry={resource.reload} />
          <LinkButton to="/findings" variant="ghost">
            ← Back to findings
          </LinkButton>
        </div>
      )}

      {chain && (
        <div className="space-y-4">
          {/* Header */}
          <div className="panel p-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={chain.severity as Severity} />
              <Tag>{acronymLabel(chain.category)}</Tag>
              <span className="ml-auto flex items-center gap-2 text-xs text-ink-faint">
                <ProvenanceDetails title="Record ids">
                  <IdRow label="Finding id" value={chain.finding_id} title={chain.finding_id} />
                  {chain.rule?.rule_id && (
                    <IdRow label="Rule id" value={chain.rule.rule_id} title={chain.rule.rule_id} />
                  )}
                  <IdRow label="Component" value={chain.component ?? '—'} title={chain.component ?? undefined} />
                </ProvenanceDetails>
                {chain.component_version && <Tag>{chain.component_version}</Tag>}
              </span>
            </div>
            <h2 className="mt-2 text-lg font-semibold leading-snug text-ink">
              {chain.title}
            </h2>
            <p className="mt-1.5 text-sm leading-relaxed text-ink-dim">{chain.summary}</p>
            <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-edge pt-3 text-xs">
              <span className="text-ink-faint">
                assessment risk{' '}
                <span className="mono text-ink">{chain.risk_score}</span>{' '}
                <SeverityBadge severity={chain.risk_severity as Severity} size="sm" />
              </span>
              <span className="text-ink-faint">
                policy <span className="mono text-ink-dim">{chain.risk_policy_version}</span>
              </span>
              <span className="text-ink-faint">
                digest <HashChip hash={chain.finding_digest} />
              </span>
              <StatusPill
                status={chain.audit_linkage_status ?? 'unavailable'}
                tone={chain.audit_linkage_status === 'linked' ? 'good' : 'neutral'}
              />
            </div>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <div className="space-y-4 xl:col-span-2">
              {/* Why detected / expected vs observed */}
              <Panel
                title="Why It Was Detected"
                subtitle="the rule, its condition, and the contradiction it found"
              >
                <div className="space-y-3 p-4">
                  <p className="text-sm leading-relaxed text-ink">
                    {chain.rule.condition ?? 'condition not reported'}
                  </p>
                  <ExpectedObserved
                    expected={ruleFactValue(chain, 'expected')}
                    observed={ruleFactValue(chain, 'observed')}
                    variable={chain.rule.source_variable}
                  />
                  <div className="rounded-md border border-edge bg-panel-2 p-3">
                    <p className="label text-ink-faint">
                      Security implication
                    </p>
                    <Prose>{chain.summary}</Prose>
                  </div>
                </div>
              </Panel>

              {/* Rule definition */}
              <Panel
                title="Rule"
                subtitle={`registered: ${chain.rule.registered ? 'yes' : 'no'}`}
              >
                <ProvenanceDetails title="Rule record" className="px-4 pt-3">
                  <IdRow label="Rule id" value={chain.rule.rule_id} title={chain.rule.rule_id} />
                </ProvenanceDetails>
                <dl className="grid grid-cols-1 gap-x-5 gap-y-3.5 p-4 md:grid-cols-2">
                  {chain.rule.source_variable && (
                    <div>
                      <dt className="label text-ink-faint">
                        Source variable
                      </dt>
                      <dd className="mt-0.5 text-sm text-ink">
                        {configTermLabel(chain.rule.source_variable)}
                      </dd>
                    </div>
                  )}
                  {chain.rule.authoritative_source && (
                    <div className="md:col-span-2">
                      <dt className="label text-ink-faint">
                        Authoritative source
                      </dt>
                      <dd className="mt-0.5 text-sm leading-snug text-ink-dim">
                        {chain.rule.authoritative_source}
                      </dd>
                    </div>
                  )}
                  {chain.rule.evidence_requirement && (
                    <div>
                      <dt className="label text-ink-faint">
                        Evidence requirement
                      </dt>
                      <dd className="mt-0.5 text-sm text-ink-dim">
                        {chain.rule.evidence_requirement}
                      </dd>
                    </div>
                  )}
                  {chain.rule.unknown_handling && (
                    <div>
                      <dt className="label text-ink-faint">
                        Unknown handling
                      </dt>
                      <dd className="mt-0.5 text-sm text-ink-dim">
                        {chain.rule.unknown_handling}
                      </dd>
                    </div>
                  )}
                  {chain.rule.dedup_behavior && (
                    <div className="md:col-span-2">
                      <dt className="label text-ink-faint">
                        Deduplication
                      </dt>
                      <dd className="mono mt-0.5 text-sm text-ink-dim">
                        {chain.rule.dedup_behavior}
                      </dd>
                    </div>
                  )}
                </dl>
              </Panel>

              {/* Custody steps */}
              <Panel
                title="Derivation Chain"
                subtitle="every stage that produced this decision, in order"
              >
                <CustodySteps steps={chain.steps} />
              </Panel>

              {/* Facts */}
              <Panel
                title="Recorded Facts"
                subtitle="values captured at the moment of the decision"
              >
                <CustodyFacts facts={chain.facts} />
              </Panel>

              {/* Limitations */}
              {chain.limitations.length > 0 && (
                <Panel
                  title="Limitations"
                  subtitle="what this chain does not establish"
                >
                  <ul className="space-y-2 p-4">
                    {chain.limitations.map((limitation) => (
                      <li key={limitation} className="flex items-start gap-2.5">
                        <span
                          className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full bg-medium/70"
                          aria-hidden="true"
                        />
                        <span className="text-sm leading-relaxed text-ink-dim">
                          {limitation}
                        </span>
                      </li>
                    ))}
                  </ul>
                </Panel>
              )}
            </div>

            {/* Right column */}
            <div className="space-y-4">
              {/* Evidence */}
              <Panel
                title="Evidence"
                subtitle={`${chain.evidence.length} artifact${chain.evidence.length === 1 ? '' : 's'} referenced`}
              >
                {chain.evidence.length === 0 ? (
                  <p className="p-4 text-sm text-ink-faint">
                    No artifact is attached to this finding.
                  </p>
                ) : (
                  <ul className="divide-y divide-edge/60">
                    {chain.evidence.map((item) => (
                      <li key={item.evidence_id} className="px-4 py-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <StatusPill
                            status={statusLabel(item.verification_status ?? 'unknown')}
                            tone={
                              item.verification_status === 'valid'
                                ? 'good'
                                : item.verification_status === 'invalid'
                                  ? 'bad'
                                  : 'neutral'
                            }
                          />
                          {item.artifact_type && (
                            <span className="text-sm text-ink">{acronymLabel(item.artifact_type)}</span>
                          )}
                          <ProvenanceDetails title="Evidence record" className="ml-auto">
                            <IdRow label="Evidence id" value={item.evidence_id} title={item.evidence_id} />
                          </ProvenanceDetails>
                        </div>
                        <p className="mt-1 text-xs text-ink-faint">
                          {item.verification_detail ?? 'no verification detail reported'}
                        </p>
                        <dl className="mt-2 space-y-1 text-xs">
                          <div className="flex justify-between gap-2">
                            <dt className="text-ink-faint">artifact</dt>
                            <dd className="truncate text-ink-dim">{acronymLabel(item.artifact_type)}</dd>
                          </div>
                          <div className="flex justify-between gap-2">
                            <dt className="text-ink-faint">size</dt>
                            <dd className="mono tnum text-ink-dim">
                              {formatBytes(item.byte_size)}
                            </dd>
                          </div>
                          <div className="flex justify-between gap-2">
                            <dt className="text-ink-faint">recorded</dt>
                            <dd className="mono truncate text-ink-dim">
                              {item.artifact_sha256?.slice(0, 16) ?? '—'}…
                            </dd>
                          </div>
                          <div className="flex justify-between gap-2">
                            <dt className="text-ink-faint">attached by</dt>
                            <dd className="text-ink-dim">
                              {(item.attached_by ?? []).join(', ') || '—'}
                            </dd>
                          </div>
                        </dl>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>

              {/* Integrity */}
              <Panel
                title="Integrity"
                subtitle={`${chain.integrity.filter((c) => c.status === 'pass').length}/${chain.integrity.length} checks passed`}
              >
                <IntegrityChecks checks={chain.integrity} />
              </Panel>

              {/* Recommendation */}
              {chain.recommendation && (
                <Panel
                  title="Proposed Response"
                  subtitle="policy proposal only — nothing was executed"
                >
                  <div className="space-y-2.5 p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded border border-low/35 bg-low/10 px-2 py-0.5 text-sm font-medium text-low">
                        {chain.recommendation.action}
                      </span>
                      <Tag>priority {chain.recommendation.priority}</Tag>
                      <StatusPill
                        status={chain.recommendation.applied ? 'applied' : 'not applied'}
                        tone={chain.recommendation.applied ? 'bad' : 'neutral'}
                      />
                    </div>
                    {chain.recommendation.rationale && (
                      <p className="text-sm leading-relaxed text-ink-dim">
                        {chain.recommendation.rationale}
                      </p>
                    )}
                    {chain.recommendation.required_roles &&
                      chain.recommendation.required_roles.length > 0 && (
                        <p className="text-xs text-ink-faint">
                          required roles:{' '}
                          <span className="mono text-ink-dim">
                            {chain.recommendation.required_roles.join(', ')}
                          </span>
                        </p>
                      )}
                    {chain.recommendation.limitations &&
                      chain.recommendation.limitations.length > 0 && (
                        <ul className="space-y-1 border-t border-edge pt-2.5">
                          {chain.recommendation.limitations.map((limitation) => (
                            <li key={limitation} className="text-xs text-medium/80">
                              {limitation}
                            </li>
                          ))}
                        </ul>
                      )}
                  </div>
                </Panel>
              )}

              {/* Determinism */}
              {chain.determinism && (
                <Panel title="Determinism" subtitle="how this chain was produced">
                  <dl className="space-y-2 p-4 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <dt className="text-ink-faint">deterministic</dt>
                      <dd>
                        <StatusPill
                          status={String(chain.determinism.deterministic)}
                          tone={chain.determinism.deterministic ? 'good' : 'warn'}
                        />
                      </dd>
                    </div>
                    {typeof chain.determinism.order === 'string' && (
                      <div>
                        <dt className="text-ink-faint">ordering</dt>
                        <dd className="mono text-xs text-ink-dim">
                          {chain.determinism.order}
                        </dd>
                      </div>
                    )}
                    {typeof chain.determinism.digest_algorithm === 'string' && (
                      <div>
                        <dt className="text-ink-faint">digest</dt>
                        <dd className="mono text-xs text-ink-dim">
                          {chain.determinism.digest_algorithm}
                        </dd>
                      </div>
                    )}
                    {chain.determinism.reads_wall_clock !== undefined && (
                      <div className="flex items-center justify-between gap-2">
                        <dt className="text-ink-faint">reads wall clock</dt>
                        <dd className="mono text-ink-dim">
                          {String(chain.determinism.reads_wall_clock)}
                        </dd>
                      </div>
                    )}
                  </dl>
                </Panel>
              )}

              <LinkButton
                to={`/assessments/${encodeURIComponent(assessmentId)}`}
                className="w-full"
              >
                Open assessment report →
              </LinkButton>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/**
 * The custody chain records the expected and observed values as facts rather
 * than top-level fields, so read them from the fact list by category prefix.
 */
function ruleFactValue(chain: CustodyExplanation, kind: 'expected' | 'observed'): unknown {
  const candidates = chain.facts.filter((fact) => {
    const id = fact.fact_id
    if (kind === 'expected') return id.startsWith('expected.')
    return id.startsWith('observed.') || id.startsWith('derived.observed')
  })
  if (candidates.length === 1) return candidates[0].value
  if (candidates.length > 1) {
    return candidates.map((fact) => `${fact.label.replace(/^planned /, '')}: ${formatValue(fact.value)}`).join(' · ')
  }
  return null
}

export { ruleFactValue }
