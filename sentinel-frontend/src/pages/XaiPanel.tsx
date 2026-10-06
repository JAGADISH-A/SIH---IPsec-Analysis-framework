import { Panel, Tag, Prose, StatusPill, SeverityBadge } from '@/components/ui'
import { IdRow, ProvenanceDetails } from '@/components/kit'
import { acronymLabel } from '@/lib/labels'
import { EmptyState } from '@/components/states'
import { formatNumber, humanize } from '@/lib/format'
import type { AssessmentBundle, Severity } from '@/types'

/**
 * The assessment-scoped explainability view.
 *
 * Authority note rendered prominently in the UI: the deterministic risk engine
 * produced the findings and the score. This layer describes them and nothing
 * more — it cannot add, re-score, suppress or override a finding.
 */
export function XaiPanel({ bundle }: { bundle: AssessmentBundle }) {
  const xai = bundle.xai
  const summary = xai?.summary ?? {}
  const score = xai?.score_explanation
  const metadata = xai?.metadata ?? {}
  const inputSummary = (metadata.input_summary ?? {}) as Record<string, unknown>
  const unknownHandling = (metadata.unknown_handling ?? {}) as Record<string, boolean>
  const evidencePolicy = (metadata.evidence_policy ?? {}) as Record<string, unknown>

  const findingExplanations = xai?.finding_explanations ?? []
  const mlExplanations = xai?.ml_explanations ?? []
  const unknownExplanations = xai?.unknown_explanations ?? []
  const naExplanations = xai?.not_applicable_explanations ?? []

  return (
    <div className="space-y-4">
      {/* Authority banner */}
      <div className="panel border-sentinel/25 bg-sentinel/[0.04] p-4">
        <div className="flex items-start gap-2.5">
          <span
            className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-sentinel/40 text-sentinel"
            aria-hidden="true"
          >
            <svg viewBox="0 0 16 16" className="h-3 w-3" fill="none">
              <circle cx="8" cy="8" r="6.2" stroke="currentColor" strokeWidth="1.3" />
              <path
                d="M8 7.2v4M8 4.9h.01"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
              />
            </svg>
          </span>
          <div>
            <h3 className="text-sm font-semibold text-sentinel">
              Explanatory layer — not a decision maker
            </h3>
            <p className="mt-1 text-sm leading-relaxed text-ink-dim">
              {summary.overall_explanation ??
                'The explainability engine renders the deterministic risk assessment. It derives no new vulnerability, changes no score, and cannot override an authoritative result.'}
            </p>
          </div>
        </div>
      </div>

      {/* Explanation counters */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        {[
          { label: 'Finding explanations', value: summary.finding_explanations ?? findingExplanations.length, tone: 'text-sentinel' },
          { label: 'ML explanations', value: summary.ml_explanations ?? mlExplanations.length, tone: 'text-low' },
          { label: 'Unknown (evidence gaps)', value: summary.unknown_explanations ?? unknownExplanations.length, tone: 'text-ink-dim' },
          { label: 'Not applicable', value: summary.not_applicable_explanations ?? naExplanations.length, tone: 'text-ink-dim' },
          { label: 'Evidence refs', value: summary.evidence_refs ?? 0, tone: 'text-good' },
        ].map((item) => (
          <div key={item.label} className="panel p-3">
            <p className="label text-ink-faint">{item.label}</p>
            <p className={`mono tnum mt-1 text-2xl leading-none ${item.tone}`}>
              {formatNumber(item.value)}
            </p>
          </div>
        ))}
      </div>

      {/* Score explanation */}
      {score && (
        <Panel
          title="Score Explanation"
          subtitle={`how the risk engine arrived at ${score.score}`}
        >
          <div className="space-y-3 p-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className="mono tnum text-3xl font-semibold text-ink">{score.score}</span>
              <SeverityBadge severity={score.severity as Severity} />
              {Array.isArray(score.severity_band) && (
                <span className="mono text-xs text-ink-faint">
                  band {String(score.severity_band[0])} {String(score.severity_band[1])}–
                  {String(score.severity_band[2])}
                </span>
              )}
            </div>
            <Prose>{score.explanation}</Prose>
            <ProvenanceDetails title="Score provenance">
              <IdRow label="Producer" value={score.provenance} title={score.provenance} />
              <IdRow
                label="Risk policy"
                value={score.risk_policy_version}
                title={score.risk_policy_version}
              />
              <IdRow label="Raw sum" value={String(score.raw_sum)} title={String(score.raw_sum)} />
            </ProvenanceDetails>
            {score.contributions?.length > 0 && (
              <div className="overflow-x-auto border-t border-edge pt-3">
                <table className="data-table min-w-[520px]">
                  <thead>
                    <tr className="text-left">
                      {['Finding', 'Rule', 'Category', 'Severity', 'Weight', 'Added'].map((heading) => (
                        <th
                          key={heading}
                          className="pb-1.5 label text-ink-faint"
                        >
                          {heading}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {score.contributions.map((contribution) => (
                      <tr key={contribution.finding_id} className="border-t border-edge-soft">
                        <td className="py-1.5 mono text-xs text-ink">
                          {contribution.finding_id}
                        </td>
                        <td className="py-1.5 mono text-xs text-ink-faint">
                          {contribution.rule_id}
                        </td>
                        <td className="py-1.5 text-xs text-ink-dim">
                          {humanize(contribution.category)}
                        </td>
                        <td className="py-1.5 text-xs text-ink-dim">
                          {contribution.severity}
                        </td>
                        <td className="py-1.5 mono tnum text-xs text-ink-dim">
                          {contribution.weight}
                        </td>
                        <td className="py-1.5 mono tnum text-xs text-ink">
                          +{contribution.added}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* Finding explanations */}
      <Panel
        title="Finding Explanations"
        subtitle="one narrative per risk finding"
        bodyClassName="divide-y divide-edge"
      >
        {findingExplanations.length === 0 ? (
          <EmptyState
            title="No finding explanations"
            description="The risk engine raised no finding for this assessment."
            icon="check"
          />
        ) : (
          findingExplanations.map((explanation) => (
            <article key={explanation.finding_id} className="p-4">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={explanation.severity as Severity} size="sm" />
                <span className="mono text-xs text-ink-faint">
                  {explanation.finding_id}
                </span>
                <Tag className="ml-auto">{explanation.provenance}</Tag>
              </div>
              <h3 className="mt-1.5 text-base font-medium text-ink">{explanation.title}</h3>

              <div className="mt-3 grid gap-3 lg:grid-cols-2">
                <div className="rounded-md border border-sentinel/20 bg-sentinel/[0.04] p-3">
                  <p className="label text-sentinel/80">
                    Why it was detected
                  </p>
                  <p className="mt-1 text-sm leading-relaxed text-ink-dim">
                    {explanation.why_it_was_flagged}
                  </p>
                </div>
                <div className="rounded-md border border-edge bg-panel-2 p-3">
                  <p className="label text-ink-faint">
                    Expected → observed
                  </p>
                  <div className="mono mt-1.5 flex flex-wrap items-center gap-2 text-sm">
                    <span className="rounded bg-sentinel/10 px-1.5 py-0.5 text-sentinel">
                      {String(explanation.expected ?? '—')}
                    </span>
                    <span className="text-ink-faint">→</span>
                    <span className="rounded bg-critical/10 px-1.5 py-0.5 text-critical">
                      {String(explanation.observed ?? '—')}
                    </span>
                    <span className="text-ink-faint">({explanation.related_variable})</span>
                  </div>
                  <p className="mt-1.5 text-xs text-ink-faint">{explanation.reason}</p>
                </div>
              </div>

              <p className="mt-3 text-sm leading-relaxed text-ink-dim">
                {explanation.description}
              </p>

              <div className="mt-3 flex flex-wrap items-center gap-1.5">
                {explanation.explanation_categories?.map((category) => (
                  <Tag key={category}>{category}</Tag>
                ))}
                {explanation.evidence_refs?.length > 0 && (
                  <Tag className="border-good/30 bg-good/5 text-good">
                    {explanation.evidence_refs.length} evidence ref
                    {explanation.evidence_refs.length === 1 ? '' : 's'}
                  </Tag>
                )}
              </div>

              {explanation.contributing_factors && explanation.contributing_factors.length > 0 && (
                <ul className="mt-2.5 space-y-1">
                  {explanation.contributing_factors.map((factor) => (
                    <li key={factor} className="flex items-start gap-2 text-xs text-ink-faint">
                      <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-sentinel/60" aria-hidden="true" />
                      {factor}
                    </li>
                  ))}
                </ul>
              )}

              {explanation.limitations && explanation.limitations.length > 0 && (
                <div className="mt-3 rounded-md border border-medium/25 bg-medium/[0.05] p-2.5">
                  <p className="label text-medium/80">
                    Limitations
                  </p>
                  <ul className="mt-1 space-y-1">
                    {explanation.limitations.map((limitation) => (
                      <li key={limitation} className="text-xs leading-snug text-ink-dim">
                        {limitation}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </article>
          ))
        )}
      </Panel>

      {/* ML explanations */}
      {mlExplanations.length > 0 && (
        <Panel
          title="ML Explanations"
          subtitle="model-derived evidence, never an authoritative protocol observation"
          bodyClassName="divide-y divide-edge"
        >
          {mlExplanations.map((explanation, index) => (
            <article key={`${explanation.model_version}-${index}`} className="p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Tag className="border-low/30 bg-low/5 text-low">
                  {acronymLabel(explanation.explanation_kind)}
                </Tag>
                <ProvenanceDetails title="Model provenance">
                  <IdRow
                    label="Model version"
                    value={explanation.model_version ?? 'unknown model'}
                    title={explanation.model_version ?? undefined}
                  />
                </ProvenanceDetails>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-ink-dim">
                {explanation.explanation}
              </p>
              {explanation.limitations?.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {explanation.limitations.map((limitation) => (
                    <li key={limitation} className="text-xs text-medium/80">
                      {limitation}
                    </li>
                  ))}
                </ul>
              )}
            </article>
          ))}
        </Panel>
      )}

      {/* Evidence-gap explanations */}
      {(unknownExplanations.length > 0 || naExplanations.length > 0) && (
        <div className="grid gap-4 lg:grid-cols-2">
          <VariableExplanationList
            title="Unknown Variables"
            subtitle="evidence gaps — not vulnerabilities"
            items={unknownExplanations}
            tone="neutral"
          />
          <VariableExplanationList
            title="Not Applicable Variables"
            subtitle="out of scope for the evaluated rule"
            items={naExplanations}
            tone="neutral"
          />
        </div>
      )}

      {/* Engine metadata */}
      {(Object.keys(inputSummary).length > 0 ||
        Object.keys(unknownHandling).length > 0 ||
        Object.keys(evidencePolicy).length > 0) && (
        <Panel
          title="Explainability Engine Metadata"
          subtitle={`version ${metadata.explainability_engine_version ?? '—'}`}
        >
          <div className="space-y-3 p-4">
            {Object.keys(inputSummary).length > 0 && (
              <div>
                <p className="mb-1.5 label text-ink-faint">
                  Inputs supplied
                </p>
                <ul className="flex flex-wrap gap-1.5">
                  {Object.entries(inputSummary).map(([key, value]) => (
                    <li key={key}>
                      <Tag>
                        {humanize(key)}{' '}
                        <span className="mono text-ink-dim">{String(value)}</span>
                      </Tag>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {Object.keys(unknownHandling).length > 0 && (
              <div>
                <p className="mb-1.5 label text-ink-faint">
                  Unknown handling
                </p>
                <ul className="space-y-1">
                  {Object.entries(unknownHandling).map(([key, value]) => (
                    <li key={key} className="flex items-center gap-2 text-sm">
                      <StatusPill
                        status={value ? 'yes' : 'no'}
                        tone={value ? 'warn' : 'good'}
                        label={value ? 'yes' : 'no'}
                      />
                      <span className="text-ink-dim">{humanize(key)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {evidencePolicy.fabricates_references !== undefined && (
              <div>
                <p className="mb-1.5 label text-ink-faint">
                  Evidence policy
                </p>
                <p className="text-sm text-ink-dim">
                  Fabricates references:{' '}
                  <StatusPill
                    status={evidencePolicy.fabricates_references ? 'yes' : 'no'}
                    tone={evidencePolicy.fabricates_references ? 'bad' : 'good'}
                  />
                </p>
                {typeof evidencePolicy.note === 'string' && (
                  <p className="mt-1.5 text-xs leading-relaxed text-ink-faint">
                    {evidencePolicy.note}
                  </p>
                )}
              </div>
            )}
          </div>
        </Panel>
      )}
    </div>
  )
}

function VariableExplanationList({
  title,
  subtitle,
  items,
  tone,
}: {
  title: string
  subtitle: string
  items: Record<string, unknown>[]
  tone: 'neutral' | 'warn'
}) {
  return (
    <Panel title={title} subtitle={subtitle}>
      {items.length === 0 ? (
        <EmptyState title="None recorded" />
      ) : (
        <ul className="max-h-[340px] divide-y divide-edge/60 overflow-y-auto">
          {items.map((item, index) => {
            const variable = String(item.variable ?? item.name ?? `item-${index}`)
            const explanation =
              typeof item.explanation === 'string'
                ? item.explanation
                : typeof item.reason === 'string'
                  ? item.reason
                  : typeof item.detail === 'string'
                    ? item.detail
                    : null
            return (
              <li key={`${variable}-${index}`} className="px-4 py-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono text-xs text-ink">{variable}</span>
                  {Boolean(item.status) && (
                    <span
                      className={`rounded border px-1.5 py-0.5 text-xs ${
                        tone === 'warn'
                          ? 'border-medium/30 bg-medium/10 text-medium'
                          : 'border-edge text-ink-faint'
                      }`}
                    >
                      {String(item.status)}
                    </span>
                  )}
                </div>
                {explanation && (
                  <p className="mt-1 text-xs leading-snug text-ink-faint">{explanation}</p>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </Panel>
  )
}
