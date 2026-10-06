import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Panel, SeverityBadge, Tag } from '@/components/ui'
import { EmptyState } from '@/components/states'
import { humanize, formatValue, truncate } from '@/lib/format'
import { configTermLabel } from '@/lib/labels'
import type { AssessmentBundle, Finding, Severity } from '@/types'

/**
 * One finding row. The title links to the finding detail view, which renders
 * the custody chain from the XAI endpoint. Nothing here is derived locally —
 * severity, title and description are the risk engine's own output.
 */
function FindingRow({
  finding,
  assessmentId,
}: {
  finding: Finding
  assessmentId: string
}) {
  const mismatch =
    finding.expected_value !== undefined &&
    finding.observed_value !== undefined &&
    String(finding.expected_value) !== String(finding.observed_value)

  return (
    <li className="row-hover border-b border-edge-soft last:border-0">
      <Link
        to={`/findings/${encodeURIComponent(assessmentId)}/${encodeURIComponent(finding.finding_id)}`}
        className="block px-4 py-3"
      >
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity as Severity} size="sm" />
          <span className="mono text-xs text-ink-faint">{finding.finding_id}</span>
          <Tag className="ml-auto">{humanize(finding.category)}</Tag>
        </div>
        <p className="mt-1.5 text-sm font-medium leading-snug text-ink">
          {finding.title}
        </p>
        <p className="mt-1 text-sm leading-relaxed text-ink-faint">
          {truncate(finding.description, 180)}
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
          <span className="text-ink-faint">
            rule <span className="mono text-ink-dim">{finding.rule_id}</span>
          </span>
          <span className="text-ink-faint">
            source <span className="mono text-ink-dim">{finding.source}</span>
          </span>
          {mismatch && (
            <span className="text-ink-faint">
              <span>{configTermLabel(finding.related_variable)}</span>:{' '}
              <span className="mono">{formatValue(finding.expected_value)}</span>{' '}
              →{' '}
              <span className="mono text-critical">{formatValue(finding.observed_value)}</span>
            </span>
          )}
          {finding.evidence_refs && finding.evidence_refs.length > 0 && (
            <span className="text-ink-faint">
              {finding.evidence_refs.length} evidence ref
              {finding.evidence_refs.length === 1 ? '' : 's'}
            </span>
          )}
        </div>
      </Link>
    </li>
  )
}

/**
 * Findings for one assessment, rendered straight from `bundle.risk.findings`
 * so the detail page never needs a second request for its Findings tab.
 */
export function FindingsList({
  bundle,
  title = 'Findings',
  limit,
  action,
}: {
  bundle: AssessmentBundle
  title?: string
  limit?: number
  action?: ReactNode
}) {
  const findings = bundle.risk?.findings ?? []
  const visible = limit ? findings.slice(0, limit) : findings

  return (
    <Panel
      title={title}
      subtitle={`${findings.length} finding${findings.length === 1 ? '' : 's'} from ${bundle.risk?.risk_policy_version ?? 'the risk engine'}`}
      action={action}
    >
      {findings.length === 0 ? (
        <EmptyState
          title="No findings"
          description="The deterministic risk engine raised no finding for this assessment."
          icon="check"
        />
      ) : (
        <ul>
          {visible.map((finding) => (
            <FindingRow
              key={`${finding.finding_id}-${finding.sequence ?? 0}`}
              finding={finding}
              assessmentId={bundle.assessment_id}
            />
          ))}
        </ul>
      )}
    </Panel>
  )
}
