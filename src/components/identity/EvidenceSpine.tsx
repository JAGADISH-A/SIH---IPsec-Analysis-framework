import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronRight, FileWarning, Fingerprint, ShieldAlert, Waypoints } from 'lucide-react'
import { cx } from '../../lib/cx'
import { ConfidenceBadge } from './ConfidenceLens'
import { DataSourceBadge } from './DataSourceBadge'
import { DATA_SOURCE_LABEL, type EvidenceReference } from '../../types/evidence'
import type { TunnelSpineStep } from '../../types/identity'

/**
 * The Evidence Spine.
 *
 * The chain of reasoning between packets and a conclusion: the exchange, the
 * traffic, the finding, the risk. It exists because a security conclusion
 * without a visible derivation is just an assertion — this makes "how do you
 * know?" answerable in one click, at the same place the conclusion is shown.
 *
 * Steps expand in place. There is no modal and no separate page: the spine is
 * read next to what it explains, and the evidence stays attached to the step
 * that produced it.
 */

const KIND_ICON: Record<TunnelSpineStep['kind'], typeof Waypoints> = {
  exchange: Waypoints,
  traffic: Fingerprint,
  finding: FileWarning,
  risk: ShieldAlert,
}

const KIND_CLASS: Record<TunnelSpineStep['kind'], string> = {
  exchange: 'border-accent-400/60 bg-accent-dim text-accent-300',
  traffic: 'border-info/60 bg-info-dim text-info',
  finding: 'border-warning/60 bg-warning-dim text-warning',
  risk: 'border-danger/60 bg-danger-dim text-danger',
}

/** The artefacts behind one step: packet range, field, rule and reasoning. */
function EvidenceArtefact({ evidence }: { evidence: EvidenceReference }) {
  return (
    <div className="flex flex-col gap-0.5 border-t border-edge pt-1.5">
      <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[10px] text-mist-faint">
        {evidence.packetRange ? <span>Packets {evidence.packetRange}</span> : null}
        {evidence.field ? <span>Field: {evidence.field}</span> : null}
        {evidence.ruleId ? <span>Rule: {evidence.ruleId}</span> : null}
        {evidence.model ? <span>Model: {evidence.model}</span> : null}
      </span>
      <span className="text-[11px] text-mist-dim">{evidence.explanation}</span>
      <span className="flex items-center gap-1.5">
        <DataSourceBadge source={evidence.source} />
        <span className="font-mono text-[10.5px] text-mist-faint">Value: {evidence.rawValue}</span>
      </span>
    </div>
  )
}

export function EvidenceSpine({
  steps,
  className,
  emptyLabel = 'No evidence chain is available for this tunnel.',
}: {
  steps: TunnelSpineStep[]
  className?: string
  emptyLabel?: string
}) {
  const [openId, setOpenId] = useState<string | null>(null)

  if (steps.length === 0) {
    return <p className={cx('text-[11.5px] text-mist-faint', className)}>{emptyLabel}</p>
  }

  return (
    <ol className={cx('flex flex-col', className)}>
      {steps.map((step, index) => {
        const Icon = KIND_ICON[step.kind]
        const last = index === steps.length - 1
        const open = openId === step.id

        return (
          <li key={step.id} className="flex gap-3">
            <div className="flex flex-col items-center">
              <span
                className={cx(
                  'flex size-5 shrink-0 items-center justify-center rounded-full border',
                  KIND_CLASS[step.kind],
                  open && 'ring-2 ring-accent-400/40',
                )}
                aria-hidden
              >
                <Icon className="size-3" />
              </span>
              {!last ? <span className="w-px flex-1 bg-edge-strong" aria-hidden /> : null}
            </div>

            <div className={cx('min-w-0 flex-1', last ? 'pb-0' : 'pb-3')}>
              <button
                type="button"
                onClick={() => setOpenId(open ? null : step.id)}
                aria-expanded={open}
                className="group flex w-full items-start gap-2 rounded text-left hover:bg-night-800/60"
              >
                <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <span className="flex flex-wrap items-center gap-1.5">
                    <span className="truncate text-[12px] font-medium text-mist">{step.label}</span>
                    <span className="text-[9.5px] font-semibold uppercase tracking-[0.07em] text-mist-faint">
                      {step.kind}
                    </span>
                    <DataSourceBadge source={step.state} />
                    {step.confidence !== null ? <ConfidenceBadge confidence={step.confidence} prefix="" /> : null}
                  </span>
                  <span className="text-[11.5px] text-mist-dim">{step.detail}</span>
                </span>
                <ChevronRight
                  className={cx(
                    'mt-0.5 size-3.5 shrink-0 text-mist-faint transition-transform',
                    open && 'rotate-90',
                  )}
                  aria-hidden
                />
              </button>

              {open ? (
                <div className="mt-1.5 flex flex-col gap-2 rounded border border-edge bg-night-800/60 px-2.5 py-2">
                  <span className="font-mono text-[10px] uppercase tracking-wide text-mist-faint">
                    {step.packetRange ? `Packets ${step.packetRange}` : DATA_SOURCE_LABEL[step.state]}
                  </span>
                  {step.evidence.length === 0 ? (
                    <span className="text-[11px] text-mist-faint">
                      No individual evidence record is attached to this step.
                    </span>
                  ) : (
                    step.evidence.map((evidence) => <EvidenceArtefact key={evidence.id} evidence={evidence} />)
                  )}
                  {step.linkTo ? (
                    <Link
                      to={step.linkTo}
                      className="mt-0.5 inline-flex w-fit items-center gap-1 text-[11px] text-accent-300 hover:underline"
                    >
                      Open the record this step refers to
                      <ChevronRight className="size-3" aria-hidden />
                    </Link>
                  ) : null}
                </div>
              ) : null}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
