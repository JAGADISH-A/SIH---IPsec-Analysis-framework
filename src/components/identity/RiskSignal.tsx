import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { CircleAlert, HelpCircle, Info, Minus, OctagonAlert, TriangleAlert } from 'lucide-react'
import { cx } from '../../lib/cx'
import { SEVERITY_LABEL, type Severity } from '../../types/evidence'
import { ConfidenceBadge } from './ConfidenceLens'

/**
 * The Risk Signal.
 *
 * Severity is never communicated by colour alone: every signal carries an icon
 * and a word, so it survives a monochrome screen, a colour-blind reader and a
 * printed report. Colour is the third channel, not the first.
 *
 * A signal is a conclusion, so it is also a link: clicking one takes the reader
 * to the finding and the evidence behind it rather than leaving the claim
 * unexplained.
 */

const SIGNAL_ICON: Record<Severity, typeof OctagonAlert> = {
  critical: OctagonAlert,
  high: TriangleAlert,
  medium: CircleAlert,
  low: Info,
  informational: Minus,
  unknown: HelpCircle,
}

const SIGNAL_CLASS: Record<Severity, string> = {
  critical: 'border-critical/50 bg-critical-dim text-critical',
  high: 'border-danger/50 bg-danger-dim text-danger',
  medium: 'border-warning/50 bg-warning-dim text-warning',
  low: 'border-info/50 bg-info-dim text-info',
  informational: 'border-edge bg-night-800 text-mist-dim',
  unknown: 'border-edge border-dashed bg-night-800 text-mist-faint',
}

export interface RiskSignalProps {
  severity: Severity
  /** Overrides the severity word, e.g. a short cause like "PFS disabled". */
  label?: string
  /** Confidence in the risk assessment itself. */
  confidence?: number | null
  /** Opens the finding that carries this risk. */
  findingId?: string
  onSelect?: () => void
  className?: string
  children?: ReactNode
}

export function RiskSignal({
  severity,
  label,
  confidence,
  findingId,
  onSelect,
  className,
  children,
}: RiskSignalProps) {
  const Icon = SIGNAL_ICON[severity]
  const word = SEVERITY_LABEL[severity]
  const body = (
    <>
      <Icon className="size-3 shrink-0" aria-hidden />
      <span className="font-semibold uppercase tracking-wide">{word}</span>
      {label ? <span className="truncate font-normal normal-case text-mist-dim">{label}</span> : null}
    </>
  )
  const interactive = Boolean(findingId || onSelect)
  const classes = cx(
    'inline-flex max-w-full items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10.5px]',
    SIGNAL_CLASS[severity],
    interactive && 'transition-colors hover:brightness-125 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-400',
    className,
  )

  const title = label
    ? `${word} risk — ${label}. Select to inspect the finding and its evidence.`
    : `${word} risk. Select to inspect the finding and its evidence.`

  const signal =
    findingId && !onSelect ? (
      <Link to={`/findings/${findingId}`} className={classes} title={title}>
        {body}
      </Link>
    ) : onSelect ? (
      <button type="button" onClick={onSelect} className={classes} title={title}>
        {body}
      </button>
    ) : (
      <span className={classes} title={title}>
        {body}
      </span>
    )

  if (confidence === undefined) return signal

  return (
    <span className="inline-flex min-w-0 items-center gap-1.5">
      {signal}
      {children}
      {confidence !== null ? <ConfidenceBadge confidence={confidence} prefix="" /> : null}
    </span>
  )
}
