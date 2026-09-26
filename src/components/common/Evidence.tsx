import type { ReactNode } from 'react'
import { HelpCircle, Lock } from 'lucide-react'
import { cx } from '../../lib/cx'
import {
  DATA_SOURCE_DESCRIPTION,
  DATA_SOURCE_LABEL,
  SEVERITY_LABEL,
  UNKNOWN_LABEL,
  type DataSource,
  type ProtocolValue,
  type Severity,
} from '../../types/evidence'
import { Badge, type BadgeTone } from './Badge'
import { Tooltip } from './Tooltip'

/* ------------------------------------------------------------------ */
/* Severity                                                             */
/* ------------------------------------------------------------------ */

const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
  informational: 'muted',
  unknown: 'muted',
}

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'border-critical/50 bg-critical-dim text-critical',
  high: 'border-danger/50 bg-danger-dim text-danger',
  medium: 'border-warning/50 bg-warning-dim text-warning',
  low: 'border-info/50 bg-info-dim text-info',
  informational: 'border-edge bg-night-800 text-mist-dim',
  unknown: 'border-edge border-dashed bg-night-800 text-mist-faint',
}

/** Severity pill for the platform's six-rung ladder, including Unknown. */
export function SeverityTag({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide',
        SEVERITY_CLASS[severity],
        className,
      )}
    >
      {severity === 'unknown' ? <HelpCircle className="size-3" aria-hidden /> : null}
      {SEVERITY_LABEL[severity]}
    </span>
  )
}

export { SEVERITY_TONE }

/* ------------------------------------------------------------------ */
/* Confidence                                                           */
/* ------------------------------------------------------------------ */

export type ConfidenceBand = 'high' | 'medium' | 'low' | 'unknown'

export function confidenceBand(confidence: number | null): ConfidenceBand {
  if (confidence === null) return 'unknown'
  if (confidence >= 0.9) return 'high'
  if (confidence >= 0.75) return 'medium'
  if (confidence >= 0.5) return 'low'
  return 'unknown'
}

const CONFIDENCE_TONE: Record<ConfidenceBand, BadgeTone> = {
  high: 'success',
  medium: 'info',
  low: 'warning',
  unknown: 'muted',
}

const CONFIDENCE_LABEL: Record<ConfidenceBand, string> = {
  high: 'High confidence',
  medium: 'Medium confidence',
  low: 'Low confidence',
  unknown: 'Confidence unknown',
}

/**
 * Confidence badge.
 *
 * A null confidence renders as an explicit "Unknown", never as 0% — an absent
 * estimate and a zero estimate mean very different things.
 */
export function ConfidenceTag({
  confidence,
  className,
  showLabel,
}: {
  confidence: number | null
  className?: string
  showLabel?: boolean
}) {
  const band = confidenceBand(confidence)
  const text =
    band === 'unknown'
      ? 'Unknown'
      : `${Math.round((confidence ?? 0) * 100)}%`
  return (
    <Tooltip
      label={
        band === 'unknown'
          ? 'No confidence estimate was available for this value.'
          : `${CONFIDENCE_LABEL[band]} — ${Math.round((confidence ?? 0) * 100)}%`
      }
    >
      <Badge tone={CONFIDENCE_TONE[band]} className={cx('font-mono', className)}>
        {showLabel ? `${CONFIDENCE_LABEL[band]}: ${text}` : `AI ${text}`}
      </Badge>
    </Tooltip>
  )
}

/** Thin confidence bar for detail panels. */
export function ConfidenceMeter({ confidence, className }: { confidence: number | null; className?: string }) {
  const band = confidenceBand(confidence)
  const width = confidence === null ? 0 : Math.round(Math.min(1, Math.max(0, confidence)) * 100)
  const bar =
    band === 'high' ? 'bg-success' : band === 'medium' ? 'bg-info' : band === 'low' ? 'bg-warning' : 'bg-mist-faint'
  return (
    <div className={cx('flex items-center gap-2', className)}>
      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-night-700"
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={confidence === null ? undefined : width}
        aria-label="Confidence"
      >
        <div className={cx('h-full rounded-full', bar)} style={{ width: `${width}%` }} />
      </div>
      <span className="w-10 shrink-0 text-right font-mono text-[11px] text-mist-dim">
        {confidence === null ? '—' : `${width}%`}
      </span>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Provenance                                                           */
/* ------------------------------------------------------------------ */

const SOURCE_TONE: Record<DataSource, BadgeTone> = {
  observed: 'success',
  inferred: 'accent',
  configured: 'info',
  calculated: 'info',
  unknown: 'muted',
}

export function SourceTag({ source, className }: { source: DataSource; className?: string }) {
  return (
    <Tooltip label={DATA_SOURCE_DESCRIPTION[source]}>
      <Badge tone={SOURCE_TONE[source]} className={className}>
        {DATA_SOURCE_LABEL[source]}
      </Badge>
    </Tooltip>
  )
}

/* ------------------------------------------------------------------ */
/* Protocol values                                                      */
/* ------------------------------------------------------------------ */

const STATUS_TONE: Record<ProtocolValue['status'], BadgeTone> = {
  observed: 'success',
  strong: 'success',
  acceptable: 'info',
  warning: 'warning',
  weak: 'danger',
  critical: 'danger',
  unknown: 'muted',
}

/**
 * A single protocol value with its provenance.
 *
 * When the platform does not know the value this renders an explicit
 * "Unknown — insufficient evidence" treatment, which is the whole point of the
 * evidence model: a gap in the data is information, not something to paper over.
 */
export function ProtocolValueDisplay<T>({
  field,
  value,
  format,
  showSource = true,
  className,
}: {
  field?: string
  value: ProtocolValue<T> | null | undefined
  format?: (raw: T) => string
  showSource?: boolean
  className?: string
}) {
  if (!value || value.value === null || value.value === undefined) {
    return (
      <div className={cx('flex flex-col gap-0.5', className)}>
        {field ? <span className="text-[11px] text-mist-faint">{field}</span> : null}
        <span className="inline-flex items-center gap-1.5 text-[13px] text-mist-faint">
          <HelpCircle className="size-3.5" aria-hidden />
          {UNKNOWN_LABEL}
        </span>
        <span className="text-[11px] text-mist-faint">Insufficient evidence in the capture.</span>
      </div>
    )
  }

  const text = format ? format(value.value) : String(value.value)

  return (
    <div className={cx('flex flex-col gap-0.5', className)}>
      {field ? <span className="text-[11px] text-mist-faint">{field}</span> : null}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-[13px] text-mist">{text}</span>
        <Badge tone={STATUS_TONE[value.status]}>{value.status}</Badge>
        {showSource ? <SourceTag source={value.source} /> : null}
        {value.confidence !== null ? <ConfidenceTag confidence={value.confidence} /> : null}
      </div>
      {value.note ? <span className="text-[11px] text-mist-faint">{value.note}</span> : null}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Gating notice                                                        */
/* ------------------------------------------------------------------ */

/**
 * Shown wherever restricted content is withheld. The frontend must never
 * pretend the data does not exist — it says what is gated and why.
 */
export function RestrictedNotice({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <div className={cx('flex items-start gap-2 rounded-lg border border-edge bg-night-800/70 p-3', className)}>
      <Lock className="mt-0.5 size-4 shrink-0 text-mist-faint" aria-hidden />
      <p className="text-xs leading-relaxed text-mist-dim">
        {children ?? 'Access to this content requires an authorised account.'}
      </p>
    </div>
  )
}
