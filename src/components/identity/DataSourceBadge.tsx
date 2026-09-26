import { HelpCircle } from 'lucide-react'
import { SourceTag } from '../common/Evidence'
import { ConfidenceBadge } from './ConfidenceLens'
import { cx } from '../../lib/cx'
import { UNKNOWN_LABEL, type DataSource, type ProtocolValue } from '../../types/evidence'

/**
 * Provenance display.
 *
 * A value without its origin is an assertion; with it, it is a measurement.
 * `DataSourceBadge` labels how a value was obtained — observed from packets,
 * inferred by a model, configured by the testbed, calculated by the platform,
 * or unknown — and `ProvenanceValue` puts that label next to the value it
 * describes. The distinction is deliberately quiet: a reader should notice
 * provenance when they look for it, not be interrupted by it.
 */

export interface DataSourceBadgeProps {
  source: DataSource
  confidence?: number | null
  className?: string
}

/** Provenance pill, optionally carrying the confidence of the same value. */
export function DataSourceBadge({ source, confidence, className }: DataSourceBadgeProps) {
  if (source === 'unknown' && confidence === undefined) {
    return (
      <span
        className={cx(
          'inline-flex items-center gap-1 rounded-full border border-dashed border-edge px-1.5 py-px text-[10px] text-mist-faint',
          className,
        )}
      >
        <HelpCircle className="size-2.5" aria-hidden />
        Unknown
      </span>
    )
  }

  return (
    <span className={cx('inline-flex items-center gap-1', className)}>
      <SourceTag source={source} />
      {confidence !== undefined ? <ConfidenceBadge confidence={confidence} prefix="" /> : null}
    </span>
  )
}

/**
 * A single value with its provenance and confidence.
 *
 * When the platform does not know the value this renders the explicit unknown
 * treatment — a gap in the data is information, not something to fill in.
 */
export function ProvenanceValue<T>({
  field,
  value,
  format,
  className,
  showConfidence = true,
}: {
  field?: string
  value: ProtocolValue<T> | null | undefined
  format?: (raw: T) => string
  className?: string
  showConfidence?: boolean
}) {
  if (!value || value.value === null || value.value === undefined) {
    return (
      <div className={cx('flex min-w-0 flex-col gap-0.5', className)}>
        {field ? <span className="text-[9.5px] font-semibold uppercase tracking-[0.07em] text-mist-faint">{field}</span> : null}
        <span className="inline-flex items-center gap-1 font-mono text-[12px] text-mist-faint">
          <HelpCircle className="size-3" aria-hidden />
          {UNKNOWN_LABEL}
        </span>
      </div>
    )
  }

  const text = format ? format(value.value) : String(value.value)

  return (
    <div className={cx('flex min-w-0 flex-col gap-0.5', className)}>
      {field ? <span className="text-[9.5px] font-semibold uppercase tracking-[0.07em] text-mist-faint">{field}</span> : null}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="truncate font-mono text-[12px] text-mist" title={text}>
          {text}
        </span>
        <DataSourceBadge source={value.source} />
        {showConfidence && value.confidence !== null ? <ConfidenceBadge confidence={value.confidence} prefix="" /> : null}
      </div>
    </div>
  )
}
