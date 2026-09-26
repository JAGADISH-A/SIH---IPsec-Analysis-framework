import type { ReactNode } from 'react'
import { cx } from '../../lib/cx'
import type { RiskBand } from '../../types/session'
import type { Severity } from '../../types/evidence'

/** Shared, tiny session/finding presentation pieces. */

export const RISK_TONE = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
  informational: 'muted',
  unknown: 'muted',
} as const

const RISK_CLASS: Record<RiskBand, string> = {
  critical: 'border-critical/50 bg-critical-dim text-critical',
  high: 'border-danger/50 bg-danger-dim text-danger',
  medium: 'border-warning/50 bg-warning-dim text-warning',
  low: 'border-info/50 bg-info-dim text-info',
}

export function RiskTag({ band, score, className }: { band: RiskBand; score?: number; className?: string }) {
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide',
        RISK_CLASS[band],
        className,
      )}
    >
      {band}
      {score !== undefined ? <span className="font-mono opacity-80">{score}</span> : null}
    </span>
  )
}

/** Section heading used inside detail pages. */
export function DetailSection({
  title,
  description,
  actions,
  children,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 className="text-[13px] font-semibold tracking-wide text-mist">{title}</h2>
          {description ? <p className="mt-0.5 text-[11px] text-mist-faint">{description}</p> : null}
        </div>
        {actions}
      </div>
      {children}
    </section>
  )
}

export function UnknownValue({ reason }: { reason?: string }) {
  return (
    <span className="text-[12px] text-mist-faint">
      {reason ?? 'Unknown — insufficient evidence in the capture.'}
    </span>
  )
}

export function SeverityLegend({ items }: { items: { severity: Severity; count: number }[] }) {
  return (
    <ul className="flex flex-wrap gap-2">
      {items.map((item) => (
        <li key={item.severity} className="flex items-center gap-1.5 text-[11px] text-mist-dim">
          <span className={cx('size-2 rounded-sm', LEGEND_CLASS[item.severity])} aria-hidden />
          {item.severity} <span className="font-mono text-mist-faint">{item.count}</span>
        </li>
      ))}
    </ul>
  )
}

const LEGEND_CLASS: Record<Severity, string> = {
  critical: 'bg-critical',
  high: 'bg-danger',
  medium: 'bg-warning',
  low: 'bg-info',
  informational: 'bg-mist-faint',
  unknown: 'bg-night-600',
}
