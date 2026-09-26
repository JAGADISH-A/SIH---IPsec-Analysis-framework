import type { HTMLAttributes } from 'react'
import { cx } from '../../lib/cx'
import type { RiskLevel } from '../../types/security'

export interface SeverityBadgeProps extends HTMLAttributes<HTMLSpanElement> {
  severity: RiskLevel | 'none'
}

const STYLES: Record<RiskLevel | 'none', string> = {
  critical: 'bg-critical-dim text-[#ff8b97] border-critical/40',
  high: 'bg-danger-dim text-danger border-danger/40',
  medium: 'bg-warning-dim text-warning border-warning/40',
  low: 'bg-info-dim text-info border-info/40',
  info: 'bg-night-700 text-mist-dim border-edge',
  none: 'bg-night-700 text-mist-faint border-edge',
}

export function SeverityBadge({ severity, className, children, ...rest }: SeverityBadgeProps) {
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1 rounded-full border px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide',
        STYLES[severity],
        className,
      )}
      {...rest}
    >
      {children ?? severity}
    </span>
  )
}