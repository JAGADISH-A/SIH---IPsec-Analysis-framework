import type { HTMLAttributes } from 'react'
import type { SeverityTone } from '../../types/common'
import { cx } from '../../lib/cx'

export type BadgeTone = SeverityTone | 'muted'

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone
  dot?: boolean
  pulse?: boolean
}

const TONE: Record<BadgeTone, string> = {
  accent: 'border-accent-500/40 bg-accent-dim text-accent-300',
  info: 'border-info/40 bg-info-dim text-info',
  success: 'border-success/40 bg-success-dim text-success',
  warning: 'border-warning/40 bg-warning-dim text-warning',
  danger: 'border-danger/40 bg-danger-dim text-danger',
  muted: 'border-edge bg-night-800 text-mist-dim',
}

const DOT: Record<BadgeTone, string> = {
  accent: 'bg-accent-400',
  info: 'bg-info',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
  muted: 'bg-mist-faint',
}

/** Small tonal pill for labels and status. For risk levels use SeverityBadge. */
export function Badge({ tone = 'muted', dot, pulse, className, children, ...rest }: BadgeProps) {
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold tracking-wide',
        TONE[tone],
        className,
      )}
      {...rest}
    >
      {dot ? (
        <span
          aria-hidden
          className={cx('size-1.5 rounded-full', DOT[tone], pulse && 'animate-pulse-dot')}
        />
      ) : null}
      {children}
    </span>
  )
}