import type { SeverityTone } from '../../types/common'
import { cx } from '../../lib/cx'

export interface StatusDotProps {
  tone?: SeverityTone
  pulse?: boolean
  size?: 'sm' | 'md'
  className?: string
}

const TONE: Record<SeverityTone, string> = {
  accent: 'bg-accent-400',
  info: 'bg-info',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
}

const SIZE = {
  sm: 'size-1.5',
  md: 'size-2',
}

export function StatusDot({ tone = 'info', pulse, size = 'md', className }: StatusDotProps) {
  return (
    <span
      aria-hidden
      className={cx(
        'inline-block shrink-0 rounded-full',
        TONE[tone],
        SIZE[size],
        pulse && 'animate-pulse-dot',
        className,
      )}
    />
  )
}

export interface StatusPillProps {
  tone?: SeverityTone
  label: string
  pulse?: boolean
}

export function StatusPill({ tone = 'info', label, pulse }: StatusPillProps) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-edge bg-night-800 px-2.5 py-1 text-xs font-medium text-mist-dim">
      <StatusDot tone={tone} pulse={pulse} size="sm" />
      {label}
    </span>
  )
}