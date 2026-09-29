import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { severityStyle } from '@/lib/format'

/* ------------------------------------------------------------------ panel */

export function Panel({
  title,
  subtitle,
  action,
  className = '',
  bodyClassName = '',
  children,
}: {
  title?: ReactNode
  subtitle?: ReactNode
  action?: ReactNode
  className?: string
  bodyClassName?: string
  children: ReactNode
}) {
  return (
    <section className={`panel overflow-hidden ${className}`}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 border-b border-edge-soft px-4 py-3">
          <div className="min-w-0">
            {title && <h2 className="panel-title">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-ink-faint">{subtitle}</p>}
          </div>
          {action && <div className="shrink-0">{action}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  )
}

/**
 * A panel with no title bar, for content that supplies its own heading. Used
 * where a section needs a different internal structure than a title/subtitle
 * pair allows.
 */
export function PlainPanel({
  className = '',
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return <section className={`panel ${className}`}>{children}</section>
}

/* ------------------------------------------------------------------ badge */

/**
 * Severity, as a tinted chip. Colour is the primary signal and the word is
 * always present too, so the meaning survives greyscale printing, colour
 * blindness and a glance.
 */
export function SeverityBadge({
  severity,
  size = 'md',
}: {
  severity: string | null | undefined
  size?: 'sm' | 'md'
}) {
  const style = severityStyle(severity)
  const label = (severity ?? 'UNRATED').toUpperCase()
  const sizing = size === 'sm' ? 'px-1.5 py-px text-2xs' : 'px-2 py-0.5 text-xs'
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded font-semibold ${style.bg} ${style.text} ${sizing} ring-1 ring-inset ${style.border}`}
    >
      {label}
    </span>
  )
}

export function StatusPill({
  status,
  label,
  tone = 'neutral',
}: {
  status: string
  label?: string
  tone?: 'neutral' | 'good' | 'warn' | 'bad' | 'info'
}) {
  const tones: Record<string, string> = {
    neutral: 'bg-panel-3 text-ink-dim ring-1 ring-inset ring-edge',
    good: 'bg-good/8 text-good ring-1 ring-inset ring-good/25',
    warn: 'bg-medium/10 text-medium ring-1 ring-inset ring-medium/25',
    bad: 'bg-critical/8 text-critical ring-1 ring-inset ring-critical/25',
    info: 'bg-sentinel/8 text-sentinel ring-1 ring-inset ring-sentinel/25',
  }
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${tones[tone]}`}
    >
      {label ?? status}
    </span>
  )
}

/** Neutral metadata chip. The workhorse label for ids, versions and modes. */
export function Tag({
  children,
  tone = 'neutral',
  className = '',
}: {
  children: ReactNode
  /** A tag that marks state rather than a value gets a colour. */
  tone?: 'neutral' | 'accent' | 'good' | 'warn' | 'bad'
  className?: string
}) {
  const TONES: Record<string, string> = {
    neutral: 'bg-panel-3 text-ink-dim',
    accent: 'bg-sentinel/10 text-sentinel',
    good: 'bg-good/10 text-good',
    warn: 'bg-medium/10 text-medium',
    bad: 'bg-critical/10 text-critical',
  }
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium ${TONES[tone]} ${className}`}
    >
      {children}
    </span>
  )
}

/* ------------------------------------------------------------- data pieces */

/**
 * A labelled value. `label` is subordinate metadata, so it is set small and in
 * the muted ink; the value carries the visual weight.
 */
export function KeyValue({
  label,
  value,
  mono = false,
  className = '',
}: {
  label: ReactNode
  value: ReactNode
  mono?: boolean
  className?: string
}) {
  return (
    <div className={`flex flex-col gap-0.5 ${className}`}>
      <dt className="label">{label}</dt>
      <dd className={`break-words text-base text-ink ${mono ? 'mono text-xs' : ''}`}>
        {value ?? '—'}
      </dd>
    </div>
  )
}

/**
 * A single figure with a caption. The number is set in tabular mono at a size
 * that reads as data rather than as a headline.
 */
export function Metric({
  label,
  value,
  hint,
}: {
  label: ReactNode
  value: ReactNode
  hint?: ReactNode
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="label">{label}</span>
      <span className="tnum text-xl font-semibold leading-tight tracking-tight text-ink">
        {value}
      </span>
      {hint && <span className="text-xs text-ink-faint">{hint}</span>}
    </div>
  )
}

/**
 * A truncated digest with the full value on hover. Rendered as a quiet chip
 * rather than the old glowing monospace token, because digests are supporting
 * evidence, not the subject of the screen.
 */
export function HashChip({
  hash,
  title,
}: {
  hash: string | null | undefined
  title?: string
}) {
  if (!hash) return <span className="text-ink-faint">—</span>
  return (
    <span
      title={title ?? hash}
      className="mono inline-flex cursor-help items-center rounded bg-panel-3 px-1.5 py-0.5 text-2xs text-ink-dim"
    >
      {hash.slice(0, 12)}
      {hash.length > 12 && <span className="text-ink-faint">…</span>}
    </span>
  )
}

export function Prose({ children }: { children: ReactNode }) {
  return (
    <p className="whitespace-pre-line text-base leading-relaxed text-ink-dim">{children}</p>
  )
}

/* ---------------------------------------------------------------- actions */

const BUTTON_BASE =
  'inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-base font-medium transition-colors disabled:pointer-events-none disabled:opacity-50'

const BUTTON_VARIANT: Record<'primary' | 'secondary' | 'ghost' | 'danger', string> = {
  // The accent is reserved for the one action a screen wants you to take. The
  // fill uses the deep step so white text clears contrast on the dark surface.
  primary: 'bg-sentinel-deep text-white hover:bg-sentinel',
  secondary: 'border border-edge bg-panel text-ink hover:bg-panel-2',
  ghost: 'text-ink-dim hover:bg-panel-3 hover:text-ink',
  danger: 'border border-critical/30 bg-critical/8 text-critical hover:bg-critical/15',
}

export function LinkButton({
  to,
  href,
  external,
  children,
  variant = 'secondary',
  className = '',
}: {
  /** Internal route. */
  to?: string
  /** External URL; renders a real anchor so middle-click and copy-link work. */
  href?: string
  external?: boolean
  children: ReactNode
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  className?: string
}) {
  const classNames = `${BUTTON_BASE} ${BUTTON_VARIANT[variant]} ${className}`
  if (href) {
    return (
      <a
        href={href}
        className={classNames}
        {...(external ? { target: '_blank', rel: 'noreferrer' } : {})}
      >
        {children}
      </a>
    )
  }
  return (
    <Link to={to ?? '/'} className={classNames}>
      {children}
    </Link>
  )
}

export function Button({
  children,
  onClick,
  variant = 'primary',
  type = 'button',
  disabled = false,
  className = '',
}: {
  children: ReactNode
  onClick?: () => void
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
  type?: 'button' | 'submit'
  disabled?: boolean
  className?: string
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`${BUTTON_BASE} ${BUTTON_VARIANT[variant]} ${className}`}
    >
      {children}
    </button>
  )
}

/** A muted inline link, for "view all →" style affordances. */
export function TextLink({
  to,
  children,
  className = '',
}: {
  to: string
  children: ReactNode
  className?: string
}) {
  return (
    <Link
      to={to}
      className={`text-sm font-medium text-sentinel transition-colors hover:text-ink ${className}`}
    >
      {children}
    </Link>
  )
}

/* -------------------------------------------------------------- data cell */

export function DataCell({ children, mono = false }: { children: ReactNode; mono?: boolean }) {
  return (
    <span
      className={`block truncate text-base text-ink ${mono ? 'mono text-xs text-ink-dim' : ''}`}
    >
      {children}
    </span>
  )
}
