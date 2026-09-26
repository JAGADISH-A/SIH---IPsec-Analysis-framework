import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { cx } from '../../lib/cx'

export interface LauncherPanelProps {
  /** Short, uppercase panel title — a tool label, not a headline. */
  title: string
  icon: LucideIcon
  /** One sentence naming the job the panel does. */
  description?: string
  /** Right-hand side of the header strip: a status, a count, a mode read-out. */
  aside?: ReactNode
  /** Pinned band below the body, so a tall panel reads as header/body/footer. */
  footer?: ReactNode
  bodyClassName?: string
  className?: string
  children: ReactNode
}

/**
 * Frame shared by the launchpad's analysis panels.
 *
 * Four bands — header, description, flexible body, optional footer — because
 * every panel here names its job, holds controls in the body and commits to an
 * action in the footer, and the action must not drift when the body grows.
 * Drawn with the app's own panel tokens so the launchers sit in the same
 * surface as every other page.
 */
export function LauncherPanel({
  title,
  icon: Icon,
  description,
  aside,
  footer,
  bodyClassName,
  className,
  children,
}: LauncherPanelProps) {
  return (
    <section className={cx('flex min-h-0 flex-col rounded-md border border-edge bg-night-900', className)}>
      <header className="flex shrink-0 items-center gap-2 border-b border-edge px-3 py-[7px]">
        <Icon className="size-3.5 shrink-0 text-accent-300" aria-hidden />
        <h2 className="section-title">{title}</h2>
        {aside ? <div className="ml-auto flex min-w-0 items-center gap-2">{aside}</div> : null}
      </header>

      {description ? (
        <p className="shrink-0 px-3 pt-2.5 text-[11.5px] leading-snug text-mist-dim">{description}</p>
      ) : null}

      <div className={cx('flex min-h-0 flex-1 flex-col px-3 pb-3', description ? 'pt-2.5' : 'pt-3', bodyClassName)}>
        {children}
      </div>

      {footer ? (
        <div className="flex shrink-0 flex-wrap items-center gap-2 border-t border-edge px-3 py-2">{footer}</div>
      ) : null}
    </section>
  )
}
