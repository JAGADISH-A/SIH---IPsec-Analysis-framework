import type { HTMLAttributes, ReactNode } from 'react'
import { cx } from '../../lib/cx'

export interface PanelProps extends HTMLAttributes<HTMLDivElement> {
  raised?: boolean
  padded?: boolean
  flush?: boolean
}

export function Panel({ raised, padded, flush, className, children, ...rest }: PanelProps) {
  return (
    <div
      className={cx(
        raised ? 'panel-raised' : 'panel',
        !flush && 'overflow-hidden',
        className,
      )}
      {...rest}
    >
      {padded ? <div className="p-4">{children}</div> : children}
    </div>
  )
}

export interface PanelHeaderProps {
  title: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  className?: string
}

export function PanelHeader({ title, subtitle, actions, className }: PanelHeaderProps) {
  return (
    <div className={cx('panel-header', className)}>
      <div className="flex min-w-0 flex-col gap-0.5">
        <div className="panel-title">{title}</div>
        {subtitle ? <div className="truncate text-xs text-mist-faint">{subtitle}</div> : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  )
}