import type { HTMLAttributes, ReactNode } from 'react'
import { cx } from '../../lib/cx'

export interface CardProps extends Omit<HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  footer?: ReactNode
  padded?: boolean
  raised?: boolean
  flush?: boolean
}

/** Content surface: optional header, padded body and footer. */
export function Card({
  title,
  subtitle,
  actions,
  footer,
  padded,
  raised,
  flush,
  className,
  children,
  ...rest
}: CardProps) {
  return (
    <div
      className={cx(
        raised ? 'panel-raised' : 'panel',
        !flush && 'overflow-hidden',
        className,
      )}
      {...rest}
    >
      {title || actions ? (
        <div className="panel-header">
          <div className="flex min-w-0 flex-col gap-0.5">
            {title ? <div className="panel-title">{title}</div> : null}
            {subtitle ? <div className="truncate text-xs text-mist-faint">{subtitle}</div> : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      {padded ? <div className="p-4">{children}</div> : children}
      {footer ? <div className="border-t border-edge px-4 py-2.5">{footer}</div> : null}
    </div>
  )
}