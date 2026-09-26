import type { ReactNode } from 'react'
import { cx } from '../../lib/cx'

export interface EmptyStateProps {
  icon?: ReactNode
  title: string
  description?: ReactNode
  action?: ReactNode
  className?: string
}

export function EmptyState({ icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cx('flex flex-col items-center justify-center gap-3 px-6 py-14 text-center', className)}>
      {icon ? (
        <div className="flex size-11 items-center justify-center rounded-lg border border-edge bg-night-800 text-mist-dim">
          {icon}
        </div>
      ) : null}
      <div>
        <div className="text-sm font-medium text-mist">{title}</div>
        {description ? <div className="mt-1 text-xs text-mist-faint">{description}</div> : null}
      </div>
      {action ? <div className="mt-1">{action}</div> : null}
    </div>
  )
}