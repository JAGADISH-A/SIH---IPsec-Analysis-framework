import type { ReactNode } from 'react'
import { AlertTriangle, Inbox, RefreshCw } from 'lucide-react'
import { cx } from '../../lib/cx'
import { errorDetail, errorMessage } from '../../services/api/apiClient'
import { Button } from './Button'
import { EmptyState } from './EmptyState'
import { Skeleton } from './Skeleton'

/**
 * Query state wrappers.
 *
 * Every data surface in the product renders exactly one of loading, error or
 * empty, so those treatments are written once here. Errors always expose the
 * operator-readable message and never leak a raw transport string.
 */

export function LoadingPanel({ label = 'Loading', rows = 4, className }: { label?: string; rows?: number; className?: string }) {
  return (
    <div className={cx('flex flex-col gap-2 p-4', className)} role="status" aria-live="polite">
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className={cx('h-8 w-full', index === 0 && 'h-9 w-1/3')} />
      ))}
    </div>
  )
}

export interface ErrorPanelProps {
  error: unknown
  onRetry?: () => void
  title?: string
  className?: string
  compact?: boolean
}

export function ErrorPanel({ error, onRetry, title = 'Could not load this data', className, compact }: ErrorPanelProps) {
  const detail = errorDetail(error)
  return (
    <div
      role="alert"
      className={cx(
        'flex flex-col items-start gap-2 rounded-lg border border-danger/40 bg-danger-dim/40 p-4',
        compact && 'p-3',
        className,
      )}
    >
      <div className="flex items-center gap-2 text-[13px] font-semibold text-danger">
        <AlertTriangle className="size-4" aria-hidden />
        {title}
      </div>
      <p className="text-xs text-mist-dim">{errorMessage(error)}</p>
      {detail ? <p className="font-mono text-[11px] text-mist-faint">Detail: {detail}</p> : null}
      {onRetry ? (
        <Button size="sm" onClick={onRetry}>
          <RefreshCw className="size-3.5" aria-hidden />
          Try again
        </Button>
      ) : null}
    </div>
  )
}

export function EmptyPanel({
  title,
  description,
  action,
  icon,
  className,
}: {
  title: string
  description?: ReactNode
  action?: ReactNode
  icon?: ReactNode
  className?: string
}) {
  return <EmptyState icon={icon ?? <Inbox className="size-5" />} title={title} description={description} action={action} className={className} />
}

export interface QueryBoundaryProps {
  isLoading: boolean
  isError: boolean
  error?: unknown
  onRetry?: () => void
  isEmpty?: boolean
  loadingRows?: number
  emptyTitle?: string
  emptyDescription?: ReactNode
  emptyAction?: ReactNode
  children: ReactNode
  className?: string
}

/**
 * Renders the loading, error or empty state, and only then the content — so a
 * page can never flash stale rows while a refetch is in flight.
 */
export function QueryBoundary({
  isLoading,
  isError,
  error,
  onRetry,
  isEmpty,
  loadingRows,
  emptyTitle = 'Nothing to show',
  emptyDescription,
  emptyAction,
  children,
  className,
}: QueryBoundaryProps) {
  if (isLoading) return <LoadingPanel rows={loadingRows} className={className} />
  if (isError) return <ErrorPanel error={error} onRetry={onRetry} className={className} />
  if (isEmpty) {
    return <EmptyPanel title={emptyTitle} description={emptyDescription} action={emptyAction} className={className} />
  }
  return <>{children}</>
}
