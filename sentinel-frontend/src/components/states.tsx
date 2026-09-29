import type { ReactNode } from 'react'
import { ApiRequestError } from '@/api/client'

/* ---------------------------------------------------------------- loading */

export function Spinner({ className = '' }: { className?: string }) {
  return (
    <span
      className={`inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-edge border-t-sentinel ${className}`}
      role="status"
      aria-label="Loading"
    />
  )
}

export function LoadingPanel({
  label = 'Loading',
  rows = 3,
  fullPage = false,
}: {
  label?: string
  rows?: number
  fullPage?: boolean
}) {
  return (
    <div
      className={fullPage ? 'flex min-h-[60vh] items-center justify-center p-6' : undefined}
      role="status"
      aria-live="polite"
    >
      <div className={fullPage ? 'w-full max-w-2xl' : undefined}>
        <div className="panel p-5">
          <div className="mb-4 flex items-center gap-2.5 text-ink-dim">
            <Spinner />
            <span className="text-base">{label}…</span>
          </div>
          <div className="space-y-2.5">
            {Array.from({ length: rows }).map((_, index) => (
              <div
                key={index}
                className="skeleton h-3"
                style={{ opacity: 1 - index * 0.16 }}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export function LoadingCards({ count = 4 }: { count?: number }) {
  return (
    <div
      className="grid grid-cols-2 gap-3 lg:grid-cols-4"
      role="status"
      aria-live="polite"
      aria-label="Loading"
    >
      {Array.from({ length: count }).map((_, index) => (
        <div key={index} className="panel skeleton h-24 border-0" />
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------ error */

/**
 * The single user-facing error surface.
 *
 * It separates the two failure kinds that look identical in devtools but mean
 * completely different things to whoever is holding the page:
 *
 *  - `status === 0`   the request never completed. Either nothing is listening,
 *                     or the browser blocked the response. For a cross-origin
 *                     read the most common cause is the server omitting
 *                     `Access-Control-Allow-Origin`, so that is named
 *                     explicitly instead of being reported as "offline".
 *  - `status >= 400`  the server answered and declined. The server's own
 *                     message is authoritative and is shown verbatim.
 *
 * It never prints a stack trace.
 */
export function ErrorState({
  error,
  onRetry,
  compact = false,
}: {
  error: ApiRequestError | null
  onRetry?: () => void
  compact?: boolean
}) {
  if (!error) return null

  const isNetwork = error.status === 0
  const isCors = isNetwork && error.service === 'analytics'
  const heading = isCors
    ? 'The analytics API could not be read from this page'
    : error.title

  return (
    <div role="alert" className={`panel ${compact ? 'p-3' : 'p-4'}`}>
      <div className="flex items-start gap-3">
        <span
          className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${
            isNetwork ? 'bg-medium/12 text-medium' : 'bg-critical/10 text-critical'
          }`}
          aria-hidden="true"
        >
          <svg viewBox="0 0 16 16" className="h-3 w-3" fill="none">
            <path
              d="M8 1.8 14.8 14H1.2L8 1.8Z"
              stroke="currentColor"
              strokeWidth="1.4"
              strokeLinejoin="round"
            />
            <path d="M8 6.2v3.6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            <circle cx="8" cy="11.8" r="0.85" fill="currentColor" />
          </svg>
        </span>

        <div className="min-w-0 flex-1">
          <h3 className="text-base font-semibold text-ink">{heading}</h3>
          <p className="mt-1 text-base leading-relaxed text-ink-dim">{error.detail}</p>

          {isCors && (
            <p className="mt-2 rounded border border-edge bg-panel-2 px-2.5 py-2 text-xs leading-relaxed text-ink-dim">
              A cross-origin read needs the server to return
              <code className="mono mx-1 text-ink">Access-Control-Allow-Origin</code>
              for this page&apos;s origin. Restart the analytics API with that origin
              permitted, for example:
              <code className="mono mt-1 block break-all text-ink-dim">
                FRONTEND_ORIGIN={typeof window !== 'undefined' ? window.location.origin : '&lt;origin&gt;'}
                {' ./scripts/serve-backend.sh'}
              </code>
            </p>
          )}

          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-2xs text-ink-faint">
            <span className="mono">
              {error.service} · {error.code}
              {error.status ? ` · http ${error.status}` : ' · no response'}
            </span>
            {error.requestId && <span className="mono">req {error.requestId}</span>}
          </div>

          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-edge bg-panel px-2.5 py-1.5 text-sm font-medium text-ink transition-colors hover:bg-panel-2"
            >
              <svg viewBox="0 0 16 16" className="h-3 w-3" fill="none" aria-hidden="true">
                <path
                  d="M13.5 8a5.5 5.5 0 1 1-1.7-4M13.5 1.5V5H10"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              Retry
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ empty */

export function EmptyState({
  title,
  description,
  action,
  icon = 'inbox',
}: {
  title: string
  description?: ReactNode
  action?: ReactNode
  icon?: 'inbox' | 'search' | 'check' | 'filter'
}) {
  const icons: Record<string, ReactNode> = {
    inbox: (
      <path
        d="M2 9.5h3.2l1 2h3.6l1-2H14M2 9.5 3.6 3h8.8L14 9.5v3.2H2V9.5Z"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinejoin="round"
      />
    ),
    search: (
      <g stroke="currentColor" strokeWidth="1.4" strokeLinecap="round">
        <circle cx="7" cy="7" r="4.2" />
        <path d="m10.2 10.2 3.3 3.3" />
      </g>
    ),
    check: (
      <g stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="8" cy="8" r="6" />
        <path d="m5.2 8.2 2 2 3.6-4" />
      </g>
    ),
    filter: (
      <path
        d="M2.5 3.5h11l-4.2 5v4l-2.6 1.2v-5.2L2.5 3.5Z"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinejoin="round"
      />
    ),
  }

  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <span
        className="flex h-10 w-10 items-center justify-center rounded-full bg-panel-3 text-ink-faint"
        aria-hidden="true"
      >
        <svg viewBox="0 0 16 16" className="h-4.5 w-4.5" fill="none">
          {icons[icon]}
        </svg>
      </span>
      <div>
        <p className="text-base font-medium text-ink">{title}</p>
        {description && (
          <p className="mx-auto mt-1 max-w-md text-base leading-relaxed text-ink-faint">
            {description}
          </p>
        )}
      </div>
      {action}
    </div>
  )
}

/* --------------------------------------------------------- resource switch */

/**
 * One place that turns the four possible states of a backend call into the
 * right block, so no page has to re-implement the branching.
 */
export function ResourceState<T>({
  loading,
  error,
  data,
  onRetry,
  loadingView,
  isEmpty,
  emptyView,
  children,
}: {
  loading: boolean
  error: ApiRequestError | null
  data: T | null
  onRetry?: () => void
  loadingView?: ReactNode
  isEmpty?: (data: T) => boolean
  emptyView?: ReactNode
  children: (data: T) => ReactNode
}) {
  if (loading) return <>{loadingView ?? <LoadingPanel />}</>
  if (error) return <ErrorState error={error} onRetry={onRetry} />
  if (data === null) return <>{loadingView ?? <LoadingPanel />}</>
  if (isEmpty?.(data)) return <>{emptyView ?? <EmptyState title="Nothing to show" />}</>
  return <>{children(data)}</>
}
