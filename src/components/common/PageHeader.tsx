import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { cx } from '../../lib/cx'

export interface PageHeaderProps {
  title: ReactNode
  description?: ReactNode
  /** Page-level controls: filters, exports, primary action. */
  actions?: ReactNode
  /** Short metadata row: record counts, last updated, status. */
  meta?: ReactNode
  breadcrumb?: { label: string; to?: string }[]
  className?: string
}

/**
 * Standard page header: breadcrumb, title, description, metadata and actions.
 *
 * It is document flow inside the scrolling `<main>`, not a fixed bar, so a page
 * is never trapped behind chrome and keyboard focus moves through it naturally.
 */
export function PageHeader({ title, description, actions, meta, breadcrumb, className }: PageHeaderProps) {
  return (
    <div className={cx('border-b border-edge bg-night-900/60 px-4 py-4 lg:px-6', className)}>
      {breadcrumb && breadcrumb.length > 0 ? (
        <nav aria-label="Breadcrumb" className="mb-1.5">
          <ol className="flex flex-wrap items-center gap-1.5 text-[11px] text-mist-faint">
            {breadcrumb.map((crumb, index) => (
              <li key={`${crumb.label}-${index}`} className="flex items-center gap-1.5">
                {index > 0 ? <span aria-hidden>/</span> : null}
                {crumb.to ? (
                  <Link to={crumb.to} className="hover:text-mist-dim hover:underline">
                    {crumb.label}
                  </Link>
                ) : (
                  <span className="text-mist-dim">{crumb.label}</span>
                )}
              </li>
            ))}
          </ol>
        </nav>
      ) : null}

      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold tracking-tight text-mist lg:text-xl">{title}</h1>
          {description ? (
            <p className="mt-1 max-w-3xl text-[13px] leading-relaxed text-mist-dim">{description}</p>
          ) : null}
          {meta ? <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-mist-faint">{meta}</div> : null}
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
    </div>
  )
}

export function PageBody({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx('flex flex-col gap-4 p-4 lg:p-6', className)}>{children}</div>
}

/** Consistent page padding + scroll container for document-style pages. */
export function PageScroll({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx('h-full overflow-y-auto', className)}>{children}</div>
}
