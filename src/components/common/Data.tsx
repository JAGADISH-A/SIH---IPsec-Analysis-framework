import { useMemo, useState, type ReactNode } from 'react'
import { Check, ChevronLeft, ChevronRight, Copy } from 'lucide-react'
import { cx } from '../../lib/cx'
import { Button } from './Button'

/* ------------------------------------------------------------------ */
/* Key/value list                                                       */
/* ------------------------------------------------------------------ */

export interface KeyValueItem {
  label: ReactNode
  value: ReactNode
  /** Rendered under the value in a muted tone. */
  note?: ReactNode
  mono?: boolean
}

export function KeyValueList({ items, className, columns = 1 }: { items: KeyValueItem[]; className?: string; columns?: 1 | 2 }) {
  return (
    <dl
      className={cx(
        'grid gap-x-6 gap-y-3',
        columns === 2 ? 'sm:grid-cols-2' : 'grid-cols-1',
        className,
      )}
    >
      {items.map((item, index) => (
        <div key={index} className="min-w-0">
          <dt className="text-[11px] uppercase tracking-wide text-mist-faint">{item.label}</dt>
          <dd
            className={cx(
              'mt-0.5 break-words text-[13px] text-mist',
              item.mono && 'font-mono text-xs',
            )}
          >
            {item.value}
          </dd>
          {item.note ? <p className="mt-0.5 text-[11px] text-mist-faint">{item.note}</p> : null}
        </div>
      ))}
    </dl>
  )
}

/* ------------------------------------------------------------------ */
/* JSON viewer                                                          */
/* ------------------------------------------------------------------ */

/** Pretty-printed raw payload with a copy affordance. */
export function JsonBlock({ value, className, maxHeight = 420, label = 'Raw data' }: { value: unknown; className?: string; maxHeight?: number; label?: string }) {
  const [copied, setCopied] = useState(false)
  const text = useMemo(() => {
    try {
      return JSON.stringify(value, null, 2) ?? 'null'
    } catch {
      return '// The value could not be serialised for display.'
    }
  }, [value])

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1_500)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className={cx('flex flex-col overflow-hidden rounded-lg border border-edge bg-night-950', className)}>
      <div className="flex items-center justify-between border-b border-edge px-3 py-1.5">
        <span className="font-mono text-[11px] text-mist-faint">{label}</span>
        <Button size="sm" variant="ghost" onClick={() => void copy()} aria-label="Copy JSON">
          {copied ? <Check className="size-3.5 text-success" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      <pre
        className="overflow-auto p-3 font-mono text-[11.5px] leading-relaxed text-mist-dim"
        style={{ maxHeight }}
        tabIndex={0}
      >
        {text}
      </pre>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Pagination                                                           */
/* ------------------------------------------------------------------ */

export interface PaginationProps {
  page: number
  pageSize: number
  total: number
  onPageChange: (page: number) => void
  onPageSizeChange?: (pageSize: number) => void
  className?: string
  label?: string
}

export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
  className,
  label = 'records',
}: PaginationProps) {
  const pages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)))
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1
  const last = Math.min(total, page * pageSize)

  return (
    <nav
      aria-label={`Pagination for ${label}`}
      className={cx('flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-[11px] text-mist-faint', className)}
    >
      <span className="font-mono">
        {first}–{last} of {total} {label}
      </span>
      <div className="flex items-center gap-1.5">
        {onPageSizeChange ? (
          <label className="flex items-center gap-1.5">
            <span>Rows</span>
            <select
              className="field h-7 w-auto py-0 text-[11px]"
              value={pageSize}
              onChange={(event) => onPageSizeChange(Number(event.target.value))}
            >
              {[10, 25, 50, 100].map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <Button
          size="icon-sm"
          aria-label="Previous page"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          <ChevronLeft className="size-3.5" aria-hidden />
        </Button>
        <span className="px-1 font-mono">
          {page} / {pages}
        </span>
        <Button
          size="icon-sm"
          aria-label="Next page"
          disabled={page >= pages}
          onClick={() => onPageChange(page + 1)}
        >
          <ChevronRight className="size-3.5" aria-hidden />
        </Button>
      </div>
    </nav>
  )
}

/* ------------------------------------------------------------------ */
/* Filter bar                                                           */
/* ------------------------------------------------------------------ */

export interface ToolbarProps {
  children: ReactNode
  className?: string
  /** Right-aligned result count or active-filter summary. */
  trailing?: ReactNode
}

export function Toolbar({ children, className, trailing }: ToolbarProps) {
  return (
    <div className={cx('flex flex-wrap items-end gap-2 border-b border-edge px-3 py-2.5', className)}>
      <div className="flex flex-1 flex-wrap items-end gap-2">{children}</div>
      {trailing ? <div className="flex items-center gap-2 text-[11px] text-mist-faint">{trailing}</div> : null}
    </div>
  )
}

/** A removable filter chip. */
export function FilterChip({ label, value, onClear }: { label: string; value: string; onClear: () => void }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-edge bg-night-800 py-0.5 pl-2 pr-1 text-[11px] text-mist-dim">
      <span className="text-mist-faint">{label}</span>
      <span className="max-w-40 truncate font-mono text-mist">{value}</span>
      <button
        type="button"
        onClick={onClear}
        aria-label={`Remove ${label} filter`}
        className="rounded-full px-1 text-mist-faint hover:text-danger"
      >
        ×
      </button>
    </span>
  )
}
