import type { ReactNode, SelectHTMLAttributes } from 'react'
import { ChevronDown } from 'lucide-react'
import { cx } from '../../lib/cx'

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: ReactNode
  hint?: string
}

/** Styled native select with a custom chevron. */
export function Select({ label, hint, className, id, children, ...rest }: SelectProps) {
  const selectId = id ?? (label ? `select-${label.toString().toLowerCase().replace(/[^a-z0-9]+/g, '-')}` : undefined)
  return (
    <div className="flex flex-col gap-1">
      {label ? (
        <label htmlFor={selectId} className="label">
          {label}
        </label>
      ) : null}
      <div className="relative">
        <select
          id={selectId}
          className={cx('field appearance-none pr-9', className)}
          {...rest}
        >
          {children}
        </select>
        <ChevronDown
          className="pointer-events-none absolute right-3 top-1/2 size-3.5 -translate-y-1/2 text-mist-faint"
          aria-hidden
        />
      </div>
      {hint ? <p className="text-xs text-mist-faint">{hint}</p> : null}
    </div>
  )
}