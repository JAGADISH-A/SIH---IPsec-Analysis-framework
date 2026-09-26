import type { InputHTMLAttributes, ReactNode } from 'react'
import { cx } from '../../lib/cx'

export interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: ReactNode
  hint?: string
  error?: string
  leading?: ReactNode
  trailing?: ReactNode
}

/** Labeled text input consistent with the global `.field` styling. */
export function Field({
  label,
  hint,
  error,
  leading,
  trailing,
  className,
  id,
  ...rest
}: FieldProps) {
  const inputId = id ?? (label ? `field-${label.toString().toLowerCase().replace(/[^a-z0-9]+/g, '-')}` : undefined)
  return (
    <div className="flex flex-col gap-1">
      {label ? (
        <label htmlFor={inputId} className="label">
          {label}
        </label>
      ) : null}
      <div className="relative">
        {leading ? (
          <span className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-mist-faint">
            {leading}
          </span>
        ) : null}
        <input
          id={inputId}
          spellCheck={false}
          className={cx(
            'field',
            leading != null && 'pl-9',
            (trailing != null || error != null) && 'pr-9',
            error && 'border-danger/70 focus:border-danger focus:shadow-none',
            className,
          )}
          aria-invalid={error ? true : undefined}
          {...rest}
        />
        {trailing ? (
          <span className="absolute inset-y-0 right-0 flex items-center pr-3">{trailing}</span>
        ) : null}
      </div>
      {error ? <p className="text-xs text-danger">{error}</p> : null}
      {!error && hint ? <p className="text-xs text-mist-faint">{hint}</p> : null}
    </div>
  )
}