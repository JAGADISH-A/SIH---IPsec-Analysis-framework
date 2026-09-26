import { useId, useState, type KeyboardEvent, type ReactNode } from 'react'
import { cx } from '../../lib/cx'

export interface TabItem {
  id: string
  label: ReactNode
  disabled?: boolean
}

export interface TabsProps {
  items: TabItem[]
  /** Controlled active id. */
  value?: string
  /** Initial id when uncontrolled. */
  defaultValue?: string
  onChange?: (id: string) => void
  className?: string
  /** Accessible name for the tab list. */
  ariaLabel?: string
  /**
   * Prefix for WAI-ARIA ids. Each tab renders with
   * `id="{prefix}-tab-{id}"` and `aria-controls="{prefix}-{id}"`; the
   * consumer's tab panels should use `id="{prefix}-{id}"` +
   * `aria-labelledby="{prefix}-tab-{id}"`.
   */
  panelIdPrefix?: string
}

/**
 * Horizontal tab strip. Selection is controlled when `value` is provided,
 * otherwise it manages its own state. Implements the WAI-ARIA tabs pattern
 * (roving tabindex, arrow-key / Home / End navigation, id + aria-controls
 * wiring). Panels are rendered by the consumer using the active id.
 */
export function Tabs({
  items,
  value,
  defaultValue,
  onChange,
  className,
  ariaLabel = 'Section tabs',
  panelIdPrefix,
}: TabsProps) {
  const [internal, setInternal] = useState(defaultValue ?? items[0]?.id)
  const fallbackPrefix = useId().replace(/:/g, '-')
  const prefix = panelIdPrefix ?? fallbackPrefix
  const active = value ?? internal
  const select = (id: string) => {
    if (value === undefined) setInternal(id)
    onChange?.(id)
  }

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const enabledIds = items.filter((item) => !item.disabled).map((item) => item.id)
    const currentIndex = enabledIds.indexOf(active)
    if (currentIndex === -1 || enabledIds.length === 0) return
    let next = -1
    if (event.key === 'ArrowRight') next = (currentIndex + 1) % enabledIds.length
    else if (event.key === 'ArrowLeft') next = (currentIndex - 1 + enabledIds.length) % enabledIds.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = enabledIds.length - 1
    if (next === -1) return
    event.preventDefault()
    const id = enabledIds[next]
    select(id)
    document.getElementById(`${prefix}-tab-${id}`)?.focus()
  }

  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      onKeyDown={onKeyDown}
      className={cx('flex items-center gap-1 border-b border-edge', className)}
    >
      {items.map((item) => {
        const selected = item.id === active
        const disabled = item.disabled
        return (
          <button
            key={item.id}
            id={`${prefix}-tab-${item.id}`}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={`${prefix}-${item.id}`}
            tabIndex={selected ? 0 : -1}
            aria-disabled={disabled || undefined}
            disabled={disabled}
            onClick={() => select(item.id)}
            className={cx(
              '-mb-px inline-flex h-9 items-center gap-1.5 border-b-2 px-3 text-[13px] font-medium transition-colors',
              selected
                ? 'border-accent-500 text-mist'
                : 'border-transparent text-mist-dim hover:border-edge-strong hover:text-mist',
              disabled && 'cursor-not-allowed opacity-40 hover:border-transparent hover:text-mist-dim',
            )}
          >
            {item.label}
          </button>
        )
      })}
    </div>
  )
}