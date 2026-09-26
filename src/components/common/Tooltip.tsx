import { useId, useRef, useState, type ReactNode } from 'react'
import { cx } from '../../lib/cx'

export interface TooltipProps {
  label: ReactNode
  side?: 'top' | 'bottom'
  children: ReactNode
  className?: string
}

/**
 * Lightweight hover/focus tooltip. Delays appear so it only fires on
 * deliberate pointing, and hides on pointer-leave or Escape.
 */
export function Tooltip({ label, side = 'top', children, className }: TooltipProps) {
  const [visible, setVisible] = useState(false)
  const timer = useRef<number>(0)
  const labelId = useId()

  const show = () => {
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setVisible(true), 350)
  }
  const hide = () => {
    window.clearTimeout(timer.current)
    setVisible(false)
  }

  return (
    <span
      className="group/tt relative inline-flex"
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
      onKeyDown={(event) => {
        if (event.key === 'Escape') hide()
      }}
    >
      {children}
      {visible ? (
        <span
          role="tooltip"
          id={labelId}
          className={cx(
            'pointer-events-none absolute left-1/2 z-50 -translate-x-1/2 whitespace-nowrap rounded-md border border-edge bg-night-800 px-2.5 py-1 text-[11px] font-medium text-mist shadow-popover',
            side === 'top' ? 'bottom-full mb-1.5' : 'top-full mt-1.5',
            'animate-fade-in',
            className,
          )}
        >
          {label}
        </span>
      ) : null}
    </span>
  )
}