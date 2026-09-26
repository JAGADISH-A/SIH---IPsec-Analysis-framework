import {
  cloneElement,
  createContext,
  isValidElement,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type AriaAttributes,
  type ButtonHTMLAttributes,
  type ReactElement,
  type ReactNode,
} from 'react'
import { NavLink } from 'react-router-dom'
import { cx } from '../../lib/cx'

interface DropdownContextValue {
  open: boolean
  panelId: string
  close(): void
  toggle(): void
}

const DropdownContext = createContext<DropdownContextValue | null>(null)

function useDropdown(): DropdownContextValue {
  const value = useContext(DropdownContext)
  if (!value) {
    throw new Error('Dropdown subcomponents must be used within <Dropdown>')
  }
  return value
}

export interface DropdownProps {
  children: ReactNode
  onOpenChange?: (open: boolean) => void
  className?: string
}

/**
 * Headless menu container: manages open state, outside-pointer dismissal and
 * Escape. Compose with <DropdownTrigger> and <DropdownMenu>.
 */
export function Dropdown({ children, onOpenChange, className }: DropdownProps) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const panelId = useId()

  useEffect(() => {
    if (!open) return
    const onPointerDown = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const setOpenWrapped = useCallback(
    (next: boolean) => {
      setOpen(next)
      onOpenChange?.(next)
    },
    [onOpenChange],
  )

  const value = useMemo<DropdownContextValue>(
    () => ({
      open,
      panelId,
      close: () => setOpenWrapped(false),
      toggle: () => setOpenWrapped(!open),
    }),
    [open, panelId, setOpenWrapped],
  )

  return (
    <div ref={rootRef} className={cx('relative inline-block', className)}>
      <DropdownContext.Provider value={value}>{children}</DropdownContext.Provider>
    </div>
  )
}

export interface DropdownTriggerProps {
  children: ReactElement
}

/** Injects toggle + a11y props into the trigger element. */
export function DropdownTrigger({ children }: DropdownTriggerProps) {
  const { open, toggle } = useDropdown()
  if (!isValidElement(children)) return null
  const element = children as ReactElement<{ onClick?: () => void } & AriaAttributes>
  return cloneElement(element, {
    onClick: () => toggle(),
    'aria-expanded': open,
    'aria-haspopup': 'menu',
  })
}

export interface DropdownMenuProps {
  children: ReactNode
  align?: 'left' | 'right'
  className?: string
}

export function DropdownMenu({ children, align = 'right', className }: DropdownMenuProps) {
  const { open, panelId } = useDropdown()
  if (!open) return null
  return (
    <div
      id={panelId}
      role="menu"
      className={cx(
        'animate-drop-in absolute top-full z-50 mt-2 min-w-[180px] overflow-hidden rounded-lg border border-edge bg-night-800 shadow-popover',
        align === 'right' ? 'right-0' : 'left-0',
        className,
      )}
    >
      {children}
    </div>
  )
}

export interface DropdownMenuItemProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Icon rendered before the label. */
  icon?: ReactNode
}

export function DropdownMenuItem({ icon, className, children, ...rest }: DropdownMenuItemProps) {
  return (
    <button
      type="button"
      role="menuitem"
      className={cx(
        'flex w-full items-center gap-2.5 px-3 py-2 text-left text-[13px] text-mist-dim transition-colors hover:bg-night-700 hover:text-mist',
        className,
      )}
      {...rest}
    >
      {icon ? <span className="flex size-4 shrink-0 items-center justify-center">{icon}</span> : null}
      {children}
    </button>
  )
}

export interface DropdownMenuLinkProps {
  to: string
  icon?: ReactNode
  children: ReactNode
  end?: boolean
  onNavigate?: () => void
  active?: boolean
  className?: string
}

/** NavLink-shaped menu entry, for menus that navigate rather than act. */
export function DropdownMenuLink({ to, icon, children, end, onNavigate, active, className }: DropdownMenuLinkProps) {
  return (
    <NavLink
      to={to}
      end={end}
      role="menuitem"
      onClick={onNavigate}
      className={cx(
        'flex w-full items-center gap-2.5 px-3 py-2 text-left text-[13px] transition-colors hover:bg-night-700 hover:text-mist',
        active && 'bg-accent-dim text-accent-300',
        className,
      )}
    >
      {icon ? <span className="flex size-4 shrink-0 items-center justify-center">{icon}</span> : null}
      {children}
    </NavLink>
  )
}

export function DropdownMenuHeader({ children }: { children: ReactNode }) {
  return <div className="border-b border-edge px-3 py-2.5">{children}</div>
}

export function DropdownMenuFooter({ children }: { children: ReactNode }) {
  return <div className="border-t border-edge px-3 py-2">{children}</div>
}