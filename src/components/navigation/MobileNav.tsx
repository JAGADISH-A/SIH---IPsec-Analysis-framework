import { NavLink } from 'react-router-dom'
import { Bot, Menu } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { cx } from '../../lib/cx'
import { useAiAssistant } from '../../state/aiAssistant.tsx'
import { ALL_NAV_ITEMS } from './navData.ts'

/**
 * Compact navigation for screens below `md`: one sheet holding every route,
 * so nothing is unreachable on a phone. The desktop bar is hidden there.
 */
export function MobileNav() {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const { toggleAssistant } = useAiAssistant()

  useEffect(() => {
    if (!open) return
    const onPointerDown = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false)
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

  const close = () => setOpen(false)

  return (
    <div ref={rootRef} className="relative md:hidden">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-label="Open navigation menu"
        aria-expanded={open}
        aria-haspopup="menu"
        className="btn btn-ghost btn-icon"
      >
        <Menu className="size-4" aria-hidden />
      </button>
      {open ? (
        <nav
          aria-label="All pages"
          className="animate-drop-in absolute right-0 top-full z-50 mt-2 max-h-[70vh] w-72 overflow-y-auto rounded-lg border border-edge bg-night-800 shadow-popover"
        >
          <div className="p-1.5">
            <div className="px-2 pb-1 pt-1.5 text-[10px] font-medium uppercase tracking-wide text-mist-faint">
              Navigate
            </div>
            {ALL_NAV_ITEMS.map(({ to, label, icon: Icon }) => (
              <NavLink key={to} to={to} end={to === '/'} onClick={close} className="block">
                {({ isActive }) => (
                  <span
                    className={cx(
                      'flex w-full items-center gap-2.5 rounded px-3 py-2 text-[13px] transition-colors',
                      isActive
                        ? 'bg-accent-dim text-accent-300'
                        : 'text-mist-dim hover:bg-night-700 hover:text-mist',
                    )}
                  >
                    <Icon className="size-4" aria-hidden />
                    {label}
                  </span>
                )}
              </NavLink>
            ))}
            <div className="my-1 h-px bg-edge" aria-hidden />
            <button
              type="button"
              onClick={() => {
                close()
                toggleAssistant()
              }}
              className="flex w-full items-center gap-2.5 rounded px-3 py-2 text-left text-[13px] text-mist-dim transition-colors hover:bg-night-700 hover:text-mist"
            >
              <Bot className="size-4" aria-hidden />
              AI Assistant
            </button>
          </div>
        </nav>
      ) : null}
    </div>
  )
}
