import { NavLink } from 'react-router-dom'
import { MoreHorizontal } from 'lucide-react'
import { cx } from '../../lib/cx'
import {
  Dropdown,
  DropdownMenu,
  DropdownMenuHeader,
  DropdownMenuLink,
  DropdownTrigger,
} from '../common/Dropdown.tsx'
import { PRIMARY_NAV_ITEMS, MORE_NAV_ITEMS } from './navData.ts'

/**
 * Primary page links rendered inside the top navigation bar. Each item is a
 * real route; the active one is marked with a subtle emerald tint plus a 2px
 * underline pinned to the bottom of the bar. Labels collapse to icons first so
 * the six primary destinations always fit without wrapping.
 */
export function NavItems() {
  return (
    <nav aria-label="Primary" className="flex items-center gap-0.5">
      {PRIMARY_NAV_ITEMS.map(({ to, label, icon: Icon }) => (
        <NavLink key={to} to={to} end={to === '/'} className="group relative" title={label}>
          {({ isActive }) => (
            <>
              <span
                className={cx(
                  'nav-item relative hidden h-9 md:inline-flex',
                  isActive && 'nav-item-active',
                )}
              >
                <Icon className="size-[15px]" aria-hidden />
                <span className="hidden lg:inline">{label}</span>
                <span className="sr-only lg:hidden">{label}</span>
              </span>
              <span
                aria-hidden
                className={cx(
                  'pointer-events-none absolute inset-x-1 -bottom-2.5 hidden h-0.5 rounded-full bg-accent-400 transition-opacity md:block',
                  isActive ? 'opacity-100' : 'opacity-0',
                )}
              />
            </>
          )}
        </NavLink>
      ))}

      <MoreMenu />
    </nav>
  )
}

/**
 * Everything that does not earn a permanent slot in the bar. The menu is
 * keyboard-operable, dismisses on Escape or outside click, and marks the active
 * route so the current page is always identifiable.
 */
function MoreMenu() {
  return (
    <Dropdown>
      <DropdownTrigger>
        <button
          type="button"
          className="nav-item h-9"
          aria-label="More pages"
          title="More pages"
        >
          <MoreHorizontal className="size-[15px]" aria-hidden />
          <span className="hidden lg:inline">More</span>
        </button>
      </DropdownTrigger>

      <DropdownMenu align="left" className="w-72">
        <DropdownMenuHeader>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-mist-faint">More pages</div>
        </DropdownMenuHeader>
        <div className="p-1.5">
          {MORE_NAV_ITEMS.map(({ to, label, description, icon: Icon }) => (
            <DropdownMenuLink key={to} to={to} end icon={<Icon className="size-4" aria-hidden />}>
              <span className="flex min-w-0 flex-col">
                <span>{label}</span>
                <span className="truncate text-[11px] text-mist-faint">{description}</span>
              </span>
            </DropdownMenuLink>
          ))}
        </div>
      </DropdownMenu>
    </Dropdown>
  )
}
