import { ChevronDown, LogOut, Settings, UserRound } from 'lucide-react'
import { cx } from '../../lib/cx'
import {
  Dropdown,
  DropdownMenu,
  DropdownMenuFooter,
  DropdownMenuHeader,
  DropdownMenuItem,
  DropdownTrigger,
} from '../common/Dropdown.tsx'

const PROFILE = {
  name: 'A. Nguyen',
  role: 'Security Analyst',
  initials: 'AN',
}

export function ProfileMenu() {
  return (
    <Dropdown>
      <DropdownTrigger>
        <button
          type="button"
          aria-label="Profile menu"
          className={cx(
            'flex h-8 items-center gap-2 rounded-full border border-edge bg-night-800 py-0 pl-0.5 pr-2 text-mist-dim transition-colors hover:border-edge-strong hover:text-mist',
            '[&[aria-expanded=true]]:border-edge-strong',
          )}
        >
          <span className="flex size-[26px] items-center justify-center overflow-hidden rounded-full bg-night-600 text-[11px] font-semibold text-accent-300">
            {PROFILE.initials}
          </span>
          <span className="hidden text-xs font-medium lg:inline">{PROFILE.name}</span>
          <ChevronDown className="size-3.5" aria-hidden />
        </button>
      </DropdownTrigger>

      <DropdownMenu className="w-56">
        <DropdownMenuHeader>
          <div className="text-[13px] font-medium text-mist">{PROFILE.name}</div>
          <div className="text-[11px] text-mist-faint">{PROFILE.role}</div>
        </DropdownMenuHeader>
        <div className="p-1.5">
          <DropdownMenuItem icon={<Settings className="size-4" aria-hidden />}>
            Session settings
          </DropdownMenuItem>
          <DropdownMenuItem icon={<UserRound className="size-4" aria-hidden />}>
            Profile
          </DropdownMenuItem>
          <DropdownMenuItem
            className="text-danger hover:text-danger"
            icon={<LogOut className="size-4 text-danger" aria-hidden />}
          >
            Sign out
          </DropdownMenuItem>
        </div>
        <DropdownMenuFooter>
          <div className="text-[10px] text-mist-faint">UI build · mock data layer</div>
        </DropdownMenuFooter>
      </DropdownMenu>
    </Dropdown>
  )
}