import { Link } from 'react-router-dom'
import { Moon, Sparkles, Sun } from 'lucide-react'
import { cx } from '../../lib/cx'
import { useAiAssistant } from '../../state/aiAssistant.tsx'
import { useSettings } from '../../state/settings.tsx'
import { Logo } from '../common/Logo.tsx'
import { NavItems } from './NavItems.tsx'
import { MobileNav } from './MobileNav.tsx'
import { FilterToggle } from './FilterToggle.tsx'
import { LiveStatus } from './LiveStatus.tsx'
import { NotificationBell } from './NotificationBell.tsx'
import { ProfileMenu } from './ProfileMenu.tsx'

function AiAssistantButton() {
  const { open, toggleAssistant } = useAiAssistant()
  return (
    <button
      type="button"
      onClick={toggleAssistant}
      aria-label="AI Assistant"
      aria-expanded={open}
      title="AI Assistant"
      className={cx('nav-item h-9', open && 'nav-item-active')}
    >
      <Sparkles className="size-[15px] text-accent-400" aria-hidden />
      <span className="hidden lg:inline">AI Assistant</span>
    </button>
  )
}

function ThemeToggle() {
  const { settings, resolvedTheme, update } = useSettings()
  const next = resolvedTheme === 'dark' ? 'light' : 'dark'
  return (
    <button
      type="button"
      onClick={() => update('theme', next)}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
      className="nav-item h-9 px-2"
      data-active={settings.theme}
    >
      {resolvedTheme === 'dark' ? (
        <Sun className="size-[15px]" aria-hidden />
      ) : (
        <Moon className="size-[15px]" aria-hidden />
      )}
    </button>
  )
}

/**
 * The application's only persistent chrome: a deep-navy bar carrying the brand,
 * the six primary routes, an overflow menu for the rest, the display-filter
 * magnifier, the AI assistant, the live capture indicator, notifications, the
 * theme toggle and the profile menu. There is no sidebar — everything the
 * product used to hang off one lives here.
 *
 * The bar paints from the chrome tokens, so it stays navy in light mode while
 * the rest of the product follows the active theme.
 */
export function TopNav() {
  return (
    <header className="nav-surface relative z-30 flex h-14 shrink-0 items-center gap-2 border-b px-3 lg:gap-3 lg:px-4">
      <Link to="/" aria-label="IPsec Sentinel — home" className="shrink-0">
        <Logo markSize={22} />
      </Link>

      <div className="chrome-divider mx-0.5 hidden md:block" aria-hidden />

      <NavItems />
      <MobileNav />

      <div className="flex-1" />

      <div className="hidden items-center md:flex">
        <FilterToggle />
      </div>

      <div className="chrome-divider hidden lg:block" aria-hidden />

      <div className="hidden lg:block">
        <AiAssistantButton />
      </div>

      <div className="chrome-divider hidden lg:block" aria-hidden />

      <LiveStatus />
      <ThemeToggle />
      <NotificationBell />
      <ProfileMenu />
    </header>
  )
}
