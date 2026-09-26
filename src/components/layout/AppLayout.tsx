import { Outlet } from 'react-router-dom'
import { TopNav } from '../navigation/TopNav.tsx'
import { AiAssistantPanel } from '../ai/AiAssistantPanel.tsx'

/**
 * Application shell.
 *
 * The root is a full-viewport column — no centred max-width wrapper, no floating
 * card, no sidebar. The `<main>` slot is a fixed-height viewport area with its
 * own clipping: workspace pages (the analyzer) fill it and manage their own
 * scroll regions, while document pages (marketing, about) scroll inside it.
 * Nothing is ever zoomed out or letterboxed into a centred column.
 */
export function AppLayout() {
  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-night-950">
      <TopNav />
      <main className="relative min-h-0 flex-1 overflow-hidden">
        <Outlet />
      </main>
      <AiAssistantPanel />
    </div>
  )
}
