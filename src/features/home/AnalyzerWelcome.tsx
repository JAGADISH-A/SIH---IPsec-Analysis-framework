import { AnalyzerStatusBar } from './AnalyzerStatusBar'
import { CaptureLauncher } from './CaptureLauncher'
import { PcapLauncher } from './PcapLauncher'
import { RecentTunnels } from './RecentTunnels'
import { WelcomeMasthead } from './WelcomeMasthead'
import { useRecentTunnels } from '../../hooks/queries'
import type { HomeSummary } from '../../types/home'

/**
 * The analysis launchpad.
 *
 * A launch screen, not a page about the product: what the analyzer is doing
 * right now, the two ways to start an investigation, the tunnels that can be
 * reopened, and the instrument footer. No hero, no feature narrative and no
 * chart — those belong on the pages that own them, and the top navigation
 * already carries the rest of the workspaces, so repeating them here would
 * only cost the reader vertical space.
 *
 * The launcher row and the tunnel list are the only two flexible rows, and both
 * are capped, so a tall viewport grows them up to a limit and leaves the
 * remainder above the bottom-pinned status strip rather than stretching a panel
 * into a field of empty space. Below `lg` everything stacks in document order
 * and the column scrolls.
 */
export interface AnalyzerWelcomeProps {
  summary: HomeSummary
}

export function AnalyzerWelcome({ summary }: AnalyzerWelcomeProps) {
  // Tunnels come from the tunnel service, not the welcome-screen summary: a
  // tunnel is a session reconstructed from a capture, and one service must own
  // that model or two screens will eventually disagree about it.
  const tunnels = useRecentTunnels(6)

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden">
      <WelcomeMasthead capabilities={summary.capabilities} mockMode={summary.mockMode} />

      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3 lg:gap-3.5 lg:p-4">
        <div className="grid min-h-0 shrink-0 gap-3 lg:min-h-[248px] lg:max-h-[320px] lg:flex-[1_1_0] lg:shrink lg:grid-cols-2">
          <CaptureLauncher />
          <PcapLauncher />
        </div>

        <RecentTunnels tunnels={tunnels.data ?? []} />

        <AnalyzerStatusBar
          className="mt-auto shrink-0"
          protocols={summary.protocols}
          capabilities={summary.capabilities}
        />
      </div>
    </div>
  )
}
