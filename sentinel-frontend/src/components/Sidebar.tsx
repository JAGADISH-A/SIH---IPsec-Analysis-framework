import { NavLink } from 'react-router-dom'
import { getAnalyticsHealth } from '@/api/analytics'
import { getControlHealth } from '@/api/control'
import { useResource } from '@/hooks/useResource'

type NavItem = { to: string; label: string; end?: boolean; hint?: string }
type NavGroup = { label: string; items: NavItem[] }

/**
 * Navigation, grouped by the question an analyst is asking.
 *
 * Analysis is where work starts: what is on the wire now, what was assessed,
 * and the store-wide summary. Investigation is the cross-cutting evidence
 * surface reached once something needs explaining. System holds the action and
 * the health readout.
 *
 * Finding-level investigation happens *inside* Packet Analysis: the selected
 * packet opens the in-workspace surface, so Findings is not a parallel
 * destination. The finding routes still exist as deep links.
 */
const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Analysis',
    items: [
      { to: '/', label: 'Packet Analysis', end: true, hint: 'Live packet analysis workspace' },
      { to: '/assessments', label: 'Assessments', hint: 'Every assessment on record' },
      { to: '/reports', label: 'Reports', hint: 'A read-only summary of the store' },
    ],
  },
  {
    label: 'Investigation',
    items: [
      { to: '/activity', label: 'Live Activity', hint: 'Live monitors and event streams' },
      { to: '/evidence', label: 'Evidence Library', hint: 'Every recorded evidence reference' },
      { to: '/explainability', label: 'Explainability', hint: 'AI explanations across the store' },
      { to: '/analysis', label: 'ML Analysis', hint: 'Model signals and drift' },
    ],
  },
  {
    label: 'System',
    items: [
      { to: '/run', label: 'Run Assessment', hint: 'Configure and run a new test' },
      { to: '/system', label: 'System Status', hint: 'Backend planes and connectivity' },
    ],
  },
]

function Wordmark() {
  return (
    <span className="flex items-center gap-2.5">
      <span
        className="flex h-7 w-7 items-center justify-center rounded-md bg-sentinel/10"
        aria-hidden="true"
      >
        <svg viewBox="0 0 24 24" className="h-4 w-4 text-sentinel" fill="none">
          <path
            d="M12 2.8 4.6 5.7v5.9c0 4.5 3.1 8.2 7.4 9.4 4.3-1.2 7.4-4.9 7.4-9.4V5.7L12 2.8Z"
            stroke="currentColor"
            strokeWidth="1.7"
            strokeLinejoin="round"
          />
          <path
            d="M12 8.6v3.4M12 14.7h.01"
            stroke="currentColor"
            strokeWidth="1.9"
            strokeLinecap="round"
          />
        </svg>
      </span>
      <span className="text-base font-semibold leading-none tracking-tight text-ink">
        Sentinel
      </span>
    </span>
  )
}

/**
 * Connection state for both API planes.
 *
 * A small solid dot, no glow and no pulse animation. It reads the real health
 * endpoints and is never optimistically green: `loading` is not `connected`, and
 * an error is not `degraded`. A CORS-blocked read arrives here as a fetch
 * rejection, which is indistinguishable from "nothing listening" — so the
 * `title` attribute spells out which of the two the browser reported, and the
 * `SystemStatus` page carries the actionable explanation.
 */
function useConnectionState() {
  const analytics = useResource<{ status: string }>((signal) => getAnalyticsHealth(signal))
  const control = useResource<{ status: string }>((signal) => getControlHealth(signal))

  const describe = (resource: { loading: boolean; error: unknown }) => {
    if (resource.loading) return { ok: false, text: 'checking', title: 'Checking…' }
    if (resource.error) {
      return {
        ok: false,
        text: 'unreachable',
        title:
          'The browser could not read a response. The API may be down, or its CORS policy may not include this page’s origin.',
      }
    }
    return { ok: true, text: 'connected', title: 'Reachable and responding' }
  }

  return { analytics: describe(analytics), control: describe(control) }
}

function StatusDot({ ok }: { ok: boolean }) {
  return (
    <span
      className={`h-1.5 w-1.5 shrink-0 rounded-full ${ok ? 'bg-good' : 'bg-critical'}`}
      aria-hidden="true"
    />
  )
}

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const connection = useConnectionState()

  return (
    <nav
      className="flex h-full w-[228px] shrink-0 flex-col border-r border-edge bg-abyss"
      aria-label="Primary"
    >
      <div className="border-b border-edge px-4 py-4">
        <Wordmark />
        <p className="mt-1.5 text-2xs text-ink-faint">IPsec Security Assessment</p>
      </div>

      <div className="flex-1 overflow-y-auto px-2.5 py-4">
        {NAV_GROUPS.map((group, groupIndex) => (
          <div key={group.label} className={groupIndex === 0 ? '' : 'mt-6'}>
            <p className="label px-2.5 pb-1.5">{group.label}</p>
            <ul className="space-y-0.5">
              {group.items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    onClick={onNavigate}
                    title={item.hint}
                    className={({ isActive }) =>
                      `flex items-center gap-2.5 rounded-md px-2.5 py-[7px] text-sm transition-colors ${
                        isActive
                          ? 'bg-sentinel/8 font-medium text-sentinel'
                          : 'text-ink-dim hover:bg-panel-3 hover:text-ink'
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <span
                          className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                            isActive ? 'bg-sentinel' : 'bg-transparent'
                          }`}
                          aria-hidden="true"
                        />
                        {item.label}
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <div className="border-t border-edge px-4 py-3">
        <p className="label mb-2">System status</p>
        <ul className="space-y-1.5">
          {(
            [
              ['Analytics', connection.analytics],
              ['Control', connection.control],
            ] as const
          ).map(([label, state]) => (
            <li key={label} className="flex items-center justify-between gap-2">
              <span className="text-xs text-ink-faint">{label}</span>
              <span
                className="flex items-center gap-1.5 text-xs text-ink-dim"
                title={state.title}
              >
                <StatusDot ok={state.ok} />
                {state.text}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  )
}
