import { NavLink } from 'react-router-dom'
import { getAnalyticsHealth } from '@/api/analytics'
import { getControlHealth } from '@/api/control'
import { useResource } from '@/hooks/useResource'

type NavItem = { to: string; label: string; end?: boolean; hint?: string; unavailable?: boolean }

/**
 * Navigation follows the analyst's path through the product rather than the
 * repository's module layout.
 *
 * One item is retained but marked unavailable: report documents have no
 * producer in the analytics plane, and the audit found none. Keeping it
 * visible with an explicit marker is more honest than deleting the entry,
 * which would hide the gap, or rendering an empty view, which would imply the
 * capability exists and is merely empty today. The threat matrix, once in the
 * same position, now points at a real route: the backend records both of its
 * axes (severity, planner posture), so the matrix is a cross-tabulation of
 * existing facts rather than a computed capability.
 */
const NAV_ITEMS: NavItem[] = [
  { to: '/overview', label: 'Overview', hint: 'What the store holds, ordered by time' },
  { to: '/', label: 'Live Screening', end: true, hint: 'Live packet capture and screening' },
  {
    to: '/configuration',
    label: 'IPsec Configuration',
    hint: 'Configured tunnel parameters per assessment',
  },
  { to: '/analysis', label: 'Traffic Analysis', hint: 'Traffic classification and model signals' },
  { to: '/assessments', label: 'Security Assessment', hint: 'Every assessment on record' },
  { to: '/reports', label: 'Reports', hint: 'Read-only summary of the store', unavailable: true },
  {
    to: '/threat-matrix',
    label: 'Threat Matrix',
    hint: 'Assessments by severity and planner posture',
  },
  { to: '/settings', label: 'Settings', hint: 'Backend planes and connectivity' },
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
        <ul className="space-y-0.5">
          {NAV_ITEMS.map((item) => (
            <li key={item.to}>
              <NavLink
                to={item.to}
                end={item.end}
                onClick={onNavigate}
                title={item.hint}
                className={({ isActive }) =>
                  [
                    'flex items-center gap-2 rounded-md px-2.5 py-1.5 text-sm transition-colors',
                    isActive
                      ? 'bg-sentinel/10 font-medium text-ink'
                      : 'text-ink-dim hover:bg-panel-2 hover:text-ink',
                  ].join(' ')
                }
              >
                <span className="truncate">{item.label}</span>
                {item.unavailable ? (
                  <span className="ml-auto shrink-0 text-2xs uppercase tracking-wide text-ink-faint">
                    Not available
                  </span>
                ) : null}
              </NavLink>
            </li>
          ))}
        </ul>
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
