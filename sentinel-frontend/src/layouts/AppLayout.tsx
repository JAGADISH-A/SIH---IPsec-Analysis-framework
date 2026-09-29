import { useEffect, useState } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import { Sidebar } from '@/components/Sidebar'
import { getAnalyticsHealth } from '@/api/analytics'
import { getControlHealth } from '@/api/control'
import { useResource } from '@/hooks/useResource'
import { ANALYTICS_API_URL, CONTROL_API_URL } from '@/config'

/**
 * Page title for the topbar, derived from the active route.
 *
 * Kept as a plain table rather than route config so that legacy paths which now
 * redirect still report the page the user actually landed on.
 */
function useRouteTitle(): string {
  const { pathname } = useLocation()
  if (pathname === '/' || pathname === '/console' || pathname === '/overview') return 'Packet Analysis'
  if (pathname.startsWith('/assessments/')) return 'Assessment'
  if (pathname === '/assessments') return 'Assessments'
  if (pathname === '/reports') return 'Reports'
  if (pathname.startsWith('/findings/')) return 'Finding'
  if (pathname === '/findings') return 'Findings'
  if (pathname === '/evidence') return 'Evidence Library'
  if (pathname === '/xai' || pathname === '/explainability') return 'Explainability'
  if (pathname === '/ml' || pathname === '/analysis') return 'ML Analysis'
  if (pathname.startsWith('/run/') || pathname.startsWith('/experiments/')) return 'Run Assessment'
  if (pathname === '/run' || pathname === '/experiments') return 'Run Assessment'
  if (pathname === '/system') return 'System Status'
  return 'Not Found'
}

/**
 * A single, quiet connectivity readout in the header.
 *
 * Replaces two boxed chips with port numbers. The port was implementation
 * detail; what an analyst needs is whether the data behind this page is real,
 * and a link to the page that explains it when it is not.
 */
function ConnectionSummary() {
  const analytics = useResource((signal) => getAnalyticsHealth(signal))
  const control = useResource((signal) => getControlHealth(signal))

  const state = (resource: { loading: boolean; error: unknown }) =>
    resource.loading ? 'checking' : resource.error ? 'unreachable' : 'connected'

  const anyDown = analytics.error || control.error

  return (
    <Link
      to="/system"
      title={
        anyDown
          ? 'A backend could not be read from this page. Open System Status for detail.'
          : `Analytics ${ANALYTICS_API_URL} · Control ${CONTROL_API_URL}`
      }
      className="flex shrink-0 items-center gap-2 rounded-md border border-edge bg-panel px-2 py-1 text-xs text-ink-dim transition-colors hover:bg-panel-2"
    >
      <span className="flex items-center gap-1.5" title={ANALYTICS_API_URL}>
        <span
          className={`h-1.5 w-1.5 rounded-full ${
            analytics.loading ? 'bg-ink-faint' : analytics.error ? 'bg-critical' : 'bg-good'
          }`}
          aria-hidden="true"
        />
        Analytics <span className="sr-only">{state(analytics)}</span>
      </span>
      <span className="text-edge-soft" aria-hidden="true">
        /
      </span>
      <span className="flex items-center gap-1.5" title={CONTROL_API_URL}>
        <span
          className={`h-1.5 w-1.5 rounded-full ${
            control.loading ? 'bg-ink-faint' : control.error ? 'bg-critical' : 'bg-good'
          }`}
          aria-hidden="true"
        />
        Control <span className="sr-only">{state(control)}</span>
      </span>
    </Link>
  )
}

function Topbar({ onToggleNav }: { onToggleNav: () => void }) {
  const title = useRouteTitle()

  return (
    <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-edge bg-canvas/85 px-4 py-2.5 backdrop-blur-sm lg:px-6">
      <button
        type="button"
        onClick={onToggleNav}
        className="rounded border border-edge p-1.5 text-ink-dim transition-colors hover:bg-panel-2 hover:text-ink lg:hidden"
        aria-label="Toggle navigation"
      >
        <svg viewBox="0 0 16 16" className="h-4 w-4" fill="none">
          <path
            d="M2 4h12M2 8h12M2 12h12"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        </svg>
      </button>

      <div className="min-w-0 flex-1">
        <h1 className="truncate text-lg font-semibold tracking-tight text-ink">{title}</h1>
      </div>

      <ConnectionSummary />
    </header>
  )
}

export function AppLayout() {
  const [navOpen, setNavOpen] = useState(false)
  const { pathname } = useLocation()

  useEffect(() => {
    setNavOpen(false)
    // Guarded: scrollTo is not present on every element implementation, and a
    // failed scroll reset must never break navigation.
    const scroller = document.getElementById('main-scroll')
    if (scroller && typeof scroller.scrollTo === 'function') scroller.scrollTo({ top: 0 })
  }, [pathname])

  return (
    <div className="flex min-h-screen">
      <div className="sticky top-0 hidden h-screen lg:block">
        <Sidebar />
      </div>

      {navOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button
            type="button"
            className="absolute inset-0 bg-ink/25"
            onClick={() => setNavOpen(false)}
            aria-label="Close navigation"
          />
          <div className="popover absolute left-0 top-0 h-full w-64">
            <Sidebar onNavigate={() => setNavOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onToggleNav={() => setNavOpen((open) => !open)} />
        <main id="main-scroll" className="flex-1 px-4 py-5 lg:px-6 lg:py-6">
          <Outlet />
        </main>
        <footer className="border-t border-edge px-6 py-3">
          <p className="text-xs text-ink-faint">
            Sentinel reads the deterministic assessment store. Every score, severity and
            finding shown here is produced by the backend risk engine — nothing is
            synthesised in the browser.
          </p>
        </footer>
      </div>
    </div>
  )
}

export function Breadcrumbs({ trail }: { trail: { to?: string; label: string }[] }) {
  return (
    <nav aria-label="Breadcrumb" className="mb-3 flex flex-wrap items-center gap-1.5">
      {trail.map((crumb, index) => (
        <span key={`${crumb.label}-${index}`} className="flex items-center gap-1.5">
          {index > 0 && (
            <span className="text-ink-faint/50" aria-hidden="true">
              /
            </span>
          )}
          {crumb.to ? (
            <Link
              to={crumb.to}
              className="text-sm text-ink-faint transition-colors hover:text-ink"
            >
              {crumb.label}
            </Link>
          ) : (
            <span className="text-sm text-ink">{crumb.label}</span>
          )}
        </span>
      ))}
    </nav>
  )
}

/**
 * The standard page header: a title, one line of orientation, and optional
 * primary action. Used instead of each page inventing its own heading so that
 * vertical rhythm is identical across the product.
 */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string
  description?: string
  actions?: React.ReactNode
}) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h2 className="text-2xl font-semibold tracking-tight text-ink">{title}</h2>
        {description && (
          <p className="mt-1 max-w-3xl text-base text-ink-dim">{description}</p>
        )}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  )
}
