import { Link, useLocation } from 'react-router-dom'
import { ANALYTICS_API_URL, CONTROL_API_URL } from '@/config'

/** Unknown routes fall back to a way back into the real data, not a dead end. */
export function NotFound() {
  const location = useLocation()
  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <div className="panel max-w-lg p-6 text-center">
        <p className="mono label text-ink-faint">404</p>
        <h1 className="mt-2 text-lg font-semibold text-ink">No such view</h1>
        <p className="mt-2 text-sm leading-relaxed text-ink-dim">
          <span className="mono text-ink-faint">{location.pathname}</span> is not a route in
          Sentinel. Nothing was inferred or substituted for the missing page.
        </p>
        <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
          <Link
            to="/"
            className="rounded border border-sentinel/40 bg-sentinel/10 px-3 py-1.5 text-sm text-sentinel transition-colors hover:bg-sentinel/20"
          >
            Packet Analysis
          </Link>
          <Link
            to="/assessments"
            className="rounded border border-edge bg-panel-2 px-3 py-1.5 text-sm text-ink-dim transition-colors hover:text-ink"
          >
            Assessments
          </Link>
          <Link
            to="/findings"
            className="rounded border border-edge bg-panel-2 px-3 py-1.5 text-sm text-ink-dim transition-colors hover:text-ink"
          >
            Findings
          </Link>
          <Link
            to="/system"
            className="rounded border border-edge bg-panel-2 px-3 py-1.5 text-sm text-ink-dim transition-colors hover:text-ink"
          >
            Backend status
          </Link>
        </div>
        <p className="mt-4 text-xs text-ink-faint">
          Analytics {ANALYTICS_API_URL} · control {CONTROL_API_URL}
        </p>
      </div>
    </div>
  )
}
