import { useLocation, Link } from 'react-router-dom'
import { Compass } from 'lucide-react'
import { PageBody, PageHeader, PageScroll } from '../common/PageHeader.tsx'
import { Panel } from '../common/Panel.tsx'
import { ALL_NAV_ITEMS } from '../navigation/navData.ts'

/**
 * 404.
 *
 * The route is shown verbatim so a mistyped path can be diagnosed, and every
 * real destination is offered rather than just a "go back" link.
 */
export function NotFoundPage() {
  const location = useLocation()

  return (
    <PageScroll>
      <PageHeader
        title="Page not found"
        description="The address you followed is not part of this application."
        meta={
          <span className="font-mono">
            {location.pathname}
            {location.search}
          </span>
        }
        actions={
          <Link to="/" className="btn">
            <Compass className="size-3.5" aria-hidden />
            Home
          </Link>
        }
      />

      <PageBody>
        <Panel padded>
          <h2 className="text-[13px] font-semibold tracking-wide text-mist">
            If you expected this page, it may have moved
          </h2>
          <p className="mt-1 text-[12px] leading-relaxed text-mist-dim">
            The analyzer used to live at <code className="font-mono">/live</code> and PCAP upload at{' '}
            <code className="font-mono">/pcap</code>. Both still redirect, so old links keep working. Every destination
            in the current information architecture is below.
          </p>

          <ul className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {ALL_NAV_ITEMS.map((item) => (
              <li key={item.to}>
                <Link
                  to={item.to}
                  className="flex items-start gap-2 rounded-md border border-edge bg-night-900 p-2.5 hover:border-accent-500"
                >
                  <item.icon className="mt-0.5 size-4 shrink-0 text-mist-faint" aria-hidden />
                  <span className="min-w-0">
                    <span className="block text-[12.5px] font-medium text-mist">{item.label}</span>
                    <span className="block text-[11px] text-mist-faint">{item.description}</span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
      </PageBody>
    </PageScroll>
  )
}
