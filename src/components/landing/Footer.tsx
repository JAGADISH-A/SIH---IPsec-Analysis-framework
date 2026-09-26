import { Link } from 'react-router-dom'
import { Logo } from '../common/Logo.tsx'
import { ALL_NAV_ITEMS } from '../navigation/navData.ts'
import { RFC_REFERENCES } from '../../lib/findings'

/** Site footer — mirrors the primary navigation and cites the standards used. */
export function Footer() {
  return (
    <footer className="w-full border-t border-edge bg-night-900/60">
      <div className="mx-auto w-full max-w-[1560px] px-5 py-10 lg:px-8">
        <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)_minmax(0,1fr)]">
          <div>
            <Link to="/" aria-label="IPsec Sentinel — home">
              <Logo markSize={20} />
            </Link>
            <p className="mt-3 max-w-xs text-[12.5px] leading-relaxed text-mist-dim">
              A frontend-only preview of an IPsec traffic analysis workspace. No backend, no real capture, no external
              services.
            </p>
          </div>

          <nav aria-label="Footer" className="grid gap-6 sm:grid-cols-2">
            <div>
              <div className="label">Platform</div>
              <ul className="mt-2.5 grid gap-1.5">
                {ALL_NAV_ITEMS.map((item) => (
                  <li key={item.to}>
                    <Link
                      to={item.to}
                      className="text-[12.5px] text-mist-dim transition-colors hover:text-mist"
                    >
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <div className="label">Standards</div>
              <ul className="mt-2.5 grid gap-1.5">
                {RFC_REFERENCES.map((reference) => (
                  <li key={reference.id} className="text-[12.5px] text-mist-dim">
                    <span className="mono-tab text-mist-faint">{reference.id}</span> {reference.title}
                  </li>
                ))}
              </ul>
            </div>
          </nav>

          <div>
            <div className="label">Runtime</div>
            <dl className="mt-2.5 grid gap-1.5">
              {[
                ['Capture', 'Simulated in-browser stream'],
                ['PCAP', 'Deterministic mock analysis'],
                ['Assistant', 'Local canned responses'],
                ['Transport', 'Service interfaces ready'],
              ].map(([label, value]) => (
                <div key={label} className="flex gap-2 text-[12.5px]">
                  <dt className="mono-tab w-[74px] shrink-0 text-mist-faint">{label}</dt>
                  <dd className="min-w-0 text-mist-dim">{value}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>

        <div className="mt-9 flex flex-col gap-1.5 border-t border-edge pt-4 text-[11px] text-mist-faint sm:flex-row sm:items-center sm:justify-between">
          <span>© 2026 IPsec Sentinel</span>
          <span className="mono-tab">IKEv2 · ESP · AH — RFC 7296 / 4303 / 4302</span>
          <span>Frontend UI preview — no backend</span>
        </div>
      </div>
    </footer>
  )
}
