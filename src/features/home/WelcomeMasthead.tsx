import { Badge } from '../../components/common/Badge'
import { StatusDot } from '../../components/common/StatusDot'
import { env } from '../../config/env'
import { HOME_STATE_LABEL, type HomeCapability } from '../../types/home'

/**
 * Launchpad masthead.
 *
 * States what this workspace is and nothing more: the product, the kind of
 * workspace it is, that it is a research prototype, and whether the analyzer
 * can actually run. There is no hero copy and no feature narrative — the
 * panels below are the content, and these two lines exist to orient the reader
 * in one glance without pushing the analysis panels off a 1366×768 screen.
 *
 * Readiness is reported from the capability list rather than asserted, so a
 * build without a backend says so in the same place an operator looks first.
 */
export interface WelcomeMastheadProps {
  capabilities: HomeCapability[]
  mockMode: boolean
}

export function WelcomeMasthead({ capabilities, mockMode }: WelcomeMastheadProps) {
  const analyzer = capabilities.find((capability) => capability.id === 'packet-analyzer')
  const ready = analyzer?.state !== 'offline'

  return (
    <header className="flex shrink-0 flex-wrap items-start justify-between gap-x-6 gap-y-1 border-b border-edge bg-night-900/60 px-4 py-2 lg:px-6">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-[15px] font-semibold tracking-tight text-mist">{env.appName}</h1>
          <Badge tone="muted" className="uppercase tracking-wide">
            Research Prototype
          </Badge>
        </div>
        <p className="flex flex-wrap items-baseline gap-x-2 text-[12px] text-mist-dim">
          <span>IPsec Security Analysis Workspace</span>
          <span aria-hidden className="text-edge-strong">
            ·
          </span>
          <span className="text-[11.5px] text-mist-faint">
            Capture traffic, inspect IPsec tunnels, and investigate evidence-backed security findings.
          </span>
        </p>
      </div>

      <div className="flex shrink-0 items-center gap-2.5 pt-0.5">
        {mockMode ? <Badge tone="muted">Mock data</Badge> : null}
        <span
          className="inline-flex items-center gap-1.5 text-[11.5px] font-medium text-mist-dim"
          title={analyzer?.detail ?? 'In-browser packet dissection'}
        >
          {ready ? (
            <StatusDot tone="accent" pulse={false} size="sm" />
          ) : (
            <span aria-hidden className="inline-block size-1.5 rounded-full border border-mist-faint" />
          )}
          {ready ? 'Analyzer Ready' : `Analyzer ${HOME_STATE_LABEL[analyzer?.state ?? 'offline']}`}
        </span>
      </div>
    </header>
  )
}
