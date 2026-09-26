import { SERVICE_TARGET } from '../../services'
import { cx } from '../../lib/cx'
import { HOME_STATE_LABEL, type HomeCapability, type HomeProtocol } from '../../types/home'

/**
 * Instrument footer.
 *
 * Two facts an operator should not have to hunt for: which protocols the
 * dissector decodes, and where the figures on this screen came from. A missing
 * backend is drawn as a hollow ring — an absent integration, not a failure.
 */
export interface AnalyzerStatusBarProps {
  protocols: HomeProtocol[]
  capabilities: HomeCapability[]
  className?: string
}

export function AnalyzerStatusBar({ protocols, capabilities, className }: AnalyzerStatusBarProps) {
  const offline = capabilities.filter((capability) => capability.state === 'offline')

  return (
    <div className={cx('flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-edge pt-2', className)}>
      <h2 className="section-title">Dissectors</h2>
      <ul className="flex flex-wrap items-center gap-1.5">
        {protocols.map((protocol) => (
          <li
            key={protocol.label}
            className="chip mono-tab"
            title={`${protocol.label} — ${protocol.description} (${protocol.rfc})`}
          >
            {protocol.label}
            <span className="text-mist-faint">{protocol.rfc}</span>
          </li>
        ))}
      </ul>

      <div className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1">
        {offline.map((capability) => (
          <span
            key={capability.id}
            className="flex items-center gap-1.5 text-[11px] text-mist-faint"
            title={capability.detail}
          >
            <span aria-hidden className="inline-block size-1.5 rounded-full border border-mist-faint" />
            {capability.label} · {HOME_STATE_LABEL[capability.state]}
          </span>
        ))}
        <span className="mono-tab text-[10.5px] text-mist-faint">data: {SERVICE_TARGET}</span>
      </div>
    </div>
  )
}
