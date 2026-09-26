import { useLayoutEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, Waypoints } from 'lucide-react'
import { ConfidencePopover } from '../../components/identity/ConfidenceLens'
import { RiskSignal } from '../../components/identity/RiskSignal'
import { TunnelConfigLine, TunnelDnaStrip } from '../../components/identity/TunnelDNA'
import { cx } from '../../lib/cx'
import { formatCompact, formatDayTime } from '../../lib/format'
import { SESSION_STATUS_LABEL, type SessionStatus } from '../../types/session'
import type { TunnelIdentity } from '../../types/identity'
import { LauncherPanel } from './LauncherPanel'

/**
 * Width at which the panel is sized by the page layout instead of by its rows.
 *
 * Matches the `lg:` breakpoint the panel's flex sizing is declared at: above it
 * the height comes from the flex row, below it from the content.
 */
const SIZED_BY_LAYOUT_QUERY = '(min-width: 1024px)'

/**
 * Tunnels listed when the panel is not sized by the page layout.
 *
 * In the stacked layout the panel is as tall as its rows, so there is no height
 * to measure against; a short fixed list keeps the launchpad to roughly one
 * screen and leaves the full list to `/vpn-sessions`.
 */
const STACKED_ROW_LIMIT = 3

/**
 * Lifecycle state is text, not severity: a closed tunnel is not "high risk", so
 * it is written out rather than coloured. Only the states an operator acts on
 * are tinted.
 */
const STATUS_CLASS: Record<SessionStatus, string> = {
  active: 'text-success',
  rekeying: 'text-info',
  draining: 'text-warning',
  closed: 'text-mist-faint',
  failed: 'text-danger',
  unavailable: 'text-mist-faint',
}

/**
 * Recent tunnel investigations.
 *
 * Not a file list: each row is a tunnel, read as a tunnel — who talks to whom,
 * how it was negotiated, the lifecycle reconstructed from its packets, the risk
 * that lifecycle produced and how sure the platform is. That is the same
 * identity `/vpn-sessions` shows in full, compressed to the facts needed to
 * decide what to investigate next.
 *
 * The row count is whatever the panel can show without scrolling, measured
 * against the panel's own height, so a tall monitor lists more tunnels instead
 * of leaving a void and a short one never hides a row behind a nested scrollbar.
 */
export interface RecentTunnelsProps {
  tunnels: TunnelIdentity[]
}

export function RecentTunnels({ tunnels }: RecentTunnelsProps) {
  const regionRef = useRef<HTMLUListElement>(null)
  const rowRef = useRef<HTMLLIElement>(null)
  const [rows, setRows] = useState(tunnels.length)

  useLayoutEffect(() => {
    const media = window.matchMedia(SIZED_BY_LAYOUT_QUERY)

    function apply() {
      const region = regionRef.current
      // Below the breakpoint the panel is as tall as its rows, so the list is
      // capped instead of measured and the page scrolls past it.
      if (!media.matches || !region) {
        setRows(Math.min(tunnels.length, STACKED_ROW_LIMIT))
        return
      }
      const row = rowRef.current?.getBoundingClientRect().height ?? 34
      const fits = Math.floor(region.clientHeight / row)
      setRows(Math.max(1, Math.min(tunnels.length, fits)))
    }

    apply()
    const observer = new ResizeObserver(apply)
    if (regionRef.current) observer.observe(regionRef.current)
    media.addEventListener('change', apply)
    return () => {
      observer.disconnect()
      media.removeEventListener('change', apply)
    }
  }, [tunnels.length])

  const visible = tunnels.slice(0, rows)
  const totalPackets = tunnels.reduce((sum, tunnel) => sum + tunnel.packetCount, 0)

  return (
    <LauncherPanel
      title="Recent tunnels"
      icon={Waypoints}
      className="shrink-0 lg:min-h-[140px] lg:max-h-[640px] lg:flex-[1_1_0] lg:shrink"
      aside={
        <span className="mono-tab text-[10.5px] text-mist-faint">
          {visible.length === tunnels.length ? `${tunnels.length} shown` : `${visible.length} of ${tunnels.length}`} ·{' '}
          {formatCompact(totalPackets)} packets
        </span>
      }
      footer={
        <Link
          to="/vpn-sessions"
          className="ml-auto flex items-center gap-1 text-[11.5px] text-mist-dim hover:text-accent-300"
        >
          View all tunnels
          <ArrowRight className="size-3.5" aria-hidden />
        </Link>
      }
    >
      {tunnels.length === 0 ? (
        <p className="flex flex-1 items-center justify-center text-[12px] text-mist-faint">
          No tunnels analysed yet — start a live capture or open a PCAP.
        </p>
      ) : (
        <ul ref={regionRef} className="-m-1 min-h-0 flex-1 overflow-hidden">
          {visible.map((tunnel, index) => (
            <li
              key={tunnel.id}
              ref={index === 0 ? rowRef : undefined}
              className={cx(
                'relative flex flex-wrap items-center gap-x-3 gap-y-0.5 border-b border-edge/60 px-2 py-1',
                'lg:py-0.5',
                'transition-colors hover:bg-night-800/70 focus-within:bg-night-800/70',
                'last:border-b-0 lg:flex-nowrap',
              )}
            >
              {/* The row navigates through a stretched link overlay rather than
                  by wrapping the whole row in an anchor, so the confidence lens
                  can keep its own button: an interactive element nested inside a
                  link is invalid and unreachable by keyboard. */}
              <Link
                to={`/vpn-sessions/${tunnel.id}`}
                className={cx(
                  'flex w-full min-w-0 flex-wrap items-center gap-x-3 gap-y-0.5 lg:w-auto lg:flex-1',
                  'focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent-500',
                  'after:absolute after:inset-0 after:content-[""]',
                )}
                title={`${tunnel.label} — ${tunnel.packetCount.toLocaleString('en-US')} packets, ${tunnel.findingCount} findings, last activity ${formatDayTime(tunnel.lastActivityAt)}`}
              >
                <span className="flex min-w-0 items-center gap-x-2 lg:w-[19rem] lg:shrink-0">
                  <span className="mono-tab shrink-0 text-accent-300">{tunnel.id}</span>
                  <span
                    className="mono-tab min-w-0 truncate text-mist"
                    title={`${tunnel.initiator.address} ↔ ${tunnel.responder.address}`}
                  >
                    {tunnel.initiator.address} ↔ {tunnel.responder.address}
                  </span>
                </span>

                <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-0.5">
                  <TunnelConfigLine tunnel={tunnel} />
                  <TunnelDnaStrip dna={tunnel.dna} />
                </span>
              </Link>

              <span className="relative z-10 flex shrink-0 items-center gap-2">
                <span
                  className={cx(
                    'text-[9.5px] font-semibold uppercase tracking-[0.07em]',
                    STATUS_CLASS[tunnel.status],
                  )}
                >
                  {SESSION_STATUS_LABEL[tunnel.status]}
                </span>
                <RiskSignal
                  severity={tunnel.severity}
                  label={
                    tunnel.findingCount > 0
                      ? `${tunnel.findingCount} finding${tunnel.findingCount === 1 ? '' : 's'}`
                      : undefined
                  }
                />
                <ConfidencePopover
                  confidence={tunnel.confidence}
                  detail={{
                    field: 'Overall assessment',
                    value: tunnel.encryption.value ?? 'Unknown',
                    source: 'calculated',
                    evidence: tunnel.assessmentEvidence,
                    explanation: 'Composite of the tunnel risk score and the findings raised against it.',
                  }}
                />
              </span>
            </li>
          ))}
        </ul>
      )}
    </LauncherPanel>
  )
}
