import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Activity, ArrowRight, ChevronDown, Square } from 'lucide-react'
import { Button } from '../../components/common/Button'
import { StatusDot } from '../../components/common/StatusDot'
import { cx } from '../../lib/cx'
import { formatCompact, formatDuration } from '../../lib/format'
import { CAPTURE_INTERFACES, useCaptureStore } from '../../state/capture'
import { LauncherPanel } from './LauncherPanel'
import type { CaptureStartOptions } from '../../services/api/captureService'
import type { SeverityTone } from '../../types/common'
import type { CaptureStatus } from '../../types/traffic'

/**
 * Capture mode.
 *
 * The filter is a real capture-engine expression handed to `CaptureService`, not
 * a display filter: it is the same string the backend will compile when the live
 * transport arrives, so the option means the same thing in both builds.
 */
const IPSEC_FILTER = 'ip proto 50 or ip proto 51 or udp port 500 or udp port 4500'

const MODES: { id: 'live' | 'ipsec'; label: string; hint: string; filter?: string }[] = [
  { id: 'live', label: 'Live', hint: 'Every packet the interface receives', filter: undefined },
  { id: 'ipsec', label: 'IPsec only', hint: `IKEv2, ESP and AH — ${IPSEC_FILTER}`, filter: IPSEC_FILTER },
]

/** Lifecycle read-out for each phase of the capture session. */
const PHASE_STATUS: Record<CaptureStatus, { label: string; tone: SeverityTone }> = {
  idle: { label: 'No capture running', tone: 'info' },
  starting: { label: 'Starting capture…', tone: 'warning' },
  running: { label: 'Capturing', tone: 'accent' },
  paused: { label: 'Capture paused', tone: 'warning' },
  stopping: { label: 'Stopping capture…', tone: 'warning' },
  stopped: { label: 'Capture stopped', tone: 'info' },
  error: { label: 'Capture error', tone: 'danger' },
}

/** Label above value, hairline separated — the analyzer's readout idiom. */
function Stat({ label, value, tone, title }: { label: string; value: string; tone?: 'accent' | 'warning'; title: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5 border-l border-edge pl-2.5 first:border-l-0 first:pl-0" title={title}>
      <span className="text-[9.5px] font-semibold uppercase tracking-[0.07em] text-mist-faint">{label}</span>
      <span
        className={cx(
          'mono-tab text-[15px] font-semibold leading-none',
          tone === 'accent' ? 'text-accent-300' : tone === 'warning' ? 'text-warning' : 'text-mist',
        )}
      >
        {value}
      </span>
    </div>
  )
}

/**
 * The first thing on the screen: start a live capture.
 *
 * Controls the one application-wide capture session, so this panel launches it
 * rather than implementing a second capture. While a capture runs, the session
 * is the source of truth — the mode read-out mirrors the filter the session was
 * actually started with instead of a pending selection, and the primary action
 * opens the analyzer where the packets are.
 */
export function CaptureLauncher() {
  const navigate = useNavigate()
  const { capture, summary, now, interfaceName, setInterfaceName, start, stop } = useCaptureStore()
  const [requestedMode, setRequestedMode] = useState<'live' | 'ipsec'>('live')

  const phase = capture.status
  const active = phase === 'running' || phase === 'starting' || phase === 'paused'
  const runningMode = capture.filter === IPSEC_FILTER ? 'ipsec' : 'live'
  const mode = active ? runningMode : requestedMode
  const modeMeta = MODES.find((entry) => entry.id === mode) ?? MODES[0]

  const statusTone = PHASE_STATUS[phase].tone
  const statusLabel =
    phase === 'running' ? `Capturing on ${capture.interfaceName ?? interfaceName}` : PHASE_STATUS[phase].label

  const durationMs = capture.startedAt ? Math.max(0, now - new Date(capture.startedAt).getTime()) : 0

  /**
   * The panel's single primary action: get the operator to the analyzer.
   *
   * If a capture is already running it only navigates — one application-wide
   * session exists, so the launcher never starts a second one behind the
   * analyzer's back.
   */
  function handleOpen() {
    if (!active) {
      const options: CaptureStartOptions | undefined = modeMeta.filter ? { filter: modeMeta.filter } : undefined
      start(options)
    }
    navigate('/live-monitor?view=analyzer')
  }

  return (
    <LauncherPanel
      title="Start Live Capture"
      description="Monitor IPsec traffic in real time and inspect packets as they arrive."
      icon={Activity}
      aside={
        <span className="flex items-center gap-1.5 text-[11px] text-mist-faint" role="status" aria-live="polite">
          <StatusDot tone={statusTone} pulse={active} size="sm" />
          <span className="hidden sm:inline">{statusLabel}</span>
        </span>
      }
      footer={
        <>
          <Button variant="primary" onClick={handleOpen} disabled={phase === 'stopping'}>
            Open Live Monitor
            <ArrowRight className="size-3.5" aria-hidden />
          </Button>
          {active ? (
            <Button size="sm" variant="ghost" onClick={stop}>
              <Square className="size-3 fill-current" aria-hidden />
              Stop
            </Button>
          ) : null}
          <span className="ml-auto text-[10.5px] text-mist-faint" title="Capture duration">
            {active
              ? formatDuration(durationMs)
              : 'Packets are simulated in the browser — no interface is read in this build.'}
          </span>
        </>
      }
    >
      <div className="flex flex-1 flex-col gap-3">
        <div className="flex flex-col gap-1">
          <label className="label" htmlFor="home-capture-interface">
            Select interface
          </label>
          <div className="relative">
            <select
              id="home-capture-interface"
              value={interfaceName}
              onChange={(event) => setInterfaceName(event.target.value)}
              className="field appearance-none pr-9 font-mono text-[12px]"
            >
              {CAPTURE_INTERFACES.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
            <ChevronDown
              className="pointer-events-none absolute right-3 top-1/2 size-3.5 -translate-y-1/2 text-mist-faint"
              aria-hidden
            />
          </div>
        </div>

        <div className="flex flex-col gap-1">
          <span className="label" id="home-capture-mode-label">
            Capture mode
          </span>
          <div
            role="radiogroup"
            aria-labelledby="home-capture-mode-label"
            className="flex overflow-hidden rounded-[var(--radius-sm)] border border-edge-strong"
          >
            {MODES.map((entry) => {
              const selected = entry.id === mode
              return (
                <button
                  key={entry.id}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  disabled={active}
                  title={active ? 'Stop the capture to change mode' : entry.hint}
                  onClick={() => setRequestedMode(entry.id)}
                  className={cx(
                    'flex flex-1 items-center justify-center gap-1.5 px-2.5 py-[6px] text-[12px] font-medium transition-colors',
                    selected
                      ? 'bg-accent-dim text-accent-300'
                      : 'bg-night-900 text-mist-dim hover:bg-night-800',
                    active && 'cursor-not-allowed opacity-70 hover:bg-night-900',
                  )}
                >
                  <span
                    aria-hidden
                    className={cx(
                      'size-1.5 rounded-full border',
                      selected ? 'border-accent-400 bg-accent-400' : 'border-mist-faint',
                    )}
                  />
                  {entry.label}
                </button>
              )
            })}
          </div>
          <p className="truncate font-mono text-[10.5px] text-mist-faint" title={modeMeta.hint}>
            {modeMeta.filter ?? 'no capture filter'}
          </p>
        </div>

        {/* Live read-out of the running session, so this panel is a status
            surface as well as a launcher. Empty space below the last packet in a
            buffer is the same affordance a packet list gives. */}
        {active ? (
          <dl className="mt-auto flex gap-3 border-t border-edge pt-2.5">
            <Stat label="Packets" value={formatCompact(summary.packetCount)} title="Packets currently buffered" />
            <Stat
              label="IPsec"
              value={formatCompact(summary.ipsecCount)}
              tone="accent"
              title="IKEv2, ESP and AH packets"
            />
            <Stat
              label="High"
              value={formatCompact(summary.highCount + summary.alertCount)}
              tone="warning"
              title="Packets flagged high or critical risk"
            />
          </dl>
        ) : null}
      </div>
    </LauncherPanel>
  )
}
