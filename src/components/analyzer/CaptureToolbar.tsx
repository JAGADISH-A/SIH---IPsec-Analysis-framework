import { Activity, ChevronDown, Pause, Play, Radio, Square, Trash2 } from 'lucide-react'
import { cx } from '../../lib/cx'
import { formatBitsPerSecond, formatCompact, formatDuration } from '../../lib/format'
import { CAPTURE_INTERFACES, useCaptureStore } from '../../state/capture.tsx'
import { useSearchFilter } from '../../state/searchFilter.tsx'
import type { CaptureState, StreamOrder } from '../../types/traffic'

type Phase = 'running' | 'paused' | 'starting' | 'stopping' | 'stopped' | 'error'

function phaseOf(state: CaptureState): Phase {
  switch (state.status) {
    case 'running':
      return 'running'
    case 'paused':
      return 'paused'
    case 'starting':
      return 'starting'
    case 'stopping':
      return 'stopping'
    case 'error':
      return 'error'
    default:
      return 'stopped'
  }
}

const PHASE_META: Record<
  Phase,
  { label: string; dot: string; pulse: boolean; text: string }
> = {
  running: { label: 'Capturing packets…', dot: 'var(--color-ws-esp)', pulse: true, text: 'var(--color-ws-esp)' },
  starting: { label: 'Starting capture…', dot: 'var(--color-ws-medium)', pulse: true, text: 'var(--color-ws-medium)' },
  paused: { label: 'Capture paused', dot: 'var(--color-ws-medium)', pulse: false, text: 'var(--color-ws-medium)' },
  stopping: { label: 'Stopping capture…', dot: 'var(--color-ws-medium)', pulse: true, text: 'var(--color-ws-medium)' },
  stopped: { label: 'Capture stopped', dot: 'var(--color-ws-faint)', pulse: false, text: 'var(--color-ws-dim)' },
  error: { label: 'Capture error', dot: 'var(--color-ws-critical)', pulse: false, text: 'var(--color-ws-critical)' },
}

const ORDER_OPTIONS: { value: StreamOrder; label: string; hint: string }[] = [
  { value: 'newest-first', label: 'Newest first', hint: 'Newest packets at the top of the list' },
  { value: 'newest-last', label: 'Newest last', hint: 'Newest packets appended at the bottom' },
]

function Stat({
  label,
  value,
  tone,
  title,
}: {
  label: string
  value: string
  tone?: 'critical' | 'high' | 'medium' | 'accent'
  title?: string
}) {
  return (
    <div className="ws-stat" title={title}>
      <span className="ws-stat-label">{label}</span>
      <span className="ws-stat-value" data-tone={tone}>
        {value}
      </span>
    </div>
  )
}

function CaptureDot({ color, pulse }: { color: string; pulse: boolean }) {
  return (
    <span
      aria-hidden
      className={cx('inline-block size-2 shrink-0 rounded-full', pulse && 'animate-pulse-dot')}
      style={{ background: color }}
    />
  )
}

/**
 * Capture toolbar — the first strip under the navigation. Left to right: the
 * capture lifecycle controls, the interface selector, the live status, then a
 * compact statistics readout.
 *
 * These are analyzer readouts (label above value, hairline separators), not
 * marketing cards: the whole bar is 38px tall so the packet stream keeps the
 * vertical space.
 */
export function CaptureToolbar({ onClear }: { onClear(): void }) {
  const {
    capture,
    summary,
    now,
    order,
    setOrder,
    interfaceName,
    setInterfaceName,
    start,
    stop,
    pause,
    resume,
    packets,
  } = useCaptureStore()
  const { isOpen: filterOpen, toggle: toggleFilter, hasQuery } = useSearchFilter()

  const phase = phaseOf(capture)
  const meta = PHASE_META[phase]
  const active = phase === 'running' || phase === 'starting'
  const durationMs = capture.startedAt ? Math.max(0, now - new Date(capture.startedAt).getTime()) : 0

  return (
    <div className="ws-bar ws-bar-raised" role="toolbar" aria-label="Capture controls">
      {/* Lifecycle */}
      {active ? (
        <>
          <button
            type="button"
            className="ws-btn"
            onClick={pause}
            disabled={phase === 'starting'}
            title="Stop emitting packets but keep the session open"
          >
            <Pause className="size-3.5" aria-hidden />
            Pause
          </button>
          <button type="button" className="ws-btn ws-btn-danger" onClick={stop}>
            <Square className="size-3 fill-current" aria-hidden />
            Stop
          </button>
        </>
      ) : phase === 'paused' ? (
        <>
          <button type="button" className="ws-btn ws-btn-primary" onClick={resume}>
            <Play className="size-3.5" aria-hidden />
            Resume
          </button>
          <button type="button" className="ws-btn ws-btn-danger" onClick={stop}>
            <Square className="size-3 fill-current" aria-hidden />
            Stop
          </button>
        </>
      ) : (
        <button
          type="button"
          className="ws-btn ws-btn-primary"
          onClick={() => start()}
          disabled={phase === 'stopping'}
        >
          <Play className="size-3.5" aria-hidden />
          Start Capture
        </button>
      )}

      <button
        type="button"
        className="ws-btn"
        onClick={onClear}
        disabled={packets.length === 0}
        title="Discard the buffered packets"
      >
        <Trash2 className="size-3.5" aria-hidden />
        Clear
      </button>

      {/* Interface selector */}
      <div className="relative ml-1 w-[112px] shrink-0">
        <select
          value={interfaceName}
          onChange={(event) => setInterfaceName(event.target.value)}
          aria-label="Capture interface"
          title="Capture interface"
          className="ws-select pr-6"
        >
          {CAPTURE_INTERFACES.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        <ChevronDown
          className="pointer-events-none absolute right-1.5 top-1/2 size-3 -translate-y-1/2 text-ws-faint"
          aria-hidden
        />
      </div>

      {/* Status */}
      <div className="flex min-w-0 items-center gap-2" role="status" aria-live="polite">
        <CaptureDot color={meta.dot} pulse={meta.pulse} />
        <span className="truncate text-[12px] font-semibold" style={{ color: meta.text }}>
          {meta.label}
        </span>
        <span className="ws-chip" title="Capture duration">
          <span className="mono-tab">{formatDuration(durationMs)}</span>
        </span>
        <span className="ws-chip hidden lg:inline-flex" title="Packets are simulated in the browser — no real interface is read">
          <Radio className="size-3" aria-hidden />
          simulated
        </span>
      </div>

      {/* Live statistics */}
      <div className="ml-auto flex items-center">
        <Stat label="Packets" value={formatCompact(summary.packetCount)} title="Packets currently buffered" />
        <Stat
          label="Rate"
          value={formatBitsPerSecond(summary.rate.bitsPerSecond)}
          tone="accent"
          title={`${summary.rate.packetsPerSecond.toFixed(0)} packets/second over the last 20 seconds`}
        />
        <Stat label="IPsec" value={formatCompact(summary.ipsecCount)} title="IKEv2, ESP and AH packets" />
        <Stat
          label="High"
          value={formatCompact(summary.highCount + summary.alertCount)}
          tone="high"
          title="Packets flagged high or critical risk"
        />
        <Stat
          label="Medium"
          value={formatCompact(summary.mediumCount)}
          tone="medium"
          title="Packets flagged medium risk"
        />
      </div>

      {/* Display filter toggle (mirrors the magnifier in the top nav) */}
      <button
        type="button"
        className={cx('ws-btn ws-btn-ghost', (filterOpen || hasQuery) && 'ws-btn-active')}
        onClick={toggleFilter}
        aria-expanded={filterOpen}
        title="Display filter (Ctrl+K)"
      >
        <Activity className="size-3.5" aria-hidden />
        <span className="hidden xl:inline">Filter</span>
      </button>

      {/* Stream order */}
      <div className="flex shrink-0 overflow-hidden rounded-[3px] border border-ws-line-strong" role="group" aria-label="Stream order">
        {ORDER_OPTIONS.map((option) => (
          <button
            key={option.value}
            type="button"
            onClick={() => setOrder(option.value)}
            aria-pressed={order === option.value}
            title={option.hint}
            className={cx(
              'h-[24px] px-2 text-[10.5px] font-semibold transition-colors',
              order === option.value
                ? 'bg-ws-accent text-white'
                : 'bg-ws-panel text-ws-dim hover:bg-ws-hover',
            )}
          >
            {option.label}
          </button>
        ))}
      </div>
    </div>
  )
}
