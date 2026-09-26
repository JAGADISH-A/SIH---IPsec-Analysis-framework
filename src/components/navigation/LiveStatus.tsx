import { cx } from '../../lib/cx'
import { useCaptureStatus } from '../../hooks/useCapture'
import type { CaptureState } from '../../types/traffic'
import { StatusDot } from '../common/StatusDot.tsx'

function toneFor(status: CaptureState['status']): 'accent' | 'info' | 'warning' | 'danger' {
  switch (status) {
    case 'running':
      return 'accent'
    case 'starting':
    case 'stopping':
    case 'paused':
      return 'warning'
    case 'error':
      return 'danger'
    default:
      return 'info'
  }
}

function labelFor(state: CaptureState): string {
  switch (state.status) {
    case 'running':
      return `Capturing · ${state.interfaceName ?? 'eth0'}`
    case 'starting':
      return 'Starting capture…'
    case 'paused':
      return 'Capture paused'
    case 'stopping':
      return 'Stopping capture…'
    case 'stopped':
      return 'Capture stopped'
    case 'error':
      return 'Capture error'
    default:
      return 'Capture idle'
  }
}

/** Mirrors the live capture lifecycle from the top navigation. */
export function LiveStatus() {
  const state = useCaptureStatus()

  const active = state.status === 'running' || state.status === 'starting'

  return (
    <span
      className={cx(
        'inline-flex items-center gap-2 rounded-full border border-edge px-2.5 py-1 text-xs font-medium',
        active ? 'bg-accent-dim text-accent-300' : 'bg-night-800 text-mist-dim',
      )}
      title="Live capture status"
    >
      <StatusDot tone={toneFor(state.status)} pulse={active} size="sm" />
      <span className="hidden sm:inline">{labelFor(state)}</span>
    </span>
  )
}