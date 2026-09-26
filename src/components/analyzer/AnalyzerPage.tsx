import { RefreshCw, WifiOff } from 'lucide-react'
import { useCaptureStore } from '../../state/capture.tsx'
import { usePacketSelection } from '../../state/packetSelection.tsx'
import { CaptureToolbar } from './CaptureToolbar.tsx'
import { DisplayFilterBar } from './DisplayFilterBar.tsx'
import { PacketTable } from './PacketTable.tsx'

/**
 * Live Analyzer — the application workspace.
 *
 * The page is a single full-height column with no outer page padding, no hero
 * block and no centred wrapper:
 *
 *   TOP NAV
 *     ↓
 *   CAPTURE TOOLBAR
 *     ↓
 *   DISPLAY FILTER   (collapsed by default, expands in place)
 *     ↓
 *   PACKET TABLE     (takes every remaining pixel, scrolls on its own)
 *     ↓  click a row
 *   INLINE PACKET DETAIL (expands directly under that row)
 *
 * All state comes from the app-wide capture store, which talks to the
 * transport-agnostic service interfaces rather than to mock classes directly.
 */
export function AnalyzerPage() {
  const { capture, packets, interfaceName, loading, unavailable, start, clear } = useCaptureStore()
  const { selectPacket } = usePacketSelection()

  // Clearing the buffer also drops the expanded packet, otherwise the detail
  // block would linger pinned above an empty list.
  const handleClear = () => {
    clear()
    selectPacket(null)
  }

  if (unavailable) {
    return (
      <div className="ws flex h-full flex-col">
        <CaptureUnavailable message={capture.error} onRetry={() => start()} />
      </div>
    )
  }

  return (
    <div className="ws flex h-full min-h-0 flex-col overflow-hidden">
      <CaptureToolbar onClear={handleClear} />
      <DisplayFilterBar />
      <PacketTable
        packets={packets}
        interfaceName={interfaceName}
        captureStatus={capture.status}
        onStartCapture={() => start()}
        loading={loading}
        arrivalTick={packets.length}
      />
    </div>
  )
}

function CaptureUnavailable({ message, onRetry }: { message?: string; onRetry: () => void }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 px-6 text-center" role="alert">
      <span className="flex size-10 items-center justify-center rounded-[3px] border border-ws-critical bg-ws-critical-dim text-ws-critical">
        <WifiOff className="size-4" aria-hidden />
      </span>
      <div>
        <div className="text-[13px] font-semibold text-ws-text">Capture connection unavailable</div>
        <div className="mx-auto mt-1 max-w-sm text-[11.5px] text-ws-dim">
          {message ?? 'The capture service could not be reached. Reconnect to resume monitoring.'}
        </div>
      </div>
      <button type="button" className="ws-btn ws-btn-primary" onClick={onRetry}>
        <RefreshCw className="size-3.5" aria-hidden />
        Reconnect
      </button>
    </div>
  )
}
