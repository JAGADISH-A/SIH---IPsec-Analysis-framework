import { useEffect, useState } from 'react'
import { services } from '../services'
import type { CaptureService } from '../services/api/captureService'
import type { CaptureState } from '../types/traffic'

/**
 * Read-only mirror of the capture lifecycle for surfaces that only need the
 * status (the top navigation badge). The full packet buffer and controls live
 * in the app-wide `CaptureProvider` — see `src/state/capture.tsx`.
 */
export function useCaptureStatus(captureService: CaptureService = services.capture): CaptureState {
  const [state, setState] = useState<CaptureState>(() => captureService.getState())
  useEffect(() => captureService.subscribeState(setState), [captureService])
  return state
}
