import type { PacketStream } from './packetService'
import type { Unsubscribe } from '../../types/common'
import type { CaptureState } from '../../types/traffic'

export interface CaptureStartOptions {
  interfaceName?: string
  filter?: string
  /** Seed the store with this many pre-generated packets so the UI starts dense. */
  warmUpPackets?: number
}

/** A running capture session handed back to the UI. */
export interface CaptureSessionHandle {
  readonly sessionId: string
  readonly stream: PacketStream
  stop(): Promise<void>
}

/**
 * Source-agnostic control over an incoming packet stream. The UI must never
 * know whether packets originate from a frontend mock generator, a WebSocket,
 * or a backend API — it only talks to this interface. Swapping the mock
 * implementation for a real transport later requires changing zero UI code.
 */
export interface CaptureService {
  start(options?: CaptureStartOptions): Promise<CaptureSessionHandle>
  stop(sessionId?: string): Promise<void>
  /** Suspend packet emission without ending the session. */
  pause(sessionId?: string): Promise<void>
  /** Resume a paused session. */
  resume(sessionId?: string): Promise<void>
  getState(): CaptureState
  subscribeState(listener: (state: CaptureState) => void): Unsubscribe
}