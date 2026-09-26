import type { LiveEvent, LiveMonitorSnapshot } from '../../types/events'
import type { Unsubscribe } from '../../types/common'

/**
 * Live analysis events.
 *
 * The subscription contract is deliberately transport-shaped rather than
 * socket-shaped: a mock implementation emits on a timer, a real one relays
 * WebSocket or SSE frames. Consumers only ever see `LiveEvent`.
 */
export interface LiveEventService {
  /** Start receiving events. Returns the teardown function. */
  subscribe(listener: (event: LiveEvent) => void): Unsubscribe
  getSnapshot(): Promise<LiveMonitorSnapshot>
  /** Set emission rate for the mock; ignored by real transports. */
  setInterval(ms: number): void
}
