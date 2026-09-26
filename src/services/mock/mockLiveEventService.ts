import type { LiveEventService } from '../api/liveEventService'
import type { LiveEvent, LiveEventType, LiveMonitorSnapshot } from '../../types/events'
import { LIVE_EVENT_LABEL } from '../../types/events'
import { mockDataset } from './mockData'
import { SimpleEmitter } from './tools'

/**
 * Mock live event source.
 *
 * Emits a rolling window of the dataset's events on a timer, exactly as a
 * WebSocket relay would. Nothing above this class knows it is a timer, so the
 * live monitor code is already written for the real transport.
 */
export class MockLiveEventService implements LiveEventService {
  private readonly emitter = new SimpleEmitter<LiveEvent>()
  private timer: number | null = null
  private intervalMs = 2_600
  private cursor = 0
  private readonly recent: LiveEvent[] = []
  private readonly counters = new Map<LiveEventType, number>()
  private activeSessions = 0
  private packetsPerSecond = 0
  private bytesPerSecond = 0

  constructor() {
    this.seed()
  }

  subscribe(listener: (event: LiveEvent) => void): () => void {
    this.ensureRunning()
    return this.emitter.subscribe(listener)
  }

  async getSnapshot(): Promise<LiveMonitorSnapshot> {
    const events = mockDataset.sessions.filter(
      (session) => session.status === 'active' || session.status === 'rekeying',
    )
    this.activeSessions = events.length
    return {
      activeSessions: this.activeSessions,
      packetsPerSecond: this.packetsPerSecond,
      bytesPerSecond: this.bytesPerSecond,
      lastEventAt: this.recent.at(-1)?.timestamp ?? null,
      captureStatus: 'Capturing',
      captureId: 'CAP-LIVE',
      interfaceName: 'eth1',
      monitoringStatus: 'monitoring',
      eventsPerMinute: this.recent.filter(
        (event) => Date.now() - Date.parse(event.timestamp) < 60_000,
      ).length,
      eventBreakdown: [...this.counters.entries()]
        .map(([type, count]) => ({ type, label: LIVE_EVENT_LABEL[type], count }))
        .sort((a, b) => b.count - a.count),
      updatedAt: new Date().toISOString(),
    }
  }

  setInterval(ms: number): void {
    this.intervalMs = Math.max(250, ms)
    if (this.timer !== null) {
      window.clearInterval(this.timer)
      this.timer = null
      this.ensureRunning()
    }
  }

  /** Prime counters and rate estimates from the static dataset. */
  private seed(): void {
    const events = mockDataset.liveEvents(60)
    for (const event of events.slice(-20)) {
      this.counters.set(event.type, (this.counters.get(event.type) ?? 0) + 1)
    }
    this.packetsPerSecond = 118 + (mockDataset.now % 40)
    this.bytesPerSecond = this.packetsPerSecond * 812
  }

  private ensureRunning(): void {
    if (this.timer !== null) return
    this.timer = window.setInterval(() => {
      const events = mockDataset.liveEvents(64)
      if (events.length === 0) return
      this.cursor = (this.cursor + 1) % events.length
      const event = events[this.cursor]
      if (!event) return
      this.counters.set(event.type, (this.counters.get(event.type) ?? 0) + 1)
      this.recent.push(event)
      if (this.recent.length > 60) this.recent.shift()
      this.packetsPerSecond = 60 + Math.round(Math.abs(Math.sin(this.cursor / 3)) * 220)
      this.bytesPerSecond = this.packetsPerSecond * 780
      this.emitter.emit(event)
    }, this.intervalMs)
  }
}
