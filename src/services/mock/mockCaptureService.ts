import type { Unsubscribe } from '../../types/common'
import type { CaptureState } from '../../types/traffic'
import type {
  CaptureService,
  CaptureSessionHandle,
  CaptureStartOptions,
} from '../api/captureService'
import type { MockPacketService } from './mockPacketService'
import { MockPacketGenerator } from './mockPacketGenerator'
import { SimpleEmitter } from './tools'

/**
 * Simulated packet stream. Drives a MockPacketGenerator on a timer and feeds
 * the packet store, publishing lifecycle state. This is the frontend-only
 * stand-in for a real capture transport: a later WebSocket or backend-backed
 * implementation of `CaptureService` replaces this class without UI changes.
 */
export class MockCaptureService implements CaptureService {
  private state: CaptureState = { status: 'idle' }
  private stateEmitter = new SimpleEmitter<CaptureState>()
  private timer: ReturnType<typeof setInterval> | null = null
  private generator: MockPacketGenerator | null = null
  private activeSession: CaptureSessionHandle | null = null
  private readonly packeter: MockPacketService

  constructor(packeter: MockPacketService) {
    this.packeter = packeter
  }

  getState(): CaptureState {
    return this.state
  }

  subscribeState(listener: (state: CaptureState) => void): Unsubscribe {
    return this.stateEmitter.subscribe(listener)
  }

  private currentId(): string | undefined {
    return this.state.captureId
  }

  private isOwned(targetId: string | undefined): boolean {
    if (!targetId) return true
    return this.state.captureId === targetId
  }

  async start(options?: CaptureStartOptions): Promise<CaptureSessionHandle> {
    if (this.timer || this.generator) {
      throw new Error('A packet stream is already running')
    }
    this.setState({ status: 'starting', interfaceName: options?.interfaceName, filter: options?.filter })
    await new Promise((resolve) => setTimeout(resolve, 450))

    const sessionId = `cap-${Date.now().toString(36)}`
    this.generator = new MockPacketGenerator({ startIso: new Date().toISOString() })

    this.setState({
      status: 'running',
      captureId: sessionId,
      interfaceName: options?.interfaceName ?? 'eth0',
      filter: options?.filter,
      startedAt: new Date().toISOString(),
    })

    if (options?.warmUpPackets) {
      for (let i = 0; i < options.warmUpPackets; i += 1) {
        this.packeter.ingest(this.generator.next())
      }
    }

    this.startTicking()

    this.activeSession = {
      sessionId,
      stream: this.packeter.stream,
      stop: () => this.stop(sessionId),
    }
    return this.activeSession
  }

  async pause(sessionId?: string): Promise<void> {
    if (!this.isOwned(sessionId ?? this.currentId())) return
    if (this.state.status !== 'running') return
    this.stopTicking()
    this.setState({ ...this.state, status: 'paused' })
  }

  async resume(sessionId?: string): Promise<void> {
    if (!this.isOwned(sessionId ?? this.currentId())) return
    if (this.state.status !== 'paused') return
    this.setState({ ...this.state, status: 'running' })
    if (this.generator) this.startTicking()
  }

  async stop(sessionId?: string): Promise<void> {
    const targetId = sessionId ?? this.currentId()
    if (!this.isOwned(targetId)) return
    if (this.state.status === 'idle' || this.state.status === 'stopping') return
    const wasActive = this.state.status === 'running' || this.state.status === 'starting' || this.state.status === 'paused'
    this.setState({ status: wasActive ? 'stopping' : 'stopped', captureId: targetId })
    this.stopTicking()
    this.generator = null
    this.activeSession = null
    await new Promise((resolve) => setTimeout(resolve, 250))
    if (this.state.captureId === targetId) {
      this.setState({ status: 'idle' })
    }
  }

  /** Emit 1-3 packets per tick — a stand-in for a live bus. */
  private startTicking(): void {
    this.stopTicking()
    this.timer = setInterval(() => {
      const burst = 1 + Math.floor(Math.random() * 3)
      for (let i = 0; i < burst; i += 1) {
        if (this.generator) this.packeter.ingest(this.generator.next())
      }
    }, 320)
  }

  private stopTicking(): void {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
  }

  private setState(state: CaptureState): void {
    this.state = state
    this.stateEmitter.emit(state)
  }
}