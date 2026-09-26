import type { Unsubscribe } from '../../types/common'
import type {
  PCAPAnalysis,
  PcapFileInfo,
  PcapProcessingStage,
  PcapUploadHandle,
  PcapUploadState,
} from '../../types/pcap'
import type { PcapService } from '../api/pcapService'
import { SimpleEmitter, mulberry32 } from './tools'

interface StageSpec {
  stage: PcapProcessingStage
  percent: number
  message: string
  durationMs: number
}

/** Simulated pipeline. Two analyzing emissions read as "Extracting IPsec
 * protocols…" then "Running security analysis…" in the UI stepper. */
const STAGES: readonly StageSpec[] = [
  { stage: 'uploading', percent: 12, message: 'Uploading…', durationMs: 700 },
  { stage: 'validating', percent: 26, message: 'Verifying capture header…', durationMs: 500 },
  { stage: 'parsing', percent: 48, message: 'Parsing packets…', durationMs: 950 },
  { stage: 'analyzing', percent: 68, message: 'Extracting IPsec protocols…', durationMs: 800 },
  { stage: 'analyzing', percent: 88, message: 'Running security analysis…', durationMs: 900 },
  { stage: 'complete', percent: 100, message: 'Complete', durationMs: 0 },
]

/* ------------------------------------------------------------------ */
/* Deterministic result derivation (no real parsing yet).              */
/* ------------------------------------------------------------------ */

function hashString(value: string): number {
  let hash = 2166136261
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return hash >>> 0
}

const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value))

function deriveResult(file: PcapFileInfo): PCAPAnalysis {
  const rand = mulberry32(hashString(`${file.name}:${file.sizeBytes}:ipsec-sentinel`))

  // Bigger file ⇒ more packets, with stable per-file variation.
  const base = clamp(Math.round(file.sizeBytes / 190), 350, 60000)
  const packetsAnalyzed = Math.round(base * (0.82 + rand() * 0.36))

  const ipsecPackets = Math.round(packetsAnalyzed * (0.34 + rand() * 0.18))
  const ikev2 = Math.round(ipsecPackets * (0.17 + rand() * 0.09))
  const esp = Math.round(ipsecPackets * (0.55 + rand() * 0.14))
  const ah = Math.round(ipsecPackets * (0.08 + rand() * 0.06))
  const highRisk = Math.round(ipsecPackets * (0.05 + rand() * 0.06))
  const mediumRisk = Math.round(ipsecPackets * (0.11 + rand() * 0.09))

  return {
    fileName: file.name,
    packetsAnalyzed,
    ipsecPackets,
    ikev2,
    esp,
    ah,
    highRisk,
    mediumRisk,
  }
}

/* ------------------------------------------------------------------ */
/* Upload handle                                                      */
/* ------------------------------------------------------------------ */

class MockUploadHandle implements PcapUploadHandle {
  private state: PcapUploadState
  private emitter = new SimpleEmitter<PcapUploadState>()
  private timer: ReturnType<typeof setTimeout> | null = null
  private cancelled = false

  constructor(file: PcapFileInfo) {
    this.state = {
      file,
      stage: 'uploading',
      percent: 0,
      message: 'Initializing upload…',
    }
    this.advance(0)
  }

  subscribe(listener: (state: PcapUploadState) => void): Unsubscribe {
    return this.emitter.subscribe(listener)
  }

  getSnapshot(): PcapUploadState {
    return this.state
  }

  cancel(): void {
    this.cancelled = true
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = null
    }
    this.publish({ stage: 'error', percent: this.state.percent, message: 'Upload cancelled' })
  }

  private advance(index: number): void {
    if (this.cancelled || index >= STAGES.length) {
      if (!this.cancelled && this.state.stage !== 'complete') {
        this.publish(STAGES[STAGES.length - 1])
      }
      return
    }
    const spec = STAGES[index]
    this.publish(spec)
    if (spec.durationMs > 0) {
      this.timer = setTimeout(() => this.advance(index + 1), spec.durationMs)
    }
  }

  private publish(spec: Pick<PcapUploadState, 'stage' | 'percent' | 'message'>): void {
    const result =
      spec.stage === 'complete' && !this.state.result ? deriveResult(this.state.file) : this.state.result
    this.state = { ...this.state, ...spec, ...(result ? { result } : {}) }
    this.emitter.emit(this.state)
  }
}

/** Simulated end-to-end PCAP processing (no real parsing yet — a real
 * backend replaces this class behind the same `PcapService` contract). */
export class MockPcapService implements PcapService {
  startUpload(file: File): PcapUploadHandle {
    return new MockUploadHandle({
      name: file.name,
      sizeBytes: file.size,
      type: file.type,
    })
  }
}