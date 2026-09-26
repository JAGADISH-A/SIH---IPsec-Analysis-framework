export interface ProtocolCount {
  protocol: string
  count: number
  bytes: number
  /** 0..1 share of total packets. */
  percentage: number
}

export interface CaptureStatistics {
  captureId: string
  startedAt: string
  durationMs: number
  packetCount: number
  byteCount: number
  packetsPerSecond: number
  bytesPerSecond: number
  averagePacketSize: number
  packetsDropped: number
  byProtocol: ProtocolCount[]
}

export type CaptureStatus =
  | 'idle'
  | 'starting'
  | 'running'
  | 'paused'
  | 'stopping'
  | 'stopped'
  | 'error'

/** Where newly arriving packets are inserted in the display table. */
export type StreamOrder = 'newest-first' | 'newest-last'

export interface CaptureState {
  status: CaptureStatus
  captureId?: string
  /** Physical interface name, e.g. "en0" or "eth0". */
  interfaceName?: string
  filter?: string
  startedAt?: string
  error?: string
}