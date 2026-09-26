import type { Unsubscribe } from '../../types/common'
import type { Packet } from '../../types/packet'

export interface PacketQuery {
  filter?: string
  cursor?: string
  limit?: number
}

export interface PacketPage {
  items: Packet[]
  total: number
  nextCursor: string | null
}

/** Evented stream of packets arriving into the UI in real time. */
export interface PacketStream {
  subscribe(listener: (packet: Packet) => void): Unsubscribe
}

/**
 * Query API over a packet store (live capture, PCAP archive, or backend).
 * Swappable: mock implementations live in services/mock, real HTTP/WebSocket
 * implementations implement the same contract.
 */
export interface PacketService {
  readonly stream: PacketStream
  query(params: PacketQuery): Promise<PacketPage>
  getById(id: string): Promise<Packet | null>
  /** Remove every buffered packet (used by the "clear capture" action). */
  clear(): void
}