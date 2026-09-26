import type { Unsubscribe } from '../../types/common'
import type { Packet } from '../../types/packet'
import type {
  PacketService,
  PacketQuery,
  PacketPage,
  PacketStream,
} from '../api/packetService'
import { SimpleEmitter } from './tools'

/** Packets retained by the service before the oldest are overwritten. */
export const SERVICE_RING_BUFFER = 8192

function matchesFilter(packet: Packet, needle: string): boolean {
  return (
    packet.protocol.toLowerCase().includes(needle) ||
    packet.source.toLowerCase().includes(needle) ||
    packet.destination.toLowerCase().includes(needle) ||
    packet.info.toLowerCase().includes(needle) ||
    packet.protocolStack.some((p) => p.toLowerCase().includes(needle))
  )
}

/**
 * In-memory packet store feeding live UI. A real backend service will
 * implement the same PacketService contract.
 */
export class MockPacketService implements PacketService {
  private readonly store: Packet[] = []
  private readonly emitter = new SimpleEmitter<Packet>()

  get stream(): PacketStream {
    return this.emitter
  }

  ingest(packet: Packet): void {
    this.store.push(packet)
    if (this.store.length > SERVICE_RING_BUFFER) {
      this.store.splice(0, this.store.length - SERVICE_RING_BUFFER)
    }
    this.emitter.emit(packet)
  }

  async query(params: PacketQuery = {}): Promise<PacketPage> {
    const limit = params.limit ?? 200
    const start = params.cursor ? Number.parseInt(params.cursor, 36) || 0 : 0
    const base = params.filter ? this.store.filter((p) => matchesFilter(p, params.filter!.trim().toLowerCase())) : this.store
    const items = base.slice(start, start + limit)
    const reached = start + items.length < base.length
    return {
      items,
      total: base.length,
      nextCursor: reached ? (start + items.length).toString(36) : null,
    }
  }

  async getById(id: string): Promise<Packet | null> {
    return this.store.find((p) => p.id === id) ?? null
  }

  clear(): void {
    this.store.length = 0
  }

  subscribe(listener: (packet: Packet) => void): Unsubscribe {
    return this.emitter.subscribe(listener)
  }
}