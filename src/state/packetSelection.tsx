import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import type { Packet } from '../types/packet'

export interface PacketSelectionValue {
  /** The packet currently selected anywhere in the app (single source of truth). */
  packet: Packet | null
  selectPacket(packet: Packet | null): void
}

const PacketSelectionContext = createContext<PacketSelectionValue | null>(null)

/**
 * App-global "selected packet". The Live Analyzer's packet table drives it;
 * the AI assistant and any future packet-focused surfaces consume it. Kept as
 * an object snapshot so consumers never have to re-resolve by id.
 */
export function PacketSelectionProvider({ children }: { children: ReactNode }) {
  const [packet, setPacket] = useState<Packet | null>(null)
  const selectPacket = useCallback((next: Packet | null) => setPacket(next), [])

  const value = useMemo<PacketSelectionValue>(() => ({ packet, selectPacket }), [packet, selectPacket])

  return <PacketSelectionContext.Provider value={value}>{children}</PacketSelectionContext.Provider>
}

export function usePacketSelection(): PacketSelectionValue {
  const value = useContext(PacketSelectionContext)
  if (!value) {
    throw new Error('usePacketSelection must be used within a PacketSelectionProvider')
  }
  return value
}