import { useCallback } from 'react'
import { services } from '../services'
import type { FilterService, FilterValidation } from '../services/api/filterService'
import type { Packet } from '../types/packet'

/**
 * Packet-filter evaluation bound to the `FilterService` interface (a
 * Wireshark-inspired subset today, a backend filter engine later).
 */
export function usePacketFilter(filterService: FilterService = services.filter) {
  const matches = useCallback(
    (packet: Packet, expression: string | null) => filterService.matches(packet, expression),
    [filterService],
  )

  const validate = useCallback(
    (expression: string): FilterValidation => filterService.validate(expression),
    [filterService],
  )

  return { matches, validate }
}