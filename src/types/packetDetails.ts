/** One decoded key/value row rendered in the packet detail panel. */
export interface DetailRow {
  title: string
  value: string
  note?: string
}

/** A 16-bytes-per-line hex dump row for the Raw Packet tab. */
export interface HexLine {
  offset: string
  /** 16 hex bytes, grouped 8 + 8 for readability. */
  hex: string
  /** Printable-ASCII rendering of the same bytes. */
  ascii: string
}

/**
 * Fully-constructed payload for a packet's inline detail panel. Built by a
 * pure helper (`buildPacketDetails`) from a decoded packet; a real backend can
 * return the same shape directly so the UI never depends on mock generation.
 */
export interface PacketDetails {
  /** Frame-level summary rows (Overview tab). */
  overview: DetailRow[]
  /** IPsec-specific rows (Protocol Details tab). */
  protocols: DetailRow[]
  /** Deterministic byte dump (Raw Packet tab). */
  hex: HexLine[]
}