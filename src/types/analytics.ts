/** Highest-level protocol families shown in the traffic chart / donut. */
export type ProtocolFamily = 'IKEv2' | 'ESP' | 'AH' | 'Other'

/** One time bucket in a rolling traffic window. */
export interface TrafficBin {
  total: number
  ipsec: number
  other: number
}

/** Rolling window of traffic derived from a packet set. */
export interface TrafficWindow {
  bins: TrafficBin[]
  windowBytes: number
  windowPackets: number
  bitsPerSecond: number
  packetsPerSecond: number
  maxBytes: number
}

/**
 * Aggregate volume + security statistics the analyzer derives from a buffered
 * packet set. A real backend can compute these server-side and return the same
 * shape — the UI only depends on this interface.
 */
export interface TrafficStatistics {
  packetCount: number
  byteCount: number
  ipsecCount: number
  highCount: number
  mediumCount: number
  lowCount: number
  alertCount: number
  rate: TrafficWindow
}

/** Per-protocol packet share used by the distribution donut. */
export interface ProtocolDistribution {
  label: ProtocolFamily
  count: number
  /** 0..100 share of total packets. */
  pct: number
}