import type { Timestamped } from './common'
import type { PacketFinding, RiskLevel } from './security'
import type { ProtocolLayer, IpsecDetails } from './protocol'

/** Highest-level classification shown in the packet table. */
export type PacketProtocolName =
  | 'IKEv2'
  | 'ESP'
  | 'AH'
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'DNS'
  | 'TLS'
  | 'HTTP'

/** Summary role a packet plays in an IPsec conversation. */
export type PacketRole =
  | 'normal'
  | 'ike-handshake'
  | 'encrypted'
  | 'anomaly'
  | 'alert'

export interface Packet extends Timestamped {
  /** Stable unique identifier (opaque id assigned by the capture engine). */
  id: string
  /** 1-based capture sequence number displayed in the table. */
  number: number
  source: string
  destination: string
  /** Primary protocol shown in the protocol column. */
  protocol: PacketProtocolName
  /** Raw frame length in bytes, including link-layer header. */
  length: number
  /** One-line description of the packet. */
  info: string
  /** Highest severity finding on this packet, null when clean. */
  risk: RiskLevel | null
  /** Every protocol present, ordered from L2 -> L7. */
  protocolStack: string[]
  role: PacketRole
  /** Security findings raised against this packet (empty when clean). */
  findings: PacketFinding[]
  /** Decoded protocol layers, ordered bottom-up. */
  layers: ProtocolLayer[]
  /** Decoded IPsec-relevant metadata when the packet is IKEv2/ESP/AH. */
  ipsec?: IpsecDetails
}

/** Lightweight row projection kept out of component code for testability. */
export function packetRowText(packet: Packet): string {
  const parts = [packet.protocol, packet.source, packet.destination, packet.length]
  return parts.filter(Boolean).join(' ')
}