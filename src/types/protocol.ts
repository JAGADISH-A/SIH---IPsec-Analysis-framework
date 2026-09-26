import type { Packet } from './packet'

/** A single decoded protocol field within a layer, e.g. "Source Address". */
export interface ProtocolField {
  name: string
  /** Human readable key label, e.g. "Source Address". */
  title: string
  /** Raw/decoded value as a string so the UI stays backend-agnostic. */
  value: string
  /** Optional extra context rendered as muted text. */
  note?: string
  /** Whether the value has been resolved/decoded rather than raw. */
  decoded?: boolean
}

/** One protocol layer in the dissection tree (orden from L2 to L7). */
export interface ProtocolLayer {
  id: string
  /** Long protocol name, e.g. "Internet Security Association and Key Management Protocol". */
  name: string
  /** Short display abbreviation, e.g. "IKEv2". */
  abbreviation: string
  /** Stable key used for filtering, e.g. "ikev2". */
  key: string
  summary?: string
  fields: ProtocolField[]
}

export type LayerTone =
  | 'link'
  | 'network'
  | 'transport'
  | 'application'
  | 'ipsec'
  | 'encrypted'

export interface ProtocolLayerMeta {
  tone: LayerTone
  colorVar: string
}

/* ------------------------------------------------------------------ */
/* IPsec specifics                                                     */
/* ------------------------------------------------------------------ */

export type IpsecSecurityProtocol = 'ikev2' | 'esp' | 'ah' | 'esp-null'

export type Ikev2ExchangeType =
  | 'IKE_SA_INIT'
  | 'IKE_SA_AUTH'
  | 'CREATE_CHILD_SA'
  | 'INFORMATIONAL'
  | 'INVALID'

export interface Ikev2Message {
  exchangeType: Ikev2ExchangeType
  exchangeCode: number
  initiatorSpi: string
  responderSpi: string
  messageId: string
  flags: string[]
  length: number
}

export interface Ikev2Proposal {
  number: number
  protocolId: string
  transforms: string[]
}

export interface EncryptionSpec {
  algorithm: string
  keyBitLength: number
  /** Relative cryptographic strength. */
  strength: 'strong' | 'legacy' | 'weak' | 'broken'
}

export interface IntegritySpec {
  algorithm: string
  strength: 'strong' | 'legacy' | 'weak' | 'broken'
}

export interface EspHeader {
  spi: string
  sequenceNumber: number
  nextHeader: string
  encryptionAlgorithm?: string
  integrityAlgorithm?: string
  /** Tunnel encapsulation parameters when ESP is used in tunnel mode. */
  inner?: { source: string; destination: string; protocol: string }
}

export interface AhHeader {
  spi: string
  sequenceNumber: number
  integrityAlgorithm: string
}

export interface IpsecDetails {
  /** Security association mode negotiated for this traffic. */
  mode: 'transport' | 'tunnel'
  /** Security protocols present on this packet. */
  securityProtocols: IpsecSecurityProtocol[]
  encryption?: EncryptionSpec
  integrity?: IntegritySpec
  perfectForwardSecrecy?: boolean
  ikev2?: Ikev2Message
  proposals?: Ikev2Proposal[]
  esp?: EspHeader
  ah?: AhHeader
}

export interface PacketContext {
  packet: Packet
  layers: ProtocolLayer[]
  ipsec?: IpsecDetails
}