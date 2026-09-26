import type { Packet } from '../types/packet'

/** Human-readable IPsec posture for a packet, shared by the AI drawer and
 * the mocked analysis engine so both describe the packet consistently. */
export interface PacketIpsecSummary {
  /** Display names of the security protocols present (e.g. "ESP", "AH", "ESP-NULL"). */
  securityProtocols: string[]
  /** Human label for the negotiated encryption transform, e.g. "AES-GCM-256". */
  encryption?: string
  /** Human label for the integrity transform, e.g. "HMAC-SHA2-256". */
  integrity?: string
  /** SA parameter index literal, e.g. "0x1a2b3c4d" or IKEv2 "0x… / 0x…". */
  spi?: string
  /** Key size in bits when negotiated (IKE/AH packets). */
  keyBits?: string
  mode?: 'transport' | 'tunnel'
  pfs?: boolean
}

const ENCR_LABEL: Record<string, string> = {
  'ENCR_AES_GCM_16 (24)': 'AES-GCM-256',
  'AES-GCM-256': 'AES-GCM-256',
  'ENCR_AES_CBC (12)': 'AES-128-CBC',
  'ENCR_3DES_CBC (3)': '3DES-CBC',
  'ENCR_DES (2)': 'DES',
  ESP_NULL: 'ESP-NULL',
}

const INTEG_LABEL: Record<string, string> = {
  'AUTH_HMAC_SHA2_256_128 (12)': 'HMAC-SHA2-256',
  'AUTH_HMAC_SHA1_96 (3)': 'HMAC-SHA1-96',
  'AUTH_HMAC_MD5_96 (2)': 'HMAC-MD5-96',
}

function label(map: Record<string, string>, raw: string): string {
  return map[raw] ?? raw
}

export function packetIpsecSummary(packet: Packet): PacketIpsecSummary {
  const ipsec = packet.ipsec
  if (!ipsec) return { securityProtocols: [] }

  const securityProtocols = ipsec.securityProtocols.map((protocol) =>
    protocol === 'esp-null' ? 'ESP-NULL' : protocol.toUpperCase(),
  )

  const encryptionRaw = ipsec.encryption?.algorithm ?? ipsec.esp?.encryptionAlgorithm ?? ''
  const integrityRaw =
    ipsec.integrity?.algorithm ?? ipsec.esp?.integrityAlgorithm ?? ipsec.ah?.integrityAlgorithm ?? ''

  return {
    securityProtocols,
    encryption: encryptionRaw ? label(ENCR_LABEL, encryptionRaw) : undefined,
    integrity: integrityRaw ? label(INTEG_LABEL, integrityRaw) : undefined,
    spi: ipsec.ikev2
      ? `0x${ipsec.ikev2.initiatorSpi} / 0x${ipsec.ikev2.responderSpi}`
      : ipsec.esp
        ? `0x${ipsec.esp.spi}`
        : ipsec.ah
          ? `0x${ipsec.ah.spi}`
          : undefined,
    keyBits: ipsec.encryption?.keyBitLength != null ? String(ipsec.encryption.keyBitLength) : undefined,
    mode: ipsec.mode,
    pfs: ipsec.perfectForwardSecrecy,
  }
}