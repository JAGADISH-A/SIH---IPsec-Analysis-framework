import type { Packet } from '../types/packet'
import type { DetailRow, HexLine, PacketDetails } from '../types/packetDetails'
import { formatArrivalTime } from './format'

/* ------------------------------------------------------------------ */
/* Pure presentation helpers for the inline packet detail panel.       */
/* Kept out of components so the UI stays thin.                        */
/* ------------------------------------------------------------------ */

/** Overview tab rows — the frame-level summary the user asked for. */
export function overviewRows(packet: Packet, interfaceName: string): DetailRow[] {
  return [
    { title: 'Frame length', value: `${packet.length} bytes` },
    { title: 'Interface', value: interfaceName },
    { title: 'Arrival time', value: formatArrivalTime(packet.timestamp) },
    { title: 'Source', value: packet.source },
    { title: 'Destination', value: packet.destination },
    { title: 'Protocol', value: packet.protocol },
    { title: 'Length', value: `${packet.length} bytes` },
  ]
}

/**
 * IPsec-specific fields for the Protocol Details tab, derived from the
 * decoded `packet.ipsec` metadata. Empty for non-IPsec packets.
 *
 * - ESP: SPI, Sequence Number, Payload Length, Next Header (+ SA params)
 * - IKEv2: Exchange Type, Initiator/Responder SPI, Security Association,
 *          Encryption, Integrity, DH Group
 * - AH: SPI, Sequence Number, Authentication Data, Next Header
 */
export function ipsecDetailRows(packet: Packet): DetailRow[] {
  const ipsec = packet.ipsec
  if (!ipsec) return []
  const rows: DetailRow[] = []

  if (packet.protocol === 'IKEv2' && ipsec.ikev2) {
    const msg = ipsec.ikev2
    const proposal = ipsec.proposals?.[0]
    const transforms = proposal?.transforms ?? []
    rows.push({ title: 'Exchange Type', value: msg.exchangeType })
    rows.push({ title: 'Exchange Code', value: String(msg.exchangeCode) })
    rows.push({ title: 'Initiator SPI', value: msg.initiatorSpi })
    rows.push({ title: 'Responder SPI', value: msg.responderSpi })
    rows.push({ title: 'Message ID', value: msg.messageId })
    rows.push({ title: 'Flags', value: msg.flags.length > 0 ? msg.flags.join(' · ') : '—' })
    rows.push({
      title: 'Security Association',
      value: proposal
        ? `${proposal.protocolId}: ${proposal.transforms.join(' · ')}`
        : ipsec.encryption?.algorithm ?? '—',
    })
    rows.push({
      title: 'Encryption',
      value: ipsec.encryption?.algorithm ?? transforms[0] ?? '—',
      note: ipsec.encryption ? `${ipsec.encryption.keyBitLength}-bit · ${ipsec.encryption.strength}` : undefined,
    })
    rows.push({
      title: 'Integrity',
      value: ipsec.integrity?.algorithm ?? transforms[2] ?? '—',
      note: ipsec.integrity ? ipsec.integrity.strength : undefined,
    })
    rows.push({
      title: 'DH Group',
      value: transforms[3] ?? (ipsec.perfectForwardSecrecy ? 'PFS enabled' : '—'),
      note: ipsec.perfectForwardSecrecy ? 'Perfect Forward Secrecy' : undefined,
    })
    rows.push({ title: 'Mode', value: ipsec.mode === 'tunnel' ? 'Tunnel mode' : 'Transport mode' })
  } else if (packet.protocol === 'ESP' && ipsec.esp) {
    const esp = ipsec.esp
    const payloadLength = Math.max(0, packet.length - 54)
    rows.push({ title: 'SPI', value: `0x${esp.spi}` })
    rows.push({ title: 'Sequence Number', value: String(esp.sequenceNumber) })
    rows.push({ title: 'Payload Length', value: `${payloadLength} bytes` })
    rows.push({ title: 'Next Header', value: esp.nextHeader })
    rows.push({ title: 'Encryption Algorithm', value: esp.encryptionAlgorithm ?? '—' })
    rows.push({ title: 'Integrity Algorithm', value: esp.integrityAlgorithm ?? '—' })
    rows.push({ title: 'Mode', value: ipsec.mode === 'tunnel' ? 'Tunnel mode' : 'Transport mode' })
    if (esp.inner) {
      rows.push({
        title: 'Inner Flow',
        value: `${esp.inner.source} → ${esp.inner.destination} (${esp.inner.protocol})`,
        note: 'tunnel-mode inner packet',
      })
    }
  } else if (packet.protocol === 'AH' && ipsec.ah) {
    rows.push({ title: 'SPI', value: `0x${ipsec.ah.spi}` })
    rows.push({ title: 'Sequence Number', value: String(ipsec.ah.sequenceNumber) })
    rows.push({ title: 'Authentication Data', value: ipsec.ah.integrityAlgorithm })
    rows.push({ title: 'Next Header', value: 'IPv4 (4)' })
    rows.push({ title: 'Mode', value: ipsec.mode === 'tunnel' ? 'Tunnel mode' : 'Transport mode' })
  }

  return rows
}

/* ------------------------------------------------------------------ */
/* Deterministic mock byte generator for the Raw Packet hex dump.      */
/* Seeded per packet id so re-opening a packet shows the same bytes.   */
/* A real backend replaces this with true wire bytes later.            */
/* ------------------------------------------------------------------ */

function hashString(input: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < input.length; i += 1) {
    h ^= input.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return h >>> 0
}

function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

/** Build a deterministic 16-bytes-per-line hex dump for the packet. */
export function mockHexDump(packet: Packet): HexLine[] {
  const byteCount = Math.max(0, packet.length)
  const rand = mulberry32(hashString(`${packet.id}:${packet.number}`) || 1)
  const bytes: number[] = []
  for (let i = 0; i < byteCount; i += 1) {
    bytes.push(Math.floor(rand() * 256))
  }

  const lines: HexLine[] = []
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16)
    const toHex = (arr: number[]): string => arr.map((b) => b.toString(16).padStart(2, '0')).join(' ')
    const ascii = chunk
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'))
      .join('')
    const hex =
      chunk.length > 8
        ? `${toHex(chunk.slice(0, 8))}   ${toHex(chunk.slice(8))}`
        : toHex(chunk)
    lines.push({
      offset: i.toString(16).padStart(4, '0'),
      hex: hex.padEnd(8 * 3 - 1 + 3 + 8 * 3 - 1, ' '),
      ascii: ascii.padEnd(16, ' '),
    })
  }
  return lines
}

/** Assemble every panel payload for a packet in one call. */
export function buildPacketDetails(packet: Packet, interfaceName: string): PacketDetails {
  return {
    overview: overviewRows(packet, interfaceName),
    protocols: ipsecDetailRows(packet),
    hex: mockHexDump(packet),
  }
}