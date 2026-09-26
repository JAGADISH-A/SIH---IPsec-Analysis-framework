import type { Packet } from '../../types/packet'
import type {
  ProtocolField,
  ProtocolLayer,
  IpsecDetails,
  Ikev2Message,
  EncryptionSpec,
  Ikev2Proposal,
} from '../../types/protocol'
import type {
  PacketFinding,
  RiskLevel,
  FindingCategory,
} from '../../types/security'
import { riskSeverityIndex } from '../../types/security'
import { mulberry32, pick, rangeInt, randomHex, generateId } from './tools'

export interface MockGeneratorConfig {
  /** ISO timestamp of capture start. */
  startIso: string
  seed?: number
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function keyOf(raw: string): string {
  return raw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
}

function field(title: string, value: string, note?: string): ProtocolField {
  return { name: keyOf(title), title, value, note, decoded: note !== undefined }
}

function layer(
  id: string,
  name: string,
  abbreviation: string,
  summary: string,
  fields: ProtocolField[],
): ProtocolLayer {
  return { id, name, abbreviation, key: id, summary, fields }
}

function finding(
  id: string,
  packetId: string,
  category: FindingCategory,
  severity: RiskLevel,
  title: string,
  description: string,
  affectedField: string,
  recommendation?: string,
): PacketFinding {
  return {
    id,
    packetId,
    category,
    severity,
    title,
    description,
    affectedFields: [affectedField],
    recommendation,
    ruleId: `SENT-${id.toUpperCase()}`,
  }
}

/** Collapse a finding set into the packet's top-level risk level. */
function riskOf(findings: readonly PacketFinding[]): RiskLevel | null {
  if (findings.length === 0) return null
  return findings.reduce<RiskLevel>(
    (worst, f) => (riskSeverityIndex(f.severity) < riskSeverityIndex(worst) ? f.severity : worst),
    findings[0].severity,
  )
}

function ethernetIpLayers(
  macSrc: string,
  macDst: string,
  ipSrc: string,
  ipDst: string,
  ipProtocol: string,
): ProtocolLayer[] {
  return [
    layer('eth', 'Ethernet II', 'ETH', `Ethernet II, Src: ${macSrc}, Dst: ${macDst}`, [
      field('Destination', macDst, 'You'),
      field('Source', macSrc, 'Peer'),
      field('Type', 'IPv4 (0x0800)'),
    ]),
    layer(
      'ip',
      'Internet Protocol Version 4',
      'IPv4',
      `Internet Protocol Version 4, Src: ${ipSrc}, Dst: ${ipDst}`,
      [
        field('Version', '4'),
        field('Header Length', '20 bytes'),
        field('Protocol', ipProtocol),
        field('Source Address', ipSrc),
        field('Destination Address', ipDst),
      ],
    ),
  ]
}

function ipProtocolLabel(proto: number): string {
  if (proto === 1) return 'ICMP (1)'
  if (proto === 6) return 'TCP (6)'
  if (proto === 17) return 'UDP (17)'
  if (proto === 50) return 'ESP (50)'
  if (proto === 51) return 'AH (51)'
  return String(proto)
}

function udpLayer(sport: number, dport: number, len: number): ProtocolLayer {
  return layer('udp', 'User Datagram Protocol', 'UDP', `Src Port: ${sport}, Dst Port: ${dport}`, [
    field('Source Port', String(sport)),
    field('Destination Port', String(dport)),
    field('Length', String(len)),
  ])
}

function ikev2Layer(message: Ikev2Message, proposals: readonly Ikev2Proposal[]): ProtocolLayer {
  const proposalFields = proposals.map((p, i) => ({ p, i }))
  return layer(
    'ikev2',
    'Internet Security Association and Key Management Protocol',
    'IKEv2',
    `IKEv2 ${message.exchangeType}, SPI ${message.initiatorSpi}/${message.responderSpi}`,
    [
      field('Initiator SPI', message.initiatorSpi),
      field('Responder SPI', message.responderSpi),
      field('Exchange Type', message.exchangeType),
      field('Message ID', message.messageId),
      field('Flags', message.flags.join(', ')),
      field('Length', `${message.length} bytes`),
      ...proposalFields.flatMap(({ p }) => [
        field(
          `Proposal ${p.number}`,
          '',
          `${p.protocolId}: ${p.transforms.join(' · ')}`,
        ),
      ]),
    ],
  )
}

function espLayers(spi: string, seq: number, encryptNote: string): ProtocolLayer[] {
  return [
    layer('esp', 'Encapsulating Security Payload', 'ESP', `SPI: 0x${spi}, Seq: ${seq}`, [
      field('SPI', `0x${spi}`),
      field('Sequence Number', String(seq)),
      field('Next Header', 'IPv4 (4)'),
      field('Encrypted Payload', 'Encrypted (pad to boundary)', encryptNote),
    ]),
    layer(
      'payload',
      'Payload (Encrypted)',
      'DATA',
      'Encrypted payload — not decodable without matching SA',
      [field('Encrypted Payload', `${rangeInt(random(), 60, 1200)} bytes`, encryptNote)],
    ),
  ]
}

/* ------------------------------------------------------------------ */
/* Scenario builders                                                  */
/* ------------------------------------------------------------------ */

interface IkeSuite {
  encr: string
  prf: string
  integ: string
  dh: string
  bits: number
  strength: EncryptionSpec['strength']
  pfs: boolean
}

function buildIkeInit(
  number: number,
  timeIso: string,
  relativeTimeMs: number,
  packetId: string,
  isResponse: boolean,
  mode: 'strong' | 'weak' | 'legacy',
): Packet {
  const initiatorSpi = randomHex(random(), 8)
  const responderSpi = isResponse ? randomHex(random(), 8) : '0000000000000000'

  const suites: Record<'strong' | 'weak' | 'legacy', IkeSuite> = {
    strong: {
      encr: 'ENCR_AES_GCM_16 (24)',
      prf: 'PRF_HMAC_SHA2_256 (5)',
      integ: 'AUTH_HMAC_SHA2_256_128 (12)',
      dh: 'ECP Group 19 (256-bit)',
      bits: 256,
      strength: 'strong' as const,
      pfs: true,
    },
    weak: {
      encr: 'ENCR_DES (2)',
      prf: 'PRF_HMAC_MD5 (2)',
      integ: 'AUTH_HMAC_MD5_96 (2)',
      dh: 'MODP Group 1 (768-bit)',
      bits: 64,
      strength: 'broken' as const,
      pfs: false,
    },
    legacy: {
      encr: 'ENCR_AES_CBC (12)',
      prf: 'PRF_HMAC_SHA1 (3)',
      integ: 'AUTH_HMAC_SHA1_96 (3)',
      dh: 'MODP Group 14 (2048-bit)',
      bits: 128,
      strength: 'legacy' as const,
      pfs: false,
    },
  }
  const suite = suites[mode]

  const ipsec: IpsecDetails = {
    mode: 'tunnel',
    securityProtocols: ['ikev2'],
    perfectForwardSecrecy: suite.pfs,
    ikev2: {
      exchangeType: 'IKE_SA_INIT',
      exchangeCode: 34,
      initiatorSpi,
      responderSpi,
      messageId: '0x00000000',
      flags: isResponse ? ['Response'] : ['Initiator'],
      length: isResponse ? 262 : 224,
    },
    proposals: [
      {
        number: 1,
        protocolId: 'IKE',
        transforms: [suite.encr, suite.prf, suite.integ, suite.dh],
      },
    ],
    encryption: {
      algorithm: suite.encr,
      keyBitLength: suite.bits,
      strength: suite.strength,
    },
  }

  const findings: PacketFinding[] =
    mode === 'weak'
      ? [
          finding(
            'ikev2_weak_crypto',
            packetId,
            'encryption',
            'high',
            'Weak IKEv2 cryptographic suite',
            'IKE_SA_INIT negotiates DES and HMAC-MD5, both cryptographically broken and prohibited by modern standards (RFC 8247 / 8242).',
            'proposal',
            'Require AES-GCM with at least 128-bit keys and SHA-2 based integrity.',
          ),
        ]
      : mode === 'legacy'
        ? [
            finding(
              'ikev2_legacy_suite',
              packetId,
              'configuration',
              'medium',
              'Legacy proposal without PFS',
              'The IKE proposal uses AES-CBC with HMAC-SHA1 and no Diffie-Hellman group offering Perfect Forward Secrecy. Functional but below modern posture.',
              'proposal',
              'Negotiate AES-GCM with an ECP DH group to enable PFS.',
            ),
          ]
        : []

  return {
    id: packetId,
    number,
    timestamp: timeIso,
    relativeTimeMs,
    source: '10.8.0.2',
    destination: '10.8.0.1',
    protocol: 'IKEv2',
    protocolStack: ['eth', 'ip', 'udp', 'ikev2'],
    length: isResponse ? 262 : 224,
    info: `${isResponse ? 'IKE_SA_INIT response' : 'IKE_SA_INIT request'} — SA: ${suite.encr}, ${suite.integ}, ${suite.dh}`,
    role: 'ike-handshake',
    findings,
    risk: riskOf(findings),
    layers: [
      ...ethernetIpLayers('a4:5e:60:11:8b:0c', '00:1b:21:9e:7f:72', '10.8.0.2', '10.8.0.1', ipProtocolLabel(17)),
      udpLayer(4500, 500, 208),
      ikev2Layer(ipsec.ikev2!, ipsec.proposals ?? []),
    ],
    ipsec,
  }
}

function buildIkeAuth(
  number: number,
  timeIso: string,
  relativeTimeMs: number,
  packetId: string,
): Packet {
  const extendedLifetime = random()() < 0.3
  const ipsec: IpsecDetails = {
    mode: 'tunnel',
    securityProtocols: ['ikev2'],
    perfectForwardSecrecy: true,
    ikev2: {
      exchangeType: 'IKE_SA_AUTH',
      exchangeCode: 35,
      initiatorSpi: randomHex(random(), 8),
      responderSpi: randomHex(random(), 8),
      messageId: '0x00000001',
      flags: ['Initiator', 'Response'],
      length: 1024,
    },
    encryption: { algorithm: 'AES-GCM-256', keyBitLength: 256, strength: 'strong' },
  }

  const findings: PacketFinding[] = extendedLifetime
    ? [
        finding(
          'ikev2_long_lifetime',
          packetId,
          'configuration',
          'low',
          'Extended SA lifetime',
          'The IKE SA lifetime exceeds the recommended 24-hour maximum, increasing the rekey exposure window.',
          'lifetime',
          'Limit SA lifetime to 24h or less and rekey with PFS.',
        ),
      ]
    : []

  return {
    id: packetId,
    number,
    timestamp: timeIso,
    relativeTimeMs,
    source: '10.8.0.2',
    destination: '10.8.0.1',
    protocol: 'IKEv2',
    protocolStack: ['eth', 'ip', 'udp', 'ikev2'],
    length: 1024,
    info: extendedLifetime
      ? 'IKE_SA_AUTH (Phase 1), AUTH: HMAC-SHA2-256-128, lifetime 48h'
      : 'IKE_SA_AUTH (Phase 1), AUTH: HMAC-SHA2-256-128, Traffic Selectors installed',
    role: 'ike-handshake',
    findings,
    risk: riskOf(findings),
    layers: [
      ...ethernetIpLayers('a4:5e:60:11:8b:0c', '00:1b:21:9e:7f:72', '10.8.0.2', '10.8.0.1', ipProtocolLabel(17)),
      udpLayer(4500, 4500, 986),
      ikev2Layer(ipsec.ikev2!, []),
    ],
    ipsec,
  }
}

function buildEsp(
  number: number,
  timeIso: string,
  relativeTimeMs: number,
  packetId: string,
  variant: 'strong' | 'legacy' | 'null',
): Packet {
  const spi = randomHex(random(), 4)
  const seq = Math.floor(random()() * 10000) + 1

  const spec: Record<'strong' | 'legacy' | 'null', { encryption: EncryptionSpec; integrity: string }> = {
    strong: {
      encryption: { algorithm: 'AES-GCM-256', keyBitLength: 256, strength: 'strong' },
      integrity: 'AES-GMAC',
    },
    legacy: {
      encryption: { algorithm: 'ENCR_3DES_CBC (3)', keyBitLength: 112, strength: 'legacy' },
      integrity: 'HMAC-SHA1-96',
    },
    null: {
      encryption: { algorithm: 'ESP_NULL', keyBitLength: 0, strength: 'weak' },
      integrity: 'HMAC-SHA2-256',
    },
  }

  const { encryption, integrity } = spec[variant]

  const findings: PacketFinding[] =
    variant === 'null'
      ? [
          finding(
            'esp_null',
            packetId,
            'encryption',
            'critical',
            'ESP configured with NULL encryption',
            'ESP packets carry an ESP_NULL SA: payload confidentiality is disabled while a security trailer is still emitted. ESP-NULL is only permitted in controlled debugging scenarios.',
            'encrypted_payload',
            'Bind real AES-GCM encryption to the SA and renegotiate the tunnel.',
          ),
        ]
      : variant === 'legacy'
        ? [
            finding(
              'esp_3des',
              packetId,
              'encryption',
              'medium',
              'Legacy ESP encryption (3DES-CBC)',
              'ESP uses 3DES-CBC with HMAC-SHA1 — deprecated by RFC 8247 and limited to 112-bit effective security.',
              'encrypted_payload',
              'Migrate the SA to AES-GCM with a 128-bit or larger key.',
            ),
          ]
        : []

  const ipsec: IpsecDetails = {
    mode: 'tunnel',
    securityProtocols: variant === 'null' ? ['esp', 'esp-null'] : ['esp'],
    encryption,
    integrity: { algorithm: integrity, strength: variant === 'legacy' ? 'legacy' : 'strong' },
    perfectForwardSecrecy: true,
    esp: {
      spi,
      sequenceNumber: seq,
      nextHeader: 'IPv4 (4)',
      encryptionAlgorithm: encryption.algorithm,
      integrityAlgorithm: integrity,
      inner: { source: '10.9.1.24', destination: '10.9.2.41', protocol: 'UDP' },
    },
  }

  const length = rangeInt(random(), 88, 1446)

  return {
    id: packetId,
    number,
    timestamp: timeIso,
    relativeTimeMs,
    source: '10.8.0.1',
    destination: '10.8.0.2',
    protocol: 'ESP',
    protocolStack: ['eth', 'ip', 'esp'],
    length,
    info:
      variant === 'null'
        ? `ESP (ESP_NULL, ${integrity}), SPI: 0x${spi}, Len: ${length}`
        : `ESP (${encryption.algorithm}, ${integrity}), SPI: 0x${spi}, Len: ${length}`,
    role: 'encrypted',
    findings,
    risk: riskOf(findings),
    layers: [
      ...ethernetIpLayers('00:1b:21:9e:7f:72', 'a4:5e:60:11:8b:0c', '10.8.0.1', '10.8.0.2', ipProtocolLabel(50)),
      ...espLayers(spi, seq, encryption.algorithm),
    ],
    ipsec,
  }
}

function buildAh(
  number: number,
  timeIso: string,
  relativeTimeMs: number,
  packetId: string,
  variant: 'strong' | 'md5' | 'sha1',
): Packet {
  const spi = randomHex(random(), 4)
  const seq = Math.floor(random()() * 10000) + 1
  const algorithms: Record<'strong' | 'md5' | 'sha1', string> = {
    strong: 'HMAC-SHA2-256',
    md5: 'HMAC-MD5-96',
    sha1: 'HMAC-SHA1-96',
  }
  const algorithm = algorithms[variant]

  const findings: PacketFinding[] =
    variant === 'md5'
      ? [
          finding(
            'ah_md5',
            packetId,
            'integrity',
            'high',
            'AH uses deprecated HMAC-MD5-96',
            'Authentication Header integrity relies on HMAC-MD5, which is collision-prone and cryptographically broken (RFC 8242).',
            'integrity_algorithm',
            'Upgrade to HMAC-SHA2-256 or AES-GMAC.',
          ),
        ]
      : variant === 'sha1'
        ? [
            finding(
              'ah_sha1',
              packetId,
              'integrity',
              'medium',
              'AH integrity uses deprecated HMAC-SHA1-96',
              'Authentication Header integrity relies on HMAC-SHA1-96, deprecated under current guidance. Acceptable for legacy interop only.',
              'integrity_algorithm',
              'Move to HMAC-SHA2-256 or AES-GMAC.',
            ),
          ]
        : []

  const ipsec: IpsecDetails = {
    mode: 'transport',
    securityProtocols: ['ah'],
    integrity: { algorithm, strength: variant === 'strong' ? 'strong' : variant === 'md5' ? 'broken' : 'legacy' },
    perfectForwardSecrecy: true,
    ah: { spi, sequenceNumber: seq, integrityAlgorithm: algorithm },
  }

  return {
    id: packetId,
    number,
    timestamp: timeIso,
    relativeTimeMs,
    source: '10.4.8.15',
    destination: '10.4.8.16',
    protocol: 'AH',
    protocolStack: ['eth', 'ip', 'ah'],
    length: 92,
    info: `AH (${algorithm}), SPI: 0x${spi}, Seq: ${seq}`,
    role: 'normal',
    findings,
    risk: riskOf(findings),
    layers: [
      ...ethernetIpLayers('a4:5e:60:11:8b:0c', '00:1b:21:9e:7f:72', '10.4.8.15', '10.4.8.16', ipProtocolLabel(51)),
      layer('ah', 'Authentication Header', 'AH', `SPI: 0x${spi}, Seq: ${seq}`, [
        field('SPI', `0x${spi}`),
        field('Sequence Number', String(seq)),
        field('Integrity Algorithm', algorithm),
      ]),
    ],
    ipsec,
  }
}

function buildBackground(
  number: number,
  timeIso: string,
  relativeTimeMs: number,
  packetId: string,
): Packet {
  const kind = pick(random(), ['dns', 'tcp-syn', 'tls-hello', 'icmp'] as const)

  if (kind === 'dns') {
    const tid = rangeInt(random(), 0, 65535).toString(16).padStart(4, '0').toUpperCase()
    return {
      id: packetId,
      number,
      timestamp: timeIso,
      relativeTimeMs,
      source: '10.20.1.5',
      destination: '8.8.8.8',
      protocol: 'DNS',
      protocolStack: ['eth', 'ip', 'udp', 'dns'],
      length: 78,
      info: `Standard query 0x${tid} A api.example.com`,
      role: 'normal',
      findings: [],
      risk: null,
      layers: [
        ...ethernetIpLayers('a4:5e:60:11:8b:0c', '00:1b:21:9e:7f:72', '10.20.1.5', '8.8.8.8', ipProtocolLabel(17)),
        udpLayer(53205, 53, 44),
        layer('dns', 'Domain Name System', 'DNS', `Standard query 0x${tid}`, [
          field('Transaction ID', `0x${tid}`),
          field('Questions', '1'),
          field('A', 'api.example.com'),
        ]),
      ],
    }
  }

  if (kind === 'tcp-syn') {
    return {
      id: packetId,
      number,
      timestamp: timeIso,
      relativeTimeMs,
      source: '10.20.1.5',
      destination: '10.20.0.10',
      protocol: 'TCP',
      protocolStack: ['eth', 'ip', 'tcp'],
      length: 66,
      info: '[SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM',
      role: 'normal',
      findings: [],
      risk: null,
      layers: [
        ...ethernetIpLayers('a4:5e:60:11:8b:0c', '00:1b:21:9e:7f:72', '10.20.1.5', '10.20.0.10', ipProtocolLabel(6)),
        layer('tcp', 'Transmission Control Protocol', 'TCP', '[SYN] Seq=0 Win=64240 Len=0 MSS=1460', [
          field('Source Port', String(rangeInt(random(), 1024, 65335))),
          field('Destination Port', '443'),
          field('Flags', '0x002 (SYN)'),
        ]),
      ],
    }
  }

  if (kind === 'tls-hello') {
    return {
      id: packetId,
      number,
      timestamp: timeIso,
      relativeTimeMs,
      source: '10.20.1.5',
      destination: '10.20.0.10',
      protocol: 'TLS',
      protocolStack: ['eth', 'ip', 'tcp', 'tls'],
      length: 285,
      info: 'Client Hello, SNI: vault.corp.local, TLSv1.3',
      role: 'normal',
      findings: [],
      risk: null,
      layers: [
        ...ethernetIpLayers('a4:5e:60:11:8b:0c', '00:1b:21:9e:7f:72', '10.20.1.5', '10.20.0.10', ipProtocolLabel(6)),
        layer('tcp', 'Transmission Control Protocol', 'TCP', 'TLSv1.3 Record Layer', [
          field('Source Port', '5122'),
          field('Destination Port', '443'),
          field('Record Length', '275'),
        ]),
        layer('tls', 'Transport Layer Security', 'TLS', 'TLSv1.3 Client Hello', [
          field('Record Version', 'TLS 1.3 (0x0304)'),
          field('SNI', 'vault.corp.local'),
          field('Cipher Suites', '12 suites (TLS_AES_256_GCM_SHA384)'),
        ]),
      ],
    }
  }

  return {
    id: packetId,
    number,
    timestamp: timeIso,
    relativeTimeMs,
    source: '10.20.1.5',
    destination: '10.20.1.1',
    protocol: 'ICMP',
    protocolStack: ['eth', 'ip', 'icmp'],
    length: 98,
    info: 'Echo (ping) request id=0x0432 seq=1/768, ttl=64',
    role: 'normal',
    findings: [],
      risk: null,
    layers: [
      ...ethernetIpLayers('a4:5e:60:11:8b:0c', '00:1b:21:9e:7f:72', '10.20.1.5', '10.20.1.1', ipProtocolLabel(1)),
      layer('icmp', 'Internet Control Message Protocol', 'ICMP', 'Echo (ping) request', [
        field('Type', '8 (Echo request)'),
        field('Code', '0'),
      ]),
    ],
  }
}

function buildCreateChildSa(
  number: number,
  timeIso: string,
  relativeTimeMs: number,
  packetId: string,
): Packet {
  const isInitiator = random()() < 0.5
  const transforms = ['ENCR_AES_GCM_16 (24)', 'AUTH_HMAC_SHA2_256_128 (12)', 'ESN']
  const ipsec: IpsecDetails = {
    mode: 'tunnel',
    securityProtocols: ['ikev2'],
    perfectForwardSecrecy: true,
    ikev2: {
      exchangeType: 'CREATE_CHILD_SA',
      exchangeCode: 36,
      initiatorSpi: randomHex(random(), 8),
      responderSpi: randomHex(random(), 8),
      messageId: '0x00000002',
      flags: isInitiator ? ['Initiator'] : ['Response'],
      length: 412,
    },
    proposals: [{ number: 1, protocolId: 'ESP', transforms }],
    encryption: { algorithm: 'ENCR_AES_GCM_16 (24)', keyBitLength: 256, strength: 'strong' },
  }

  const findings: PacketFinding[] = []

  return {
    id: packetId,
    number,
    timestamp: timeIso,
    relativeTimeMs,
    source: '10.8.0.2',
    destination: '10.8.0.1',
    protocol: 'IKEv2',
    protocolStack: ['eth', 'ip', 'udp', 'ikev2'],
    length: 412,
    info: isInitiator
      ? 'IKEv2 CREATE_CHILD_SA — ESP: AES-GCM-256, ESN, PFS (DH ECP Group 19)'
      : 'IKEv2 CREATE_CHILD_SA response — ESP SA established',
    role: 'ike-handshake',
    findings,
    risk: null,
    layers: [
      ...ethernetIpLayers('a4:5e:60:11:8b:0c', '00:1b:21:9e:7f:72', '10.8.0.2', '10.8.0.1', ipProtocolLabel(17)),
      udpLayer(4500, 4500, 412),
      ikev2Layer(ipsec.ikev2!, ipsec.proposals ?? []),
    ],
    ipsec,
  }
}

/* ------------------------------------------------------------------ */
/* Generator                                                          */
/* ------------------------------------------------------------------ */

type Random = () => number
let RAND: Random = mulberry32(20260923)

function setRandom(rng: Random): void {
  RAND = rng
}

function random(): Random {
  return RAND
}

export class MockPacketGenerator {
  private rng: Random
  private startEpoch: number
  private index = 0
  private currentMs = 0

  constructor(config: MockGeneratorConfig) {
    this.rng = mulberry32(config.seed ?? 20260923)
    setRandom(this.rng)
    this.startEpoch = new Date(config.startIso).getTime()
  }

  next(): Packet {
    this.index += 1
    this.currentMs += rangeInt(this.rng, 8, 700)
    const timeIso = new Date(this.startEpoch + this.currentMs).toISOString()
    const id = generateId('pkt', this.index)

    // Cyclic narrative: IKE handshake phases, child SA setup, ESP data,
    // AH integrity-checked traffic and occasional anomalies.
    switch (this.index % 8) {
      case 0:
        return buildIkeInit(this.index, timeIso, this.currentMs, id, false, 'strong')
      case 1: {
        const r = this.rng()
        const mode = r < 0.3 ? 'weak' : r < 0.55 ? 'legacy' : 'strong'
        return buildIkeInit(this.index, timeIso, this.currentMs, id, true, mode)
      }
      case 2:
        return buildIkeAuth(this.index, timeIso, this.currentMs, id)
      case 3:
        return buildCreateChildSa(this.index, timeIso, this.currentMs, id)
      case 4:
        return buildEsp(this.index, timeIso, this.currentMs, id, 'strong')
      case 5: {
        const r = this.rng()
        return buildEsp(this.index, timeIso, this.currentMs, id, r < 0.4 ? 'legacy' : 'strong')
      }
      case 6: {
        const r = this.rng()
        const mode = r < 0.3 ? 'md5' : r < 0.6 ? 'sha1' : 'strong'
        return buildAh(this.index, timeIso, this.currentMs, id, mode)
      }
      default:
        return this.index % 16 === 7
          ? buildEsp(this.index, timeIso, this.currentMs, id, 'null')
          : buildBackground(this.index, timeIso, this.currentMs, id)
    }
  }
}