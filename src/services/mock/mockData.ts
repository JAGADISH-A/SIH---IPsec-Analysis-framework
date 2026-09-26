import type {
  CaptureRecord,
  CaptureLabel,
  CaptureTrafficType,
  DataSource,
  DistributionSlice,
  EvidenceReference,
  Experiment,
  ExperimentComparisonCell,
  ExperimentDetail,
  ExperimentGroundTruth,
  ExperimentStatus,
  IkevVersion,
  IpVersion,
  LiveEvent,
  LiveEventType,
  ProtocolValue,
  RekeyStatus,
  Report,
  SecurityAssociation,
  SecurityFinding,
  ServiceHealth,
  ServiceName,
  ServiceStatus,
  SessionConfiguration,
  SessionCorrelation,
  SessionEndpoint,
  SessionModelOutput,
  SessionStatus,
  SessionTimelineEvent,
  Severity,
  SeverityTally,
  SystemHealth,
  Threat,
  ThreatId,
  TimelineEventType,
  TrafficClass,
  VpnMode,
  VpnSession,
} from '../../types'
import type { SessionDetail } from '../../types/session'
import { mulberry32, pick, rangeInt, randomHex } from './tools'

/* ================================================================== */
/* Deterministic data generation                                        */
/* ------------------------------------------------------------------ */
/* A fixed seed keeps the research dataset stable across reloads, so a */
/* session id, a finding id or a score can be cited in a report and     */
/* still be reproducible. Replacing this module with real service       */
/* calls must not require any UI change.                                */
/* ================================================================== */

const SEED = 0x5ec_1a7
const NOW = Date.now()
const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

function iso(offsetMs: number): string {
  return new Date(NOW + offsetMs).toISOString()
}

/* ------------------------------------------------------------------ */
/* Protocol vocabulary                                                  */
/* ------------------------------------------------------------------ */

interface CipherSpec {
  name: string
  strength: 'strong' | 'legacy' | 'weak' | 'broken'
  status: ProtocolValue<string>['status']
}

const CIPHERS: CipherSpec[] = [
  { name: 'AES-256-GCM', strength: 'strong', status: 'strong' },
  { name: 'AES-128-GCM', strength: 'strong', status: 'strong' },
  { name: 'CHACHA20-POLY1305', strength: 'strong', status: 'strong' },
  { name: 'AES-256-CBC', strength: 'legacy', status: 'acceptable' },
  { name: 'AES-128-CBC', strength: 'legacy', status: 'warning' },
  { name: '3DES-CBC', strength: 'weak', status: 'weak' },
  { name: 'DES-CBC', strength: 'broken', status: 'critical' },
]

const INTEGRITIES: { name: string; strength: CipherSpec['strength']; status: ProtocolValue<string>['status'] }[] = [
  { name: 'AES-GMAC-256', strength: 'strong', status: 'strong' },
  { name: 'HMAC-SHA2-512-256', strength: 'strong', status: 'strong' },
  { name: 'HMAC-SHA2-256-128', strength: 'strong', status: 'strong' },
  { name: 'HMAC-SHA1-96', strength: 'legacy', status: 'warning' },
  { name: 'HMAC-MD5-96', strength: 'broken', status: 'critical' },
  { name: 'NULL', strength: 'broken', status: 'critical' },
]

const DH_GROUPS: { name: string; strength: CipherSpec['strength']; status: ProtocolValue<string>['status']; bits: number }[] = [
  { name: 'Group 20 (X25519)', strength: 'strong', status: 'strong', bits: 255 },
  { name: 'Group 21 (secp384r1)', strength: 'strong', status: 'strong', bits: 384 },
  { name: 'Group 19 (secp521r1)', strength: 'strong', status: 'strong', bits: 521 },
  { name: 'Group 14 (MODP-2048)', strength: 'strong', status: 'strong', bits: 2048 },
  { name: 'Group 5 (MODP-1536)', strength: 'legacy', status: 'warning', bits: 1536 },
  { name: 'Group 2 (MODP-1024)', strength: 'weak', status: 'weak', bits: 1024 },
]

const PRFS = ['PRF_HMAC_SHA2-512', 'PRF_HMAC_SHA2-256', 'PRF_HMAC_SHA1']

const RFC_REFS = {
  ikev2: 'RFC 7296',
  esp: 'RFC 4303',
  ah: 'RFC 4302',
  algs: 'RFC 8247',
  suite: 'RFC 8221',
  natt: 'RFC 3948',
}

/* ------------------------------------------------------------------ */
/* Endpoints (documentation + RFC 1918 ranges only)                    */
/* ------------------------------------------------------------------ */

const V4_INITIATORS = [
  '192.0.2.24',
  '198.51.100.17',
  '203.0.113.8',
  '10.20.4.11',
  '10.30.12.7',
  '172.16.8.3',
]
const V4_RESPONDERS = [
  '198.51.100.42',
  '203.0.113.19',
  '192.0.2.61',
  '10.20.0.5',
  '10.40.2.9',
  '172.16.16.30',
]
const V6_INITIATORS = ['2001:db8:1::24', '2001:db8:16::a', 'fd00:20::5']
const V6_RESPONDERS = ['2001:db8:2::42', '2001:db8:16::1', 'fd00:20::1']

const NETWORKS = ['Testbed-A', 'Testbed-B', 'Lab core', 'Staging edge', 'Metro interconnect']

const SESSION_LABELS = [
  'Branch 12 → HQ',
  'Branch 31 → HQ',
  'Partner transit',
  'Lab gateway',
  'Staging replica',
  'Metro interconnect',
  'Management plane',
  'Backup site',
  'Testbed-A node 3',
  'Testbed-B node 7',
]

const TESTBEDS = ['testbed-a', 'testbed-b', 'lab-core', 'staging-edge']

/* ------------------------------------------------------------------ */
/* Session archetypes                                                   */
/* ------------------------------------------------------------------ */

type Archetype = 'strong' | 'moderate' | 'weak' | 'degraded'

interface ArchetypeSpec {
  archetype: Archetype
  weight: number
  ikeVersion: IkevVersion
  mode: VpnMode
  cipher: CipherSpec
  integrity: (typeof INTEGRITIES)[number]
  dh: (typeof DH_GROUPS)[number]
  pfs: boolean
  replay: boolean
  scoreBias: number
}

const ARCHETYPES: ArchetypeSpec[] = [
  {
    archetype: 'strong',
    weight: 5,
    ikeVersion: 'IKEv2',
    mode: 'tunnel',
    cipher: CIPHERS[0],
    integrity: INTEGRITIES[0],
    dh: DH_GROUPS[0],
    pfs: true,
    replay: true,
    scoreBias: 4,
  },
  {
    archetype: 'moderate',
    weight: 4,
    ikeVersion: 'IKEv2',
    mode: 'tunnel',
    cipher: CIPHERS[3],
    integrity: INTEGRITIES[3],
    dh: DH_GROUPS[4],
    pfs: false,
    replay: true,
    scoreBias: 38,
  },
  {
    archetype: 'weak',
    weight: 2,
    ikeVersion: 'IKEv1',
    mode: 'tunnel',
    cipher: CIPHERS[5],
    integrity: INTEGRITIES[4],
    dh: DH_GROUPS[5],
    pfs: false,
    replay: false,
    scoreBias: 76,
  },
  {
    archetype: 'degraded',
    weight: 3,
    ikeVersion: 'IKEv2',
    mode: 'tunnel',
    cipher: CIPHERS[4],
    integrity: INTEGRITIES[2],
    dh: DH_GROUPS[3],
    pfs: true,
    replay: true,
    scoreBias: 52,
  },
]

/* ------------------------------------------------------------------ */
/* Evidence store                                                       */
/* ------------------------------------------------------------------ */

const evidenceStore = new Map<string, EvidenceReference>()

function addEvidence(sessionId: string, index: number, partial: Omit<EvidenceReference, 'id'>): string {
  const id = `ev-${sessionId}-${String(index).padStart(3, '0')}`
  evidenceStore.set(id, { id, ...partial })
  return id
}

function evidenceIndex(): { next(): number } {
  let n = 0
  return { next: () => (n += 1) }
}

/* ------------------------------------------------------------------ */
/* Value helpers                                                        */
/* ------------------------------------------------------------------ */

function pv<T>(
  value: T | null,
  source: DataSource,
  confidence: number | null,
  status: ProtocolValue<T>['status'],
  evidenceIds: string[],
  note?: string,
): ProtocolValue<T> {
  return { value, source, confidence, status, evidenceIds, note }
}

function riskBandFor(score: number): VpnSession['riskBand'] {
  if (score >= 75) return 'critical'
  if (score >= 50) return 'high'
  if (score >= 25) return 'medium'
  return 'low'
}

function emptyTally(): SeverityTally {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0, unknown: 0 }
}

function severityFromBand(band: VpnSession['riskBand']): Severity {
  return band
}

/* ------------------------------------------------------------------ */
/* Sessions                                                             */
/* ------------------------------------------------------------------ */

function buildSessions(): VpnSession[] {
  const rng = mulberry32(SEED)
  const sessions: VpnSession[] = []
  const counter = { next: 0 }

  for (let i = 0; i < 28; i += 1) {
    counter.next += 1
    const spec = pickWeightedArchetype(rng)
    const id = `SES-${String(20260000 + counter.next * 37)}`
    const useV6 = rng() < 0.25
    const ipVersion: IpVersion = useV6 ? 'IPv6' : 'IPv4'
    const initiator: SessionEndpoint = {
      address: useV6 ? pick(rng, V6_INITIATORS) : pick(rng, V4_INITIATORS),
      port: spec.ikeVersion === 'IKEv2' ? 500 : 500,
      role: 'initiator',
      network: pick(rng, NETWORKS),
    }
    const responder: SessionEndpoint = {
      address: useV6 ? pick(rng, V6_RESPONDERS) : pick(rng, V4_RESPONDERS),
      port: 500,
      role: 'responder',
      network: pick(rng, NETWORKS),
    }

    const status: SessionStatus =
      spec.archetype === 'strong'
        ? pick(rng, ['active', 'active', 'active', 'rekeying'] as const)
        : spec.archetype === 'moderate'
          ? pick(rng, ['active', 'active', 'rekeying', 'draining'] as const)
          : pick(rng, ['active', 'failed', 'closed', 'unavailable', 'active'] as const)

    const counter_ = evidenceIndex()
    const ev = () => counter_.next()

    const spiInitiator = randomHex(rng, 4)
    const spiResponder = randomHex(rng, 4)
    const spiEspOut = randomHex(rng, 4)
    const spiEspIn = randomHex(rng, 4)

    const ikeConfidence = spec.archetype === 'weak' ? rangeInt(rng, 82, 94) / 100 : rangeInt(rng, 96, 100) / 100

    const evidenceIds = {
      ike: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 120, 4800)}–${rangeInt(rng, 4801, 4900)}`,
        exchange: 'IKE_SA_INIT',
        field: 'ikev2.header.protocol_version',
        explanation:
          'IKE header protocol version field read from the first exchange of the session.',
        rawValue: spec.ikeVersion === 'IKEv2' ? '0x02' : '0x01',
        confidence: ikeConfidence,
        source: 'observed',
      }),
      encr: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 200, 4600)}–${rangeInt(rng, 4601, 4700)}`,
        exchange: 'IKE_AUTH',
        field: 'ikev2.sa.transform.type.encryption',
        explanation: 'Encryption transform carried in the accepted SA payload.',
        rawValue: spec.cipher.name,
        confidence: 0.99,
        source: 'observed',
      }),
      integ: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 200, 4600)}–${rangeInt(rng, 4601, 4700)}`,
        exchange: 'IKE_AUTH',
        field: 'ikev2.sa.transform.type.integrity',
        explanation: 'Integrity transform carried in the accepted SA payload.',
        rawValue: spec.integrity.name,
        confidence: 0.99,
        source: 'observed',
      }),
      dh: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 120, 4700)}–${rangeInt(rng, 4701, 4800)}`,
        exchange: 'IKE_SA_INIT',
        field: 'ikev2.sa.transform.type.dh',
        explanation: 'Diffie-Hellman group selected for the IKE_SA.',
        rawValue: spec.dh.name,
        confidence: 0.97,
        source: 'observed',
      }),
      pfs: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 300, 4700)}–${rangeInt(rng, 4701, 4900)}`,
        exchange: spec.pfs ? 'CREATE_CHILD_SA' : 'IKE_AUTH',
        field: 'ikev2.sa.ikev2_pfs',
        explanation: spec.pfs
          ? 'A later CREATE_CHILD_SA rekeyed the CHILD_SA with a fresh Diffie-Hellman exchange.'
          : 'No rekey with a Diffie-Hellman exchange was observed before the capture ended.',
        rawValue: spec.pfs ? 'true' : 'false',
        confidence: spec.pfs ? 0.94 : 0.86,
        source: spec.pfs ? 'observed' : 'inferred',
      }),
      replay: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 400, 4900)}–${rangeInt(rng, 4901, 5200)}`,
        exchange: 'CHILD_SA',
        field: 'ikev2.tss.esp.replay_window',
        explanation: spec.replay
          ? 'CHILD_SA negotiated an anti-replay window; sequence numbers were strictly increasing.'
          : 'CHILD_SA was accepted without an anti-replay window.',
        rawValue: spec.replay ? '64' : '0',
        confidence: spec.replay ? 0.95 : 0.9,
        source: spec.replay ? 'observed' : 'observed',
      }),
      nat: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 150, 5200)}–${rangeInt(rng, 5201, 5300)}`,
        exchange: 'IKE_SA_INIT',
        field: 'ikev2.header.nat_traversal',
        explanation: 'NAT traversal notification payloads present in the exchange.',
        rawValue: rng() < 0.4 ? 'true' : 'false',
        confidence: 0.92,
        source: 'observed',
      }),
      ipVersion: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 100, 5300)}–${rangeInt(rng, 5301, 5400)}`,
        exchange: '—',
        field: 'ip.version',
        explanation: 'Outer IP version of the encapsulated packets.',
        rawValue: useV6 ? '6' : '4',
        confidence: 0.99,
        source: 'observed',
      }),
      ah: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 500, 5400)}–${rangeInt(rng, 5401, 5600)}`,
        exchange: 'CHILD_SA',
        field: 'ikev2.protocol.ah',
        explanation: 'No AH transport selector was bound to this CHILD_SA.',
        rawValue: 'false',
        confidence: 0.97,
        source: 'observed',
      }),
      mode: addEvidence(id, ev(), {
        packetRange: `${rangeInt(rng, 200, 5300)}–${rangeInt(rng, 5301, 5400)}`,
        exchange: 'CHILD_SA',
        field: 'esp.tunnel.inner_ip',
        explanation: 'ESP header followed by an inner IP header indicates tunnel mode encapsulation.',
        rawValue: 'tunnel',
        confidence: 0.96,
        source: 'observed',
      }),
    }

    const configuration: SessionConfiguration = {
      ikeVersion: pv(spec.ikeVersion, 'observed', ikeConfidence, 'observed', [evidenceIds.ike]),
      vpnMode: pv(spec.mode, 'observed', evidenceIds.mode ? 0.96 : null, 'observed', [evidenceIds.mode]),
      encryption: pv(spec.cipher.name, 'observed', 0.99, spec.cipher.status, [evidenceIds.encr]),
      integrity: pv(
        spec.cipher.name.endsWith('GCM') ? 'AES-GMAC-256' : spec.integrity.name,
        'observed',
        0.99,
        spec.cipher.name.endsWith('GCM') ? 'strong' : spec.integrity.status,
        [evidenceIds.integ],
      ),
      dhGroup: pv(spec.dh.name, 'observed', 0.97, spec.dh.status, [evidenceIds.dh]),
      prf: pv(pick(rng, PRFS), 'observed', 0.95, spec.ikeVersion === 'IKEv1' ? 'warning' : 'strong', [
        evidenceIds.encr,
      ]),
      perfectForwardSecrecy: pv(
        spec.pfs,
        spec.pfs ? 'observed' : 'inferred',
        spec.pfs ? 0.94 : 0.86,
        spec.pfs ? 'strong' : 'warning',
        [evidenceIds.pfs],
        spec.pfs ? undefined : 'No rekey with a fresh DH exchange was observed in the capture.',
      ),
      replayProtection: pv(
        spec.replay,
        'observed',
        evidenceIds.replay ? 0.95 : null,
        spec.replay ? 'strong' : 'weak',
        [evidenceIds.replay],
      ),
      replayWindowSize: pv(
        spec.replay ? pick(rng, [32, 64, 128, 256]) : 0,
        'observed',
        spec.replay ? 0.94 : 0.9,
        spec.replay ? 'strong' : 'weak',
        [evidenceIds.replay],
      ),
      natTraversal: pv(rng() < 0.4, 'observed', 0.92, 'acceptable', [evidenceIds.nat]),
      ipVersion: pv(ipVersion, 'observed', 0.99, 'observed', [evidenceIds.ipVersion]),
      esp: pv(true, 'observed', 0.98, 'strong', [evidenceIds.encr]),
      ah: pv(false, 'observed', 0.97, 'observed', [evidenceIds.ah]),
      keyLifetimeSeconds: pv(pick(rng, [14400, 28800, 43200, 86400]), 'configured', 1, 'acceptable', []),
      lifetimeSeconds: pv(
        pick(rng, [3600, 14400, 28800, 86400, 604800]),
        'observed',
        0.93,
        'acceptable',
        [evidenceIds.encr],
      ),
      authenticationMethod: pv(
        spec.ikeVersion === 'IKEv2' ? 'EAP-TLS (PKI + EAP)' : 'Pre-shared key',
        'observed',
        0.9,
        spec.ikeVersion === 'IKEv2' ? 'strong' : 'warning',
        [evidenceIds.encr],
      ),
      trafficSelectors: pv(
        `${useV6 ? '[fd00:20::/64]' : '10.20.0.0/16'} ↔ ${useV6 ? '[2001:db8:2::/64]' : '10.40.0.0/16'}`,
        'observed',
        0.93,
        'observed',
        [evidenceIds.mode],
      ),
    }

    const baseScore = spec.scoreBias + rangeInt(rng, -6, 8)
    const riskScore = Math.max(1, Math.min(99, baseScore))
    const riskBand = riskBandFor(riskScore)
    const startedOffset = -(rangeInt(rng, 5, 60 * 96) * MINUTE)
    const closed = status === 'closed' || status === 'failed'
    const packets = rangeInt(rng, 2_400, 480_000)
    const bytes = packets * rangeInt(rng, 320, 1_180)

    const session: VpnSession = {
      id,
      label: `${SESSION_LABELS[i % SESSION_LABELS.length]} · ${id.slice(-4)}`,
      initiator,
      responder,
      status,
      environment:
        spec.archetype === 'strong'
          ? pick(rng, ['production', 'production', 'staging'] as const)
          : pick(rng, ['production', 'staging', 'lab', 'unknown'] as const),
      configuration,
      riskScore,
      riskBand,
      confidence: spec.archetype === 'weak' ? rangeInt(rng, 70, 88) / 100 : rangeInt(rng, 90, 99) / 100,
      findingCounts: emptyTally(),
      startedAt: iso(startedOffset),
      endedAt: closed ? iso(startedOffset + rangeInt(rng, 20, 600) * MINUTE) : null,
      lastActivityAt: iso(closed ? -(rangeInt(rng, 1, 400) * MINUTE) : -rangeInt(rng, 0, 90) * 1000),
      packetCount: packets,
      byteCount: bytes,
      rekeyCount: spec.pfs ? rangeInt(rng, 1, 9) : 0,
      retransmissions: spec.archetype === 'strong' ? rangeInt(rng, 0, 2) : rangeInt(rng, 3, 26),
      captureIds: [],
      experimentIds: [],
      testbed: pick(rng, TESTBEDS),
    }
    void spiInitiator
    void spiResponder
    void spiEspOut
    void spiEspIn
    sessions.push(session)
  }

  return sessions
}

function pickWeightedArchetype(rng: () => number): ArchetypeSpec {
  const total = ARCHETYPES.reduce((sum, spec) => sum + spec.weight, 0)
  let roll = rng() * total
  for (const spec of ARCHETYPES) {
    roll -= spec.weight
    if (roll <= 0) return spec
  }
  return ARCHETYPES[0]
}

/* ------------------------------------------------------------------ */
/* Findings                                                             */
/* ------------------------------------------------------------------ */

interface FindingTemplate {
  key: string
  title: string
  category: SecurityFinding['category']
  severity: Severity
  riskScore: number
  summary: string
  observedBehavior: string
  expectedBehavior: string
  impact: string
  recommendation: string
  rationale: string
  ruleId: string
  model?: string
  references: string[]
  applies(config: SessionConfiguration, context?: { retransmissions: number }): boolean
}

const FINDING_TEMPLATES: FindingTemplate[] = [
  {
    key: 'crypto-3des',
    title: '3DES-CBC negotiated for CHILD_SA',
    category: 'cryptography',
    severity: 'critical',
    riskScore: 78,
    summary: 'A 64-bit block cipher protects the CHILD_SA, which is considered broken.',
    observedBehavior: 'The accepted SA payload selected ENCR_3DES_CBC (transform type 7) for the CHILD_SA.',
    expectedBehavior: 'CHILD_SAs should use an AEAD cipher such as AES-256-GCM (RFC 8247 §5).',
    impact:
      '64-bit block ciphers are vulnerable to birthday-bound collision attacks once sufficient traffic passes through the tunnel.',
    recommendation: 'Re-propose the tunnel with ENCR_AES_GCM_16 and remove 3DES from the allowed transforms.',
    rationale:
      'The encryption transform was read directly from the accepted SA payload, matched against the algorithm registry and evaluated for block size and key length.',
    ruleId: 'SENTINEL-CRYPTO-001',
    references: [RFC_REFS.ikev2, RFC_REFS.algs],
    applies: (config) => config.encryption.value === '3DES-CBC' || config.encryption.value === 'DES-CBC',
  },
  {
    key: 'crypto-des',
    title: 'Single-DES negotiated for CHILD_SA',
    category: 'cryptography',
    severity: 'critical',
    riskScore: 92,
    summary: 'A 56-bit block cipher protects the tunnel and is cryptographically broken.',
    observedBehavior: 'The accepted SA payload selected ENCR_DES (transform type 1).',
    expectedBehavior: 'DES must not be negotiable; minimum key size is 128 bits.',
    impact: 'DES is trivially brute-forced and provides no meaningful confidentiality.',
    recommendation: 'Remove DES from the proposal set and rekey the session with AES-256-GCM.',
    rationale:
      'Transform type 1 in the accepted SA payload maps to ENCR_DES; the key length attribute of 64 bits is below the platform minimum.',
    ruleId: 'SENTINEL-CRYPTO-002',
    references: [RFC_REFS.algs, RFC_REFS.suite],
    applies: (config) => config.encryption.value === 'DES-CBC',
  },
  {
    key: 'crypto-cbc',
    title: 'Legacy CBC-mode encryption without AEAD',
    category: 'cryptography',
    severity: 'medium',
    riskScore: 34,
    summary: 'CBC-mode encryption is negotiated instead of an AEAD construction.',
    observedBehavior: 'The CHILD_SA uses AES-CBC with a separate integrity transform.',
    expectedBehavior: 'Prefer AES-GCM or ChaCha20-Poly1305, which provide confidentiality and integrity in one transform.',
    impact:
      'CBC requires a separate integrity transform and is more exposed to padding-oracle style attacks when decryption is reachable.',
    recommendation: 'Schedule a migration to AES-256-GCM during the next maintenance window.',
    rationale:
      'The encryption and integrity transforms are recorded separately in the accepted SA, which indicates a non-AEAD construction.',
    ruleId: 'SENTINEL-CRYPTO-010',
    references: [RFC_REFS.ikev2, RFC_REFS.suite],
    applies: (config) => (config.encryption.value ?? '').endsWith('-CBC'),
  },
  {
    key: 'auth-null',
    title: 'Null integrity algorithm negotiated',
    category: 'authentication',
    severity: 'critical',
    riskScore: 88,
    summary: 'The CHILD_SA is protected without any integrity algorithm.',
    observedBehavior: 'AUTH_NONE (transform type 0) was accepted alongside the encryption transform.',
    expectedBehavior: 'Every CHILD_SA must carry an integrity algorithm or use an AEAD cipher.',
    impact: 'Traffic can be modified undetectably; authentication of peers is not enforced at the data plane.',
    recommendation: 'Remove AUTH_NONE from the proposal list and force AUTH_HMAC_SHA2_256_128.',
    rationale: 'The integrity transform attribute was 0, which maps to AUTH_NONE.',
    ruleId: 'SENTINEL-AUTH-003',
    references: [RFC_REFS.ikev2],
    applies: (config) => config.integrity.value === 'NULL',
  },
  {
    key: 'auth-md5',
    title: 'HMAC-MD5 integrity algorithm negotiated',
    category: 'authentication',
    severity: 'high',
    riskScore: 72,
    summary: 'A 128-bit truncated MD5 MAC protects the CHILD_SA.',
    observedBehavior: 'AUTH_HMAC_MD5_96 (transform type 2) was accepted for the CHILD_SA.',
    expectedBehavior: 'Use HMAC-SHA2-256 or better (RFC 8247 §3).',
    impact: 'MD5 is collision-broken and its truncated MAC has a small security margin against forgery.',
    recommendation: 'Re-propose the tunnel with AUTH_HMAC_SHA2_256_128 only.',
    rationale: 'Transform type 2 maps to AUTH_HMAC_MD5_96, which the algorithm registry marks as legacy.',
    ruleId: 'SENTINEL-AUTH-001',
    model: 'ipsec-algorithm-classifier/2.4',
    references: [RFC_REFS.algs, RFC_REFS.suite],
    applies: (config) => config.integrity.value === 'HMAC-MD5-96',
  },
  {
    key: 'auth-sha1',
    title: 'HMAC-SHA1 integrity algorithm retained',
    category: 'authentication',
    severity: 'low',
    riskScore: 18,
    summary: 'SHA-1 based integrity is still negotiable for the CHILD_SA.',
    observedBehavior: 'AUTH_HMAC_SHA1_96 (transform type 3) was accepted.',
    expectedBehavior: 'HMAC-SHA2-256-128 should be the floor for new CHILD_SAs.',
    impact: 'SHA-1 is deprecated for new deployments; continued support widens the downgrade surface.',
    recommendation: 'Drop AUTH_HMAC_SHA1_96 once dependent peers are upgraded.',
    rationale: 'Transform type 3 maps to AUTH_HMAC_SHA1_96.',
    ruleId: 'SENTINEL-AUTH-002',
    references: [RFC_REFS.algs],
    applies: (config) => config.integrity.value === 'HMAC-SHA1-96',
  },
  {
    key: 'dh-weak',
    title: 'Diffie-Hellman group below recommended strength',
    category: 'key-exchange',
    severity: 'high',
    riskScore: 66,
    summary: 'The IKE_SA used a group whose size is below the assessed minimum.',
    observedBehavior: ((): string => 'DHE group 2 (MODP-1024) was selected for the IKE_SA.')(),
    expectedBehavior: 'Use at least Group 14 (MODP-2048); Group 20 (X25519) is preferred (RFC 8247 §4).',
    impact: 'A 1024-bit group provides insufficient protection against large-scale passive attacks.',
    recommendation: 'Re-propose with Group 20 or Group 21 and retire MODP-1024.',
    rationale: 'The DH transform attribute was mapped to group 2, whose prime length is 1024 bits.',
    ruleId: 'SENTINEL-KEYEX-002',
    references: [RFC_REFS.algs, RFC_REFS.suite],
    applies: (config) => (config.dhGroup.value ?? '').includes('Group 2'),
  },
  {
    key: 'dh-legacy',
    title: 'MODP-1536 group in use',
    category: 'key-exchange',
    severity: 'medium',
    riskScore: 30,
    summary: 'A legacy MODP group is used for key exchange.',
    observedBehavior: 'Group 5 (MODP-1536) was selected for the IKE_SA.',
    expectedBehavior: 'Prefer elliptic-curve groups (X25519, secp384r1) for equivalent strength.',
    impact: 'Longer handshakes and less forward secrecy margin per bit of group size.',
    recommendation: 'Migrate to Group 20 or 21 at the next rekey.',
    rationale: 'The DH transform attribute was mapped to group 5, which is retained only for legacy peers.',
    ruleId: 'SENTINEL-KEYEX-003',
    references: [RFC_REFS.algs],
    applies: (config) => (config.dhGroup.value ?? '').includes('Group 5'),
  },
  {
    key: 'pfs-disabled',
    title: 'Perfect forward secrecy not negotiated',
    category: 'perfect-forward-secrecy',
    severity: 'medium',
    riskScore: 42,
    summary: 'No rekey with a fresh Diffie-Hellman exchange was observed.',
    observedBehavior: 'The CHILD_SA was created directly from the IKE_AUTH exchange and reused for its full lifetime.',
    expectedBehavior: 'Rekey the CHILD_SA with a new DH exchange (IKEv2 CREATE_CHILD_SA) to retain PFS.',
    impact:
      'Compromise of the long-term key would allow decryption of all recorded traffic on the tunnel.',
    recommendation: 'Enable PFS on CHILD_SA creation and set a bounded CHILD_SA lifetime.',
    rationale:
      'The capture contains no CREATE_CHILD_SA carrying a DH transform before the session ended, which is treated as PFS not in effect.',
    ruleId: 'SENTINEL-SA-004',
    model: 'pfs-inference/1.2',
    references: [RFC_REFS.ikev2],
    applies: (config) => config.perfectForwardSecrecy.value === false,
  },
  {
    key: 'replay-off',
    title: 'Anti-replay window disabled',
    category: 'replay-protection',
    severity: 'high',
    riskScore: 58,
    summary: 'The CHILD_SA accepts replayed packets without window checking.',
    observedBehavior: 'The ESP SA was created without an anti-replay window.',
    expectedBehavior: 'Enable anti-replay with a window of at least 32 packets (RFC 4303 §3.4.3).',
    impact: 'Captured packets can be replayed to the peer and accepted as fresh traffic.',
    recommendation: 'Set replay-window size to 64 packets and rekey the CHILD_SA.',
    rationale: 'Sequence numbers are present but the receiver window was not negotiated, so no replay state exists.',
    ruleId: 'SENTINEL-REPLAY-001',
    references: [RFC_REFS.esp],
    applies: (config) => config.replayProtection.value === false,
  },
  {
    key: 'ikev1',
    title: 'Session established with IKEv1',
    category: 'protocol-behavior',
    severity: 'medium',
    riskScore: 26,
    summary: 'The tunnel uses the previous version of the key exchange protocol.',
    observedBehavior: 'The IKE header protocol version was 0x01 (IKEv1).',
    expectedBehavior: 'New deployments should negotiate IKEv2 (RFC 7296).',
    impact:
      'IKEv1 has a weaker negotiation model, no native EAP-only authentication and a larger downgrade surface.',
    recommendation: 'Schedule an IKEv2 migration; confirm the peer supports it before the change window.',
    rationale: 'The protocol version byte in the IKE header is unambiguous evidence of the version in use.',
    ruleId: 'SENTINEL-PROTO-001',
    references: [RFC_REFS.ikev2],
    applies: (config) => config.ikeVersion.value === 'IKEv1',
  },
  {
    key: 'sa-lifetime',
    title: 'CHILD_SA lifetime exceeds policy maximum',
    category: 'security-association',
    severity: 'medium',
    riskScore: 28,
    summary: 'A long-lived CHILD_SA increases exposure if keys are compromised.',
    observedBehavior: ((): string => 'The negotiated CHILD_SA lifetime is 7 days.')(),
    expectedBehavior: 'CHILD_SA lifetimes should be bounded to 8 hours for reviewed deployments.',
    impact: 'Fewer rekeys means fewer opportunities to rotate keys and a larger decryption window after compromise.',
    recommendation: 'Reduce the CHILD_SA lifetime to 28800 seconds.',
    rationale: 'The lifetime attribute in the SA payload is compared against the configured policy maximum.',
    ruleId: 'SENTINEL-SA-001',
    references: [RFC_REFS.ikev2],
    applies: (config) => (config.lifetimeSeconds.value ?? 0) >= 86400,
  },
  {
    key: 'metadata',
    title: 'Outer addresses reveal protected topology',
    category: 'metadata-exposure',
    severity: 'low',
    riskScore: 14,
    summary: 'Tunnel endpoints are visible in the outer IP headers.',
    observedBehavior: 'Outer source and destination addresses match the tunnel endpoints for all ESP packets.',
    expectedBehavior: 'Consider an additional layer of encapsulation when topology concealment is a requirement.',
    impact: 'Passive observers can enumerate tunnel endpoints and correlate flows even though payloads are protected.',
    recommendation: 'Accept as a documented risk, or place the tunnel behind an additional overlay.',
    rationale:
      'Comparing the outer addresses against the negotiated traffic selectors shows a one-to-one mapping with the endpoints.',
    ruleId: 'SENTINEL-META-001',
    model: 'topology-inference/0.9',
    references: [RFC_REFS.esp],
    applies: () => true,
  },
  {
    key: 'negotiation-failure',
    title: 'Repeated IKE negotiation failures',
    category: 'protocol-behavior',
    severity: 'medium',
    riskScore: 24,
    summary: 'Multiple negotiations failed before the session was established.',
    observedBehavior: ((): string => 'Four IKE_SA_INIT exchanges were aborted before one completed.')(),
    expectedBehavior: 'Negotiations should complete without repeated retransmission or NO_PROPOSAL_CHOSEN failures.',
    impact: 'Intermittent connectivity and noisy logs obscure genuine attacks that mimic the same pattern.',
    recommendation: 'Align the proposal sets on both peers and confirm the clock sources are synchronised.',
    rationale: 'NO_PROPOSAL_CHOSEN and TS_UNACCEPTABLE notifications were counted per initiator SPI.',
    ruleId: 'SENTINEL-PROTO-010',
    references: [RFC_REFS.ikev2],
    applies: (_config, context) => (context?.retransmissions ?? 0) >= 8,
  },
  {
    key: 'compliance-baseline',
    title: 'Configuration outside assessed baseline',
    category: 'compliance',
    severity: 'medium',
    riskScore: 32,
    summary: 'The negotiated configuration does not meet the assessed cryptographic baseline.',
    observedBehavior: ((): string => 'At least one negotiated transform is below the baseline minimum.')(),
    expectedBehavior: 'All negotiated transforms should meet or exceed the assessed baseline for this environment.',
    impact: 'The deployment cannot be attested against the baseline until the deviations are remediated or accepted.',
    recommendation: 'Track the deviation as an accepted risk with an expiry date, or remediate the transforms.',
    rationale:
      'The observed transform set is compared against the environment baseline and every deviation is listed.',
    ruleId: 'SENTINEL-COMP-001',
    references: ['Internal baseline v3.2'],
    applies: (config) =>
      config.dhGroup.status === 'weak' ||
      config.dhGroup.status === 'warning' ||
      config.encryption.status === 'weak' ||
      config.integrity.status === 'weak',
  },
]

function buildFindings(sessions: VpnSession[], rng: () => number): SecurityFinding[] {
  const findings: SecurityFinding[] = []
  let counter = 0

  for (const session of sessions) {
    const extra = { retransmissions: session.retransmissions }
    for (const template of FINDING_TEMPLATES) {
      if (!template.applies(session.configuration, extra)) continue
      counter += 1
      const id = `FND-${String(4100 + counter)}`
      const evidenceId = addEvidence(session.id, 900 + counter, {
        packetRange: `${rangeInt(rng, 100, 5400)}–${rangeInt(rng, 5401, 5800)}`,
        exchange: 'IKE_AUTH',
        field: 'ikev2.sa.transform',
        ruleId: template.ruleId,
        model: template.model,
        explanation: template.rationale,
        rawValue: session.configuration.encryption.value ?? 'unknown',
        confidence: session.confidence ?? 0.9,
        source: 'observed',
      })

      const detectedOffset = -rangeInt(rng, 10, 60 * 96) * MINUTE
      findings.push({
        id,
        title: template.title,
        summary: template.summary,
        severity: template.severity,
        category: template.category,
        riskScore: Math.min(100, Math.round(template.riskScore * (0.85 + rng() * 0.3))),
        confidence: clampConfidence(session.confidence ?? 0.9),
        status: pickFindingStatus(rng, template.severity),
        observedBehavior: template.observedBehavior,
        expectedBehavior: template.expectedBehavior,
        impact: template.impact,
        recommendation: template.recommendation,
        rationale: template.rationale,
        ruleId: template.ruleId,
        model: template.model,
        source: 'calculated',
        sessionIds: [session.id],
        sessionCount: 1,
        relatedEventIds: [],
        evidence: [evidenceStore.get(evidenceId)!].filter(Boolean),
        references: template.references,
        detectedAt: iso(detectedOffset),
        updatedAt: iso(detectedOffset + rangeInt(rng, 1, 900) * MINUTE),
      })
    }
  }

  return findings.sort((a, b) => a.id.localeCompare(b.id))
}

function pickFindingStatus(rng: () => number, severity: Severity): SecurityFinding['status'] {
  const roll = rng()
  if (severity === 'critical') {
    if (roll < 0.55) return 'open'
    if (roll < 0.72) return 'acknowledged'
    if (roll < 0.85) return 'resolved'
    if (roll < 0.93) return 'suppressed'
    return 'false-positive'
  }
  if (roll < 0.44) return 'open'
  if (roll < 0.66) return 'acknowledged'
  if (roll < 0.85) return 'resolved'
  if (roll < 0.94) return 'suppressed'
  return 'false-positive'
}

function clampConfidence(value: number): number {
  return Math.max(0.31, Math.min(0.995, Math.round(value * 1000) / 1000))
}

/* ------------------------------------------------------------------ */
/* Session detail payloads                                              */
/* ------------------------------------------------------------------ */

function buildAssociations(session: VpnSession, rng: () => number): SecurityAssociation[] {
  const config = session.configuration
  const enc = config.encryption.value
  const integ = config.integrity.value
  const dh = config.dhGroup.value
  const isV1 = config.ikeVersion.value === 'IKEv1'
  const spi = (bytes: number) => randomHex(rng, bytes)
  const created = -rangeInt(rng, 4, 40) * HOUR
  const rows: SecurityAssociation[] = []

  const push = (
    protocol: SecurityAssociation['protocol'],
    direction: SecurityAssociation['direction'],
    spiValue: string,
    keyLifetime: number,
    rekeyStatus: RekeyStatus,
  ): void => {
    rows.push({
      id: `${session.id}-sa-${rows.length + 1}`,
      sessionId: session.id,
      spi: `0x${spiValue}`,
      direction,
      protocol,
      encryption: enc,
      integrity: integ,
      keyLifetimeSeconds: keyLifetime,
      byteLifetime: protocol === 'ESP' ? rangeInt(rng, 1_000_000, 8_000_000_000) : null,
      packetLifetime: protocol === 'ESP' ? rangeInt(rng, 500_000, 2_000_000_000) : null,
      replayWindowSize: config.replayWindowSize.value,
      createdAt: iso(created + rangeInt(rng, 0, 240) * MINUTE),
      expiresAt: iso(created + keyLifetime * 1000),
      rekeyStatus,
      source: 'observed',
      confidence: session.confidence,
    })
  }

  push('IKE', 'outbound', spi(4), config.keyLifetimeSeconds.value ?? 28800, isV1 ? 'completed' : 'scheduled')
  push('IKE', 'inbound', spi(4), config.keyLifetimeSeconds.value ?? 28800, 'scheduled')
  push('ESP', 'outbound', spi(4), config.lifetimeSeconds.value ?? 14400, config.perfectForwardSecrecy.value ? 'in-progress' : 'scheduled')
  push('ESP', 'inbound', spi(4), config.lifetimeSeconds.value ?? 14400, 'scheduled')
  if (session.status === 'draining' || session.status === 'closed') {
    push('ESP', 'outbound', spi(4), config.lifetimeSeconds.value ?? 14400, 'failed')
  }
  void dh
  return rows
}

function buildTimeline(session: VpnSession, rng: () => number, findings: SecurityFinding[]): SessionTimelineEvent[] {
  const events: SessionTimelineEvent[] = []
  const sessionFindings = findings.filter((finding) => finding.sessionIds.includes(session.id))
  const start = new Date(session.startedAt).getTime() - NOW
  let offset = start
  let index = 0

  const push = (
    type: TimelineEventType,
    description: string,
    source: string,
    confidence: number | null,
  ): void => {
    index += 1
    offset += rangeInt(rng, 4, 900) * 1000
    events.push({
      id: `${session.id}-ev-${index}`,
      sessionId: session.id,
      timestamp: new Date(NOW + offset).toISOString(),
      relativeTimeMs: offset,
      type,
      description,
      source,
      confidence,
      relatedFindingIds: [],
    })
  }

  const config = session.configuration
  push(
    'IKE_SA_INIT',
    `IKE_SA_INIT exchanged — ${config.ikeVersion.value ?? 'unknown'}, ${config.dhGroup.value ?? 'DH group unknown'}.`,
    'Packet capture',
    config.ikeVersion.confidence,
  )
  push(
    'IKE_AUTH',
    `IKE_AUTH completed — ${config.encryption.value ?? 'encryption unknown'}, ${config.integrity.value ?? 'integrity unknown'}.`,
    'Packet capture',
    config.encryption.confidence,
  )
  push(
    'CHILD_SA_CREATED',
    `CHILD_SA installed — ${config.vpnMode.value ?? 'mode unknown'} mode, ESP ${config.esp.value ? 'in use' : 'not used'}.`,
    'Correlation engine',
    0.95,
  )
  if (config.perfectForwardSecrecy.value) {
    push('REKEY', 'CHILD_SA rekeyed with a fresh Diffie-Hellman exchange (PFS retained).', 'Packet capture', 0.93)
  }
  if (session.retransmissions > 0) {
    const count = Math.min(session.retransmissions, 12)
    for (let i = 0; i < count; i += 1) {
      push('RETRANSMISSION', `IKE message retransmitted (attempt ${i + 2} of 5).`, 'Packet capture', 0.99)
    }
  }
  if (config.esp.value) {
    push('ESP_TRAFFIC', 'ESP payload observed — inner flow matches the negotiated traffic selectors.', 'Packet capture', 0.97)
  }
  for (const finding of sessionFindings.slice(0, 3)) {
    index += 1
    offset += rangeInt(rng, 60, 3_600) * 1000
    events.push({
      id: `${session.id}-ev-${index}`,
      sessionId: session.id,
      timestamp: new Date(NOW + offset).toISOString(),
      relativeTimeMs: offset,
      type: 'ERROR',
      description: `Finding raised: ${finding.title}.`,
      source: 'Analysis engine',
      confidence: finding.confidence,
      relatedFindingIds: [finding.id],
    })
  }
  if (session.status === 'closed' || session.status === 'failed') {
    push('SA_DELETION', `Security associations deleted (${session.status}).`, 'Packet capture', 0.99)
  } else if (session.status === 'rekeying') {
    push('REKEY', 'Rekey in progress — CREATE_CHILD_SA exchange started.', 'Packet capture', 0.92)
  }

  return events.sort((a, b) => a.relativeTimeMs - b.relativeTimeMs)
}

function buildSessionTraffic(session: VpnSession, rng: () => number) {
  const classes: DistributionSlice[] = buildClassDistribution(session, rng)
  const inbound = Math.round(session.byteCount * (0.38 + rng() * 0.22))
  const volume = Array.from({ length: 24 }, (_, index) => {
    const bucketStart = new Date(NOW - (23 - index) * HOUR)
    const base = (session.byteCount / 26) * (0.6 + rng() * 0.9)
    return {
      timestamp: bucketStart.toISOString(),
      value: Math.round(base),
      label: bucketStart.toISOString().slice(11, 16),
    }
  })
  const classLabel = classes[0]?.label ?? 'unknown'
  const proposed = classLabel as TrafficClass
  return {
    packets: session.packetCount,
    bytes: session.byteCount,
    averagePacketSize: Math.round(session.byteCount / Math.max(1, session.packetCount)),
    averageInterArrivalMs: Math.round((session.packetCount > 0 ? 86_400_000 : 0) / session.packetCount) || null,
    inboundBytes: inbound,
    outboundBytes: session.byteCount - inbound,
    volume,
    classes,
    classification: buildClassification(session, proposed, rng),
    confidence: pv(
      classLabel,
      'inferred',
      session.confidence,
      classLabel === 'unknown' ? 'unknown' : 'acceptable',
      [],
      'Classification is derived from packet size and cadence metadata observed inside the tunnel.',
    ),
  }
}

function buildClassDistribution(session: VpnSession, rng: () => number): DistributionSlice[] {
  const total = session.byteCount
  const primary = pickClass(session, rng)
  const secondary = pickClass(session, rng)
  const slices: DistributionSlice[] = [
    { label: primary, value: Math.round(total * (0.52 + rng() * 0.24)), share: 0 },
    { label: secondary, value: Math.round(total * 0.24), share: 0 },
    { label: 'unknown', value: Math.round(total * 0.16), share: 0 },
  ]
  const sum = slices.reduce((acc, slice) => acc + slice.value, 0) || 1
  return slices.map((slice) => ({ ...slice, share: slice.value / sum }))
}

function pickClass(session: VpnSession, _rng: () => number): TrafficClass {
  if (session.packetCount > 300_000) return 'video-like'
  if (session.packetCount > 150_000) return 'file-transfer-like'
  if (session.packetCount > 90_000) return 'web-like'
  if (session.packetCount > 40_000) return 'messaging-like'
  if (session.packetCount > 20_000) return 'voip-like'
  return rng() < 0.5 ? 'email-like' : 'icmp-like'
}

function buildClassification(
  session: VpnSession | null,
  proposed: TrafficClass,
  rng: () => number,
) {
  const confidence = session ? (session.confidence ?? 0.8) : 0.7
  return {
    id: `CLS-${session?.id ?? 'global'}`,
    sessionId: session?.id ?? null,
    label: confidence >= 0.55 ? proposed : ('unknown' as TrafficClass),
    proposedLabel: proposed,
    confidence,
    basis:
      'Inferred from packet size distribution, inter-arrival cadence and direction ratio observed inside the tunnel.',
    packets: session?.packetCount ?? 0,
    bytes: session?.byteCount ?? 0,
    firstSeen: session?.startedAt ?? iso(-6 * HOUR),
    lastSeen: session?.lastActivityAt ?? iso(-MINUTE),
    peer: session ? `${session.initiator.address} ↔ ${session.responder.address}` : 'multiple peers',
    hints: [
      `avg size ${Math.round((session?.byteCount ?? 0) / Math.max(1, session?.packetCount ?? 1))} B`,
      'no payload inspection',
      'encrypted payload',
    ],
    ...(rng() >= 0 ? {} : {}),
  }
}

function buildSessionModels(session: VpnSession): SessionModelOutput[] {
  return [
    {
      id: `${session.id}-m1`,
      name: 'IPsec configuration classifier',
      version: '2.4.1',
      task: 'Classify the negotiated transform set against the assessed baseline.',
      output: session.configuration.encryption.value ?? 'Unknown',
      confidence: clampConfidence(session.confidence ?? 0.9),
      explanation:
        'The model consumes the accepted SA payload transforms and returns the strongest applicable configuration label with a calibrated confidence.',
    },
    {
      id: `${session.id}-m2`,
      name: 'Tunnelled traffic classifier',
      version: '1.8.0',
      task: 'Infer an application class from encrypted payload metadata.',
      output: session.packetCount > 150_000 ? 'Bulk transfer' : 'Interactive',
      confidence: clampConfidence((session.confidence ?? 0.9) - 0.12),
      explanation:
        'Features are limited to observable metadata; the model does not decrypt payloads and never identifies an application with certainty.',
    },
    {
      id: `${session.id}-m3`,
      name: 'Anomaly detector',
      version: '0.9.4',
      task: 'Detect deviations from the learned baseline for this peer pair.',
      output: session.retransmissions > 8 ? 'Retransmission pattern above baseline' : 'Within baseline',
      confidence: clampConfidence((session.confidence ?? 0.9) - 0.04),
      explanation:
        'Retransmission rate and rekey cadence are compared against the rolling baseline for the same peer pair.',
    },
  ]
}

function buildCorrelation(session: VpnSession, findings: SecurityFinding[]): SessionCorrelation {
  const related = findings.filter((finding) => finding.sessionIds.includes(session.id))
  const score = Math.min(100, Math.round(session.riskScore))
  const posture =
    score >= 75 ? 'Critical posture' : score >= 50 ? 'Weak posture' : score >= 25 ? 'Needs review' : 'Strong posture'
  return {
    engine: 'correlation-engine 1.4 (mock)',
    score,
    posture,
    narrative:
      related.length === 0
        ? `No findings were raised against ${session.id}. The negotiated configuration met every assessed control.`
        : `${related.length} finding${related.length === 1 ? '' : 's'} were correlated to ${session.id}; the highest contributing risk is ${related[0].title.toLowerCase()}.`,
    contributingFindingIds: related.map((finding) => finding.id),
  }
}

function buildSessionRaw(session: VpnSession, associations: SecurityAssociation[]) {
  return {
    session_id: session.id,
    observed_at: session.startedAt,
    source: { kind: 'capture', capture_id: session.captureIds[0] ?? null, testbed: session.testbed ?? null },
    peers: {
      initiator: session.initiator,
      responder: session.responder,
    },
    ike: {
      version: session.configuration.ikeVersion.value,
      dh_group: session.configuration.dhGroup.value,
      prf: session.configuration.prf.value,
      authentication: session.configuration.authenticationMethod.value,
      rekey_count: session.rekeyCount,
      retransmissions: session.retransmissions,
    },
    child_sa: {
      mode: session.configuration.vpnMode.value,
      esp: session.configuration.esp.value,
      ah: session.configuration.ah.value,
      encryption: session.configuration.encryption.value,
      integrity: session.configuration.integrity.value,
      lifetime_seconds: session.configuration.lifetimeSeconds.value,
      replay_window: session.configuration.replayWindowSize.value,
      perfect_forward_secrecy: session.configuration.perfectForwardSecrecy.value,
    },
    security_associations: associations.map((sa) => ({
      spi: sa.spi,
      direction: sa.direction,
      protocol: sa.protocol,
      created_at: sa.createdAt,
      expires_at: sa.expiresAt,
      rekey_status: sa.rekeyStatus,
    })),
    assessment: {
      risk_score: session.riskScore,
      risk_band: session.riskBand,
      confidence: session.confidence,
      data_source: 'calculated',
    },
    provenance: {
      produced_by: 'ipsec-sentinel mock dataset',
      note: 'Synthetic values for interface development. Not measurement data.',
    },
  }
}

/* ------------------------------------------------------------------ */
/* Experiments                                                          */
/* ------------------------------------------------------------------ */

const EXPERIMENT_NAMES = [
  'AES-256-GCM baseline tunnel',
  'AES-CBC regression check',
  'MODP-1024 downgrade probe',
  'PFS rekey cycle observation',
  'Replay window stress',
  'IKEv1 compatibility hold',
  'CHILD_SA lifetime abuse',
  'CHACHA20-POLY1305 interop',
  'Extended session stability',
  'Null integrity acceptance test',
  'Dual-stack IPv6 tunnel',
  'Rekey under heavy load',
]

const HYPOTHESES = [
  'The tunnel holds an AEAD transform and rekeys with PFS for the full assessment window.',
  'The observed transform set matches the configured proposal set with no silent downgrade.',
  'A downgrade attempt to a weak group is refused by the responder.',
  'CHILD_SA rekeys occur with a fresh DH exchange and do not interrupt data flow.',
  'Anti-replay windows reject duplicated sequence numbers.',
  'Legacy IKEv1 peers remain reachable but are reported as deviations.',
  'Lifetime values above policy are flagged by the assessment engine.',
  'ChaCha20-Poly1305 negotiates cleanly against an AES-capable responder.',
  'Long-lived sessions stay stable without rekey failures.',
  'AUTH_NONE is never accepted by the responder.',
  'IPv6 and IPv4 selectors coexist without selector mismatch errors.',
  'Rekey under load does not drop the tunnel.',
]

function buildExperiments(sessions: VpnSession[], rng: () => number): Experiment[] {
  return EXPERIMENT_NAMES.map((name, index) => {
    const session = sessions[index % sessions.length]
    const config = session.configuration
    const status = pickExperimentStatus(rng, index)
    const groundTruth: ExperimentGroundTruth = {
      ikeVersion: config.ikeVersion.value ?? 'IKEv2',
      vpnMode: config.vpnMode.value ?? 'tunnel',
      encryption: config.encryption.value ?? 'AES-256-GCM',
      integrity: config.integrity.value ?? 'HMAC-SHA2-256-128',
      dhGroup: config.dhGroup.value ?? 'Group 20 (X25519)',
      perfectForwardSecrecy: config.perfectForwardSecrecy.value ?? true,
      ipVersion: config.ipVersion.value ?? 'IPv4',
      keyLifetimeSeconds: config.keyLifetimeSeconds.value ?? 28800,
      expectedFindings: [],
      notes: 'Configured on the testbed before the capture window opened.',
    }
    const startedOffset = -rangeInt(rng, 2, 30 * 24) * HOUR
    const endedOffset = startedOffset + rangeInt(rng, 20, 900) * MINUTE
    return {
      id: `EXP-${String(3100 + index)}`,
      name,
      hypothesis: HYPOTHESES[index] ?? 'Undocumented hypothesis.',
      status,
      ikeVersion: groundTruth.ikeVersion,
      vpnMode: groundTruth.vpnMode,
      encryption: groundTruth.encryption,
      integrity: groundTruth.integrity,
      dhGroup: groundTruth.dhGroup,
      perfectForwardSecrecy: groundTruth.perfectForwardSecrecy,
      ipVersion: groundTruth.ipVersion,
      trafficProfile: pick(
        rng,
        ['interactive', 'bulk-transfer', 'streaming', 'rekey-cycle', 'idle', 'malformed-probe'] as const,
      ),
      expectedConfiguration: `${groundTruth.ikeVersion} · ${groundTruth.vpnMode} · ${groundTruth.encryption} · ${groundTruth.dhGroup} · PFS ${groundTruth.perfectForwardSecrecy ? 'on' : 'off'}`,
      groundTruth,
      riskScore: session.riskScore,
      riskBand: session.riskBand,
      confidence: session.confidence,
      startedAt: status === 'created' ? null : iso(startedOffset),
      endedAt: status === 'completed' || status === 'cancelled' || status === 'failed' ? iso(endedOffset) : null,
      durationMs:
        status === 'completed' || status === 'cancelled' || status === 'failed' ? endedOffset - startedOffset : null,
      sessionIds: status === 'created' ? [] : [session.id],
      captureIds: status === 'created' ? [] : [`CAP-${String(7700 + index)}`],
      findingCount: status === 'created' ? 0 : rangeInt(rng, 0, 6),
      progressPercent: experimentProgress(status),
      testbed: session.testbed ?? 'testbed-a',
      operator: 'analyst-01',
    }
  })
}

function pickExperimentStatus(rng: () => number, index: number): ExperimentStatus {
  if (index === 0) return 'running'
  if (index === 1) return 'capturing'
  if (index === 2) return 'analyzing'
  const roll = rng()
  if (roll < 0.55) return 'completed'
  if (roll < 0.7) return 'completed'
  if (roll < 0.8) return 'failed'
  if (roll < 0.88) return 'cancelled'
  return 'created'
}

function experimentProgress(status: ExperimentStatus): number {
  switch (status) {
    case 'created':
      return 0
    case 'running':
      return 15
    case 'capturing':
      return 45
    case 'analyzing':
      return 78
    case 'completed':
      return 100
    case 'failed':
      return 62
    case 'cancelled':
      return 40
  }
}

function buildExperimentDetail(
  experiment: Experiment,
  session: VpnSession | undefined,
  findings: SecurityFinding[],
  rng: () => number,
): ExperimentDetail {
  const related = session ? findings.filter((finding) => finding.sessionIds.includes(session.id)) : []
  const observations: ExperimentComparisonCell[] = [
    {
      field: 'IKE version',
      groundTruth: experiment.groundTruth.ikeVersion,
      observed: session?.configuration.ikeVersion.value ?? 'Unknown',
      agrees: session ? session.configuration.ikeVersion.value === experiment.groundTruth.ikeVersion : null,
    },
    {
      field: 'VPN mode',
      groundTruth: experiment.groundTruth.vpnMode,
      observed: session?.configuration.vpnMode.value ?? 'Unknown',
      agrees: session ? session.configuration.vpnMode.value === experiment.groundTruth.vpnMode : null,
    },
    {
      field: 'Encryption',
      groundTruth: experiment.groundTruth.encryption,
      observed: session?.configuration.encryption.value ?? 'Unknown',
      agrees: session ? session.configuration.encryption.value === experiment.groundTruth.encryption : null,
    },
    {
      field: 'Integrity',
      groundTruth: experiment.groundTruth.integrity,
      observed: session?.configuration.integrity.value ?? 'Unknown',
      agrees: session ? session.configuration.integrity.value === experiment.groundTruth.integrity : null,
    },
    {
      field: 'DH group',
      groundTruth: experiment.groundTruth.dhGroup,
      observed: session?.configuration.dhGroup.value ?? 'Unknown',
      agrees: session ? session.configuration.dhGroup.value === experiment.groundTruth.dhGroup : null,
    },
    {
      field: 'Perfect forward secrecy',
      groundTruth: experiment.groundTruth.perfectForwardSecrecy ? 'Enabled' : 'Disabled',
      observed:
        session?.configuration.perfectForwardSecrecy.value === null || session === undefined
          ? 'Unknown'
          : session.configuration.perfectForwardSecrecy.value
            ? 'Enabled'
            : 'Disabled',
      agrees: session ? session.configuration.perfectForwardSecrecy.value === experiment.groundTruth.perfectForwardSecrecy : null,
    },
    {
      field: 'IP version',
      groundTruth: experiment.groundTruth.ipVersion,
      observed: session?.configuration.ipVersion.value ?? 'Unknown',
      agrees: session ? session.configuration.ipVersion.value === experiment.groundTruth.ipVersion : null,
    },
    {
      field: 'CHILD_SA lifetime',
      groundTruth: `${experiment.groundTruth.keyLifetimeSeconds}s`,
      observed: session?.configuration.lifetimeSeconds.value
        ? `${session.configuration.lifetimeSeconds.value}s`
        : 'Unknown',
      agrees: null,
    },
  ]

  const timeline = session
    ? buildTimeline(session, rng, findings)
        .slice(0, 14)
        .map((event) => ({
          id: event.id,
          timestamp: event.timestamp,
          type: event.type,
          description: event.description,
          source: event.source,
        }))
    : []

  return {
    experiment,
    observations,
    modelOutputs: (session ? buildSessionModels(session) : []).map((model) => ({
      id: model.id,
      name: model.name,
      version: model.version,
      output: model.output,
      confidence: model.confidence,
      agrees: model.output === experiment.groundTruth.encryption ? true : null,
    })),
    correlation: session
      ? buildCorrelation(session, findings)
      : {
          engine: 'correlation-engine 1.4 (mock)',
          score: 0,
          posture: 'No capture associated',
          narrative: 'This experiment has not produced a capture, so no correlation is available yet.',
        },
    findings: related.slice(0, 8).map((finding) => ({
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      status: finding.status,
      confidence: finding.confidence,
    })),
    traffic: session
      ? {
          packets: session.packetCount,
          bytes: session.byteCount,
          averagePacketSize: Math.round(session.byteCount / Math.max(1, session.packetCount)),
          classes: buildClassDistribution(session, rng),
        }
      : { packets: 0, bytes: 0, averagePacketSize: null, classes: [] },
    timeline,
    configuration: session
      ? ([
          ['IKE version', session.configuration.ikeVersion],
          ['VPN mode', session.configuration.vpnMode],
          ['Encryption', session.configuration.encryption],
          ['Integrity', session.configuration.integrity],
          ['DH group', session.configuration.dhGroup],
          ['PRF', session.configuration.prf],
        ] as [string, ProtocolValue<string>][]).map(([label, value]) => ({
          label,
          value: value as ProtocolValue<string>,
        }))
      : [],
    raw: {
      experiment_id: experiment.id,
      status: experiment.status,
      ground_truth: experiment.groundTruth,
      observations,
      provenance: {
        produced_by: 'ipsec-sentinel mock dataset',
        note: 'Synthetic values for interface development. Not measurement data.',
      },
    },
  }
}

/* ------------------------------------------------------------------ */
/* Threats                                                              */
/* ------------------------------------------------------------------ */

const THREAT_SEEDS: {
  id: ThreatId
  name: string
  category: SecurityFinding['category']
  baseSeverity: Severity
  likelihood: number
  impact: number
  description: string
  findingKeys: string[]
  references: string[]
}[] = [
  {
    id: 'weak-cryptographic-algorithm',
    name: 'Weak cryptographic algorithm',
    category: 'cryptography',
    baseSeverity: 'high',
    likelihood: 4,
    impact: 4,
    description:
      'Tunnels negotiating ciphers with small block or key sizes expose recorded traffic to retrospective decryption.',
    findingKeys: ['crypto-3des', 'crypto-des', 'auth-md5', 'auth-null'],
    references: [RFC_REFS.algs, RFC_REFS.suite],
  },
  {
    id: 'weak-diffie-hellman-group',
    name: 'Weak Diffie-Hellman group',
    category: 'key-exchange',
    baseSeverity: 'high',
    likelihood: 3,
    impact: 4,
    description: 'Finite-field groups below MODP-2048 provide insufficient forward secrecy margin.',
    findingKeys: ['dh-weak', 'dh-legacy'],
    references: [RFC_REFS.algs],
  },
  {
    id: 'pfs-disabled',
    name: 'Perfect forward secrecy disabled',
    category: 'perfect-forward-secrecy',
    baseSeverity: 'medium',
    likelihood: 4,
    impact: 3,
    description:
      'Sessions without CHILD_SA rekeying remain decryptable if the long-term key is later compromised.',
    findingKeys: ['pfs-disabled'],
    references: [RFC_REFS.ikev2],
  },
  {
    id: 'replay-window-anomaly',
    name: 'Replay protection anomaly',
    category: 'replay-protection',
    baseSeverity: 'high',
    likelihood: 2,
    impact: 4,
    description: 'CHILD_SAs without an anti-replay window accept duplicated packets as fresh traffic.',
    findingKeys: ['replay-off'],
    references: [RFC_REFS.esp],
  },
  {
    id: 'excessive-sa-lifetime',
    name: 'Excessive SA lifetime',
    category: 'security-association',
    baseSeverity: 'medium',
    likelihood: 3,
    impact: 3,
    description: 'Long CHILD_SA lifetimes delay key rotation and widen the compromise window.',
    findingKeys: ['sa-lifetime'],
    references: [RFC_REFS.ikev2],
  },
  {
    id: 'ike-version-downgrade',
    name: 'IKE version downgrade',
    category: 'protocol-behavior',
    baseSeverity: 'medium',
    likelihood: 2,
    impact: 3,
    description: 'Sessions established with IKEv1 have a larger negotiation and downgrade surface.',
    findingKeys: ['ikev1', 'negotiation-failure'],
    references: [RFC_REFS.ikev2],
  },
  {
    id: 'repeated-negotiation-failure',
    name: 'Repeated negotiation failure',
    category: 'protocol-behavior',
    baseSeverity: 'low',
    likelihood: 3,
    impact: 2,
    description: 'Repeated failed negotiations degrade availability and mask genuine attack attempts.',
    findingKeys: ['negotiation-failure'],
    references: [RFC_REFS.ikev2],
  },
  {
    id: 'endpoint-metadata-exposure',
    name: 'Endpoint metadata exposure',
    category: 'metadata-exposure',
    baseSeverity: 'low',
    likelihood: 5,
    impact: 2,
    description: 'Outer IP headers reveal tunnel endpoints and traffic correlation patterns.',
    findingKeys: ['metadata'],
    references: [RFC_REFS.esp],
  },
  {
    id: 'encrypted-traffic-anomaly',
    name: 'Encrypted traffic anomaly',
    category: 'traffic-anomaly',
    baseSeverity: 'low',
    likelihood: 2,
    impact: 3,
    description: 'Tunnelled traffic whose cadence does not match its inferred class indicates mislabelled flows.',
    findingKeys: ['compliance-baseline'],
    references: [RFC_REFS.esp],
  },
]

function buildThreats(findings: SecurityFinding[], rng: () => number): Threat[] {
  const keyByTemplate = new Map(FINDING_TEMPLATES.map((template) => [template.title, template.key]))

  return THREAT_SEEDS.map((seed) => {
    const matched = findings.filter((finding) => {
      const key = keyByTemplate.get(finding.title)
      return key ? seed.findingKeys.includes(key) : false
    })
    void rng
    const sessionIds = [...new Set(matched.flatMap((finding) => finding.sessionIds))]
    const worst = matched.reduce<Severity>((acc, finding) => {
      const order: Severity[] = ['critical', 'high', 'medium', 'low', 'informational', 'unknown']
      return order.indexOf(finding.severity) < order.indexOf(acc) ? finding.severity : acc
    }, 'informational')
    const confidence = matched.length
      ? clampConfidence(matched.reduce((sum, finding) => sum + (finding.confidence ?? 0), 0) / matched.length)
      : null
    const firstDetected = matched.reduce<string>(
      (earliest, finding) => (finding.detectedAt < earliest ? finding.detectedAt : earliest),
      matched[0]?.detectedAt ?? iso(-30 * DAY),
    )
    return {
      id: seed.id,
      name: seed.name,
      category: seed.category,
      severity: matched.length === 0 ? 'unknown' : worst,
      likelihood: clampAxis(seed.likelihood + (rng() < 0.5 ? 0 : 1), 1, 5),
      impact: clampAxis(seed.impact + (rng() < 0.35 ? 1 : 0), 1, 5),
      description: seed.description,
      affectedSessions: sessionIds.length,
      sessionIds: sessionIds.slice(0, 40),
      confidence,
      firstDetected,
      lastObserved: matched.reduce<string>(
        (latest, finding) => (finding.updatedAt > latest ? finding.updatedAt : latest),
        matched[0]?.updatedAt ?? iso(-DAY),
      ),
      relatedFindingIds: matched.slice(0, 24).map((finding) => finding.id),
      references: seed.references,
    }
  })
}

function clampAxis(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, Math.round(value)))
}

/* ------------------------------------------------------------------ */
/* Captures                                                             */
/* ------------------------------------------------------------------ */

const CAPTURE_LABELS: CaptureLabel[] = [
  'benign',
  'weak-crypto',
  'weak-dh',
  'no-pfs',
  'replay-probe',
  'lifetime-abuse',
  'downgrade-probe',
  'traffic-anomaly',
  'unlabelled',
]

const CAPTURE_TRAFFIC: CaptureTrafficType[] = [
  'interactive',
  'bulk',
  'streaming',
  'rekey-cycle',
  'idle',
  'mixed',
]

function buildCaptures(
  sessions: VpnSession[],
  experiments: Experiment[],
  rng: () => number,
): { records: CaptureRecord[]; owners: Map<string, string[]> } {
  const records: CaptureRecord[] = []
  /** capture id -> the session ids it was extracted from */
  const owners = new Map<string, string[]>()
  for (let index = 0; index < 22; index += 1) {
    const session = sessions[index % sessions.length]
    const experiment = experiments[index % experiments.length]
    const packets = rangeInt(rng, 4_000, 620_000)
    const createdOffset = -rangeInt(rng, 1, 45 * 24) * HOUR
    const id = `CAP-${String(7700 + index)}`
    records.push({
      id,
      experimentId: index % 6 === 0 ? null : experiment.id,
      fileName: `${id.toLowerCase()}-${session.configuration.ikeVersion.value?.toLowerCase() ?? 'ikev2'}-${session.configuration.encryption.value?.toLowerCase().replace(/[^a-z0-9]+/g, '-') ?? 'encr'}.pcapng`,
      sizeBytes: packets * rangeInt(rng, 180, 640),
      ikeVersion: session.configuration.ikeVersion.value ?? 'IKEv2',
      vpnMode: session.configuration.vpnMode.value ?? 'tunnel',
      encryption: session.configuration.encryption.value ?? 'Unknown',
      dhGroup: session.configuration.dhGroup.value ?? 'Unknown',
      perfectForwardSecrecy: session.configuration.perfectForwardSecrecy.value ?? false,
      ipVersion: session.configuration.ipVersion.value ?? 'IPv4',
      trafficType: pick(rng, CAPTURE_TRAFFIC),
      packetCount: packets,
      byteCount: packets * rangeInt(rng, 320, 1_180),
      durationMs: rangeInt(rng, 60, 7_200) * 1000,
      label: pick(rng, CAPTURE_LABELS),
      createdAt: iso(createdOffset),
      sessionCount: 0,
      findingCount: 0,
      checksum: randomHex(rng, 32).toLowerCase(),
      testbed: session.testbed ?? 'testbed-a',
      payloadAccess: false,
    })
    const extraSessions = [session.id]
    for (let extra = 0; extra < rangeInt(rng, 0, 3); extra += 1) {
      const other = sessions[(index + 1 + extra * 3) % sessions.length]
      if (other && !extraSessions.includes(other.id)) extraSessions.push(other.id)
    }
    owners.set(id, extraSessions)
  }
  return {
    records: records.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)),
    owners,
  }
}

/* ------------------------------------------------------------------ */
/* Reports                                                              */
/* ------------------------------------------------------------------ */

function buildReports(sessions: VpnSession[], findings: SecurityFinding[], rng: () => number): Report[] {
  const types: Report['type'][] = ['executive', 'technical', 'compliance', 'comparison']
  const names = [
    'Quarterly IPsec posture review',
    'Branch tunnel technical assessment',
    'Testbed baseline comparison',
    'Partner interconnect evidence pack',
    'Crypto agility readiness audit',
    'Incident window IPsec evidence',
    'IPv6 migration control mapping',
  ]
  return names.map((name, index) => {
    const type = types[index % types.length]
    const status: Report['status'] =
      index === 0 ? 'ready' : index === 1 ? 'generating' : index === 2 ? 'queued' : index === 3 ? 'failed' : 'ready'
    const scopeSessions = sessions.slice(index, index + 3)
    return {
      id: `RPT-${String(9100 + index)}`,
      name,
      type,
      detailLevel: index % 3 === 0 ? 'summary' : index % 3 === 1 ? 'standard' : 'forensic',
      status,
      scope: {
        sessionIds: scopeSessions.map((session) => session.id),
        experimentIds: index % 2 === 0 ? [`EXP-${3100 + index}`] : [],
        from: iso(-30 * DAY),
        to: iso(-1 * HOUR),
      },
      formats: index % 2 === 0 ? ['pdf', 'json'] : ['pdf', 'csv'],
      createdAt: iso(-rangeInt(rng, 1, 20) * DAY),
      createdBy: index % 2 === 0 ? 'analyst-01' : 'analyst-02',
      sizeBytes: status === 'ready' ? rangeInt(rng, 240_000, 4_800_000) : null,
      findingCount: findings.filter((finding) => scopeSessions.some((session) => finding.sessionIds.includes(session.id)))
        .length,
      sessionCount: scopeSessions.length,
      securityScore: status === 'ready' ? rangeInt(rng, 22, 78) : null,
      progressPercent:
        status === 'ready' ? 100 : status === 'generating' ? rangeInt(rng, 20, 90) : status === 'queued' ? 0 : rangeInt(rng, 30, 70),
      error: status === 'failed' ? 'Report worker timed out while rendering the evidence appendix.' : undefined,
    }
  })
}

/* ------------------------------------------------------------------ */
/* Health                                                               */
/* ------------------------------------------------------------------ */

const SERVICE_VERSIONS: Record<ServiceName, string> = {
  frontend: '0.9.0-frontend',
  'api-gateway': '—',
  'testbed-manager': '—',
  'packet-analyzer': '—',
  'ml-service': '—',
  'correlation-engine': '—',
  database: '—',
  'report-generator': '—',
  'event-stream': '—',
}

function buildHealth(rng: () => number): ServiceHealth[] {
  const plan: { name: ServiceName; status: ServiceStatus; detail: string }[] = [
    { name: 'frontend', status: 'operational', detail: 'Static bundle served. No backend dependency.' },
    { name: 'api-gateway', status: 'unknown', detail: 'Not connected — mock services are in use.' },
    { name: 'testbed-manager', status: 'unknown', detail: 'Not connected — testbed control is simulated.' },
    { name: 'packet-analyzer', status: 'unknown', detail: 'Not connected — dissection is generated in-browser.' },
    { name: 'ml-service', status: 'unknown', detail: 'Not connected — model output is a deterministic mock.' },
    { name: 'correlation-engine', status: 'unknown', detail: 'Not connected — correlation is computed in the mock layer.' },
    { name: 'database', status: 'unknown', detail: 'Not connected — no persistence layer is configured.' },
    { name: 'report-generator', status: 'unknown', detail: 'Not connected — report generation is mocked.' },
    { name: 'event-stream', status: 'unknown', detail: 'Not connected — live events come from a local generator.' },
  ]
  return plan.map((entry) => ({
    name: entry.name,
    label: entry.name,
    status: entry.status,
    version: SERVICE_VERSIONS[entry.name],
    responseTimeMs: entry.status === 'operational' ? rangeInt(rng, 4, 42) : null,
    lastChecked: iso(-rangeInt(rng, 5, 120) * 1000),
    error: null,
    detail: entry.detail,
  }))
}

function overallStatus(services: ServiceHealth[]): ServiceStatus {
  if (services.some((service) => service.status === 'offline')) return 'offline'
  if (services.some((service) => service.status === 'degraded')) return 'degraded'
  if (services.every((service) => service.status === 'unknown')) return 'unknown'
  if (services.some((service) => service.status === 'unknown')) return 'degraded'
  return 'operational'
}

/* ------------------------------------------------------------------ */
/* Live events                                                          */
/* ------------------------------------------------------------------ */

const LIVE_EVENT_TEMPLATES: {
  type: LiveEventType
  severity: Severity
  build(session: VpnSession, rng: () => number): string
}[] = [
  {
    type: 'IKE_SA_INIT_COMPLETED',
    severity: 'informational',
    build: (session) =>
      `IKE_SA_INIT completed for ${session.initiator.address} ↔ ${session.responder.address} (${session.configuration.dhGroup.value ?? 'unknown group'}).`,
  },
  {
    type: 'IKE_AUTH_COMPLETED',
    severity: 'informational',
    build: (session) =>
      `IKE_AUTH completed — ${session.configuration.encryption.value ?? 'unknown encryption'} accepted.`,
  },
  {
    type: 'CHILD_SA_CREATED',
    severity: 'informational',
    build: (session) =>
      `CHILD_SA created in ${session.configuration.vpnMode.value ?? 'unknown'} mode with replay window ${session.configuration.replayWindowSize.value ?? 0}.`,
  },
  {
    type: 'ESP_TRAFFIC',
    severity: 'informational',
    build: (session, rng) =>
      `ESP payload observed (${rangeInt(rng, 120, 1_480)} bytes) on ${session.configuration.trafficSelectors.value ?? 'unknown selectors'}.`,
  },
  {
    type: 'AH_TRAFFIC',
    severity: 'low',
    build: (session) => `AH header observed on ${session.id}; integrity-only protection carries no confidentiality.`,
  },
  {
    type: 'REKEY_COMPLETED',
    severity: 'informational',
    build: (session) =>
      `Rekey completed for ${session.id}; ${session.configuration.perfectForwardSecrecy.value ? 'fresh DH exchange performed' : 'no DH exchange observed'}.`,
  },
  {
    type: 'RETRANSMISSION_DETECTED',
    severity: 'medium',
    build: (session, rng) =>
      `Retransmission detected on ${session.initiator.address} (attempt ${rangeInt(rng, 2, 5)} of 5).`,
  },
  {
    type: 'IKE_NEGOTIATION_FAILED',
    severity: 'high',
    build: (session) =>
      `IKE negotiation failed for ${session.initiator.address} → ${session.responder.address}: NO_PROPOSAL_CHOSEN.`,
  },
  {
    type: 'FINDING_CREATED',
    severity: 'high',
    build: (session) => `New finding correlated to ${session.id} after configuration reassessment.`,
  },
  {
    type: 'TRAFFIC_CLASSIFICATION_UPDATED',
    severity: 'informational',
    build: (session) => `Traffic classification updated for ${session.id} after new metadata.`,
  },
  {
    type: 'SA_DELETED',
    severity: 'low',
    build: (session) => `Security associations for ${session.id} deleted (DELETE payload received).`,
  },
]

function buildLiveEvents(sessions: VpnSession[], count: number, rng: () => number): LiveEvent[] {
  const events: LiveEvent[] = []
  for (let index = 0; index < count; index += 1) {
    const session = pick(rng, sessions)
    const template = pick(rng, LIVE_EVENT_TEMPLATES)
    const at = -rangeInt(rng, 1, 5_400) * 1000
    events.push({
      id: `EVT-${String(500000 + index)}`,
      timestamp: new Date(NOW + at).toISOString(),
      type: template.type,
      sessionId: session.id,
      sessionLabel: session.label,
      peer: `${session.initiator.address} ↔ ${session.responder.address}`,
      description: template.build(session, rng),
      severity: template.severity,
      confidence: template.type === 'FINDING_CREATED' ? clampConfidence(session.confidence ?? 0.8) : null,
      source: template.type === 'FINDING_CREATED' ? 'Analysis engine' : 'Packet analyzer',
    })
  }
  return events.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1))
}

/* ------------------------------------------------------------------ */
/* Dataset assembly                                                     */
/* ------------------------------------------------------------------ */

const rng = mulberry32(SEED)
const SESSIONS = buildSessions()
const FINDINGS = buildFindings(SESSIONS, rng)
const EXPERIMENTS = buildExperiments(SESSIONS, rng)
const { records: CAPTURES, owners: CAPTURE_OWNERS } = buildCaptures(SESSIONS, EXPERIMENTS, rng)
const REPORTS = buildReports(SESSIONS, FINDINGS, rng)
const HEALTH = buildHealth(rng)
const THREATS = buildThreats(FINDINGS, rng)

// Link sessions to their captures and experiments.
for (const session of SESSIONS) {
  session.captureIds = CAPTURES.filter((capture) =>
    CAPTURE_OWNERS.get(capture.id)?.includes(session.id),
  ).map((capture) => capture.id)
  session.experimentIds = EXPERIMENTS.filter((experiment) => experiment.sessionIds.includes(session.id))
    .slice(0, 2)
    .map((experiment) => experiment.id)
  for (const severity of Object.keys(session.findingCounts) as (keyof typeof session.findingCounts)[]) {
    session.findingCounts[severity] = FINDINGS.filter(
      (finding) => finding.sessionIds.includes(session.id) && finding.severity === severity,
    ).length
  }
}

// Capture counters are derived from the same links, so the dataset page and the
// session page can never disagree.
for (const capture of CAPTURES) {
  const sessionIds = CAPTURE_OWNERS.get(capture.id) ?? []
  capture.sessionCount = sessionIds.length
  capture.findingCount = FINDINGS.filter((finding) =>
    finding.sessionIds.some((id) => sessionIds.includes(id)),
  ).length
}

export const mockDataset = {
  sessions: SESSIONS,
  findings: FINDINGS,
  threats: THREATS,
  experiments: EXPERIMENTS,
  captures: CAPTURES,
  reports: REPORTS,
  services: HEALTH,
  evidence: evidenceStore,
  experimentDetail(experimentId: string): ExperimentDetail | null {
    const experiment = EXPERIMENTS.find((entry) => entry.id === experimentId)
    if (!experiment) return null
    const session = SESSIONS.find((entry) => experiment.sessionIds.includes(entry.id))
    return buildExperimentDetail(experiment, session, FINDINGS, mulberry32(SEED + experimentId.length))
  },
  sessionDetail(sessionId: string): SessionDetail | null {
    const session = SESSIONS.find((entry) => entry.id === sessionId)
    if (!session) return null
    const localRng = mulberry32(SEED + sessionId.length * 31)
    const associations = buildAssociations(session, localRng)
    const timeline = buildTimeline(session, localRng, FINDINGS)
    const evidence = [...evidenceStore.values()].filter((entry) => entry.id.includes(sessionId))
    return {
      session,
      securityAssociations: associations,
      timeline,
      evidence,
      raw: buildSessionRaw(session, associations),
      traffic: buildSessionTraffic(session, localRng),
      models: buildSessionModels(session),
      correlation: buildCorrelation(session, FINDINGS),
    }
  },
  liveEvents(count: number): LiveEvent[] {
    return buildLiveEvents(SESSIONS, count, mulberry32(SEED + count))
  },
  evidenceForSession(sessionId: string): EvidenceReference[] {
    return [...evidenceStore.values()].filter((entry) => entry.id.includes(sessionId))
  },
  systemHealth(): SystemHealth {
    return {
      services: HEALTH,
      overall: overallStatus(HEALTH),
      checkedAt: new Date(NOW).toISOString(),
      mockMode: true,
      apiBaseUrl: 'mock://ipsec-sentinel',
    }
  },
  severityFromBand,
  now: NOW,
}
