import type { AiService } from '../api/aiService'
import type {
  AiSession,
  AiAskRequest,
  AiAskResponse,
  AiContextRef,
} from '../../types/ai'
import type { Packet } from '../../types/packet'
import type { RiskLevel } from '../../types/security'
import { packetIpsecSummary } from '../../lib/ipsecSummary'
import { generateId } from './tools'

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

/** Minimal lookup contract — the mock resolves the selected packet like a
 * backend would, so the UI never needs to pass full packet data around. */
interface PacketLookup {
  getById(id: string): Promise<Packet | null>
}

/* ------------------------------------------------------------------ */
/* General answers (used when no packet is selected as context).       */
/* ------------------------------------------------------------------ */

interface Canned {
  match: RegExp
  answer: string
  suggestions: string[]
}

const CANNED: Canned[] = [
  {
    match: /ikev2|handshake|protocol|spi/i,
    answer:
      'IKEv2 (RFC 7296) is the control plane of the tunnel: IKE_SA_INIT negotiates the crypto suite, IKE_SA_AUTH authenticates peers and installs the SA, and CREATE_CHILD_SA derives child SAs for ESP/AH. The SPI is the tunnel identifier that binds packets to the SA holding the negotiated keys. Open the Live Analyzer, select a packet, and I will walk the exact fields on it.',
    suggestions: ['What is this SPI?', 'Explain the IKEv2 flow', 'What is CREATE_CHILD_SA?'],
  },
  {
    match: /cipher|encryption|algorithm|aes|des|gcm/i,
    answer:
      'Modern tunnels should negotiate AES-GCM with a 256-bit key (AEAD) keyed via IKEv2 — confidentiality and integrity in a single transform. Legacy suites such as DES or 3DES are high/critical findings because distinguishable plaintext and 56–64 bit effective keys are trivially brute-forced. Select an ESP or IKEv2 packet and I will tell you exactly what this capture is negotiating.',
    suggestions: ['What encryption is being used?', 'Why is ESP-NULL risky?', 'Suggest a secure configuration'],
  },
  {
    match: /pfs|forward secrecy|dh|diffie/i,
    answer:
      'Perfect Forward Secrecy means child SA keys cannot be recovered from a leaked long-term key, because each negotiation uses a fresh ephemeral Diffie-Hellman exchange. Best practice is an ECP group (19/20/21) with PFS enabled. I can confirm the DH group on any selected IKEv2 packet.',
    suggestions: ['Why is DH group 1 weak?', 'How is PFS audited?', 'Suggest a secure configuration'],
  },
  {
    match: /risk|finding|severity|weak/i,
    answer:
      'The analysis engine grades packets against RFC 8247 / 8242 and NSA IPsec guidance, mapping each failure to a severity (critical/high/medium/low). Select a packet on the Live Analyzer page and I will explain exactly why it is marked the way it is, field by field.',
    suggestions: ['Explain this packet', 'Suggest a secure configuration', 'What is risk scoring?'],
  },
  {
    match: /secure|configur|hardening|posture|recommend/i,
    answer:
      'A hardened IPsec posture: AES-GCM-256 for ESP, HMAC-SHA2-256 integrity, ECP Diffie-Hellman groups with PFS, SA lifetimes under 24h, and no NULL/DES/3DES or MD5/SHA1 anywhere in the proposal chain. The engine will flag every deviation on the packets you select.',
    suggestions: ['What encryption is being used?', 'Explain this packet', 'Why is PFS important?'],
  },
]

function cannedAnswer(question: string): Canned {
  const match = CANNED.find((c) => c.match.test(question))
  return (
    match ?? {
      match: /.*/,
      answer:
        'I am your IPsec security copilot. I analyse the packets you select on the Live Analyzer page — crypto negotiation, SPI semantics, findings and their fixes. Pick a packet, or ask me about IKEv2, ESP/AH, encryption or risk in general.',
      suggestions: [
        'Explain this packet',
        'What encryption is being used?',
        'Suggest a secure configuration',
      ],
    }
  )
}

/* ------------------------------------------------------------------ */
/* Packet-driven answers.                                              */
/* ------------------------------------------------------------------ */

interface Intent {
  test: RegExp
  say(packet: Packet, context: ReturnType<typeof packetIpsecSummary>): string
  suggestions: string[]
}

const EXPLAIN_SUGGESTIONS = [
  'Why is this marked medium risk?',
  'What is this SPI?',
  'What encryption is being used?',
  'Suggest a secure configuration',
]

const RISK_SUGGESTIONS = [
  'Explain this packet',
  'How do I fix this?',
  'What encryption is being used?',
]

const SPI_SUGGESTIONS = [
  'Who chooses the SPI?',
  'What encryption is being used?',
  'Explain this packet',
]

const ENCRYPT_SUGGESTIONS = [
  'Suggest a secure configuration',
  'Why is this marked medium risk?',
  'Explain this packet',
]

const HARDEN_SUGGESTIONS = [
  'Which packets use legacy crypto?',
  'What encryption is being used?',
  'Explain the IKEv2 handshake',
]

function riskBadge(risk: RiskLevel | null): string {
  return risk ? risk.toUpperCase() : 'CLEAN'
}

function findingBullets(packet: Packet): string {
  if (packet.findings.length === 0) return ''
  return packet.findings
    .map(
      (f) =>
        `- "${f.title}" (${f.severity.toUpperCase()}): ${f.description} Fix: ${f.recommendation ?? 'renegotiate the affected SA.'}`,
    )
    .join('\n')
}

function hardeningList(packet: Packet, summary: ReturnType<typeof packetIpsecSummary>): string {
  const items: string[] = []
  const encr = summary.encryption
  if (encr && (encodeLower(encr).includes('3des') || encodeLower(encr).includes('des') || encr === 'ESP-NULL')) {
    items.push(`Move ESP off ${summary.encryption} to AES-GCM (128-bit minimum, 256 preferred).`)
  }
  if (summary.integrity && /md5|sha1/i.test(summary.integrity)) {
    items.push(`Replace ${summary.integrity} integrity with HMAC-SHA2-256 or AES-GMAC.`)
  }
  if (summary.pfs === false) {
    items.push('Enable PFS with an ECP Diffie-Hellman group (19/20/21) for every rekey.')
  } else if (packet.protocol === 'IKEv2' && summary.pfs) {
    items.push('Keep PFS enabled (ECP group) as it is here — do not regress to MODP groups 1/2.')
  }
  if (!items.length) {
    items.push(packetIpsecRecommendation(packet))
  }
  items.push('Bound IKE/ESP SA lifetimes to under 24h and rekey before expiry with fresh DH.')
  return items.map((item) => `- ${item}`).join('\n')
}

function encodeLower(value: string): string {
  return value.toLowerCase()
}

function packetIpsecRecommendation(packet: Packet): string {
  const summary = packetIpsecSummary(packet)
  if (summary.securityProtocols.length === 0) {
    return 'This is not an IPsec packet — review surrounding SAs to confirm the negotiated suite suits your policy.'
  }
  return `Retain ${summary.encryption ?? 'the negotiated cipher'} with ${summary.integrity ?? 'strong integrity'} and PFS on ${summary.securityProtocols.join('/')} across the fleet.`
}

function encryptionCommentary(summary: ReturnType<typeof packetIpsecSummary>): string {
  const encr = summary.encryption
  if (encr === 'ESP-NULL') {
    return 'ESP-NULL transmits every payload in the clear — confidentiality is effectively disabled, which the engine grades critical.'
  }
  if (encr && /3des|des/i.test(encr)) {
    return `${encr} is deprecated under RFC 8247; its effective key strength is far below today\u2019s baseline and it is subject to practical attacks.`
  }
  if (encr && /gcm/i.test(encr)) {
    return 'AES-GCM is an authenticated-encryption construction (AEAD) and the current best practice for ESP.'
  }
  return 'The negotiated transform is acceptable but verify it against your written security policy.'
}

const INTENTS: Intent[] = [
  {
    test: /explain this packet|summarize this packet|describe this packet|what is this packet|overview of this packet|break.?down this packet/i,
    say: (packet, summary) => {
      const parts = [
        summary.encryption,
        summary.integrity,
        summary.spi ? `SPI ${summary.spi}` : undefined,
        summary.pfs != null ? `PFS ${summary.pfs ? 'enabled' : 'off'}` : undefined,
        summary.mode ? `${summary.mode} mode` : undefined,
      ].filter(Boolean)
      return (
        `Packet ${packet.number} is a ${packet.protocol} datagram (${packet.length} bytes) from ${packet.source} to ${packet.destination}, captured at ${(packet.relativeTimeMs / 1000).toFixed(3)}s. ` +
        `It sits at the ${packet.role.replace('-', ' ')} position in the conversation${parts.length ? ` and carries: ${parts.join(' · ')}` : ''}. ` +
        `Secured IPsec posture: ${riskBadge(packet.risk)}.` +
        (packet.findings.length
          ? `\n\nFindings:\n${findingBullets(packet)}`
          : '\n\nNo findings fired against this packet in the current engine build.')
      )
    },
    suggestions: EXPLAIN_SUGGESTIONS,
  },
  {
    test: /why.*risk|marked.*(medium|high|low|critical)|risk level|severity|finding/i,
    say: (packet) => {
      if (packet.findings.length === 0) {
        return (
          `Packet ${packet.number} is marked ${riskBadge(packet.risk)} — no analysis rule fired against it. ` +
          `It is classified ${packet.role}. A clean packet is not necessarily uninteresting: the risk engine only scores what it can observe, ` +
          `so this is a statement about the negotiated suite on this frame, not a blanket verdict on the tunnel.`
        )
      }
      const top = packet.findings[0]
      return (
        `Packet ${packet.number} is marked ${riskBadge(packet.risk)} because one or more controls fail current IPsec hardening guidance (RFC 8247/8242). ` +
        `The dominant driver is "${top.title}" (${top.severity.toUpperCase()}).\n\n` +
        `Findings:\n${findingBullets(packet)}\n\n` +
        `I would treat${packet.risk ? ` the ${packet.risk.toUpperCase()} items` : ' these'} as blockers for production tunnels, then re-assert the policy and re-capture to confirm they clear.`
      )
    },
    suggestions: RISK_SUGGESTIONS,
  },
  {
    test: /spi|security parameter index/i,
    say: (packet, summary) => {
      if (!summary.spi) {
        return (
          `Packet ${packet.number} (${packet.protocol}) carries no ESP/AH/IKEv2 Security Parameter Index — this frame does not hold an IPsec SA. ` +
          `The SPI only appears on IPsec-protected packets; it is the opaque handle peers use to find the SA (and its keys) for a given flow.`
        )
      }
      const owner = summary.securityProtocols.join('/')
      return (
        `The SPI on packet ${packet.number} is ${summary.spi} for the ${owner} SA. The SPI is a 32-bit (ESP/AH) or two × 64-bit (IKEv2) value chosen by the receiving side and echoed in every packet, ` +
        `letting the decryptor select the right SA and session keys without renegotiating. It is not secret — it only needs to be unique within the peer's SA table.`
      )
    },
    suggestions: SPI_SUGGESTIONS,
  },
  {
    test: /encryption|cipher|aes|gcm|cbc|des|algorithm|crypto/i,
    say: (packet, summary) => {
      if (!summary.encryption && !summary.integrity) {
        return (
          `Packet ${packet.number} (${packet.protocol}) does not negotiate an IPsec transform directly — its crypto was set by the SA established during the IKEv2 exchange. ` +
          `I can tell you the exact suite if you select the matching IKE_SA_INIT or CREATE_CHILD_SA packet.`
        )
      }
      return (
        `The ${summary.securityProtocols.join('/')} SA on packet ${packet.number} uses ${summary.encryption ?? 'an unspecified transform'} for encryption` +
        `${summary.keyBits ? ` (${summary.keyBits}-bit key)` : ''} and ${summary.integrity ?? 'no separate integrity transform'} for integrity. ` +
        `${encryptionCommentary(summary)}`
      )
    },
    suggestions: ENCRYPT_SUGGESTIONS,
  },
  {
    test: /secure configuration|secure config|harden|configure|recommend|best practice|posture|standards|fix/i,
    say: (packet, summary) => {
      const label = summary.securityProtocols.length ? `${summary.securityProtocols.join('/')} on packet ${packet.number}` : `packet ${packet.number} (${packet.protocol})`
      if (packet.findings.length === 0 && (summary.securityProtocols.length === 0)) {
        return (
          `For ${label} this is a ${packet.protocol} frame with no negotiated SA of its own. My baseline recommendation for the tunnel that carries it:\n\n` +
          `${hardeningList(packet, summary)}`
        )
      }
      return (
        `For ${label} I recommend the following, based on what I observe in this capture:\n\n` +
        `${hardeningList(packet, summary)}\n\n` +
        `Current posture on this frame: ${riskBadge(packet.risk)} with ${summary.encryption ?? 'no transform visible'} / ${summary.integrity ?? 'no integrity transform visible'}${summary.pfs != null ? ` and PFS ${summary.pfs ? 'enabled' : 'disabled'}` : ''}.`
      )
    },
    suggestions: HARDEN_SUGGESTIONS,
  },
]

function packetAnswer(packet: Packet, question: string): { content: string; suggestions: string[] } {
  const summary = packetIpsecSummary(packet)
  const intent = INTENTS.find((candidate) => candidate.test.test(question))
  return {
    content: (
      intent
        ? intent.say(packet, summary)
        : `${packetIpsecSummary(packet).securityProtocols.length ? `Packet ${packet.number} is a ${packet.protocol} frame on the ${summary.securityProtocols.join('/')} SA ` : `Packet ${packet.number} is a ${packet.protocol} datagram `}` +
          `(${riskBadge(packet.risk)}, ${summary.encryption ?? 'no transform visible'} / ${summary.integrity ?? '—'}). I can walk the dissection tree, the negotiated crypto or any finding — point me at a topic.`
    ),
    suggestions: intent ? intent.suggestions : EXPLAIN_SUGGESTIONS,
  }
}

/* ------------------------------------------------------------------ */
/* Service                                                            */
/* ------------------------------------------------------------------ */

export class MockAiService implements AiService {
  private sessions = new Map<string, AiSession>()
  private readonly packets: PacketLookup

  constructor(packets: PacketLookup) {
    this.packets = packets
  }

  async startSession(context?: AiContextRef): Promise<AiSession> {
    const now = new Date().toISOString()
    const session: AiSession = {
      id: generateId('ai-session', Date.now()),
      title: 'IPsec analysis',
      createdAt: now,
      updatedAt: now,
      messages: [],
      context,
    }
    this.sessions.set(session.id, session)
    return session
  }

  async ask(request: AiAskRequest): Promise<AiAskResponse> {
    const session = this.sessions.get(request.sessionId)
    if (!session) {
      throw new Error('Session not found')
    }
    await delay(700 + Math.random() * 900)

    const packet = request.context?.packetId
      ? await this.packets.getById(request.context.packetId)
      : null

    if (packet) {
      return packetAnswer(packet, request.question)
    }

    const canned = cannedAnswer(request.question)
    return {
      content: canned.answer,
      suggestions: canned.suggestions,
    }
  }

  async session(id: string): Promise<AiSession | null> {
    return this.sessions.get(id) ?? null
  }
}