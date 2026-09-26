/**
 * Tunnel identity, Tunnel DNA and the Evidence Spine.
 *
 * These are the shapes behind the product's signature ideas. They live in
 * `types/` rather than in a component because the tunnel is reconstructed once
 * by the analysis layer and then read by many screens: the welcome screen, the
 * session detail, the session list, the finding detail and the reports all
 * render the same tunnel and must therefore agree on it.
 *
 * Two rules hold everywhere in this file:
 *
 * 1. Nothing is asserted without provenance. Every value carries a `source`
 *    (`observed`, `inferred`, `configured`, `calculated`, `unknown`) and a
 *    confidence that may legitimately be `null`.
 * 2. A gap stays a gap. A stage that was not observed, or a confidence that
 *    could not be estimated, is reported as unknown — never filled in with a
 *    plausible default by the view.
 */

import type { DataSource, EvidenceReference, ProtocolValue, Severity } from './evidence'
import type { Environment, IkevVersion, RiskBand, SessionEndpoint, SessionStatus, VpnMode } from './session'

/* ------------------------------------------------------------------ */
/* Tunnel DNA                                                           */
/* ------------------------------------------------------------------ */

/**
 * The five stages every IPsec tunnel is reconstructed from, in negotiation
 * order. The order is the point: this is the tunnel's lifecycle, not a set of
 * unrelated status lights.
 */
export type TunnelStageId = 'IKE_SA_INIT' | 'IKE_AUTH' | 'CHILD_SA' | 'ESP' | 'REKEY'

export const TUNNEL_STAGE_ORDER: readonly TunnelStageId[] = [
  'IKE_SA_INIT',
  'IKE_AUTH',
  'CHILD_SA',
  'ESP',
  'REKEY',
] as const

export const TUNNEL_STAGE_LABEL: Record<TunnelStageId, string> = {
  IKE_SA_INIT: 'IKE_SA_INIT',
  IKE_AUTH: 'IKE_AUTH',
  CHILD_SA: 'CHILD_SA',
  ESP: 'ESP',
  REKEY: 'REKEY',
}

/** What a stage means in the RFCs, shown when a stage is inspected. */
export const TUNNEL_STAGE_DESCRIPTION: Record<TunnelStageId, string> = {
  IKE_SA_INIT: 'Initial key exchange; proposals and supported groups are read here.',
  IKE_AUTH: 'Authentication and first child SA negotiation; identities are bound here.',
  CHILD_SA: 'Child SA created for the negotiated traffic selectors.',
  ESP: 'Encrypted payload carrying tunnel traffic; the bulk of the packets.',
  REKEY: 'Rekeying of the IKE or child SA before its lifetime expires.',
}

export interface TunnelStage {
  id: TunnelStageId
  /** How the platform knows this stage happened. */
  state: DataSource
  /** 0..1, or null when it could not be estimated. */
  confidence: number | null
  /** One short, factual read-out, e.g. "Packets 1842–1871". */
  detail: string
  /** Inclusive packet range in the source capture, when packets carry it. */
  packetRange?: string
  /** Evidence records backing this stage. */
  evidenceIds: string[]
  /**
   * True when the stage has simply not happened yet in the captured window
   * (a rekey that is still scheduled, a tunnel that never got past CHILD_SA).
   * Distinct from `state: 'unknown'`, which means the platform cannot tell.
   */
  pending: boolean
}

export interface TunnelDna {
  stages: TunnelStage[]
  /** How many stages carry evidence. */
  observed: number
  total: number
  /**
   * True when IKE, authentication and child SA were all observed and traffic
   * followed — the tunnel demonstrably came up in this capture.
   */
  established: boolean
}

/* ------------------------------------------------------------------ */
/* Tunnel identity                                                      */
/* ------------------------------------------------------------------ */

/**
 * A tunnel as an investigation: who talks to whom, how it was configured, how
 * it behaved and how sure the platform is. This is the row shape the welcome
 * screen and session lists render, and the identity a packet resolves to.
 */
export interface TunnelIdentity {
  /** Session id — the tunnel's identity throughout the platform. */
  id: string
  label: string
  /** Capture this investigation was reconstructed from. */
  captureId: string | null
  initiator: SessionEndpoint
  responder: SessionEndpoint
  status: SessionStatus
  environment: Environment
  ikeVersion: ProtocolValue<IkevVersion>
  vpnMode: ProtocolValue<VpnMode>
  encryption: ProtocolValue<string>
  integrity: ProtocolValue<string>
  dhGroup: ProtocolValue<string>
  perfectForwardSecrecy: ProtocolValue<boolean>
  replayProtection: ProtocolValue<boolean>
  /** Reconstructed lifecycle. */
  dna: TunnelDna
  /** 0 (clean) – 100 (critical). */
  riskScore: number
  riskBand: RiskBand
  /** The same conclusion on the six-rung severity ladder. */
  severity: Severity
  /** Confidence in the overall assessment, 0..1 or null. */
  confidence: number | null
  packetCount: number
  findingCount: number
  evidenceCount: number
  /** Artefacts the overall risk and confidence are computed from. */
  assessmentEvidence: EvidenceReference[]
  startedAt: string
  lastActivityAt: string
}

/* ------------------------------------------------------------------ */
/* Evidence Spine                                                       */
/* ------------------------------------------------------------------ */

export type SpineStepKind = 'exchange' | 'traffic' | 'finding' | 'risk'

/**
 * One step in the chain of reasoning that produced a conclusion.
 *
 * The spine is the answer to "how do you know?" — packets, then the tunnel they
 * belonged to, then the finding, then the risk. Each step carries the evidence
 * that supports it so the view can show the artefact instead of restating it.
 */
export interface TunnelSpineStep {
  id: string
  kind: SpineStepKind
  label: string
  /** What this step contributes, in one sentence. */
  detail: string
  state: DataSource
  confidence: number | null
  /** Inclusive packet range, when the step came from packets. */
  packetRange?: string
  /** Verbatim supporting artefacts, rendered by the inspector. */
  evidence: EvidenceReference[]
  /** Route this step opens, e.g. a finding or a session. */
  linkTo?: string
}

/* ------------------------------------------------------------------ */
/* Packet → tunnel                                                      */
/* ------------------------------------------------------------------ */

/**
 * The tunnel an individual packet belongs to.
 *
 * Presented next to a dissected packet so no packet is read in isolation: the
 * reader always sees which tunnel, and which stage of it, the packet served.
 */
export interface PacketTunnelLink {
  sessionId: string
  sessionLabel: string
  /** Protocol carrying the packet, e.g. "ESP". */
  protocol: string
  initiator: string
  responder: string
  /** The stages that led to this packet, as a short chain, e.g. "IKEv2 → CHILD_SA → ESP". */
  stageChain: string
  ikeVersion: string
  dna: TunnelDna
  riskBand: RiskBand
  confidence: number | null
}
