import type { ProtocolValue, Severity } from './evidence'
import type { SeverityTally } from './analysis'

export type IkevVersion = 'IKEv1' | 'IKEv2'
export type VpnMode = 'tunnel' | 'transport'
export type IpVersion = 'IPv4' | 'IPv6' | 'Mixed'
export type SessionStatus =
  | 'active'
  | 'rekeying'
  | 'draining'
  | 'closed'
  | 'failed'
  | 'unavailable'
export type RiskBand = 'critical' | 'high' | 'medium' | 'low'
export type Environment = 'production' | 'staging' | 'lab' | 'unknown'

export const SESSION_STATUSES: readonly SessionStatus[] = [
  'active',
  'rekeying',
  'draining',
  'closed',
  'failed',
  'unavailable',
] as const

export const SESSION_STATUS_LABEL: Record<SessionStatus, string> = {
  active: 'Active',
  rekeying: 'Rekeying',
  draining: 'Draining',
  closed: 'Closed',
  failed: 'Failed',
  unavailable: 'Unavailable',
}

export const ENVIRONMENT_LABEL: Record<Environment, string> = {
  production: 'Production',
  staging: 'Staging',
  lab: 'Lab',
  unknown: 'Unknown',
}

export interface SessionEndpoint {
  address: string
  port?: number
  role: 'initiator' | 'responder'
  /** Coarse attribution label; never a geolocation claim. */
  network?: string
}

/**
 * Negotiated protocol characteristics.
 *
 * Every field is a `ProtocolValue` so the UI can always answer: what is it,
 * where did it come from, how confident are we, what is its status and what
 * evidence supports it.
 */
export interface SessionConfiguration {
  ikeVersion: ProtocolValue<IkevVersion>
  vpnMode: ProtocolValue<VpnMode>
  encryption: ProtocolValue<string>
  integrity: ProtocolValue<string>
  dhGroup: ProtocolValue<string>
  prf: ProtocolValue<string>
  perfectForwardSecrecy: ProtocolValue<boolean>
  replayProtection: ProtocolValue<boolean>
  replayWindowSize: ProtocolValue<number>
  natTraversal: ProtocolValue<boolean>
  ipVersion: ProtocolValue<IpVersion>
  esp: ProtocolValue<boolean>
  ah: ProtocolValue<boolean>
  keyLifetimeSeconds: ProtocolValue<number>
  lifetimeSeconds: ProtocolValue<number>
  authenticationMethod: ProtocolValue<string>
  trafficSelectors: ProtocolValue<string>
}

export interface VpnSession {
  id: string
  /** Human label used in the UI, e.g. "Branch → HQ". */
  label: string
  initiator: SessionEndpoint
  responder: SessionEndpoint
  status: SessionStatus
  environment: Environment
  configuration: SessionConfiguration
  /** 0 (clean) – 100 (critical) */
  riskScore: number
  riskBand: RiskBand
  /** Confidence in the overall assessment, 0..1 or null. */
  confidence: number | null
  findingCounts: SeverityTally
  startedAt: string
  endedAt: string | null
  lastActivityAt: string
  packetCount: number
  byteCount: number
  rekeyCount: number
  retransmissions: number
  captureIds: string[]
  experimentIds: string[]
  testbed?: string
}

/* ------------------------------------------------------------------ */
/* Security associations                                                */
/* ------------------------------------------------------------------ */

export type SaDirection = 'outbound' | 'inbound'
export type SaProtocol = 'IKE' | 'ESP' | 'AH'
export type RekeyStatus = 'scheduled' | 'in-progress' | 'completed' | 'failed' | 'not-applicable'

export interface SecurityAssociation {
  id: string
  sessionId: string
  /** Security Parameters Index, hex. */
  spi: string
  direction: SaDirection
  protocol: SaProtocol
  encryption: string | null
  integrity: string | null
  keyLifetimeSeconds: number | null
  /** Bytes before the SA must be rekeyed. */
  byteLifetime: number | null
  /** Packets before the SA must be rekeyed. */
  packetLifetime: number | null
  replayWindowSize: number | null
  createdAt: string
  expiresAt: string | null
  rekeyStatus: RekeyStatus
  source: ProtocolValue<never>['source']
  confidence: number | null
}

/* ------------------------------------------------------------------ */
/* Session timeline                                                     */
/* ------------------------------------------------------------------ */

export type TimelineEventType =
  | 'IKE_SA_INIT'
  | 'IKE_AUTH'
  | 'CREATE_CHILD_SA'
  | 'INFORMATIONAL'
  | 'CHILD_SA_CREATED'
  | 'ESP_TRAFFIC'
  | 'AH_TRAFFIC'
  | 'RETRANSMISSION'
  | 'REKEY'
  | 'NEGOTIATION_FAILURE'
  | 'ERROR'
  | 'SA_DELETION'

export interface SessionTimelineEvent {
  id: string
  sessionId: string
  timestamp: string
  relativeTimeMs: number
  type: TimelineEventType
  description: string
  /** Where the event was observed. */
  source: string
  confidence: number | null
  packetNumber?: number
  relatedFindingIds: string[]
}

/* ------------------------------------------------------------------ */
/* Session detail payload                                               */
/* ------------------------------------------------------------------ */

export interface SessionDetail {
  session: VpnSession
  securityAssociations: SecurityAssociation[]
  timeline: SessionTimelineEvent[]
  evidence: import('./evidence').EvidenceReference[]
  /** Verbatim backend payload for the Raw Data tab. */
  raw: unknown
  /** Traffic intelligence slice for this session. */
  traffic: import('./trafficIntelligence').SessionTraffic
  /** ML model outputs attached to the session. */
  models: SessionModelOutput[]
  /** Assessment notes produced by the correlation engine. */
  correlation: SessionCorrelation
}

export interface SessionModelOutput {
  id: string
  name: string
  version: string
  task: string
  output: string
  confidence: number | null
  /** Human explanation of what the model contributes to the conclusion. */
  explanation: string
}

export interface SessionCorrelation {
  engine: string
  score: number
  posture: string
  narrative: string
  contributingFindingIds: string[]
}

/* ------------------------------------------------------------------ */
/* Query envelope                                                       */
/* ------------------------------------------------------------------ */

export interface SessionQuery {
  search?: string
  statuses?: SessionStatus[]
  modes?: VpnMode[]
  ikeVersions?: IkevVersion[]
  ipVersions?: IpVersion[]
  riskBands?: RiskBand[]
  /** 0..1 lower bound for the confidence filter. */
  minConfidence?: number
  environments?: Environment[]
  encryption?: string[]
  from?: string
  to?: string
  page?: number
  pageSize?: number
  sort?: SessionSortKey
  direction?: 'asc' | 'desc'
}

export type SessionSortKey =
  | 'id'
  | 'ikeVersion'
  | 'mode'
  | 'encryption'
  | 'riskScore'
  | 'confidence'
  | 'status'
  | 'createdAt'

export interface SessionPage {
  items: VpnSession[]
  total: number
  page: number
  pageSize: number
}

export interface SessionReference {
  id: string
  label: string
  riskBand: RiskBand
}

export type { Severity }
