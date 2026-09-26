/**
 * Public type surface of IPsec Sentinel.
 *
 * The wire/packet model (packet, protocol, capture, pcap, analytics) is used by
 * the live analyzer; the analysis model (evidence, analysis, session, traffic,
 * events, experiment, report, dataset, health, dashboard) is used by every
 * other workspace and is what the backend will eventually serve.
 */

export * from './common'
export * from './evidence'
export * from './analysis'
export * from './session'
export * from './identity'
export * from './trafficIntelligence'
export * from './events'
export * from './experiment'
export * from './report'
export * from './dataset'
export * from './health'
export * from './dashboard'
export * from './home'

export type {
  Packet,
  PacketProtocolName,
  PacketRole,
} from './packet'
export type {
  ProtocolLayer,
  ProtocolField,
  LayerTone,
  ProtocolLayerMeta,
  IpsecDetails,
  IpsecSecurityProtocol,
  Ikev2Message,
  Ikev2Proposal,
  Ikev2ExchangeType,
  EncryptionSpec,
  IntegritySpec,
  EspHeader,
  AhHeader,
  PacketContext,
} from './protocol'
export type {
  RiskLevel,
  PacketFinding,
  FindingCategory as PacketFindingCategory,
  SecurityAssessment,
  AssessmentScore,
} from './security'
export type { CaptureState, CaptureStatus, CaptureStatistics, ProtocolCount, StreamOrder } from './traffic'
export type {
  TrafficStatistics,
  TrafficWindow,
  TrafficBin,
  ProtocolDistribution,
  ProtocolFamily,
} from './analytics'
export type { PacketDetails, DetailRow, HexLine } from './packetDetails'
export type {
  PCAPAnalysis,
  PcapUploadState,
  PcapUploadHandle,
  PcapFileInfo,
  PcapProcessingStage,
} from './pcap'
export type { AiSession, AiMessage, AiAskRequest, AiAskResponse, AiContextRef, AiRole } from './ai'
export type { Notification, NotificationKind, NotificationTone } from './notifications'

import { RISK_LEVELS, riskSeverityIndex, severityLabel } from './security'
export { RISK_LEVELS, riskSeverityIndex, severityLabel }
