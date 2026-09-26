import type { ProtocolValue } from './evidence'

/**
 * Traffic classification labels.
 *
 * Classification is an inference from observable metadata (packet sizes,
 * cadence, direction ratios). It never identifies an application with
 * certainty, and the UI says so wherever a class is shown.
 */
export type TrafficClass =
  | 'web-like'
  | 'voip-like'
  | 'video-like'
  | 'email-like'
  | 'messaging-like'
  | 'icmp-like'
  | 'file-transfer-like'
  | 'unknown'

export const TRAFFIC_CLASSES: readonly TrafficClass[] = [
  'web-like',
  'voip-like',
  'video-like',
  'email-like',
  'messaging-like',
  'icmp-like',
  'file-transfer-like',
  'unknown',
] as const

export const TRAFFIC_CLASS_LABEL: Record<TrafficClass, string> = {
  'web-like': 'Web-like',
  'voip-like': 'VoIP-like',
  'video-like': 'Video-like',
  'email-like': 'Email-like',
  'messaging-like': 'Messaging-like',
  'icmp-like': 'ICMP-like',
  'file-transfer-like': 'File-transfer-like',
  unknown: 'Unknown',
}

/**
 * Confidence below which a class is not presented as a conclusion.
 * Below the threshold the flow is reported as Unknown, never as a guess.
 */
export const CLASSIFICATION_CONFIDENCE_FLOOR = 0.55

export const CLASSIFICATION_DISCLAIMER =
  'Traffic classification is an inference based on observable metadata and may not identify the exact application.'

export interface TrafficClassification {
  id: string
  sessionId: string | null
  /** Effective class after the confidence floor has been applied. */
  label: TrafficClass
  /** The class the model proposed, even when it fell below the floor. */
  proposedLabel: TrafficClass
  confidence: number | null
  basis: string
  packets: number
  bytes: number
  firstSeen: string
  lastSeen: string
  peer: string
  /** Port/protocol hints used by the classifier. */
  hints: string[]
}

export interface TimeSeriesPoint {
  /** ISO-8601 bucket start. */
  timestamp: string
  value: number
  label?: string
}

export interface DistributionSlice {
  label: string
  value: number
  /** 0..1 share of the total. */
  share: number
}

export interface HistogramBin {
  /** Inclusive lower bound of the bin. */
  from: number
  /** Inclusive upper bound of the bin. */
  to: number
  count: number
}

export interface TrafficOverview {
  totalFlows: number
  classifiedFlows: number
  unknownFlows: number
  averageConfidence: number | null
  totalPackets: number
  totalBytes: number
  /** Bytes per bucket over the analysis window. */
  volume: TimeSeriesPoint[]
  inboundBytes: number
  outboundBytes: number
  packetSizeHistogram: HistogramBin[]
  interArrivalHistogram: HistogramBin[]
  classDistribution: DistributionSlice[]
  /** ESP / IKE / AH / other split. */
  protocolDistribution: DistributionSlice[]
  ipVersionDistribution: DistributionSlice[]
  classifications: TrafficClassification[]
  generatedAt: string
}

/** Per-session traffic slice embedded in the session detail payload. */
export interface SessionTraffic {
  packets: number
  bytes: number
  averagePacketSize: number | null
  averageInterArrivalMs: number | null
  inboundBytes: number
  outboundBytes: number
  volume: TimeSeriesPoint[]
  classes: DistributionSlice[]
  classification: TrafficClassification | null
  /** Confidence of the session-level classification, if one exists. */
  confidence: ProtocolValue<string> | null
}
