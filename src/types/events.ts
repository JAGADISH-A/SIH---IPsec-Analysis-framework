import type { Severity } from './evidence'

/**
 * Live analysis events.
 *
 * Today these are produced by a mock event source; once the backend exists the
 * same payloads arrive over WebSocket or SSE and nothing above the service
 * layer changes.
 */
export type LiveEventType =
  | 'IKE_SA_INIT_COMPLETED'
  | 'IKE_AUTH_COMPLETED'
  | 'CHILD_SA_CREATED'
  | 'ESP_TRAFFIC'
  | 'AH_TRAFFIC'
  | 'REKEY_COMPLETED'
  | 'RETRANSMISSION_DETECTED'
  | 'IKE_NEGOTIATION_FAILED'
  | 'FINDING_CREATED'
  | 'TRAFFIC_CLASSIFICATION_UPDATED'
  | 'SA_DELETED'

export const LIVE_EVENT_LABEL: Record<LiveEventType, string> = {
  IKE_SA_INIT_COMPLETED: 'IKE_SA_INIT completed',
  IKE_AUTH_COMPLETED: 'IKE_AUTH completed',
  CHILD_SA_CREATED: 'CHILD_SA created',
  ESP_TRAFFIC: 'ESP traffic detected',
  AH_TRAFFIC: 'AH traffic detected',
  REKEY_COMPLETED: 'Rekey completed',
  RETRANSMISSION_DETECTED: 'Retransmission detected',
  IKE_NEGOTIATION_FAILED: 'IKE negotiation failed',
  FINDING_CREATED: 'New finding created',
  TRAFFIC_CLASSIFICATION_UPDATED: 'Traffic classification updated',
  SA_DELETED: 'SA deleted',
}

export type MonitoringStatus = 'monitoring' | 'degraded' | 'paused' | 'offline'

export const MONITORING_STATUS_LABEL: Record<MonitoringStatus, string> = {
  monitoring: 'Monitoring',
  degraded: 'Degraded',
  paused: 'Paused',
  offline: 'Offline',
}

export interface LiveEvent {
  id: string
  timestamp: string
  type: LiveEventType
  sessionId: string | null
  sessionLabel: string
  peer: string
  description: string
  severity: Severity
  /** Confidence attached to the event's own conclusion, when any. */
  confidence: number | null
  source: string
  /** Set when the event produced or updated a finding. */
  findingId?: string
}

export interface LiveActiveSession {
  sessionId: string
  label: string
  peer: string
  ikeVersion: string
  mode: string
  encryption: string
  pfs: boolean
  riskBand: 'critical' | 'high' | 'medium' | 'low'
  packetsPerSecond: number
  lastEventAt: string
}

export interface LiveMonitorSnapshot {
  activeSessions: number
  packetsPerSecond: number
  bytesPerSecond: number
  lastEventAt: string | null
  /** Capture interface state, mirrored from the capture service. */
  captureStatus: string
  captureId: string | null
  interfaceName: string | null
  monitoringStatus: MonitoringStatus
  /** Rolling event counters over the last minute. */
  eventsPerMinute: number
  eventBreakdown: { type: LiveEventType; label: string; count: number }[]
  updatedAt: string
}
