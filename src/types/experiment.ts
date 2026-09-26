import type { ProtocolValue } from './evidence'
import type { IkevVersion, IpVersion, VpnMode } from './session'

export type ExperimentStatus =
  | 'created'
  | 'running'
  | 'capturing'
  | 'analyzing'
  | 'completed'
  | 'failed'
  | 'cancelled'

export const EXPERIMENT_STATUSES: readonly ExperimentStatus[] = [
  'created',
  'running',
  'capturing',
  'analyzing',
  'completed',
  'failed',
  'cancelled',
] as const

export const EXPERIMENT_STATUS_LABEL: Record<ExperimentStatus, string> = {
  created: 'Created',
  running: 'Running',
  capturing: 'Capturing',
  analyzing: 'Analyzing',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
}

export type TrafficProfile =
  | 'interactive'
  | 'bulk-transfer'
  | 'streaming'
  | 'rekey-cycle'
  | 'idle'
  | 'malformed-probe'

export const TRAFFIC_PROFILE_LABEL: Record<TrafficProfile, string> = {
  interactive: 'Interactive',
  'bulk-transfer': 'Bulk transfer',
  streaming: 'Streaming',
  'rekey-cycle': 'Rekey cycle',
  idle: 'Idle',
  'malformed-probe': 'Malformed probe',
}

/** What the testbed was instructed to run — the ground truth for comparison. */
export interface ExperimentGroundTruth {
  ikeVersion: IkevVersion
  vpnMode: VpnMode
  encryption: string
  integrity: string
  dhGroup: string
  perfectForwardSecrecy: boolean
  ipVersion: IpVersion
  keyLifetimeSeconds: number
  expectedFindings: string[]
  notes: string
}

export interface Experiment {
  id: string
  name: string
  hypothesis: string
  status: ExperimentStatus
  ikeVersion: IkevVersion
  vpnMode: VpnMode
  encryption: string
  integrity: string
  dhGroup: string
  perfectForwardSecrecy: boolean
  ipVersion: IpVersion
  trafficProfile: TrafficProfile
  expectedConfiguration: string
  groundTruth: ExperimentGroundTruth
  riskScore: number
  riskBand: 'critical' | 'high' | 'medium' | 'low'
  confidence: number | null
  startedAt: string | null
  endedAt: string | null
  durationMs: number | null
  sessionIds: string[]
  captureIds: string[]
  findingCount: number
  progressPercent: number
  testbed: string
  operator: string
}

export interface ExperimentComparisonCell {
  field: string
  groundTruth: string
  observed: string
  /** Whether the observation matches the configured ground truth. */
  agrees: boolean | null
}

export interface ExperimentDetail {
  experiment: Experiment
  observations: ExperimentComparisonCell[]
  modelOutputs: {
    id: string
    name: string
    version: string
    output: string
    confidence: number | null
    agrees: boolean | null
  }[]
  correlation: {
    engine: string
    score: number
    posture: string
    narrative: string
  }
  findings: {
    id: string
    title: string
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown'
    status: string
    confidence: number | null
  }[]
  traffic: {
    packets: number
    bytes: number
    averagePacketSize: number | null
    classes: { label: string; value: number; share: number }[]
  }
  timeline: {
    id: string
    timestamp: string
    type: string
    description: string
    source: string
  }[]
  /** Configuration fields the platform read from the testbed. */
  configuration: { label: string; value: ProtocolValue<string> }[]
  raw: unknown
}

export interface ExperimentQuery {
  search?: string
  statuses?: ExperimentStatus[]
  ikeVersions?: IkevVersion[]
  profiles?: TrafficProfile[]
  from?: string
  to?: string
  page?: number
  pageSize?: number
}

export interface ExperimentPage {
  items: Experiment[]
  total: number
  page: number
  pageSize: number
}

/** Ids of the experiments currently selected for comparison. */
export type ExperimentSelection = string[]
