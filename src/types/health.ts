export type ServiceStatus = 'operational' | 'degraded' | 'offline' | 'unknown'

export const SERVICE_STATUS_LABEL: Record<ServiceStatus, string> = {
  operational: 'Operational',
  degraded: 'Degraded',
  offline: 'Offline',
  unknown: 'Unknown',
}

export type ServiceName =
  | 'frontend'
  | 'api-gateway'
  | 'testbed-manager'
  | 'packet-analyzer'
  | 'ml-service'
  | 'correlation-engine'
  | 'database'
  | 'report-generator'
  | 'event-stream'

export const SERVICE_NAMES: readonly ServiceName[] = [
  'frontend',
  'api-gateway',
  'testbed-manager',
  'packet-analyzer',
  'ml-service',
  'correlation-engine',
  'database',
  'report-generator',
  'event-stream',
] as const

export const SERVICE_LABEL: Record<ServiceName, string> = {
  frontend: 'Frontend',
  'api-gateway': 'API Gateway',
  'testbed-manager': 'Testbed Manager',
  'packet-analyzer': 'Packet Analyzer',
  'ml-service': 'ML Service',
  'correlation-engine': 'Correlation Engine',
  database: 'Database',
  'report-generator': 'Report Generator',
  'event-stream': 'Event Stream',
}

export const SERVICE_DESCRIPTION: Record<ServiceName, string> = {
  frontend: 'This application. Served as static assets; no server state.',
  'api-gateway': 'REST entry point for sessions, findings, traffic and reports.',
  'testbed-manager': 'Controls the IPsec testbed: profiles, starts, stops and captures.',
  'packet-analyzer': 'Dissects captured traffic into protocol fields and SAs.',
  'ml-service': 'Runs the classification and scoring models.',
  'correlation-engine': 'Links findings, SAs and sessions into an assessment.',
  database: 'Session, finding, capture and report persistence.',
  'report-generator': 'Renders PDF, JSON and CSV report artefacts.',
  'event-stream': 'WebSocket / SSE channel carrying live analysis events.',
}

export interface ServiceHealth {
  name: ServiceName
  label: string
  status: ServiceStatus
  version: string
  /** Round-trip latency in milliseconds, or null when not measurable. */
  responseTimeMs: number | null
  lastChecked: string
  error: string | null
  /** Dependency note surfaced in the detail row. */
  detail: string
}

export interface SystemHealth {
  services: ServiceHealth[]
  /** Worst status across all services, for the summary banner. */
  overall: ServiceStatus
  checkedAt: string
  /** True while the frontend is talking to mock services. */
  mockMode: boolean
  apiBaseUrl: string
}
