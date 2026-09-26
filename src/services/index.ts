import type { PacketService } from './api/packetService'
import type { CaptureService } from './api/captureService'
import type { FilterService } from './api/filterService'
import type { AiService } from './api/aiService'
import type { PcapService } from './api/pcapService'
import type { NotificationService } from './api/notificationService'
import type { DashboardService } from './api/dashboardService'
import type { SessionService } from './api/sessionService'
import type { FindingService } from './api/findingService'
import type { TrafficService } from './api/trafficService'
import type { ExperimentService } from './api/experimentService'
import type { ReportService } from './api/reportService'
import type { DatasetService } from './api/datasetService'
import type { HealthService } from './api/healthService'
import type { LiveEventService } from './api/liveEventService'
import type { HomeService } from './api/homeService'
import type { TunnelService } from './api/tunnelService'
import { MockPacketService } from './mock/mockPacketService'
import { MockCaptureService } from './mock/mockCaptureService'
import { MockFilterService } from './mock/mockFilterService'
import { MockAiService } from './mock/mockAiService'
import { MockPcapService } from './mock/mockPcapService'
import { MockNotificationService } from './mock/mockNotificationService'
import { MockDashboardService } from './mock/mockDashboardService'
import { MockSessionService } from './mock/mockSessionService'
import { MockFindingService } from './mock/mockFindingService'
import { MockTrafficService } from './mock/mockTrafficService'
import { MockExperimentService } from './mock/mockExperimentService'
import { MockReportService } from './mock/mockReportService'
import { MockDatasetService } from './mock/mockDatasetService'
import { MockHealthService } from './mock/mockHealthService'
import { MockLiveEventService } from './mock/mockLiveEventService'
import { MockHomeService } from './mock/mockHomeService'
import { MockTunnelService } from './mock/mockTunnelService'
import { API_BASE } from './api/apiClient'

/**
 * Service composition root.
 *
 * Every consumer (through `src/hooks`) talks to these interfaces; the UI never
 * imports a mock class. Moving to the real backend means writing HTTP/WebSocket
 * classes against the same contracts and changing only the `MOCK_SERVICES` /
 * `REAL_SERVICES` wiring below.
 *
 * `capture` is deliberately transport-agnostic: today it is a frontend mock
 * generator, tomorrow it can be a WebSocket feed or a backend proxy
 * implementing the same `CaptureService` contract.
 */
export const USE_MOCK_DATA = import.meta.env.VITE_USE_MOCK_DATA !== 'false'

/** True while the frontend is serving simulated data. Surfaced in the UI. */
export const MOCK_MODE_LABEL = 'Mock data'

const packetStore = new MockPacketService()

const MOCK_SERVICES = {
  packetService: packetStore as PacketService,
  capture: new MockCaptureService(packetStore) as CaptureService,
  filter: new MockFilterService() as FilterService,
  ai: new MockAiService(packetStore) as AiService,
  pcap: new MockPcapService() as PcapService,
  notifications: new MockNotificationService() as NotificationService,
  dashboard: new MockDashboardService() as DashboardService,
  sessions: new MockSessionService() as SessionService,
  findings: new MockFindingService() as FindingService,
  traffic: new MockTrafficService() as TrafficService,
  experiments: new MockExperimentService() as ExperimentService,
  reports: new MockReportService() as ReportService,
  dataset: new MockDatasetService() as DatasetService,
  health: new MockHealthService() as HealthService,
  liveEvents: new MockLiveEventService() as LiveEventService,
  home: new MockHomeService() as HomeService,
  tunnel: new MockTunnelService() as TunnelService,
}

export type Services = typeof MOCK_SERVICES

/**
 * The platform is frontend-only in this build, so `MOCK_SERVICES` is the only
 * implementation set that exists. The flag is kept honest rather than decorative:
 * if it is turned off, the composition root says so out loud instead of silently
 * serving mock data from a build that claims to be talking to a backend.
 */
export const services: Services = MOCK_SERVICES

/** True when the build asked for HTTP services but none are wired yet. */
export const MISSING_BACKEND_WARNING = !USE_MOCK_DATA

/** Connection target shown on the System Health page. */
export const SERVICE_TARGET = USE_MOCK_DATA ? 'mock://ipsec-sentinel' : API_BASE
