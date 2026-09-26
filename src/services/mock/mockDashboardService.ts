import type { DashboardService } from '../api/dashboardService'
import type { DashboardQuery, DashboardSummary } from '../../types/dashboard'
import { buildDashboardSummary } from './mockAnalytics'
import { latency } from './mockSupport'

/**
 * Mock dashboard projection.
 *
 * The shape is what the backend will return; the numbers are derived from the
 * mock dataset so filters and totals agree with the pages they link to.
 */
export class MockDashboardService implements DashboardService {
  async getSummary(query: DashboardQuery = {}): Promise<DashboardSummary> {
    return latency(buildDashboardSummary(query.from, query.to, query.environment), 160)
  }
}
