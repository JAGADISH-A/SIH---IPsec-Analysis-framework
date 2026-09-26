import type { DashboardQuery, DashboardSummary } from '../../types/dashboard'

/**
 * Read-only analytics for the dashboard.
 *
 * The dashboard is a projection, not a source of truth: it composes session,
 * finding and health data that the backend owns. The frontend never computes a
 * score locally in production — a mock implementation may, purely to exercise
 * the UI.
 */
export interface DashboardService {
  getSummary(query?: DashboardQuery): Promise<DashboardSummary>
}
