import type { SystemHealth } from '../../types/health'

/**
 * Service health for the System Health page.
 *
 * `mockMode` is set by the frontend so the page can say plainly that the
 * statuses describe simulated components, not a running deployment.
 */
export interface HealthService {
  getHealth(): Promise<SystemHealth>
}
