import type { HomeSummary } from '../../types/home'

/**
 * Data for the welcome screen (`/`).
 *
 * A single call on purpose: the welcome screen is a launcher, not a workspace,
 * so it must not fan out into a dozen page-sized queries before it can render.
 * The backend implements the same method with one aggregate endpoint.
 */
export interface HomeService {
  getSummary(): Promise<HomeSummary>
}
