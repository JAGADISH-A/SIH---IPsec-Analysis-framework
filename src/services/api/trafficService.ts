import type { TrafficClassification, TrafficOverview } from '../../types/trafficIntelligence'

/**
 * Traffic intelligence: volume, distributions and per-session classification.
 *
 * Classification is an inference from observable metadata. Services must return
 * `label: 'unknown'` rather than a low-confidence guess, and callers are
 * expected to render the classification disclaimer.
 */
export interface TrafficService {
  getOverview(): Promise<TrafficOverview>
  getClassifications(): Promise<TrafficClassification[]>
  getClassificationForSession(sessionId: string): Promise<TrafficClassification | null>
}
