import type { TrafficService } from '../api/trafficService'
import type { TrafficClassification, TrafficOverview } from '../../types/trafficIntelligence'
import { buildTrafficOverview } from './mockAnalytics'
import { mockDataset } from './mockData'
import { latency, notFound } from './mockSupport'

/** A session with no classification is reported as Unknown, never guessed. */
function fallbackClassification(sessionId: string): TrafficClassification {
  const session = mockDataset.sessions.find((entry) => entry.id === sessionId)
  return {
    id: `CLS-${sessionId}`,
    sessionId,
    label: 'unknown',
    proposedLabel: 'unknown',
    confidence: null,
    basis: 'No classification has been computed for this session.',
    packets: session?.packetCount ?? 0,
    bytes: session?.byteCount ?? 0,
    firstSeen: session?.startedAt ?? new Date().toISOString(),
    lastSeen: session?.lastActivityAt ?? new Date().toISOString(),
    peer: session?.responder.address ?? 'unknown',
    hints: [],
  }
}

export class MockTrafficService implements TrafficService {
  async getOverview(): Promise<TrafficOverview> {
    return latency(buildTrafficOverview(), 180)
  }

  async getClassifications(): Promise<TrafficClassification[]> {
    const classifications: TrafficClassification[] = []
    for (const session of mockDataset.sessions) {
      const detail = mockDataset.sessionDetail(session.id)
      if (detail) classifications.push(detail.traffic.classification ?? fallbackClassification(session.id))
    }
    return latency(
      classifications.sort((a, b) => (b.bytes ?? 0) - (a.bytes ?? 0)),
      150,
    )
  }

  async getClassificationForSession(sessionId: string): Promise<TrafficClassification | null> {
    const detail = mockDataset.sessionDetail(sessionId)
    if (!detail) throw notFound('VPN session', sessionId)
    return latency(detail.traffic.classification ?? fallbackClassification(sessionId), 90)
  }
}
