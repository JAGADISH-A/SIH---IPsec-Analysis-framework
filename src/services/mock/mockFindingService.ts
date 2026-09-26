import type { FindingService } from '../api/findingService'
import type {
  FindingQuery,
  FindingStatus,
  FindingSummary,
  SecurityFinding,
  ThreatMatrix,
} from '../../types/analysis'
import { SEVERITIES } from '../../types/evidence'
import { mockDataset } from './mockData'
import { atLeast, inFilter, latency, matchesSearch, notFound, withinRange } from './mockSupport'

function applyQuery(findings: SecurityFinding[], query: FindingQuery): SecurityFinding[] {
  return findings.filter(
    (finding) =>
      matchesSearch(query.search, finding.title, finding.summary, finding.category, finding.observedBehavior) &&
      inFilter(finding.severity, query.severities) &&
      inFilter(finding.category, query.categories) &&
      inFilter(finding.status, query.statuses) &&
      (!query.sessionId || finding.sessionIds.includes(query.sessionId)) &&
      atLeast(finding.confidence, query.minConfidence) &&
      withinRange(finding.detectedAt, query.from, query.to),
  )
}

export class MockFindingService implements FindingService {
  private readonly findings = mockDataset.findings
  /** Operator annotations, layered over the backend-owned records. */
  private readonly annotations = new Map<string, { status: FindingStatus; note: string | null }>()

  async query(query: FindingQuery = {}): Promise<SecurityFinding[]> {
    const matched = applyQuery(this.findings, query).map((finding) => this.withAnnotation(finding))
    return latency(
      matched.sort((a, b) => (a.detectedAt < b.detectedAt ? 1 : a.detectedAt > b.detectedAt ? -1 : 0)),
      130,
    )
  }

  async getById(id: string): Promise<SecurityFinding> {
    const finding = this.findings.find((entry) => entry.id === id)
    if (!finding) throw notFound('Finding', id)
    return latency(this.withAnnotation(finding), 120)
  }

  async getSummary(query: FindingQuery = {}): Promise<FindingSummary> {
    const matched = applyQuery(this.findings, query).map((finding) => this.withAnnotation(finding))
    const bySeverity: FindingSummary['bySeverity'] = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
      unknown: 0,
    }
    for (const finding of matched) bySeverity[finding.severity] += 1
    const byStatus = (status: FindingStatus): number =>
      matched.filter((finding) => finding.status === status).length
    const confidences = matched
      .map((finding) => finding.confidence)
      .filter((value): value is number => value !== null)

    return latency(
      {
        total: matched.length,
        bySeverity,
        open: byStatus('open'),
        resolved: byStatus('resolved'),
        acknowledged: byStatus('acknowledged'),
        falsePositive: byStatus('false-positive'),
        suppressed: byStatus('suppressed'),
        averageConfidence:
          confidences.length === 0
            ? null
            : Math.round((confidences.reduce((sum, value) => sum + value, 0) / confidences.length) * 1000) /
              1000,
        lastEvaluated: new Date().toISOString(),
      },
      90,
    )
  }

  async getThreatMatrix(): Promise<ThreatMatrix> {
    return latency(
      {
        threats: mockDataset.threats,
        axes: {
          x: {
            label: 'Likelihood',
            description: 'How often this threat is expected in the observed traffic.',
          },
          y: {
            label: 'Impact',
            description: 'Severity of the consequence if the threat is realised.',
          },
        },
        generatedAt: new Date().toISOString(),
      },
      140,
    )
  }

  async setStatus(id: string, status: FindingStatus, note?: string): Promise<SecurityFinding> {
    const finding = this.findings.find((entry) => entry.id === id)
    if (!finding) throw notFound('Finding', id)
    this.annotations.set(id, { status, note: note ?? null })
    return latency(this.withAnnotation(finding), 100)
  }

  /** Severities present in the register, most severe first. */
  get availableSeverities(): readonly (typeof SEVERITIES)[number][] {
    return SEVERITIES
  }

  private withAnnotation(finding: SecurityFinding): SecurityFinding {
    const annotation = this.annotations.get(finding.id)
    if (!annotation) return finding
    return { ...finding, status: annotation.status, updatedAt: new Date().toISOString() }
  }
}
