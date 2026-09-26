import type {
  DashboardSummary,
  SecurityFinding,
  DistributionDatum,
  KpiMetric,
  Posture,
  SecurityPosture,
  TimeSeriesPoint,
  TrafficOverview,
  TrafficClassification,
  VpnSession,
} from '../../types'
import { SEVERITIES } from '../../types/evidence'
import { mockDataset } from './mockData'
import { mulberry32 } from './tools'

const HOUR = 3_600_000
const DAY = 24 * HOUR
const BASE_SEED = 0x1ce55

/* ------------------------------------------------------------------ */
/* Shared derivations                                                   */
/* ------------------------------------------------------------------ */

function toDistribution(
  entries: { label: string; value: number }[],
): DistributionDatum[] {
  const total = entries.reduce((sum, entry) => sum + entry.value, 0) || 1
  return entries
    .map((entry) => ({ label: entry.label, value: entry.value, share: entry.value / total }))
    .sort((a, b) => b.value - a.value)
}

function tallyOf(sessions: VpnSession[], field: (session: VpnSession) => string): DistributionDatum[] {
  const counts = new Map<string, number>()
  for (const session of sessions) {
    const key = field(session)
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return toDistribution([...counts.entries()].map(([label, value]) => ({ label, value })))
}

/**
 * Severity counts.
 *
 * The finding list is a parameter, not an implicit global: a tally must describe
 * exactly the set it was asked about, otherwise a filtered dashboard would report
 * a score computed from findings it is not showing.
 */
export function severityTally(
  findings: readonly SecurityFinding[] = mockDataset.findings,
): Record<(typeof SEVERITIES)[number], number> {
  const tally: Record<(typeof SEVERITIES)[number], number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    unknown: 0,
  }
  for (const finding of findings) tally[finding.severity] += 1
  return tally
}

/* ------------------------------------------------------------------ */
/* Traffic intelligence                                                 */
/* ------------------------------------------------------------------ */

const CLASS_LABELS: Record<string, string> = {
  'web-like': 'Web-like',
  'voip-like': 'VoIP-like',
  'video-like': 'Video-like',
  'email-like': 'Email-like',
  'messaging-like': 'Messaging-like',
  'icmp-like': 'ICMP-like',
  'file-transfer-like': 'File-transfer-like',
  unknown: 'Unknown',
}

export function buildTrafficOverview(): TrafficOverview {
  const rng = mulberry32(BASE_SEED)
  const sessions = mockDataset.sessions
  const classifications: TrafficClassification[] = []

  for (const session of sessions) {
    const detail = mockDataset.sessionDetail(session.id)
    const classification = detail?.traffic.classification
    if (classification) classifications.push(classification)
  }

  const totalBytes = sessions.reduce((sum, session) => sum + session.byteCount, 0)
  const totalPackets = sessions.reduce((sum, session) => sum + session.packetCount, 0)
  const inboundBytes = Math.round(
    sessions.reduce((sum, session) => sum + session.byteCount * (0.38 + rng() * 0.2), 0),
  )

  const classCounts = new Map<string, number>()
  for (const classification of classifications) {
    classCounts.set(classification.label, (classCounts.get(classification.label) ?? 0) + classification.bytes)
  }
  const classDistribution: DistributionDatum[] = toDistribution(
    [...classCounts.entries()].map(([label, value]) => ({ label: CLASS_LABELS[label] ?? label, value })),
  )

  const protocolCounts = { IKE: 0, ESP: 0, AH: 0, Other: 0 }
  for (const session of sessions) {
    const handshakes = session.rekeyCount * 6 + 4
    const payload = Math.max(0, session.packetCount - handshakes)
    if (session.configuration.esp.value) protocolCounts.ESP += payload
    if (session.configuration.ah.value) protocolCounts.AH += Math.round(payload * 0.02)
    protocolCounts.IKE += handshakes
  }

  const ipVersionDistribution = toDistribution([
    { label: 'IPv4', value: sessions.filter((session) => session.configuration.ipVersion.value === 'IPv4').length },
    { label: 'IPv6', value: sessions.filter((session) => session.configuration.ipVersion.value === 'IPv6').length },
  ])

  const volume: TimeSeriesPoint[] = Array.from({ length: 48 }, (_, index) => {
    const start = new Date(Date.now() - (47 - index) * HOUR)
    const diurnal = 0.55 + 0.45 * Math.sin(((index % 24) / 24) * Math.PI * 2)
    return {
      timestamp: start.toISOString(),
      value: Math.round((totalBytes / 190) * diurnal * (0.75 + rng() * 0.5)),
      label: start.toISOString().slice(11, 16),
    }
  })

  const packetSizeHistogram = [
    { from: 0, to: 64, count: Math.round(totalPackets * 0.04) },
    { from: 64, to: 128, count: Math.round(totalPackets * 0.11) },
    { from: 128, to: 256, count: Math.round(totalPackets * 0.19) },
    { from: 256, to: 512, count: Math.round(totalPackets * 0.28) },
    { from: 512, to: 1024, count: Math.round(totalPackets * 0.24) },
    { from: 1024, to: 1500, count: Math.round(totalPackets * 0.14) },
  ]

  const interArrivalHistogram = [
    { from: 0, to: 1, count: Math.round(totalPackets * 0.18) },
    { from: 1, to: 5, count: Math.round(totalPackets * 0.31) },
    { from: 5, to: 20, count: Math.round(totalPackets * 0.27) },
    { from: 20, to: 100, count: Math.round(totalPackets * 0.16) },
    { from: 100, to: 1000, count: Math.round(totalPackets * 0.08) },
  ]

  const classified = classifications.filter((item) => item.label !== 'unknown')
  const confidenceSum = classifications.reduce((sum, item) => sum + (item.confidence ?? 0), 0)

  return {
    totalFlows: classifications.length,
    classifiedFlows: classified.length,
    unknownFlows: classifications.length - classified.length,
    averageConfidence: classifications.length
      ? Math.round((confidenceSum / classifications.length) * 1000) / 1000
      : null,
    totalPackets,
    totalBytes,
    volume,
    inboundBytes,
    outboundBytes: totalBytes - inboundBytes,
    packetSizeHistogram,
    interArrivalHistogram,
    classDistribution,
    protocolDistribution: toDistribution(
      Object.entries(protocolCounts).map(([label, value]) => ({ label, value })),
    ),
    ipVersionDistribution,
    classifications: classifications.sort(
      (a, b) => (b.bytes ?? 0) - (a.bytes ?? 0),
    ),
    generatedAt: new Date().toISOString(),
  }
}

/* ------------------------------------------------------------------ */
/* Dashboard                                                            */
/* ------------------------------------------------------------------ */

function postureFor(score: number | null): { posture: Posture; grade: SecurityPosture['grade'] } {
  if (score === null) return { posture: 'unknown', grade: null }
  if (score >= 80) return { posture: 'critical', grade: 'F' }
  if (score >= 60) return { posture: 'weak', grade: 'D' }
  if (score >= 40) return { posture: 'needs-review', grade: 'C' }
  if (score >= 22) return { posture: 'acceptable', grade: 'B' }
  return { posture: 'strong', grade: 'A' }
}

/** Window-over-window delta for a KPI, or an explicit unknown. */
function trend(
  current: number | null,
  previous: number | null,
): Pick<KpiMetric, 'delta' | 'deltaDirection'> {
  if (current === null || previous === null) return { delta: null, deltaDirection: 'flat' }
  if (previous === 0) {
    if (current === 0) return { delta: 0, deltaDirection: 'flat' }
    return { delta: 100, deltaDirection: current > 0 ? 'up' : 'down' }
  }
  const change = Math.round(((current - previous) / previous) * 1000) / 10
  return {
    delta: change,
    deltaDirection: change > 0 ? 'up' : change < 0 ? 'down' : 'flat',
  }
}

export function buildDashboardSummary(from?: string, to?: string, environment?: string): DashboardSummary {
  const rng = mulberry32(BASE_SEED + 7)
  const allSessions = mockDataset.sessions
  const sessions = environment && environment !== 'all'
    ? allSessions.filter((session) => session.environment === environment)
    : allSessions
  const sessionIds = new Set(sessions.map((session) => session.id))
  const findings = mockDataset.findings.filter((finding) =>
    finding.sessionIds.some((id) => sessionIds.has(id)),
  )
  // Scoped to the same finding set the summary reports on.
  const tally = severityTally(findings)

  const weighted =
    tally.critical * 14 + tally.high * 7 + tally.medium * 2.4 + tally.low * 0.5 + tally.informational * 0.1
  const rawScore = Math.min(100, Math.round(weighted / 1.35))
  const { posture, grade } = postureFor(rawScore)

  const affectedSessions = sessions.filter((session) => session.riskScore >= 50).length
  const postureSummary: SecurityPosture = {
    score: sessions.length === 0 ? null : rawScore,
    grade: sessions.length === 0 ? null : grade,
    posture: sessions.length === 0 ? 'unknown' : posture,
    affectedSessions,
    lastAssessmentAt: new Date(Date.now() - 4 * 60_000).toISOString(),
    method:
      'Weighted severity score across correlated findings, normalised per analysed session. Produced by the correlation engine.',
  }

  const packetsAnalyzed = sessions.reduce((sum, session) => sum + session.packetCount, 0)
  const averageConfidence = sessions.length
    ? Math.round(
        (sessions.reduce((sum, session) => sum + (session.confidence ?? 0), 0) / sessions.length) * 1000,
      ) / 1000
    : null
  const activeSessions = sessions.filter(
    (session) => session.status === 'active' || session.status === 'rekeying',
  ).length

  const securityScoreTrend: TimeSeriesPoint[] = Array.from({ length: 14 }, (_, index) => {
    const day = new Date(Date.now() - (13 - index) * DAY)
    const value = Math.max(4, Math.min(96, rawScore + Math.round((rng() - 0.5) * 18) - (13 - index) * 0.6))
    return { timestamp: day.toISOString(), value, label: day.toISOString().slice(5, 10) }
  })

  const findingsOverTime: TimeSeriesPoint[] = Array.from({ length: 14 }, (_, index) => {
    const day = new Date(Date.now() - (13 - index) * DAY)
    return {
      timestamp: day.toISOString(),
      value: Math.max(0, Math.round(findings.length / 26 + (rng() - 0.5) * 5)),
      label: day.toISOString().slice(5, 10),
    }
  })

  const confidenceBuckets: DistributionDatum[] = toDistribution([
    { label: '90–100%', value: sessions.filter((session) => (session.confidence ?? 0) >= 0.9).length },
    { label: '75–89%', value: sessions.filter((session) => (session.confidence ?? 0) >= 0.75 && (session.confidence ?? 0) < 0.9).length },
    { label: '50–74%', value: sessions.filter((session) => (session.confidence ?? 0) >= 0.5 && (session.confidence ?? 0) < 0.75).length },
    { label: '< 50%', value: sessions.filter((session) => (session.confidence ?? 0) < 0.5).length },
  ])

  const partialReasons: string[] = []
  if (sessions.length === 0) partialReasons.push('No sessions matched the selected environment.')
  if (tally.unknown > 0) partialReasons.push(`${tally.unknown} finding(s) have an unknown severity.`)

  const negotiations = sessions.reduce((sum, session) => sum + session.rekeyCount + 1, 0)
  const rekeys = sessions.reduce((sum, session) => sum + session.rekeyCount, 0)

  const kpis: KpiMetric[] = [
    {
      id: 'security-score',
      label: 'Overall security score',
      value: postureSummary.score,
      display: postureSummary.score === null ? 'Unknown' : `${postureSummary.score}/100`,
      ...trend(securityScoreTrend.at(-1)?.value ?? null, securityScoreTrend.at(-2)?.value ?? null),
      tone: rawScore >= 60 ? 'danger' : rawScore >= 40 ? 'warning' : 'positive',
      hint: 'Weighted severity score across correlated findings. Lower is better.',
    },
    {
      id: 'active-sessions',
      label: 'Active VPN sessions',
      value: activeSessions,
      display: activeSessions.toLocaleString('en-US'),
      ...trend(activeSessions, activeSessions - 2),
      tone: 'neutral',
      hint: 'Sessions currently negotiating or carrying traffic.',
    },
    {
      id: 'sessions-analyzed',
      label: 'Sessions analyzed',
      value: sessions.length,
      display: sessions.length.toLocaleString('en-US'),
      ...trend(sessions.length, Math.max(0, sessions.length - 3)),
      tone: 'neutral',
      hint: 'Sessions with a completed analysis in the selected window.',
    },
    {
      id: 'critical-findings',
      label: 'Critical findings',
      value: tally.critical,
      display: String(tally.critical),
      ...trend(tally.critical, Math.max(0, tally.critical - 2)),
      tone: tally.critical > 0 ? 'danger' : 'positive',
      hint: 'Findings rated critical in the selected window.',
    },
    {
      id: 'high-findings',
      label: 'High findings',
      value: tally.high,
      display: String(tally.high),
      ...trend(tally.high, Math.max(0, tally.high - 3)),
      tone: tally.high > 0 ? 'warning' : 'positive',
      hint: 'Findings rated high in the selected window.',
    },
    {
      id: 'packets-analyzed',
      label: 'Packets analyzed',
      value: packetsAnalyzed,
      display: packetsAnalyzed.toLocaleString('en-US'),
      ...trend(packetsAnalyzed, Math.round(packetsAnalyzed * 0.94)),
      tone: 'neutral',
      hint: 'Packets dissected across the selected window.',
    },
    {
      id: 'ike-negotiations',
      label: 'IKE negotiations',
      value: negotiations,
      display: negotiations.toLocaleString('en-US'),
      ...trend(negotiations, rekeys),
      tone: 'neutral',
      hint: 'Initial IKE exchanges plus observed rekeys.',
    },
    {
      id: 'avg-confidence',
      label: 'Average AI confidence',
      value: averageConfidence,
      unit: '%',
      display: averageConfidence === null ? 'Unknown' : `${Math.round(averageConfidence * 100)}%`,
      ...trend(averageConfidence, averageConfidence === null ? null : Number((averageConfidence - 0.01).toFixed(3))),
      tone:
        averageConfidence === null ? 'neutral' : averageConfidence >= 0.9 ? 'positive' : averageConfidence >= 0.75 ? 'warning' : 'danger',
      hint: 'Mean confidence across model-assisted conclusions.',
    },
  ]

  const systemStatus = mockDataset
    .systemHealth()
    .services.map((service) => ({
      label: service.name,
      status: service.status,
      detail: service.detail,
    }))

  const rangeTo = to ? new Date(to) : new Date()
  const rangeFrom = from ? new Date(from) : new Date(rangeTo.getTime() - 14 * DAY)

  return {
    posture: postureSummary,
    kpis,
    severityDistribution: SEVERITIES.filter((severity) => severity !== 'unknown').map((severity) => ({
      label: severity,
      value: tally[severity],
      share: findings.length ? tally[severity] / findings.length : 0,
    })),
    securityScoreTrend,
    findingsOverTime,
    sessionsByMode: tallyOf(sessions, (session) => session.configuration.vpnMode.value ?? 'Unknown'),
    encryptionDistribution: tallyOf(sessions, (session) => session.configuration.encryption.value ?? 'Unknown'),
    aiConfidenceDistribution: confidenceBuckets,
    activeSessions: sessions
      .filter((session) => session.status === 'active' || session.status === 'rekeying')
      .slice(0, 12),
    recentFindings: [...findings]
      .sort((a, b) => (a.detectedAt < b.detectedAt ? 1 : -1))
      .slice(0, 8)
      .map((finding) => ({
        id: finding.id,
        severity: finding.severity,
        title: finding.title,
        sessionId: finding.sessionIds[0] ?? null,
        confidence: finding.confidence,
        detectedAt: finding.detectedAt,
        status: finding.status,
      })),
    findingTally: tally,
    systemStatus,
    generatedAt: new Date().toISOString(),
    range: {
      from: rangeFrom.toISOString(),
      to: rangeTo.toISOString(),
      label: `${rangeFrom.toISOString().slice(0, 10)} → ${rangeTo.toISOString().slice(0, 10)}`,
    },
    partial: partialReasons.length > 0,
    partialReasons,
  }
}
