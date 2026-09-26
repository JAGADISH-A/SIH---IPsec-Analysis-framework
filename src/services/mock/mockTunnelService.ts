import type { TunnelService } from '../api/tunnelService'
import { mockDataset } from './mockData'
import { latency, notFound } from './mockSupport'
import type { DataSource, EvidenceReference } from '../../types/evidence'
import type { SessionTimelineEvent, VpnSession } from '../../types/session'
import {
  TUNNEL_STAGE_ORDER,
  type PacketTunnelLink,
  type TunnelDna,
  type TunnelIdentity,
  type TunnelStage,
  type TunnelStageId,
  type TunnelSpineStep,
} from '../../types/identity'

/**
 * Tunnel investigation data.
 *
 * Everything here is derived from the same mock records the rest of the
 * platform reads: sessions for identity and configuration, the session timeline
 * for lifecycle stages, the evidence store for the artefacts behind each value,
 * and findings for the conclusions. The reconstruction logic lives in this
 * service, not in the components, for two reasons — a screen must never decide
 * on its own whether a stage happened, and when the backend arrives this
 * derivation simply becomes a field the server already computed.
 */

const DEFAULT_LIMIT = 6

/**
 * Timeline events describe where the platform's conclusion came from.
 *
 * `Packet capture` means a human can point at the packets. A correlation or
 * analysis engine produced a judgement rather than a reading, which is a
 * different kind of claim and is labelled as one.
 */
function stateFor(event: SessionTimelineEvent | undefined): DataSource {
  if (!event) return 'unknown'
  switch (event.source) {
    case 'Packet capture':
      return 'observed'
    case 'Correlation engine':
    case 'Analysis engine':
      return 'calculated'
    default:
      return 'inferred'
  }
}

function firstEvent(
  timeline: SessionTimelineEvent[],
  types: SessionTimelineEvent['type'][],
): SessionTimelineEvent | undefined {
  return timeline.find((event) => types.includes(event.type))
}

/**
 * Reconstruct the tunnel's lifecycle from its timeline.
 *
 * A stage with no event is reported as pending rather than as a failure: a
 * tunnel that was already up when the capture started has no IKE_SA_INIT to
 * show, and saying "IKE_SA_INIT failed" would be a different — and wrong —
 * claim.
 */
function buildDna(session: VpnSession, timeline: SessionTimelineEvent[], evidence: EvidenceReference[]): TunnelDna {
  const events: Record<TunnelStageId, SessionTimelineEvent | undefined> = {
    IKE_SA_INIT: firstEvent(timeline, ['IKE_SA_INIT']),
    IKE_AUTH: firstEvent(timeline, ['IKE_AUTH']),
    CHILD_SA: firstEvent(timeline, ['CHILD_SA_CREATED', 'CREATE_CHILD_SA']),
    ESP: firstEvent(timeline, ['ESP_TRAFFIC', 'AH_TRAFFIC']),
    REKEY: firstEvent(timeline, ['REKEY']),
  }

  const stages: TunnelStage[] = TUNNEL_STAGE_ORDER.map((id) => {
    const event = events[id]
    const state = stateFor(event)
    const stageEvidence = evidence.filter((entry) => entry.exchange === id)
    const packetRange = event?.packetNumber
      ? String(event.packetNumber)
      : (stageEvidence.find((entry) => entry.packetRange)?.packetRange ?? undefined)

    let detail: string
    if (id === 'ESP' && event) {
      detail = `${session.packetCount.toLocaleString('en-US')} packets on the tunnel`
    } else if (event) {
      detail = event.description
    } else if (id === 'REKEY') {
      detail = 'No rekey observed in this capture window'
    } else {
      detail = 'Not observed in this capture window'
    }

    return {
      id,
      state,
      confidence: event ? event.confidence : null,
      detail,
      packetRange,
      evidenceIds: stageEvidence.map((entry) => entry.id),
      pending: !event,
    }
  })

  const observed = stages.filter((stage) => !stage.pending).length
  return {
    stages,
    observed,
    total: stages.length,
    established: !stages[0].pending && !stages[1].pending && !stages[2].pending && !stages[3].pending,
  }
}

function toIdentity(session: VpnSession): TunnelIdentity {
  const detail = mockDataset.sessionDetail(session.id)
  const config = session.configuration
  const evidence = detail?.evidence ?? []
  const findings = mockDataset.findings.filter((finding) => finding.sessionIds.includes(session.id))

  return {
    id: session.id,
    label: session.label,
    captureId: session.captureIds[0] ?? null,
    initiator: session.initiator,
    responder: session.responder,
    status: session.status,
    environment: session.environment,
    ikeVersion: config.ikeVersion,
    vpnMode: config.vpnMode,
    encryption: config.encryption,
    integrity: config.integrity,
    dhGroup: config.dhGroup,
    perfectForwardSecrecy: config.perfectForwardSecrecy,
    replayProtection: config.replayProtection,
    dna: buildDna(session, detail?.timeline ?? [], evidence),
    riskScore: session.riskScore,
    riskBand: session.riskBand,
    severity: mockDataset.severityFromBand(session.riskBand),
    confidence: session.confidence,
    packetCount: session.packetCount,
    findingCount: findings.length,
    evidenceCount: evidence.length,
    assessmentEvidence: findings.flatMap((finding) => finding.evidence).slice(0, 3),
    startedAt: session.startedAt,
    lastActivityAt: session.lastActivityAt,
  }
}

export class MockTunnelService implements TunnelService {
  async listRecent(limit = DEFAULT_LIMIT): Promise<TunnelIdentity[]> {
    const ordered = [...mockDataset.sessions].sort(
      (left, right) => new Date(right.lastActivityAt).getTime() - new Date(left.lastActivityAt).getTime(),
    )
    return latency(ordered.slice(0, limit).map(toIdentity), 130)
  }

  async getIdentity(sessionId: string): Promise<TunnelIdentity> {
    const session = mockDataset.sessions.find((entry) => entry.id === sessionId)
    if (!session) throw notFound('Tunnel', sessionId)
    return latency(toIdentity(session), 110)
  }

  async getEvidenceSpine(sessionId: string): Promise<TunnelSpineStep[]> {
    const session = mockDataset.sessions.find((entry) => entry.id === sessionId)
    if (!session) throw notFound('Tunnel', sessionId)

    const detail = mockDataset.sessionDetail(sessionId)
    const timeline = detail?.timeline ?? []
    const evidence = detail?.evidence ?? []
    const findings = mockDataset.findings.filter((finding) => finding.sessionIds.includes(sessionId))
    const dna = buildDna(session, timeline, evidence)

    const steps: TunnelSpineStep[] = []

    for (const stage of dna.stages) {
      if (stage.pending) continue
      const stageEvidence = evidence.filter((entry) => stage.evidenceIds.includes(entry.id))
      steps.push({
        id: `${sessionId}-stage-${stage.id}`,
        kind: stage.id === 'ESP' ? 'traffic' : 'exchange',
        label: stage.id,
        detail:
          stage.id === 'ESP'
            ? `${session.packetCount.toLocaleString('en-US')} packets matched the negotiated traffic selectors.`
            : stage.detail,
        state: stage.state,
        confidence: stage.confidence,
        packetRange: stage.packetRange,
        evidence: stageEvidence,
        linkTo: `/vpn-sessions/${sessionId}`,
      })
    }

    for (const finding of findings) {
      steps.push({
        id: `${sessionId}-finding-${finding.id}`,
        kind: 'finding',
        label: finding.title,
        detail: finding.observedBehavior,
        state: finding.source,
        confidence: finding.confidence,
        packetRange: finding.evidence[0]?.packetRange,
        evidence: finding.evidence,
        linkTo: `/findings/${finding.id}`,
      })
    }

    steps.push({
      id: `${sessionId}-risk`,
      kind: 'risk',
      label: 'Risk assessment',
      detail: `${session.riskBand.toUpperCase()} — risk score ${session.riskScore} of 100.`,
      state: 'calculated',
      confidence: session.confidence,
      evidence: findings.flatMap((finding) => finding.evidence).slice(0, 4),
    })

    return latency(steps, 140)
  }
}

/**
 * The tunnel a single packet belongs to.
 *
 * Exposed for the live analyzer so a dissected packet is never read in
 * isolation: the reader always sees the tunnel, and the stage of the tunnel,
 * that the packet served.
 */
export function tunnelForPacket(sessionId: string | undefined): PacketTunnelLink | null {
  if (!sessionId) return null
  const session = mockDataset.sessions.find((entry) => entry.id === sessionId)
  if (!session) return null

  const detail = mockDataset.sessionDetail(session.id)
  const dna = buildDna(session, detail?.timeline ?? [], detail?.evidence ?? [])
  const observed = dna.stages.filter((stage) => !stage.pending)
  const stageChain = [
    session.configuration.ikeVersion.value ?? 'IKE?',
    ...observed.map((stage) => (stage.id === 'CHILD_SA' ? 'CHILD_SA' : stage.id)),
  ].join(' → ')

  return {
    sessionId: session.id,
    sessionLabel: session.label,
    protocol: session.configuration.esp.value ? 'ESP' : 'IKE',
    initiator: session.initiator.address,
    responder: session.responder.address,
    stageChain,
    ikeVersion: session.configuration.ikeVersion.value ?? 'Unknown',
    dna,
    riskBand: session.riskBand,
    confidence: session.confidence,
  }
}
