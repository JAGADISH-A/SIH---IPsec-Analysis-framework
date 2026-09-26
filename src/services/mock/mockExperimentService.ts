import type { ExperimentRequest, ExperimentService } from '../api/experimentService'
import type {
  Experiment,
  ExperimentDetail,
  ExperimentPage,
  ExperimentQuery,
} from '../../types/experiment'
import { mockDataset } from './mockData'
import { inFilter, invalid, latency, matchesSearch, notFound, paginate, withinRange } from './mockSupport'

/** Statuses a freshly created experiment walks through before completion. */
const RUN_SEQUENCE: Experiment['status'][] = ['created', 'running', 'capturing', 'analyzing', 'completed']

function applyQuery(query: ExperimentQuery): Experiment[] {
  return mockDataset.experiments
    .filter(
      (experiment) =>
        matchesSearch(query.search, experiment.id, experiment.name, experiment.hypothesis, experiment.testbed) &&
        inFilter(experiment.status, query.statuses) &&
        inFilter(experiment.ikeVersion, query.ikeVersions) &&
        inFilter(experiment.trafficProfile, query.profiles) &&
        withinRange(experiment.startedAt ?? experiment.endedAt ?? '', query.from, query.to),
    )
    .sort((a, b) => (a.id < b.id ? 1 : -1))
}

export class MockExperimentService implements ExperimentService {
  private readonly experiments = new Map<string, Experiment>(mockDataset.experiments.map((item) => [item.id, item]))
  private selection: string[] = mockDataset.experiments.slice(0, 2).map((item) => item.id)
  private nextId = 1
  /** Pending progress timers for runs created in this session. */
  private readonly timers = new Map<string, number>()

  async query(query: ExperimentQuery = {}): Promise<ExperimentPage> {
    const page = paginate(applyQuery(query), query.page, query.pageSize)
    return latency({ items: page.items, total: page.total, page: page.page, pageSize: page.pageSize }, 130)
  }

  async getById(id: string): Promise<ExperimentDetail> {
    const detail = mockDataset.experimentDetail(id) ?? this.detailFromState(id)
    if (!detail) throw notFound('Experiment', id)
    return latency(detail, 150)
  }

  async create(request: ExperimentRequest): Promise<Experiment> {
    if (!request.name.trim()) throw invalid('An experiment name is required.')
    const id = `EXP-NEW-${String(this.nextId).padStart(3, '0')}`
    this.nextId += 1
    const experiment: Experiment = {
      id,
      name: request.name.trim(),
      hypothesis: request.hypothesis.trim(),
      status: 'created',
      ikeVersion: request.ikeVersion,
      vpnMode: request.vpnMode,
      encryption: request.encryption,
      integrity: request.integrity,
      dhGroup: request.dhGroup,
      perfectForwardSecrecy: request.perfectForwardSecrecy,
      ipVersion: request.ipVersion,
      trafficProfile: request.trafficProfile,
      expectedConfiguration: [
        request.ikeVersion,
        request.vpnMode,
        request.encryption,
        request.integrity,
        `DH ${request.dhGroup}`,
        request.ipVersion,
        `PFS ${request.perfectForwardSecrecy ? 'on' : 'off'}`,
      ].join(' · '),
      groundTruth: {
        ikeVersion: request.ikeVersion,
        vpnMode: request.vpnMode,
        encryption: request.encryption,
        integrity: request.integrity,
        dhGroup: request.dhGroup,
        perfectForwardSecrecy: request.perfectForwardSecrecy,
        ipVersion: request.ipVersion,
        keyLifetimeSeconds: 28_800,
        expectedFindings: [],
        notes: 'Configured by the operator. The platform reads these values back from the testbed.',
      },
      riskScore: 0,
      riskBand: 'low',
      confidence: null,
      startedAt: null,
      endedAt: null,
      durationMs: null,
      sessionIds: [],
      captureIds: [],
      findingCount: 0,
      progressPercent: 0,
      testbed: 'testbed-a',
      operator: 'you',
    }
    this.experiments.set(id, experiment)
    this.startRun(id, request.durationMinutes)
    return latency(experiment, 120)
  }

  async cancel(id: string): Promise<Experiment> {
    const experiment = this.experiments.get(id)
    if (!experiment) throw notFound('Experiment', id)
    const timer = this.timers.get(id)
    if (timer !== undefined) window.clearInterval(timer)
    this.timers.delete(id)
    const cancelled: Experiment = {
      ...experiment,
      status: 'cancelled',
      endedAt: new Date().toISOString(),
      progressPercent: experiment.progressPercent,
    }
    this.experiments.set(id, cancelled)
    return latency(cancelled, 100)
  }

  async remove(id: string): Promise<void> {
    if (!this.experiments.has(id)) throw notFound('Experiment', id)
    const timer = this.timers.get(id)
    if (timer !== undefined) window.clearInterval(timer)
    this.timers.delete(id)
    this.experiments.delete(id)
    this.selection = this.selection.filter((entry) => entry !== id)
    return latency(undefined, 80)
  }

  async getSelection(): Promise<string[]> {
    return latency(this.selection, 40)
  }

  async setSelection(ids: string[]): Promise<string[]> {
    this.selection = [...new Set(ids)].filter((id) => this.experiments.has(id))
    return latency(this.selection, 40)
  }

  /**
   * Advance a new experiment through its lifecycle on a timer so the UI shows
   * real progress rather than an instant "completed".
   */
  private startRun(id: string, durationMinutes: number): void {
    const totalMs = Math.max(6_000, Math.min(90_000, durationMinutes * 1_200))
    const stepMs = Math.max(600, Math.round(totalMs / RUN_SEQUENCE.length))
    let index = 0
    const timer = window.setInterval(() => {
      const current = this.experiments.get(id)
      if (!current) {
        window.clearInterval(timer)
        this.timers.delete(id)
        return
      }
      const status = RUN_SEQUENCE[Math.min(index, RUN_SEQUENCE.length - 1)]
      index += 1
      const finished = index >= RUN_SEQUENCE.length
      const startedAt = current.startedAt ?? new Date().toISOString()
      this.experiments.set(id, {
        ...current,
        status,
        startedAt,
        endedAt: finished ? new Date().toISOString() : null,
        progressPercent: Math.min(100, Math.round((index / RUN_SEQUENCE.length) * 100)),
        riskScore: finished ? 24 : current.riskScore,
        riskBand: finished ? 'medium' : current.riskBand,
        confidence: finished ? 0.88 : current.confidence,
      })
      if (finished) {
        window.clearInterval(timer)
        this.timers.delete(id)
      }
    }, stepMs)
    this.timers.set(id, timer)
  }

  /** Detail for an experiment created in this session, built from live state. */
  private detailFromState(id: string): ExperimentDetail | null {
    const experiment = this.experiments.get(id)
    if (!experiment) return null
    return {
      experiment,
      observations: [
        { field: 'IKE version', groundTruth: experiment.groundTruth.ikeVersion, observed: experiment.ikeVersion, agrees: true },
        { field: 'Mode', groundTruth: experiment.groundTruth.vpnMode, observed: experiment.vpnMode, agrees: true },
        { field: 'Encryption', groundTruth: experiment.groundTruth.encryption, observed: experiment.encryption, agrees: true },
        { field: 'Integrity', groundTruth: experiment.groundTruth.integrity, observed: experiment.integrity, agrees: true },
        { field: 'DH group', groundTruth: experiment.groundTruth.dhGroup, observed: experiment.dhGroup, agrees: true },
        {
          field: 'Perfect forward secrecy',
          groundTruth: String(experiment.perfectForwardSecrecy),
          observed: 'pending',
          agrees: null,
        },
        { field: 'IP version', groundTruth: experiment.groundTruth.ipVersion, observed: experiment.ipVersion, agrees: true },
      ],
      modelOutputs: [],
      correlation: {
        engine: 'correlation-engine (mock)',
        score: experiment.riskScore,
        posture: experiment.riskScore >= 60 ? 'weak' : 'acceptable',
        narrative: 'The run is still in progress; findings appear once analysis completes.',
      },
      findings: [],
      traffic: { packets: 0, bytes: 0, averagePacketSize: null, classes: [] },
      timeline: [],
      configuration: [],
      raw: { experiment },
    }
  }
}
