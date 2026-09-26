import type {
  Experiment,
  ExperimentDetail,
  ExperimentPage,
  ExperimentQuery,
} from '../../types/experiment'

/** What the operator asks the testbed to run. */
export interface ExperimentRequest {
  name: string
  hypothesis: string
  ikeVersion: Experiment['ikeVersion']
  vpnMode: Experiment['vpnMode']
  encryption: string
  integrity: string
  dhGroup: string
  perfectForwardSecrecy: boolean
  ipVersion: Experiment['ipVersion']
  trafficProfile: Experiment['trafficProfile']
  durationMinutes: number
}

/**
 * Experiment lifecycle: configure, run, observe, compare.
 *
 * The experiment is the ground-truth record — what was actually configured in
 * the testbed. The detail endpoint exposes configured-versus-observed so the
 * comparison is evidence, not narrative.
 */
export interface ExperimentService {
  query(query?: ExperimentQuery): Promise<ExperimentPage>
  getById(id: string): Promise<ExperimentDetail>
  create(request: ExperimentRequest): Promise<Experiment>
  cancel(id: string): Promise<Experiment>
  remove(id: string): Promise<void>
  /** Ids the operator has pinned for side-by-side comparison. */
  getSelection(): Promise<string[]>
  setSelection(ids: string[]): Promise<string[]>
}
