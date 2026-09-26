import type { SessionDetail, SessionPage, SessionQuery } from '../../types/session'
import type { SessionReference } from '../../types/session'

/**
 * Query and retrieval of analysed VPN sessions.
 *
 * A `SessionDetail` is the composite record a session page renders: negotiated
 * configuration, security associations, timeline, evidence, traffic
 * classification, model outputs and the correlation engine's narrative.
 */
export interface SessionService {
  query(query?: SessionQuery): Promise<SessionPage>
  getDetail(id: string): Promise<SessionDetail>
  /** Lightweight references for linking findings back to sessions. */
  getReferences(ids: string[]): Promise<SessionReference[]>
  /** Distinct values available in the dataset, for filter controls. */
  getFacets(): Promise<SessionFacets>
}

export interface SessionFacets {
  encryption: string[]
  dhGroups: string[]
  environments: string[]
  testbeds: string[]
}
