import type {
  FindingQuery,
  FindingSummary,
  SecurityFinding,
  ThreatMatrix,
} from '../../types/analysis'
import type { FindingStatus } from '../../types/analysis'

/**
 * The findings register.
 *
 * Findings are produced by the analysis backend (rules, models and the
 * correlation engine). The frontend lists, filters and annotates them — it
 * never creates one, and it never changes a severity.
 */
export interface FindingService {
  query(query?: FindingQuery): Promise<SecurityFinding[]>
  getById(id: string): Promise<SecurityFinding>
  getSummary(query?: FindingQuery): Promise<FindingSummary>
  /** Likelihood/impact matrix derived from the current findings. */
  getThreatMatrix(): Promise<ThreatMatrix>
  /**
   * Triage annotation only: acknowledge, resolve, mark false positive or
   * suppress. Severity and category are read-only from the UI.
   */
  setStatus(id: string, status: FindingStatus, note?: string): Promise<SecurityFinding>
}
