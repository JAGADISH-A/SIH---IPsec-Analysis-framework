import type { Report, ReportPreview, ReportRequest } from '../../types/report'

/**
 * Report generation and artefact retrieval.
 *
 * Generation is asynchronous in production: a request returns a queued report
 * that moves through `queued → generating → ready`, and artefacts are fetched
 * once ready. `getStatus` exists so a page can poll without holding a socket.
 */
export interface ReportService {
  list(): Promise<Report[]>
  getById(id: string): Promise<Report>
  create(request: ReportRequest): Promise<Report>
  remove(id: string): Promise<void>
  getStatus(id: string): Promise<Report['status']>
  /** Rendered document for on-screen preview, before download. */
  getPreview(id: string): Promise<ReportPreview>
  /** Resolve an artefact download for a ready report. */
  getDownloadUrl(id: string, format: Report['formats'][number]): Promise<string>
}
