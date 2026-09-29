import type { ReportRequest, ReportResult } from '@/types'

/**
 * The report boundary.
 *
 * The analytics plane is read-only by contract — it has no route that renders,
 * stores, or signs a document, and adding one would be backend work this
 * change is not permitted to do. So this function issues no request and returns
 * no document.
 *
 * The seam exists because "no report service" and "no report button" are very
 * different things to an analyst: the first is a deployment fact, the second
 * hides the capability. The console shows the control, states the real reason,
 * and leaves the output empty rather than assembling a report in the browser
 * and presenting it as backend-produced evidence.
 *
 * When a real service is connected, its output must carry the same provenance
 * discipline as the rest of the app: generated text is `INFERRED` and may
 * never be attached to an evidence digest.
 */
export async function generateReport(request: ReportRequest): Promise<ReportResult> {
  void request
  return {
    status: 'unavailable',
    connected: false,
    kind: request.kind,
    entityId: request.entityId,
    reason:
      'The analytics API is a read-only projection of the assessment store and exposes no report endpoint. Sentinel does not compose a report in the browser, because a document assembled client-side would carry no authority and could be mistaken for a recorded one.',
  }
}
