import { AI_API_URL } from '@/config'
import { ApiRequestError, request } from '@/api/client'
import type { AiAnalysisRequest, AiAnalysisResult, AiExplainResponse, AiHealthResponse } from '@/types'

/**
 * The AI integration boundary.
 *
 * Two rules govern everything behind this function, and they are enforced
 * server-side as well as here:
 *
 *  1. It may only ever *add* prose on top of findings the deterministic engine
 *     already produced. It never creates, softens, or re-scores one, and the
 *     severity and score rendered in the UI always come from
 *     `analysis.authoritative`, never from the explanation text.
 *  2. Its output is labelled `INFERRED` and carries its own provenance. It is
 *     never rendered as an observation, a measurement, or evidence.
 *
 * The client is also the boundary that must not lie in the other direction: if
 * the service is down, this returns a result with no `analysis` field at all.
 * It never assembles an explanation locally, and it never fills in a missing
 * severity, score, or identifier. A panel that renders an explanation the
 * backend did not produce is worse than one that says it has none.
 */

const EXPLAIN_PATH = '/ai/explain'
const HEALTH_PATH = '/ai/health'

/**
 * Asked for on first use, so the UI can say *why* an explanation is missing
 * rather than just that it is.
 */
let healthPromise: Promise<AiHealthResponse | null> | null = null

async function fetchHealth(signal?: AbortSignal): Promise<AiHealthResponse | null> {
  try {
    return await request<AiHealthResponse>('ai', AI_API_URL, HEALTH_PATH, {
      signal,
      title: 'Unable to reach the explanation service',
      fallback: 'The explanation service did not respond.',
    })
  } catch (cause) {
    // A caller-initiated abort is not a failure to report.
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    // A missing health endpoint is not an error worth surfacing: the explain
    // call reports the real problem, and a second failure must not replace it
    // with a less specific one.
    return null
  }
}

/**
 * Reachability and capability probe, cached so the panel and the status page
 * share one request.
 *
 * A null result means "not reachable" and is cached as such; `resetAiHealth`
 * clears it, so a service started after the page loaded is picked up by the
 * retry affordance rather than by a reload.
 */
export function aiHealth(options: { signal?: AbortSignal } = {}): Promise<AiHealthResponse | null> {
  if (!healthPromise) {
    healthPromise = fetchHealth(options.signal).catch(() => null)
  }
  return healthPromise
}

/** Forget the cached health probe, so a restarted service is picked up. */
export function resetAiHealth(): void {
  healthPromise = null
}

function unavailable(
  request_: AiAnalysisRequest,
  reason: string,
  status: AiAnalysisResult['status'],
): AiAnalysisResult {
  return {
    status,
    connected: false,
    entityId: request_.entityId,
    context: request_.context,
    reason,
  }
}

/**
 * One question about one selected context.
 *
 * `POST` is used only to carry the question. The service has no other verb
 * that does anything, so this is not a mutation surface by virtue of being a
 * POST — the same reason the analytics plane can be GET-only while this one
 * cannot.
 */
export async function analyzeWithAI(
  request_: AiAnalysisRequest,
  options: { signal?: AbortSignal } = {},
): Promise<AiAnalysisResult> {
  const question = (request_.question ?? '').trim()
  if (question === '') {
    // The first "Explain with AI" click needs a question. Rather than invent
    // one, the caller supplies the default it wants to ask; if it did not, the
    // honest answer is that there is nothing to ask yet.
    return unavailable(
      request_,
      'No question was supplied. Explain what is recorded before asking a follow-up.',
      'unavailable',
    )
  }

  const history = (request_.history ?? [])
    .slice(-8)
    .map((turn) => ({ question: turn.question, answer: turn.answer }))

  try {
    const analysis = await request<AiExplainResponse>('ai', AI_API_URL, EXPLAIN_PATH, {
      method: 'POST',
      body: {
        question,
        assessment_id: request_.entityId,
        finding_id: request_.findingId ?? null,
        // Sent only when the surface knows the job. The service treats an
        // absent or unresolvable job as "root cause not recorded" and the
        // assistant says so; it never invents a cause from the finding.
        experiment_id: request_.experimentId ?? null,
        history,
      },
      signal: options.signal,
      title: 'Unable to explain this assessment',
      fallback: 'The explanation service did not return an answer.',
    })

    // Defensive: a service that answered without saying it is read-only, or
    // that claims to have made a decision, is not one this UI will render.
    // Dropping the payload keeps the panel honest about what was received.
    if (analysis?.read_only !== true || analysis?.decision_made !== false) {
      return unavailable(
        request_,
        'The explanation service returned a payload that does not declare itself read-only, so it was not displayed.',
        'unavailable',
      )
    }

    return {
      status: 'available',
      connected: true,
      entityId: request_.entityId,
      context: request_.context,
      reason: analysis.answer,
      analysis,
    }
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    const detail = cause instanceof ApiRequestError ? cause.detail : 'The request failed.'
    return unavailable(
      request_,
      `${detail} The assessment, its findings and its evidence are unaffected and remain available.`,
      // A socket failure means the optional plane is not running, which is a
      // different fact from "it is running and could not answer". The analyst
      // needs the difference: one is fixed by starting a service, the other by
      // the service itself.
      cause instanceof ApiRequestError && (cause.status === 0 || cause.status === 404)
        ? 'not_connected'
        : 'unavailable',
    )
  }
}
