import { API_TIMEOUT_MS } from '@/config'

/**
 * The three backend planes this client talks to.
 *
 * `ai` is the read-only explanation service. It is a separate process on its
 * own port because the analytics plane is GET-only by contract, and a question
 * does not belong in a query string.
 */
export type ApiService = 'analytics' | 'control' | 'ai'

/**
 * One error shape for every API plane.
 *
 * The analytics plane answers with
 *   {"error": {"code", "message", "detail", "request_id"}}
 * while the control plane (FastAPI) answers with
 *   {"detail": "..."} or a bare string. The explanation service uses the
 *   analytics envelope, so one normalizer covers all three.
 *
 * `ApiRequestError` normalizes them so no page has to branch on which server
 * produced the failure. `title` / `message` are written for a human; `code`,
 * `status` and `requestId` are for diagnostics and never shown raw.
 */
export class ApiRequestError extends Error {
  readonly status: number
  readonly code: string
  readonly requestId?: string
  readonly service: ApiService
  /** Human-facing headline, e.g. "Unable to load assessment". */
  readonly title: string
  /** Human-facing explanation, e.g. "The analytics service did not return ...". */
  readonly detail: string

  constructor(init: {
    title: string
    detail: string
    status: number
    code: string
    requestId?: string
    service: ApiService
  }) {
    super(init.detail)
    this.name = 'ApiRequestError'
    this.title = init.title
    this.detail = init.detail
    this.status = init.status
    this.code = init.code
    this.requestId = init.requestId
    this.service = init.service
  }

  get isNotFound(): boolean {
    return this.status === 404
  }

  get isOffline(): boolean {
    return this.status === 0
  }
}

type ErrorEnvelope = {
  error?: { code?: unknown; message?: unknown; detail?: unknown; request_id?: unknown }
  detail?: unknown
  message?: unknown
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === 'string' && value.trim() !== '') return value.trim()
  }
  return undefined
}

/** Pull a human message out of either backend's error envelope. */
function extractServerMessage(body: unknown): string | undefined {
  if (typeof body === 'string') return body.trim() === '' ? undefined : body
  if (!body || typeof body !== 'object') return undefined
  const envelope = body as ErrorEnvelope
  return firstString(
    envelope.error?.message,
    envelope.error?.detail,
    typeof envelope.detail === 'string' ? envelope.detail : undefined,
    envelope.message,
  )
}

function extractCode(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined
  const envelope = body as ErrorEnvelope
  return firstString(envelope.error?.code)
}

function extractRequestId(body: unknown, header: string | null): string | undefined {
  if (body && typeof body === 'object') {
    const envelope = body as ErrorEnvelope
    const fromBody = firstString(envelope.error?.request_id)
    if (fromBody) return fromBody
  }
  return firstString(header)
}

/**
 * Compose a title + detail pair for a failed call. Server text is used when it
 * is present, but a human-written fallback always exists so the UI never shows
 * a raw stack trace or a bare HTTP status.
 */
function buildError(
  service: ApiService,
  status: number,
  body: unknown,
  requestIdHeader: string | null,
  context: { title: string; fallback: string },
): ApiRequestError {
  const serverMessage = extractServerMessage(body)
  const code = extractCode(body)
  const requestId = extractRequestId(body, requestIdHeader)

  let detail: string
  if (status === 0) {
    const plane =
      service === 'analytics' ? 'analytics' : service === 'control' ? 'control' : 'AI explanation'
    detail = `Sentinel could not reach the ${plane} service. Check that the backend is running and that the URL in .env is correct.`
  } else if (status >= 500) {
    detail = serverMessage ?? 'The service reported an internal error. Check the backend log for the matching request id.'
  } else if (serverMessage) {
    detail = serverMessage
  } else {
    detail = context.fallback
  }

  return new ApiRequestError({
    title: context.title,
    detail,
    status,
    code: code ?? (status === 0 ? 'network_error' : `http_${status}`),
    requestId,
    service,
  })
}

export type RequestOptions = {
  method?: 'GET' | 'POST'
  body?: unknown
  signal?: AbortSignal
  query?: Record<string, string | number | boolean | undefined | null>
}

function buildUrl(base: string, path: string, query?: RequestOptions['query']): string {
  const url = `${base}${path}`
  if (!query) return url
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue
    params.set(key, String(value))
  }
  const qs = params.toString()
  return qs ? `${url}?${qs}` : url
}

async function readBody(response: Response): Promise<unknown> {
  const text = await response.text()
  if (text.trim() === '') return undefined
  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

/**
 * One request against one backend plane.
 *
 * The abort signal is composed with a timeout so a hung socket surfaces as a
 * normal error state instead of a spinner that never resolves.
 */
export async function request<T>(
  service: ApiService,
  base: string,
  path: string,
  options: RequestOptions & { title: string; fallback: string },
): Promise<T> {
  const { title, fallback, method = 'GET', body, signal, query } = options
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS)
  const onAbort = () => controller.abort()
  signal?.addEventListener('abort', onAbort)

  try {
    const response = await fetch(buildUrl(base, path, query), {
      method,
      signal: controller.signal,
      headers: {
        Accept: 'application/json',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    })

    const payload = await readBody(response)

    if (!response.ok) {
      throw buildError(service, response.status, payload, response.headers.get('X-Request-Id'), {
        title,
        fallback,
      })
    }
    return payload as T
  } catch (cause) {
    if (cause instanceof ApiRequestError) throw cause
    // An abort the caller asked for is not an error state; let it propagate as
    // an AbortError so React ignores the settled request.
    if (signal?.aborted) throw cause
    const aborted = cause instanceof DOMException && cause.name === 'AbortError'
    throw buildError(
      service,
      0,
      undefined,
      null,
      {
        title,
        fallback: aborted
          ? 'The request timed out before the service responded.'
          : fallback,
      },
    )
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }
}
