import axios, { AxiosError, type AxiosInstance } from 'axios'

/**
 * Normalised application error.
 *
 * Every service — mock or real — rejects with this shape, so pages render a
 * single, predictable error treatment regardless of transport. Raw backend
 * text is never rendered directly: `message` is written for an operator and
 * `details` carries non-sensitive diagnostics only.
 */
export class ServiceError extends Error {
  readonly kind: ServiceKind
  readonly status: number | null
  readonly code: string
  readonly details: string | null
  readonly retryable: boolean

  constructor(init: {
    kind: ServiceKind
    message: string
    status?: number | null
    code?: string
    details?: string | null
    retryable?: boolean
  }) {
    super(init.message)
    this.name = 'ServiceError'
    this.kind = init.kind
    this.status = init.status ?? null
    this.code = init.code ?? 'service_error'
    this.details = init.details ?? null
    this.retryable = init.retryable ?? init.kind !== 'validation'
  }
}

export type ServiceKind =
  | 'network'
  | 'timeout'
  | 'unauthorized'
  | 'forbidden'
  | 'not-found'
  | 'validation'
  | 'server'
  | 'offline'
  | 'service'

/** Raised when the browser reports no connectivity. */
export function offlineError(): ServiceError {
  return new ServiceError({
    kind: 'offline',
    code: 'offline',
    message: 'You appear to be offline. Values shown may be from cache.',
  })
}

/** The message an operator should read for a failure. */
export function errorMessage(error: unknown): string {
  if (error instanceof ServiceError) return error.message
  if (error instanceof Error) return error.message
  return 'The analysis service is currently unavailable.'
}

/** Non-sensitive detail string for the error state disclosure. */
export function errorDetail(error: unknown): string | null {
  if (error instanceof ServiceError) return error.details ?? error.code
  return null
}

export function isRetryable(error: unknown): boolean {
  return error instanceof ServiceError ? error.retryable : true
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'
export const API_BASE = API_BASE_URL

/**
 * Shared Axios instance for the future REST backend.
 *
 * It is configured but not used while `VITE_USE_MOCK_DATA` is true. Keeping it
 * wired from day one means the switch to a real backend is a configuration
 * change, not a refactor.
 *
 * No credential is ever stored here. When session handling arrives it will use
 * an httpOnly cookie set by the gateway — never a token in localStorage.
 */
export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 20_000,
  withCredentials: true,
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  },
})

/** Convert any thrown value into a `ServiceError`. */
export function toServiceError(error: unknown): ServiceError {
  if (error instanceof ServiceError) return error
  if (axios.isAxiosError(error)) return fromAxiosError(error as AxiosError)
  if (error instanceof Error) {
    return new ServiceError({ kind: 'service', message: error.message, details: null })
  }
  return new ServiceError({
    kind: 'service',
    message: 'The analysis service is currently unavailable.',
    details: null,
  })
}

function fromAxiosError(error: AxiosError): ServiceError {
  const status = error.response?.status ?? null
  if (error.code === 'ECONNABORTED') {
    return new ServiceError({
      kind: 'timeout',
      status,
      code: 'timeout',
      message: 'The analysis service did not respond in time.',
      details: error.message,
    })
  }
  if (!error.response) {
    return new ServiceError({
      kind: 'network',
      status: null,
      code: 'network_error',
      message: 'The analysis service is currently unavailable.',
      details: error.message,
    })
  }
  if (status === 401) {
    return new ServiceError({
      kind: 'unauthorized',
      status,
      code: 'session_expired',
      message: 'Your session has expired. Sign in again to continue.',
      details: null,
    })
  }
  if (status === 403) {
    return new ServiceError({
      kind: 'forbidden',
      status,
      code: 'forbidden',
      message: 'You do not have access to this resource.',
      details: null,
    })
  }
  if (status === 404) {
    return new ServiceError({
      kind: 'not-found',
      status,
      code: 'not_found',
      message: 'The requested record does not exist.',
      details: null,
    })
  }
  if (status === 422) {
    return new ServiceError({
      kind: 'validation',
      status,
      code: 'validation_failed',
      message: 'The request was rejected as invalid.',
      details: null,
    })
  }
  if (status !== null && status >= 500) {
    return new ServiceError({
      kind: 'server',
      status,
      code: 'server_error',
      message: 'The analysis service is currently unavailable.',
      details: null,
    })
  }
  return new ServiceError({
    kind: 'service',
    status,
    code: 'request_failed',
    message: 'The request could not be completed.',
    details: null,
  })
}

/**
 * Optional bearer hook for deployments that cannot use cookies.
 * Left empty on purpose: the frontend must not hold long-lived secrets.
 */
let authTokenProvider: (() => string | null) | null = null

export function setAuthTokenProvider(provider: (() => string | null) | null): void {
  authTokenProvider = provider
}

apiClient.interceptors.request.use((config) => {
  const token = authTokenProvider?.()
  if (token) {
    config.headers.set('Authorization', `Bearer ${token}`)
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error: unknown) => Promise.reject(toServiceError(error)),
)
