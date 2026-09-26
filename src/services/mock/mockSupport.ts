import { ServiceError } from '../api/apiClient'

/**
 * Shared helpers for the mock services.
 *
 * They exist so every mock service fails and paginates the same way, which
 * keeps the UI honest: if a page handles mock data correctly it will handle the
 * real service correctly too.
 */

/**
 * Simulated round-trip latency.
 *
 * Kept short by default so the UI stays responsive, but always asynchronous so
 * loading and error states are genuinely exercised rather than skipped.
 */
export function latency<T>(value: T, ms = 120): Promise<T> {
  return new Promise((resolve) => {
    window.setTimeout(() => resolve(value), ms)
  })
}

export function latencyMs(ms = 120): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms)
  })
}

/** The mock equivalent of a 404 from the backend. */
export function notFound(what: string, id: string): ServiceError {
  return new ServiceError({
    kind: 'not-found',
    status: 404,
    code: 'not_found',
    message: `${what} "${id}" does not exist in the current dataset.`,
  })
}

/** The mock equivalent of a 422 from the backend. */
export function invalid(message: string): ServiceError {
  return new ServiceError({
    kind: 'validation',
    status: 422,
    code: 'validation_failed',
    message,
    details: null,
  })
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

export const DEFAULT_PAGE_SIZE = 25

export function paginate<T>(items: T[], page?: number, pageSize?: number): Page<T> {
  const size = pageSize && pageSize > 0 ? pageSize : DEFAULT_PAGE_SIZE
  const current = page && page > 0 ? page : 1
  const start = (current - 1) * size
  return {
    items: items.slice(start, start + size),
    total: items.length,
    page: current,
    pageSize: size,
  }
}

/** Case-insensitive substring match across the supplied fields. */
export function matchesSearch(term: string | undefined, ...fields: (string | null | undefined)[]): boolean {
  const needle = term?.trim().toLowerCase()
  if (!needle) return true
  return fields.some((field) => field?.toLowerCase().includes(needle))
}

/** An absent filter means "no constraint"; an empty array means "nothing matches". */
export function inFilter<T extends string | number | boolean>(
  value: T | null | undefined,
  allowed: readonly T[] | undefined,
): boolean {
  if (!allowed || allowed.length === 0) return true
  if (value === null || value === undefined) return false
  return allowed.includes(value)
}

export function withinRange(iso: string, from?: string, to?: string): boolean {
  const time = Date.parse(iso)
  if (Number.isNaN(time)) return false
  if (from && time < Date.parse(from)) return false
  if (to && time > Date.parse(to)) return false
  return true
}

export function atLeast(value: number | null | undefined, min: number | undefined): boolean {
  if (min === undefined) return true
  if (value === null || value === undefined) return false
  return value >= min
}

/** Stable descending string sort helper for ISO timestamps. */
export function byNewest<T extends { createdAt: string }>(items: T[]): T[] {
  return [...items].sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0))
}
