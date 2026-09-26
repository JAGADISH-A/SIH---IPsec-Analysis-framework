/** Shared primitives used across the IPsec Sentinel domain model. */

/** A function that tears down a subscription. */
export type Unsubscribe = () => void

export type Nullable<T> = T | null

export interface Timestamped {
  /** ISO-8601 timestamp, e.g. "2026-09-23T14:02:11.081Z". */
  timestamp: string
  /** Milliseconds since the start of the capture/session. */
  relativeTimeMs: number
}

export type SeverityTone = 'accent' | 'info' | 'success' | 'warning' | 'danger'

export interface LabeledValue {
  label: string
  value: string
}