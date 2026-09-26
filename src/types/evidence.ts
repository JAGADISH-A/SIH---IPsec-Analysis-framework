/**
 * Evidence, provenance and confidence primitives.
 *
 * Every value the platform shows must be attributable: where it came from,
 * how sure we are, and what proves it. These three types encode that contract
 * once so no screen has to invent its own convention.
 */

/**
 * How a value was obtained.
 *
 * - `observed`   read directly from captured protocol fields
 * - `inferred`   derived by a model/classifier from observed metadata
 * - `configured` supplied by the testbed or deployment configuration
 * - `calculated` computed by the platform (scores, ratios, aggregates)
 * - `unknown`    no sufficient evidence was available
 */
export type DataSource = 'observed' | 'inferred' | 'configured' | 'calculated' | 'unknown'

export const DATA_SOURCES: readonly DataSource[] = [
  'observed',
  'inferred',
  'configured',
  'calculated',
  'unknown',
] as const

/** Qualitative condition of a value, independent of its provenance. */
export type ValueStatus =
  | 'observed'
  | 'strong'
  | 'acceptable'
  | 'warning'
  | 'weak'
  | 'critical'
  | 'unknown'

/** Severity ladder used by findings, threats and the matrix. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown'

export const SEVERITIES: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
  'unknown',
] as const

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
  unknown: 5,
}

/** A single provable artefact: a packet range, a field, a rule, a model. */
export interface EvidenceReference {
  id: string
  /** Inclusive packet range in the source capture, e.g. "1842–1871". */
  packetRange?: string
  /** Protocol exchange the value was read from, e.g. "IKE_AUTH". */
  exchange?: string
  /** Protocol field path, e.g. "ikev2.sa.transform.encr". */
  field?: string
  /** Analysis rule that produced the conclusion. */
  ruleId?: string
  /** Model or classifier that produced the conclusion. */
  model?: string
  /** Why this artefact supports the conclusion. */
  explanation: string
  /** The literal value extracted, shown verbatim. */
  rawValue: string
  confidence: number | null
  source: DataSource
}

/**
 * A value plus everything needed to defend it in front of a reviewer.
 *
 * `value` is `null` whenever the platform genuinely does not know; the UI then
 * renders the explicit "Unknown — insufficient evidence" treatment rather than
 * inventing a plausible number.
 */
export interface ProtocolValue<T = string> {
  value: T | null
  source: DataSource
  /** 0..1, or null when confidence itself cannot be estimated. */
  confidence: number | null
  status: ValueStatus
  /** Ids of the evidence records backing this value. */
  evidenceIds: string[]
  note?: string
}

/** Shorthand for a confidently observed value. */
export function observed<T>(value: T, confidence: number, evidenceIds: string[] = []): ProtocolValue<T> {
  return { value, source: 'observed', confidence, status: 'observed', evidenceIds }
}

/** Shorthand for a value produced by a model. */
export function inferred<T>(value: T, confidence: number, evidenceIds: string[] = []): ProtocolValue<T> {
  return { value, source: 'inferred', confidence, status: 'observed', evidenceIds }
}

/** Shorthand for a value read from the testbed configuration. */
export function configured<T>(value: T, confidence = 1, evidenceIds: string[] = []): ProtocolValue<T> {
  return { value, source: 'configured', confidence, status: 'observed', evidenceIds }
}

/** Shorthand for a platform-computed value. */
export function calculated<T>(value: T, confidence = 1, evidenceIds: string[] = []): ProtocolValue<T> {
  return { value, source: 'calculated', confidence, status: 'observed', evidenceIds }
}

/** The canonical "we do not know" value. */
export const UNKNOWN_VALUE = {
  value: null,
  source: 'unknown',
  confidence: null,
  status: 'unknown',
  evidenceIds: [],
} as const satisfies ProtocolValue<never>

/** Text shown wherever a value is unavailable. */
export const UNKNOWN_LABEL = 'Unknown'
export const UNKNOWN_REASON = 'Unknown — insufficient evidence in the capture.'

/** Narrows an unknown value to an explicit `null` value. */
export function valueOf<T>(value: ProtocolValue<T> | null | undefined): T | null {
  return value ? value.value : null
}

/** Confidence of a value, or null when unknown. */
export function confidenceOf<T>(value: ProtocolValue<T> | null | undefined): number | null {
  return value ? value.confidence : null
}

/** Display text for a value, degrading explicitly instead of guessing. */
export function displayValue<T>(value: ProtocolValue<T> | null | undefined, format?: (raw: T) => string): string {
  if (!value || value.value === null || value.value === undefined) return UNKNOWN_LABEL
  return format ? format(value.value) : String(value.value)
}

export const DATA_SOURCE_LABEL: Record<DataSource, string> = {
  observed: 'Observed',
  inferred: 'Inferred',
  configured: 'Configured',
  calculated: 'Calculated',
  unknown: 'Unknown',
}

export const DATA_SOURCE_DESCRIPTION: Record<DataSource, string> = {
  observed: 'Read directly from captured protocol fields.',
  inferred: 'Produced by a model or classifier from observed metadata.',
  configured: 'Supplied by the testbed or deployment configuration.',
  calculated: 'Computed by the platform from other values.',
  unknown: 'No sufficient evidence was available.',
}

export const VALUE_STATUS_LABEL: Record<ValueStatus, string> = {
  observed: 'Observed',
  strong: 'Strong',
  acceptable: 'Acceptable',
  warning: 'Warning',
  weak: 'Weak',
  critical: 'Critical',
  unknown: 'Unknown',
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
  unknown: 'Unknown',
}
