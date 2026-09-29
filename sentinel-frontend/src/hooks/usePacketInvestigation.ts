import { useCallback, useEffect, useRef, useState } from 'react'
import {
  getAssessment,
  getAssessmentDrift,
  getAssessmentFindings,
  getEvidenceIntegrity,
  getFindingExplanation,
} from '@/api/analytics'
import { ApiRequestError } from '@/api/client'
import { severityRank } from '@/lib/format'
import type {
  AssessmentBundle,
  AssessmentDriftResponse,
  CustodyExplanation,
  EvidenceIntegrity,
  Finding,
} from '@/types'

/**
 * Everything the Packet Investigation surface reads for one assessment, in
 * one place.
 *
 * A packet inherits risk from the assessment store by observed SPI, so the
 * packet's investigation is the assessment that observed it: the expected
 * (configured) state, the observed (geometric) state, the findings the
 * deterministic engine raised, its custody explanation, drift vs baseline and
 * the integrity status of the attached evidence. None of this is invented in
 * the browser — every field comes from the analytics plane, and the loading /
 * error / empty states are honest.
 */
export type PacketInvestigation = {
  loading: boolean
  error: ApiRequestError | null
  /** The store assessment the selected packet resolves to, or null. */
  assessmentId: string | null
  bundle: AssessmentBundle | null
  /** Findings for this assessment, in the store's order. */
  findings: Finding[]
  drift: AssessmentDriftResponse | null
  reload: () => void
}

export function usePacketInvestigation(assessmentId: string | null): PacketInvestigation {
  const [loading, setLoading] = useState(assessmentId !== null)
  const [error, setError] = useState<ApiRequestError | null>(null)
  const [bundle, setBundle] = useState<AssessmentBundle | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [drift, setDrift] = useState<AssessmentDriftResponse | null>(null)
  const [nonce, setNonce] = useState(0)
  const activeRef = useRef(false)

  const reload = useCallback(() => setNonce((value) => value + 1), [])

  useEffect(() => {
    activeRef.current = false
    if (!assessmentId) {
      setLoading(false)
      setError(null)
      setBundle(null)
      setFindings([])
      setDrift(null)
      return
    }

    const controller = new AbortController()
    activeRef.current = true
    setLoading(true)
    setError(null)

    const run = async () => {
      try {
        // Assessment scope only: the packet's assessment, the findings it
        // raised, and drift against the baseline. Nothing here is
        // finding-specific — see useFindingCustody for that.
        const [bundleResult, findingsResult, driftResult] = await Promise.all([
          getAssessment(assessmentId, controller.signal),
          getAssessmentFindings(assessmentId, controller.signal),
          getAssessmentDrift(assessmentId, controller.signal),
        ])
        if (!activeRef.current) return

        setBundle(bundleResult)
        setDrift(driftResult)
        setFindings(findingsResult.findings ?? [])
        setLoading(false)
      } catch (cause) {
        if (!activeRef.current || controller.signal.aborted) return
        setLoading(false)
        if (cause instanceof ApiRequestError) setError(cause)
        else
          setError(
            new ApiRequestError({
              title: 'Unable to load the packet investigation',
              detail: 'The analytics service did not return this assessment.',
              status: 0,
              code: 'unexpected_error',
              service: 'analytics',
            }),
          )
      }
    }

    void run()

    return () => {
      activeRef.current = false
      controller.abort()
    }
  }, [assessmentId, nonce])

  return {
    loading,
    error,
    assessmentId,
    bundle,
    findings,
    drift,
    reload,
  }
}

/* ------------------------------------------------------- finding custody */

export type FindingCustody = {
  /** The finding the current explanation/integrity belongs to, or null. */
  findingId: string | null
  explanation: CustodyExplanation | null
  integrity: EvidenceIntegrity | null
  /** True while this finding's custody chain is being read. */
  loading: boolean
  /** A failure that belongs to THIS finding's request, never another one's. */
  error: ApiRequestError | null
  reload: () => void
}

/**
 * The custody chain and artifact integrity for ONE finding — the one the
 * analyst is looking at, never "the most severe one" behind their back.
 *
 * The endpoint is per finding, so the request is made for the selected
 * finding id only, and it is skipped entirely when there is no assessment or
 * no selected finding. Switching findings clears the previous result before
 * the new request starts, so another finding's custody can never linger on
 * screen, and a late response for an abandoned finding is discarded.
 */
export function useFindingCustody(
  assessmentId: string | null,
  findingId: string | null,
): FindingCustody {
  const [explanation, setExplanation] = useState<CustodyExplanation | null>(null)
  const [integrity, setIntegrity] = useState<EvidenceIntegrity | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ApiRequestError | null>(null)
  const [nonce, setNonce] = useState(0)
  /** Monotonic id: only the newest run may write state. */
  const runRef = useRef(0)

  const reload = useCallback(() => setNonce((value) => value + 1), [])

  useEffect(() => {
    const run = ++runRef.current
    // Drop the previous finding's result first — including on the very first
    // run — so the panel can never show another finding's chain.
    setExplanation(null)
    setIntegrity(null)
    setError(null)

    if (!assessmentId || !findingId) {
      setLoading(false)
      return
    }

    const controller = new AbortController()
    setLoading(true)

    const settle = async () => {
      try {
        const explanationResult = await getFindingExplanation(
          assessmentId,
          findingId,
          controller.signal,
        )
        // The response must belong to the finding the analyst is looking at.
        if (run !== runRef.current) return
        if (explanationResult.finding_id && explanationResult.finding_id !== findingId) {
          setExplanation(null)
          setError(
            new ApiRequestError({
              title: 'Custody chain does not match the selected finding',
              detail: `The analytics service returned the custody chain for ${explanationResult.finding_id} while ${findingId} was requested, so it is not shown.`,
              status: 0,
              code: 'unexpected_error',
              service: 'analytics',
            }),
          )
          setLoading(false)
          return
        }
        setExplanation(explanationResult)
        setLoading(false)

        // Integrity is read from the artifact this finding's own custody chain
        // references, so it can never describe another finding's evidence.
        const evidenceId = (explanationResult.evidence ?? []).find((item) => item.evidence_id)
          ?.evidence_id
        if (evidenceId) {
          try {
            const integrityResult = await getEvidenceIntegrity(evidenceId, controller.signal)
            if (run !== runRef.current) return
            setIntegrity(integrityResult)
          } catch {
            if (run !== runRef.current) return
            // Integrity is supplemental: its absence narrows the evidence
            // section, it never blanks the custody chain.
            setIntegrity(null)
          }
        }
      } catch (cause) {
        if (run !== runRef.current) return
        setExplanation(null)
        setLoading(false)
        if (cause instanceof ApiRequestError) setError(cause)
        else
          setError(
            new ApiRequestError({
              title: `Unable to load the custody chain for ${findingId}`,
              detail: 'The analytics service did not return this finding’s explanation.',
              status: 0,
              code: 'unexpected_error',
              service: 'analytics',
            }),
          )
      }
    }

    void settle()

    return () => controller.abort()
  }, [assessmentId, findingId, nonce])

  return { findingId, explanation, integrity, loading, error, reload }
}


/** The finding that carries the most weight for "is something wrong". */
export function selectPrimaryFinding(findings: Finding[]): Finding | null {
  if (findings.length === 0) return null
  return [...findings].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity),
  )[0]
}
