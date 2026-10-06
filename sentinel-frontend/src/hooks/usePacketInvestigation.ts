import { useCallback, useEffect, useRef, useState } from 'react'
import {
  getAssessment,
  getAssessmentDrift,
  getAssessmentFindings,
} from '@/api/analytics'
import { ApiRequestError } from '@/api/client'
import type {
  AssessmentBundle,
  AssessmentDriftResponse,
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
        // raised, and drift against the baseline. Custody / evidence
        // integrity are not part of this surface.
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
