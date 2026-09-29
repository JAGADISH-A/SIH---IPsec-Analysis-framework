import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiRequestError } from '@/api/client'
import { getExperiment } from '@/api/control'
import type { ExperimentJob } from '@/types'

export type Resource<T> = {
  data: T | null
  error: ApiRequestError | null
  loading: boolean
  /** True while a *background refresh* runs and stale data is already shown. */
  refreshing: boolean
  reload: () => void
}

type Options = {
  /** When false the request is not made (e.g. a required id is missing). */
  enabled?: boolean
  /** Re-run whenever any of these change. */
  deps?: readonly unknown[]
}

/**
 * Minimal fetch-on-mount hook with a retry handle.
 *
 * Every backend-backed page in Sentinel goes through this so loading, success,
 * error and empty are handled in one place. An `enabled: false` input stays in
 * the `loading` state with no data and no error, which is what a page with a
 * missing route parameter should render.
 */
export function useResource<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  { enabled = true, deps = [] }: Options = {},
): Resource<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<ApiRequestError | null>(null)
  const [loading, setLoading] = useState(enabled)
  const [refreshing, setRefreshing] = useState(false)
  const [nonce, setNonce] = useState(0)
  const hasData = useRef(false)

  const reload = useCallback(() => setNonce((value) => value + 1), [])

  useEffect(() => {
    if (!enabled) {
      setLoading(true)
      setError(null)
      return
    }

    const controller = new AbortController()
    let active = true

    if (hasData.current) setRefreshing(true)
    else setLoading(true)
    setError(null)

    fetcher(controller.signal)
      .then((result) => {
        if (!active) return
        hasData.current = true
        setData(result)
      })
      .catch((cause: unknown) => {
        if (!active || controller.signal.aborted) return
        if (cause instanceof ApiRequestError) setError(cause)
        else
          setError(
            new ApiRequestError({
              title: 'Unable to load data',
              detail: 'The request failed for an unexpected reason.',
              status: 0,
              code: 'unexpected_error',
              service: 'analytics',
            }),
          )
      })
      .finally(() => {
        if (!active) return
        setLoading(false)
        setRefreshing(false)
      })

    return () => {
      active = false
      controller.abort()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, nonce, ...deps])

  return { data, error, loading, refreshing, reload }
}

/**
 * Poll a running experiment job until it reports a terminal status.
 *
 * Each fresh snapshot is handed to `onUpdate`. Polling stops on COMPLETED or
 * FAILED, on unmount, and when the job id changes. A transient poll failure is
 * retried on the next tick rather than replacing the page with an error.
 */
export function useJobPolling(
  jobId: string | null,
  onUpdate: (job: ExperimentJob) => void,
  intervalMs: number,
): void {
  const handler = useRef(onUpdate)
  handler.current = onUpdate

  useEffect(() => {
    if (!jobId) return
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    let stopped = false

    const tick = async () => {
      try {
        const job = await getExperiment(jobId, controller.signal)
        if (stopped) return
        handler.current(job)
        if (job.status === 'COMPLETED' || job.status === 'FAILED') return
      } catch {
        if (stopped || controller.signal.aborted) return
      }
      if (!stopped) timer = setTimeout(tick, intervalMs)
    }

    void tick()

    return () => {
      stopped = true
      if (timer) clearTimeout(timer)
      controller.abort()
    }
  }, [jobId, intervalMs])
}
