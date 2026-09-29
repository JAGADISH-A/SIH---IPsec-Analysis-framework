import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getAuditEvents } from '@/api/analytics'
import { ApiRequestError } from '@/api/client'
import { TRAFFIC_BUFFER_LIMIT, TRAFFIC_POLL_MS } from '@/config'
import {
  compareTrafficRows,
  indexAssessmentsByKey,
  indexFindingsByAssessment,
  toTrafficRow,
} from '@/lib/traffic'
import type { TrafficRow } from '@/lib/traffic'
import type { AssessmentHeader, Finding } from '@/types'

/**
 * Why the monitor is not showing events.
 *
 * These are distinguished deliberately. A store with no journal attached is
 * not the same as a store that is being polled successfully and has recorded
 * nothing, and neither is the same as a connection failure.
 */
export type FeedState =
  /** First page has not returned yet. */
  | 'connecting'
  /** Polling normally. */
  | 'live'
  /** Polling is stopped by the analyst. Rows on screen are held, not growing. */
  | 'paused'
  /** The journal answered, and it holds no events. */
  | 'empty'
  /** No journal is attached to the analytics store. */
  | 'unavailable'
  /** The analytics plane is not answering. */
  | 'offline'
  /** The last poll failed; earlier rows are still shown. */
  | 'degraded'

export type LiveTraffic = {
  rows: TrafficRow[]
  /** Rows dropped from the buffer to respect the cap, since the last reset. */
  evicted: number
  state: FeedState
  error: ApiRequestError | null
  paused: boolean
  /** Consecutive failed polls; reset by a successful one. */
  failures: number
  lastPollAtMs: number | null
  /** Server-side event count for the queried journal, not the buffer length. */
  serverTotal: number
  pause: () => void
  resume: () => void
  clear: () => void
  reconnect: () => void
}

type Props = {
  headers: AssessmentHeader[]
  findings: Finding[]
  enabled?: boolean
  intervalMs?: number
  bufferLimit?: number
  /** The dataset run to watch. `null` watches every run in the journal. */
  runId?: string | null
}

/**
 * A continuously refreshed, bounded view of the analysis audit journal.
 *
 * The analytics plane has no stream: `/api/v1/audit/events` is a filtered,
 * paged query over an append-only file. So "live" here means polling, and the
 * hook is built around the three things that makes honest:
 *
 *  - **Dedupe by `event_id`.** The event id is content-addressed and
 *    server-assigned, so it is the only stable key available. Re-polling a
 *    range re-returns events already held; they are merged, not duplicated.
 *  - **A bounded ring buffer.** The newest `bufferLimit` events are retained.
 *    Eviction is counted and surfaced, because a silently truncated list reads
 *    as a complete one.
 *  - **A real unavailable state.** A store with no journal attached reports
 *    that, instead of an empty table an analyst could read as "no traffic".
 *
 * Filtering and search are applied downstream of this hook, so pausing the
 * feed never discards the analyst's view of it.
 */
export function useLiveTraffic({
  headers,
  findings,
  enabled = true,
  intervalMs = TRAFFIC_POLL_MS,
  bufferLimit = TRAFFIC_BUFFER_LIMIT,
  runId = null,
}: Props): LiveTraffic {
  const [rows, setRows] = useState<TrafficRow[]>([])
  const [state, setState] = useState<FeedState>('connecting')
  const [error, setError] = useState<ApiRequestError | null>(null)
  const [paused, setPaused] = useState(false)
  const [failures, setFailures] = useState(0)
  const [lastPollAtMs, setLastPollAtMs] = useState<number | null>(null)
  const [serverTotal, setServerTotal] = useState(0)
  const [evicted, setEvicted] = useState(0)
  const [nonce, setNonce] = useState(0)

  // Rows are held in a ref as well as state so a poll that lands between
  // renders merges against the newest set rather than a stale closure copy.
  const rowsRef = useRef<TrafficRow[]>([])
  const seenRef = useRef<Set<string>>(new Set())
  const primedRef = useRef(false)
  // Server-side tail index (page.total of the last poll) and the durable
  // "cleared at" watermark: events at/behind it must never re-enter the view
  // after the analyst clears, even though the journal keeps them.
  const tailRef = useRef(0)
  const clearedAtRef = useRef<number | null>(null)
  // Pausing must not restart the poll loop, so the flag is read through a ref
  // and the pending timer is cancelled directly.
  const pausedRef = useRef(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  // The first poll can resolve before the assessment index does. Rows built
  // against an empty index stay stale unless re-derived when the index lands,
  // so remember the maps we last enriched against and rebuild on change.
  const indexRef = useRef<{ assessments: unknown; findings: unknown }>({
    assessments: undefined,
    findings: undefined,
  })

  const assessments = useMemo(() => indexAssessmentsByKey(headers), [headers])
  const findingsByAssessment = useMemo(
    () => indexFindingsByAssessment(findings),
    [findings],
  )

  const reset = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current)
      timerRef.current = undefined
    }
    rowsRef.current = []
    seenRef.current = new Set()
    primedRef.current = false
    tailRef.current = 0
    clearedAtRef.current = null
    setRows([])
    setEvicted(0)
    setState('connecting')
    setError(null)
    setFailures(0)
    setLastPollAtMs(null)
    setServerTotal(0)
  }, [])

  const clear = useCallback(() => {
    // Clear must be durable: advance the resume watermark to the current tail
    // so the next poll serves events recorded AFTER the clear only, never the
    // newest page of what the analyst just dismissed.
    clearedAtRef.current = tailRef.current
    rowsRef.current = []
    seenRef.current = new Set()
    setRows([])
    setEvicted(0)
  }, [])

  const reconnect = useCallback(() => {
    reset()
    setNonce((value) => value + 1)
  }, [reset])

  useEffect(() => {
    // A different run is a different journal view; do not blend them.
    reset()
  }, [runId, reset])

  useEffect(() => {
    if (!enabled) return

    const controller = new AbortController()
    let stopped = false
    let consecutive = 0
    // Only ask for the newest page each poll. The journal is append-only, so
    // the head of the list is where new activity appears. A clear sets a
    // durable watermark: events at/behind it are dismissed forever.
    let offset = clearedAtRef.current ?? 0

    // If the underlying indexes changed since the last enrichment (for example
    // they arrived after the first poll), re-derive the rows already held. The
    // source event is unchanged; only its inherited context has moved on.
    if (
      primedRef.current &&
      (assessments !== indexRef.current.assessments ||
        findingsByAssessment !== indexRef.current.findings)
    ) {
      rowsRef.current = rowsRef.current.map((row) => ({
        ...toTrafficRow(row.event, assessments, findingsByAssessment),
        key: row.key,
      }))
      setRows(rowsRef.current)
    }
    indexRef.current = { assessments, findings: findingsByAssessment }

    const tick = async () => {
      try {
        const page = await getAuditEvents(
          { limit: Math.min(bufferLimit, 500), offset, ...(runId ? { run_id: runId } : {}) },
          controller.signal,
        )
        if (stopped) return

        consecutive = 0
        setFailures(0)
        setError(null)
        setLastPollAtMs(Date.now())
        setServerTotal(page.total)

        const fresh = page.events.filter((event) => !seenRef.current.has(event.event_id))
        for (const event of fresh) seenRef.current.add(event.event_id)

        if (fresh.length > 0 || !primedRef.current) {
          const merged = [
            ...fresh.map((event) =>
              toTrafficRow(event, assessments, findingsByAssessment),
            ),
            ...rowsRef.current,
          ].sort(compareTrafficRows)

          // A content-addressed id identifies an event's *content*, not its
          // occurrence: two records recorded at different times can hash to the
          // same id, and the journal does not dedupe them. Both are real
          // records, so both are kept — dropping one would make the view
          // disagree with the journal count. They only need a unique React key,
          // assigned here in sort order so it is stable across polls.
          const occurrences = new Map<string, number>()
          const keyed = merged.map((row) => {
            const seen = (occurrences.get(row.event.event_id) ?? 0) + 1
            occurrences.set(row.event.event_id, seen)
            return seen === 1
              ? row
              : { ...row, key: `${row.event.event_id}#${seen}` }
          })

          const overflow = Math.max(0, keyed.length - bufferLimit)
          rowsRef.current = overflow > 0 ? keyed.slice(0, bufferLimit) : keyed
          if (overflow > 0) setEvicted((count) => count + overflow)
          setRows(rowsRef.current)
        }

        primedRef.current = true
        tailRef.current = page.total
        if (clearedAtRef.current !== null && rowsRef.current.length === 0) {
          // After a durable clear the view resumes exactly at the cleared
          // tail: events appended since the clear are served, and a journal
          // that has not grown returns nothing.
          offset = clearedAtRef.current
        } else {
          offset = Math.max(
            clearedAtRef.current ?? 0,
            Math.max(0, page.total - rowsRef.current.length),
          )
        }
        setState(page.total === 0 ? 'empty' : 'live')
      } catch (cause) {
        if (stopped || controller.signal.aborted) return
        consecutive += 1
        setFailures(consecutive)
        if (cause instanceof ApiRequestError) {
          setError(cause)
          // The journal is attached but unreadable, or the store has none. The
          // server distinguishes these and the distinction matters: an empty
          // store and a corrupt one are both unusable, for different reasons.
          setState(
            cause.code === 'audit_unavailable' ? 'unavailable' : consecutive >= 2 ? 'degraded' : 'offline',
          )
        } else {
          setState(consecutive >= 2 ? 'degraded' : 'offline')
        }
      }

      if (!stopped && !pausedRef.current) {
        timerRef.current = setTimeout(tick, intervalMs)
      }
    }

    void tick()

    return () => {
      stopped = true
      if (timerRef.current) clearTimeout(timerRef.current)
      controller.abort()
    }
  }, [
    assessments,
    bufferLimit,
    enabled,
    findingsByAssessment,
    intervalMs,
    nonce,
    runId,
  ])

  // Cancelling the pending timer is what makes pause immediate: no further
  // request is issued until resume, and the rows already on screen are held.
  const pause = useCallback(() => {
    pausedRef.current = true
    if (timerRef.current) {
      clearTimeout(timerRef.current)
      timerRef.current = undefined
    }
    setPaused(true)
  }, [])

  const resume = useCallback(() => {
    pausedRef.current = false
    setPaused(false)
    // Bump the nonce so the poll loop is rebuilt and refreshes straight away
    // rather than waiting out the remainder of the previous interval.
    setNonce((value) => value + 1)
  }, [])

  // Pausing must not blank the table; it stops growth only. The feed state is
  // derived here so the polling effect stays a pure data path.
  const effectiveState: FeedState = paused && (state === 'live' || state === 'paused')
    ? 'paused'
    : state

  return {
    rows,
    evicted,
    state: effectiveState,
    error,
    paused,
    failures,
    lastPollAtMs,
    serverTotal,
    pause,
    resume,
    clear,
    reconnect,
  }
}
