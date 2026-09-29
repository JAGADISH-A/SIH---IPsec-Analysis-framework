import { useCallback, useEffect, useRef, useState } from 'react'
import { getCaptureEvents } from '@/api/analytics'
import { ApiRequestError } from '@/api/client'
import { TRAFFIC_BUFFER_LIMIT, TRAFFIC_POLL_MS } from '@/config'
import type { CaptureEventsResponse, FeedPacket } from '@/types'

/**
 * Why the capture view is not showing packets.
 *
 * These are distinguished deliberately. "Waiting" means the gateway monitor
 * has not written packets yet (or the attached journal is empty) — the honest
 * state for "no traffic seen". It is not the same as "no feed attached"
 * (unavailable), and neither is the same as a connection failure.
 */
export type CaptureFeedState =
  /** First page has not returned yet. */
  | 'connecting'
  /** Polling normally; the journal is actively being written and packets exist. */
  | 'live'
  /** Polling is stopped by the analyst. Rows on screen are held, not growing. */
  | 'paused'
  /** No packets at all yet: the monitor has not written to the journal. */
  | 'waiting'
  /** The journal exists but is not being written: rows (if any) are recorded
   *  history, never current traffic. */
  | 'no_traffic'
  /** No capture feed is attached to this analytics server. */
  | 'unavailable'
  /** The analytics plane is not answering. */
  | 'offline'
  /** The last poll failed; earlier rows are still shown. */
  | 'degraded'

export type CaptureFeed = {
  packets: FeedPacket[]
  /** Rows dropped from the buffer to respect the cap, since the last reset. */
  evicted: number
  state: CaptureFeedState
  error: ApiRequestError | null
  paused: boolean
  /** Consecutive failed polls; reset by a successful one. */
  failures: number
  lastPollAtMs: number | null
  /** Server-side packet count in the journal (the whole feed, not the buffer). */
  serverTotal: number
  /** Basename of the packet journal being tailed; null while waiting. */
  feedSource: string | null
  /** Byte offset into the journal; resuming is exact, nothing re-read. */
  cursor: number
  /** Whether the journal had more rows than the last page returned. */
  hasMore: boolean
  /** Packets received in the last poll interval (rough live rate). */
  pps: number | null
  /** The reason the feed is waiting, verbatim from the server when applicable. */
  waitingReason: string | null
  /** The backend's own verdict: is the journal being actively written right
   *  now? `false` = any rows in the envelope are recorded history, not current
   *  live traffic. Never approximated client-side. */
  current: boolean
  /** Milliseconds since the journal was last written; null while waiting. */
  lastWriteAgeMs: number | null
  /** Wall-clock time of the newest complete line in the journal; null without. */
  newestObservedAtMs: number | null
  /** The server's live-freshness window in ms. */
  freshnessWindowMs: number
  pause: () => void
  resume: () => void
  clear: () => void
  /** Reset the view and re-anchor the tail to the journal's current end:
   *  pre-existing rows are history and are not restored. */
  reconnect: () => void
}

type Props = {
  enabled?: boolean
  intervalMs?: number
  bufferLimit?: number
  pageLimit?: number
  /**
   * Test/embed seam: how one capture page is fetched. Defaults to the real
   * analytics `/api/v1/capture/events` byte-tail over the network. Injecting it
   * lets the tail/clear/race state machine be driven deterministically.
   */
  fetchPage?: (cursor: number, limit: number, signal: AbortSignal) => Promise<CaptureEventsResponse>
}

/**
 * A continuously refreshed, bounded view of the xdp_monitor packet journal.
 *
 * The analytics plane has no stream: `/api/v1/capture/events` is a byte-offset
 * tail over the append-only capture journal the gateway sensor writes. "Live"
 * here means polling with an exact resume cursor, and the hook is built around
 * the three things that makes honest:
 *
 *  - **Exact resume by byte cursor.** The server returns the next byte offset
 *    with every page; a paused feed resumes exactly where it stopped and a
 *    truncated/rotated journal is detected (cursor past EOF) and retailed.
 *  - **A bounded ring buffer.** The newest `bufferLimit` packets are retained;
 *    eviction is counted and surfaced. The buffer is client-side only — the
 *    journal is never written here.
 *  - **A real waiting state.** A feed with no packets reports that explicitly
 *    ("waiting for testbed traffic") instead of an empty table that reads as
 *    "no traffic".
 *
 * The page displays newest-first; packets are appended in capture order here.
 */
export function useCaptureFeed({
  enabled = true,
  intervalMs = TRAFFIC_POLL_MS,
  bufferLimit = TRAFFIC_BUFFER_LIMIT,
  pageLimit = 500,
  fetchPage,
}: Props): CaptureFeed {
  const [packets, setPackets] = useState<FeedPacket[]>([])
  const [state, setState] = useState<CaptureFeedState>('connecting')
  const [error, setError] = useState<ApiRequestError | null>(null)
  const [paused, setPaused] = useState(false)
  const [failures, setFailures] = useState(0)
  const [lastPollAtMs, setLastPollAtMs] = useState<number | null>(null)
  const [serverTotal, setServerTotal] = useState(0)
  const [feedSource, setFeedSource] = useState<string | null>(null)
  const [cursor, setCursor] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [evicted, setEvicted] = useState(0)
  const [pps, setPps] = useState<number | null>(null)
  const [waitingReason, setWaitingReason] = useState<string | null>(null)
  const [current, setCurrent] = useState(false)
  const [lastWriteAgeMs, setLastWriteAgeMs] = useState<number | null>(null)
  const [newestObservedAtMs, setNewestObservedAtMs] = useState<number | null>(null)
  const [freshnessWindowMs, setFreshnessWindowMs] = useState(0)
  const [nonce, setNonce] = useState(0)

  const packetsRef = useRef<FeedPacket[]>([])
  const seenRef = useRef<Set<string>>(new Set())
  const cursorRef = useRef(0)
  const pausedRef = useRef(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  /** Byte end of the journal as last observed; the live-tail watermark. */
  const endRef = useRef(0)
  /**
   * Whether the tail watermark still has to be established. True at mount and
   * after every Clear: the next successful page re-anchors the tail at the
   * journal's end, so nothing already written can ever be installed.
   */
  const needsWatermarkRef = useRef(true)
  /** Bumped by clear()/reset() so an in-flight page from before is discarded. */
  const generationRef = useRef(0)
  /** The injected page fetcher, held in a ref so identity churn never restarts
   *  the poll loop. */
  const fetchPageRef = useRef(fetchPage)
  fetchPageRef.current = fetchPage

  const reset = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current)
      timerRef.current = undefined
    }
    generationRef.current += 1
    endRef.current = 0
    needsWatermarkRef.current = true
    packetsRef.current = []
    seenRef.current = new Set()
    cursorRef.current = 0
    setPackets([])
    setEvicted(0)
    setCursor(0)
    setHasMore(false)
    setPps(null)
    setWaitingReason(null)
    setCurrent(false)
    setLastWriteAgeMs(null)
    setNewestObservedAtMs(null)
    setFreshnessWindowMs(0)
    setState('connecting')
    setError(null)
    setFailures(0)
    setLastPollAtMs(null)
    setServerTotal(0)
    setFeedSource(null)
  }, [])

  const clear = useCallback(() => {
    // A view/buffer operation only; the journal is never touched. Bump the
    // generation so any page already in flight is discarded instead of merged,
    // and re-anchor the tail: the next successful page sets the watermark to
    // the journal's end at that moment, so every row written before this click
    // — including rows the last poll had not seen yet — can never be re-read.
    generationRef.current += 1
    needsWatermarkRef.current = true
    packetsRef.current = []
    seenRef.current = new Set()
    cursorRef.current = endRef.current
    setPackets([])
    setEvicted(0)
    setCursor(endRef.current)
    setHasMore(false)
  }, [])

  const reconnect = useCallback(() => {
    reset()
    setNonce((value) => value + 1)
  }, [reset])

  useEffect(() => {
    if (!enabled) return

    const controller = new AbortController()
    let stopped = false
    let consecutive = 0

    /** Merge one genuine live page into the bounded buffer. Only ever called
     *  for pages this view is allowed to display (post-watermark). */
    const install = (page: CaptureEventsResponse) => {
      // Provenance is the backend's own verdict on the page that delivered
      // these packets: `current: true` means the journal was being written as
      // it was read, so this is live traffic. Anything else (a stopped
      // journal, or a server that does not answer the question at all) is
      // recorded history and is labelled as such per packet.
      const live = page.current === true
      const fresh: FeedPacket[] = page.events
        .filter((event) => !seenRef.current.has(event.id))
        .map((event) => ({ ...event, live }))
      for (const event of fresh) seenRef.current.add(event.id)

      if (fresh.length > 0) {
        // Packets arrive in capture order; the page prepends so row zero is
        // the newest and the newest cap is the one kept.
        const merged = [...fresh, ...packetsRef.current].slice(0, bufferLimit)
        const overflow = fresh.length + packetsRef.current.length - merged.length
        packetsRef.current = merged
        if (overflow > 0) setEvicted((count) => count + overflow)
        setPackets(merged)
        setPps(Math.round((fresh.length / intervalMs) * 1000))
      } else {
        // No new events this interval. When the journal still holds packets
        // the honest rate is zero, not the stale rate from the last burst.
        setPps(page.present && page.total > 0 ? 0 : null)
      }

      setCursor(page.cursor)
      setHasMore(page.has_more)
      cursorRef.current = page.cursor
    }

    const tick = async () => {
      const generation = generationRef.current
      const startMs = Date.now()
      try {
        const load =
          fetchPageRef.current ??
          ((cursor: number, limit: number, signal: AbortSignal) =>
            getCaptureEvents({ cursor, limit }, signal))
        // cursorRef mirrors `cursor` state so an in-flight poll always reads
        // the newest offset even if a reconnect races it.
        const page = await load(cursorRef.current, pageLimit, controller.signal)
        if (stopped) return
        // Schedule the successor as soon as the page lands, so a page that is
        // discarded as stale still leaves the poll loop alive.
        if (!pausedRef.current) timerRef.current = setTimeout(tick, intervalMs)
        if (generation !== generationRef.current) return

        consecutive = 0
        setFailures(0)
        setError(null)
        setLastPollAtMs(startMs)
        setServerTotal(page.total)
        setWaitingReason(page.present ? null : page.reason)
        setFeedSource(page.present ? page.source : null)
        setCurrent(page.current === true)
        setLastWriteAgeMs(page.last_write_age_ms ?? null)
        setNewestObservedAtMs(page.newest_observed_at_ms ?? null)
        setFreshnessWindowMs(page.freshness_window_ms ?? 0)

        const journalEnd = page.size ?? page.cursor

        if (!page.present) {
          // The monitor has not written any packet yet: waiting for traffic.
          // Nothing can be below the watermark, so it holds at 0 and whatever
          // is written from here on is genuinely new.
          needsWatermarkRef.current = false
          endRef.current = 0
          setState('waiting')
          setCursor(0)
          setHasMore(false)
          cursorRef.current = 0
          setPps(null)
        } else if (needsWatermarkRef.current) {
          // Establish the tail watermark (first page of this view, or the first
          // page after a Clear). Everything at or below the journal's end right
          // now was written before we looked and is recorded history, never
          // current traffic: it is dropped and the tail resumes from the end,
          // so only rows appended after this point can ever be displayed.
          needsWatermarkRef.current = false
          endRef.current = journalEnd
          seenRef.current = new Set()
          packetsRef.current = []
          setPackets([])
          setEvicted(0)
          setCursor(journalEnd)
          setHasMore(false)
          cursorRef.current = journalEnd
          setPps(journalEnd > 0 ? 0 : null)
          setState(page.current === true ? 'live' : 'no_traffic')
        } else if (journalEnd < endRef.current) {
          // The journal was truncated/rotated and rewritten below our
          // watermark: its current head is a new history, not our traffic.
          // Drop the buffer and re-anchor the tail at the new end.
          endRef.current = journalEnd
          seenRef.current = new Set()
          packetsRef.current = []
          setPackets([])
          setEvicted(0)
          setCursor(journalEnd)
          setHasMore(false)
          cursorRef.current = journalEnd
          setPps(journalEnd > 0 ? 0 : null)
          setState(page.current === true ? 'live' : 'no_traffic')
        } else {
          endRef.current = Math.max(endRef.current, journalEnd)
          install(page)
          setState(page.current === true ? 'live' : 'no_traffic')
        }
      } catch (cause) {
        if (stopped || controller.signal.aborted) return
        if (!pausedRef.current) timerRef.current = setTimeout(tick, intervalMs)
        consecutive += 1
        setFailures(consecutive)
        if (cause instanceof ApiRequestError) {
          setError(cause)
          setState(
            cause.code === 'capture_feed_unavailable'
              ? 'unavailable'
              : consecutive >= 2
                ? 'degraded'
                : 'offline',
          )
        } else {
          setState(consecutive >= 2 ? 'degraded' : 'offline')
        }
      }
    }

    void tick()

    return () => {
      stopped = true
      if (timerRef.current) clearTimeout(timerRef.current)
      controller.abort()
    }
  }, [bufferLimit, enabled, intervalMs, nonce, pageLimit])

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
    setNonce((value) => value + 1)
  }, [])

  const effectiveState: CaptureFeedState =
    paused &&
    (state === 'live' || state === 'waiting' || state === 'no_traffic' || state === 'paused')
      ? 'paused'
      : state

  return {
    packets,
    evicted,
    state: effectiveState,
    error,
    paused,
    failures,
    lastPollAtMs,
    serverTotal,
    feedSource,
    cursor,
    hasMore,
    pps,
    waitingReason,
    current,
    lastWriteAgeMs,
    newestObservedAtMs,
    freshnessWindowMs,
    pause,
    resume,
    clear,
    reconnect,
  }
}