import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { services } from '../services'
import { useSettings } from '../state/settings'
import { env } from '../config/env'
import type { LiveEvent, LiveMonitorSnapshot } from '../types/events'

/**
 * Live event subscription.
 *
 * The hook owns exactly one subscription to the `LiveEventService` and keeps a
 * bounded buffer, so mounting several live widgets does not multiply the
 * transport traffic. Because the interface is transport-shaped, swapping the
 * mock timer for a WebSocket changes nothing above this line.
 */
const MAX_BUFFER = 200

let sharedEvents: LiveEvent[] = []
const subscribers = new Set<(events: LiveEvent[]) => void>()
let unsubscribe: (() => void) | null = null

function ensureSubscribed(): void {
  if (unsubscribe) return
  unsubscribe = services.liveEvents.subscribe((event) => {
    sharedEvents = [...sharedEvents, event].slice(-MAX_BUFFER)
    for (const listener of subscribers) listener(sharedEvents)
  })
}

function stopIfIdle(): void {
  if (subscribers.size > 0) return
  unsubscribe?.()
  unsubscribe = null
}

export function useLiveEvents(): LiveEvent[] {
  const [, force] = useState(0)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    ensureSubscribed()
    const listener = (events: LiveEvent[]) => {
      if (mounted.current) force(events.length)
    }
    subscribers.add(listener)
    return () => {
      subscribers.delete(listener)
      mounted.current = false
      stopIfIdle()
    }
  }, [])

  return sharedEvents
}

export function useLiveSnapshot(): UseLiveSnapshotResult {
  const { settings } = useSettings()
  const query = useQuery<LiveMonitorSnapshot>({
    queryKey: ['live-snapshot'],
    queryFn: () => services.liveEvents.getSnapshot(),
    refetchInterval: Math.max(2_000, settings.refreshIntervalMs),
  })

  // Keep the emission cadence aligned with the operator's refresh preference.
  useEffect(() => {
    const cadence = Math.min(env.liveEventIntervalMs, Math.max(500, settings.refreshIntervalMs / 10))
    services.liveEvents.setInterval(cadence)
  }, [settings.refreshIntervalMs])

  return query
}

type UseLiveSnapshotResult = ReturnType<typeof useQuery<LiveMonitorSnapshot, Error>>
