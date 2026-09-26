import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { computeDistribution, computeSummary } from '../lib/analytics'
import { services } from '../services'
import type { CaptureService, CaptureStartOptions } from '../services/api/captureService'
import type { PacketService } from '../services/api/packetService'
import type { ProtocolDistribution, TrafficStatistics } from '../types/analytics'
import type { Packet } from '../types/packet'
import type { CaptureState, StreamOrder } from '../types/traffic'

/** Warm-up size used the first time the app boots. */
export const WARMUP_PACKETS_BOOT = 560
/** Warm-up size for a user-triggered restart (keeps the restart responsive). */
const WARMUP_PACKETS_RESTART = 60
/** Packets kept in the view layer; the service ring buffer is larger. */
export const MAX_DISPLAY_PACKETS = 4096
const FLUSH_MS = 300
const TICK_MS = 1000

/** Capture interfaces offered by the toolbar selector. */
export const CAPTURE_INTERFACES = [
  'eth0',
  'eth1',
  'ens192',
  'wg0',
  'tun0',
  'any',
] as const

export interface CaptureStoreValue {
  /** Live lifecycle state published by the capture service. */
  capture: CaptureState
  /** Buffered packets in the current stream order. */
  packets: Packet[]
  order: StreamOrder
  setOrder(order: StreamOrder): void
  /** Ticking clock used for the capture duration readout. */
  now: number
  summary: TrafficStatistics
  distribution: ProtocolDistribution[]
  loading: boolean
  unavailable: boolean
  /** Interface the next capture will bind to. */
  interfaceName: string
  setInterfaceName(name: string): void
  start(options?: CaptureStartOptions): void
  stop(): void
  pause(): void
  resume(): void
  clear(): void
}

const CaptureContext = createContext<CaptureStoreValue | null>(null)

interface CaptureProviderProps {
  children: ReactNode
  captureService?: CaptureService
  packetService?: PacketService
  /** Set false to keep the capture dormant until the user starts it. */
  autoStart?: boolean
}

/**
 * Owns the single application-wide capture session.
 *
 * The capture outlives individual routes on purpose: a professional analyzer
 * keeps sniffing while the analyst moves between the live stream, the findings
 * register and the reporting view, so those surfaces all read the same buffer.
 *
 * Everything is still injected through the transport-agnostic service
 * interfaces (`services.capture` / `services.packetService` by default), so
 * swapping the mocks for a WebSocket-backed implementation touches only
 * `src/services/index.ts`.
 */
export function CaptureProvider({
  children,
  captureService = services.capture,
  packetService = services.packetService,
  autoStart = true,
}: CaptureProviderProps) {
  const [capture, setCapture] = useState<CaptureState>(() => captureService.getState())
  const [packets, setPackets] = useState<Packet[]>([])
  const [order, setOrderState] = useState<StreamOrder>('newest-first')
  const [now, setNow] = useState(() => Date.now())
  const [interfaceName, setInterfaceNameState] = useState<string>(
    () => captureService.getState().interfaceName ?? CAPTURE_INTERFACES[0],
  )
  const pendingRef = useRef<Packet[]>([])
  const orderRef = useRef<StreamOrder>(order)
  const bootedRef = useRef(false)

  useEffect(() => {
    orderRef.current = order
  }, [order])

  useEffect(() => {
    const unsubscribeState = captureService.subscribeState(setCapture)
    const unsubscribeStream = packetService.stream.subscribe((packet) => {
      pendingRef.current.push(packet)
    })
    return () => {
      unsubscribeState()
      unsubscribeStream()
    }
  }, [captureService, packetService])

  // Batched render flush: a burst of arriving packets becomes one commit.
  useEffect(() => {
    const timer = window.setInterval(() => {
      const batch = pendingRef.current.splice(0, pendingRef.current.length)
      if (batch.length === 0) return
      setPackets((prev) => {
        const merged =
          orderRef.current === 'newest-first'
            ? [...batch].reverse().concat(prev)
            : prev.concat(batch)
        return merged.length > MAX_DISPLAY_PACKETS ? merged.slice(0, MAX_DISPLAY_PACKETS) : merged
      })
    }, FLUSH_MS)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), TICK_MS)
    return () => window.clearInterval(timer)
  }, [])

  const start = useCallback(
    (options?: CaptureStartOptions) => {
      void captureService
        .start({
          interfaceName,
          warmUpPackets: WARMUP_PACKETS_RESTART,
          ...options,
        })
        .catch(() => {
          // A stream that is already running is not an error worth surfacing;
          // the lifecycle state published by the service is the source of truth.
        })
    },
    [captureService, interfaceName],
  )

  // Boot the capture once for the whole app session.
  useEffect(() => {
    if (!autoStart || bootedRef.current) return
    bootedRef.current = true
    void captureService
      .start({ interfaceName, warmUpPackets: WARMUP_PACKETS_BOOT })
      .catch(() => {})
  }, [autoStart, captureService, interfaceName])

  const stop = useCallback(() => {
    void captureService.stop().catch(() => {})
  }, [captureService])

  const pause = useCallback(() => {
    void captureService.pause().catch(() => {})
  }, [captureService])

  const resume = useCallback(() => {
    void captureService.resume().catch(() => {})
  }, [captureService])

  const clear = useCallback(() => {
    pendingRef.current = []
    packetService.clear()
    setPackets([])
  }, [packetService])

  const setOrder = useCallback((next: StreamOrder) => {
    orderRef.current = next
    setOrderState(next)
  }, [])

  /** Rebinding the interface restarts the capture on the new interface. */
  const setInterfaceName = useCallback(
    (name: string) => {
      setInterfaceNameState(name)
      const status = captureService.getState().status
      if (status === 'running' || status === 'paused' || status === 'starting') {
        void captureService
          .stop()
          .catch(() => {})
          .then(() => {
            void captureService
              .start({ interfaceName: name, warmUpPackets: WARMUP_PACKETS_RESTART })
              .catch(() => {})
          })
      }
    },
    [captureService],
  )

  const summary: TrafficStatistics = useMemo(() => computeSummary(packets), [packets])
  const distribution: ProtocolDistribution[] = useMemo(() => computeDistribution(packets), [packets])

  const value = useMemo<CaptureStoreValue>(
    () => ({
      capture,
      packets,
      order,
      setOrder,
      now,
      summary,
      distribution,
      loading: capture.status === 'starting',
      unavailable: capture.status === 'error',
      interfaceName,
      setInterfaceName,
      start,
      stop,
      pause,
      resume,
      clear,
    }),
    [
      capture,
      packets,
      order,
      setOrder,
      now,
      summary,
      distribution,
      interfaceName,
      setInterfaceName,
      start,
      stop,
      pause,
      resume,
      clear,
    ],
  )

  return <CaptureContext.Provider value={value}>{children}</CaptureContext.Provider>
}

export function useCaptureStore(): CaptureStoreValue {
  const value = useContext(CaptureContext)
  if (!value) {
    throw new Error('useCaptureStore must be used within a CaptureProvider')
  }
  return value
}
