import { Fragment, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { Activity, ArrowDown, FilterX, Pause, Play, Square, TriangleAlert, X } from 'lucide-react'
import { formatArrivalTime, formatCompact } from '../../lib/format'
import { isIpsecProtocol } from '../../lib/analytics'
import { useSearchFilter } from '../../state/searchFilter.tsx'
import { usePacketSelection } from '../../state/packetSelection.tsx'
import { usePacketFilter } from '../../hooks/usePacketFilter'
import { protocolStyle, riskStyle } from './workspaceTheme.ts'
import { PacketDetailPanel } from './PacketDetailPanel.tsx'
import { MAX_DISPLAY_PACKETS } from '../../state/capture.tsx'
import { SERVICE_RING_BUFFER } from '../../services/mock/mockPacketService'
import type { Packet } from '../../types/packet'
import type { CaptureState } from '../../types/traffic'

type ProtocolFilter = 'all' | 'IKEv2' | 'ESP' | 'AH' | 'ipsec' | 'other'

const PROTO_FILTERS: { value: ProtocolFilter; label: string }[] = [
  { value: 'all', label: 'All packets' },
  { value: 'ipsec', label: 'IPsec only' },
  { value: 'IKEv2', label: 'IKEv2' },
  { value: 'ESP', label: 'ESP' },
  { value: 'AH', label: 'AH' },
  { value: 'other', label: 'Other' },
]

interface NoPacketsCopy {
  icon: React.ReactNode
  title: string
  description: string
  action?: React.ReactNode
}

function noPacketsState(
  status: CaptureState['status'] | undefined,
  onStart?: () => void,
): NoPacketsCopy | null {
  switch (status) {
    case 'stopped':
    case 'idle':
      return {
        icon: <Square className="size-4" aria-hidden />,
        title: 'No packets were captured',
        description: 'The interface produced no frames before the capture ended. Start a new capture to resume monitoring.',
        action: onStart ? (
          <button type="button" className="ws-btn ws-btn-primary" onClick={onStart}>
            <Play className="size-3.5" aria-hidden />
            Start Capture
          </button>
        ) : undefined,
      }
    case 'paused':
      return {
        icon: <Pause className="size-4" aria-hidden />,
        title: 'Capture paused',
        description: 'Resume the capture to start receiving packets on the interface.',
      }
    case 'running':
    case 'starting':
    case 'stopping':
      return {
        icon: <Activity className="size-4" aria-hidden />,
        title: 'Waiting for the first packets…',
        description: 'Packets will stream in as soon as the interface observes them.',
      }
    default:
      return null
  }
}

function RiskCell({ packet }: { packet: Packet }) {
  if (!packet.risk) {
    return <span className="text-[10px] text-ws-faint">—</span>
  }
  const style = riskStyle(packet.risk)
  return (
    <span
      className="ws-risk"
      style={{ color: style.color, background: style.background, borderColor: style.color }}
    >
      {style.label}
    </span>
  )
}

function ProtocolCell({ protocol }: { protocol: Packet['protocol'] }) {
  const style = protocolStyle(protocol)
  return (
    <span className="ws-proto" style={{ color: style.color, background: style.background, borderColor: style.color }}>
      {protocol}
    </span>
  )
}

interface PacketTableProps {
  packets: Packet[]
  interfaceName?: string
  captureStatus?: CaptureState['status']
  onStartCapture?: () => void
  loading?: boolean
  /** Advancing every time the buffer grows; drives the "new packets" pill. */
  arrivalTick?: number
}

/**
 * The packet list.
 *
 * This is the centre of the product: a dense, monospaced, 23px-row table that
 * occupies all remaining vertical space and scrolls on its own. Selecting a row
 * expands the packet detail **immediately underneath that row** — the previous
 * selection collapses, nothing navigates, and no separate panel is required.
 */
export function PacketTable({
  packets,
  interfaceName = 'eth0',
  captureStatus,
  onStartCapture,
  loading = false,
  arrivalTick = 0,
}: PacketTableProps) {
  const { query, hasQuery, clear, isOpen: filterOpen, open: openFilter } = useSearchFilter()
  const { packet: selectedPacket, selectPacket } = usePacketSelection()
  const { matches, validate } = usePacketFilter()
  const [proto, setProto] = useState<ProtocolFilter>('all')
  const [pendingCount, setPendingCount] = useState(0)
  const [following, setFollowing] = useState(true)

  const scrollRef = useRef<HTMLDivElement>(null)
  const lastTickRef = useRef(arrivalTick)
  const selectedRef = useRef<HTMLTableRowElement>(null)

  const expression = query.trim()

  const filtered = useMemo(() => {
    let list = expression ? packets.filter((packet) => matches(packet, expression)) : packets
    if (proto === 'other') list = list.filter((packet) => !isIpsecProtocol(packet.protocol))
    else if (proto === 'ipsec') list = list.filter((packet) => isIpsecProtocol(packet.protocol))
    else if (proto !== 'all') list = list.filter((packet) => packet.protocol === proto)
    return list
  }, [packets, proto, expression, matches])

  const filterError = useMemo(() => {
    if (!expression) return null
    const result = validate(expression)
    return result.ok ? null : (result.error ?? 'The filter expression could not be parsed.')
  }, [expression, validate])

  const noPackets = noPacketsState(captureStatus, onStartCapture)
  const selectedVisible = selectedPacket !== null && filtered.includes(selectedPacket)
  const filterActive = hasQuery || proto !== 'all'

  /* While the analyst is reading an expanded packet we must not yank the view
     around: buffer the count of arrivals and offer an explicit jump instead. */
  useEffect(() => {
    if (arrivalTick === lastTickRef.current) return
    lastTickRef.current = arrivalTick
    if (following) return
    setPendingCount((count) => count + 1)
  }, [arrivalTick, following])

  const jumpToLive = useCallback(() => {
    setFollowing(true)
    setPendingCount(0)
    scrollRef.current?.scrollTo({ top: 0, behavior: 'smooth' })
  }, [])

  const selectAndFollow = useCallback(
    (packet: Packet) => {
      const collapse = selectedPacket?.id === packet.id
      selectPacket(collapse ? null : packet)
      if (!collapse) setFollowing(false)
    },
    [selectedPacket, selectPacket],
  )

  // Keep the expanded row in view when the selection changes.
  useLayoutEffect(() => {
    selectedRef.current?.scrollIntoView({ block: 'nearest' })
  }, [selectedPacket?.id])

  const resetFilters = () => {
    clear()
    setProto('all')
  }

  const emptyBody = filtered.length === 0 && !selectedPacket

  return (
    <div className="flex min-h-0 flex-1 flex-col bg-ws-panel">
      {/* Table header strip: protocol scope, match count, clear */}
      <div className="ws-bar ws-bar-tight">
        <select
          value={proto}
          onChange={(event) => setProto(event.target.value as ProtocolFilter)}
          aria-label="Protocol scope"
          className="ws-select w-[132px] shrink-0"
        >
          {PROTO_FILTERS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>

        <span className="text-[11px] text-ws-dim">
          {filterActive ? (
            <>
              <span className="mono-tab font-semibold text-ws-accent">{formatCompact(filtered.length)}</span>{' '}
              matched
              {hasQuery ? <span className="mono-tab text-ws-faint"> · {expression}</span> : null}
            </>
          ) : (
            <>
              <span className="mono-tab font-semibold text-ws-text">{formatCompact(filtered.length)}</span> of{' '}
              <span className="mono-tab">{formatCompact(packets.length)}</span> packets
            </>
          )}
        </span>

        {filterActive ? (
          <button type="button" className="ws-btn ws-btn-ghost" onClick={resetFilters}>
            <X className="size-3" aria-hidden />
            Clear filters
          </button>
        ) : null}

        <div className="ml-auto flex items-center gap-1.5">
          {!filterOpen ? (
            <button type="button" className="ws-btn ws-btn-ghost" onClick={openFilter} title="Open the display filter">
              <FilterX className="size-3.5" aria-hidden />
              Display filter
            </button>
          ) : null}
          <span className="hidden text-[10.5px] text-ws-faint lg:inline">
            Click a row to expand its details inline
          </span>
        </div>
      </div>

      {filterError ? (
        <div className="ws-note" data-tone="error" role="alert">
          <TriangleAlert className="mt-px size-3.5 shrink-0" aria-hidden />
          <span className="min-w-0">{filterError}</span>
        </div>
      ) : null}

      {captureStatus === 'stopped' && packets.length > 0 ? (
        <div className="ws-note" data-tone="info">
          <Square className="mt-px size-3 shrink-0" aria-hidden />
          <span className="min-w-0">
            Capture stopped — still showing the {formatCompact(packets.length)} packets it collected.
          </span>
          {onStartCapture ? (
            <button type="button" className="ws-btn ws-btn-ghost ml-auto" onClick={onStartCapture}>
              <Play className="size-3" aria-hidden />
              Start new capture
            </button>
          ) : null}
        </div>
      ) : null}

      {/* Scrollable packet stream */}
      <div ref={scrollRef} className="ws-scroll relative min-h-0 flex-1">
        <table className="ws-table min-w-[900px]">
          <thead>
            <tr>
              <th className="w-[62px] text-right">No.</th>
              <th className="w-[104px] text-right">Time</th>
              <th className="w-[132px]">Source</th>
              <th className="w-[132px]">Destination</th>
              <th className="w-[72px]">Protocol</th>
              <th className="w-[62px] text-right">Length</th>
              <th>Info</th>
              <th className="w-[74px] text-right">Risk</th>
            </tr>
          </thead>
          <tbody>
            {/* A selection hidden by the current filters stays open, pinned at the top. */}
            {selectedPacket && !selectedVisible ? (
              <tr>
                <td colSpan={8} className="!p-0">
                  <div className="ws-note" data-tone="warn">
                    <TriangleAlert className="mt-px size-3.5 shrink-0" aria-hidden />
                    <span className="min-w-0">
                      Packet {selectedPacket.number} is selected but hidden by the active filter — shown here.
                    </span>
                  </div>
                  <PacketDetailPanel
                    packet={selectedPacket}
                    interfaceName={interfaceName}
                    onCollapse={() => selectPacket(null)}
                  />
                </td>
              </tr>
            ) : null}

            {emptyBody ? (
              <TableBodyState
                loading={loading}
                hasPackets={packets.length > 0}
                noPackets={noPackets}
                filterError={filterError}
                onReset={resetFilters}
                onStart={onStartCapture}
                onOpenFilter={openFilter}
              />
            ) : (
              filtered.map((packet) => {
                const isSelected = packet.id === selectedPacket?.id
                return (
                  <Fragment key={packet.id}>
                    <tr
                      ref={isSelected ? selectedRef : undefined}
                      tabIndex={0}
                      onClick={() => selectAndFollow(packet)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          selectAndFollow(packet)
                        }
                      }}
                      aria-selected={isSelected}
                      data-selected={isSelected ? 'true' : undefined}
                      className="ws-row"
                    >
                      <td className="mono-tab text-right text-[10.5px] text-ws-faint">{packet.number}</td>
                      <td className="mono-tab text-right text-[10.5px] text-ws-dim">
                        {formatArrivalTime(packet.timestamp)}
                      </td>
                      <td className="mono-tab truncate text-[11px] text-ws-dim">{packet.source}</td>
                      <td className="mono-tab truncate text-[11px] text-ws-dim">{packet.destination}</td>
                      <td>
                        <ProtocolCell protocol={packet.protocol} />
                      </td>
                      <td className="mono-tab text-right text-[11px] text-ws-dim">{packet.length}</td>
                      <td className="truncate text-[11px] text-ws-dim" title={packet.info}>
                        {packet.info}
                      </td>
                      <td className="text-right">
                        <RiskCell packet={packet} />
                      </td>
                    </tr>

                    {isSelected ? (
                      <tr className="ws-detail-row">
                        <td colSpan={8}>
                          <PacketDetailPanel
                            packet={packet}
                            interfaceName={interfaceName}
                            onCollapse={() => selectPacket(null)}
                          />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                )
              })
            )}
          </tbody>
        </table>

        {/* Buffered-arrivals affordance: never move the analyst away from the
            packet they are reading. */}
        {pendingCount > 0 ? (
          <div className="pointer-events-none sticky bottom-3 z-20 flex justify-center">
            <button
              type="button"
              onClick={jumpToLive}
              className="ws-btn ws-btn-primary ws-float-pill pointer-events-auto"
              title="Scroll to the newest packets and resume following the stream"
            >
              <ArrowDown className="size-3.5" aria-hidden />
              {formatCompact(pendingCount)} new packet{pendingCount === 1 ? '' : 's'} — jump to live
            </button>
          </div>
        ) : null}
      </div>

      {/* Status bar */}
      <div className="ws-bar ws-bar-tight justify-between">
        <span className="text-[10.5px] text-ws-faint">
          No. · Time · Source · Destination · Protocol · Length · Info · Risk
        </span>
        <span className="mono-tab text-[10.5px] text-ws-faint">
          {formatCompact(packets.length)} of {formatCompact(MAX_DISPLAY_PACKETS)} shown ·{' '}
          {formatCompact(SERVICE_RING_BUFFER)} packet ring buffer
        </span>
      </div>
    </div>
  )
}

function TableBodyState({
  loading,
  hasPackets,
  noPackets,
  filterError,
  onReset,
  onStart,
  onOpenFilter,
}: {
  loading: boolean
  hasPackets: boolean
  noPackets: NoPacketsCopy | null
  filterError: string | null
  onReset(): void
  onStart?: () => void
  onOpenFilter(): void
}) {
  const cell = 'px-4 py-10 text-center'

  if (loading) {
    return (
      <tr aria-busy="true">
        <td colSpan={8} className={cell}>
          <div className="mx-auto flex max-w-md flex-col gap-2">
            {Array.from({ length: 9 }).map((_, index) => (
              <div key={index} className="h-3 animate-pulse rounded bg-ws-sunken" />
            ))}
          </div>
        </td>
      </tr>
    )
  }

  if (!hasPackets) {
    return (
      <tr>
        <td colSpan={8} className={cell}>
          <div className="mx-auto max-w-md">
            <div className="text-[13px] font-semibold text-ws-text">
              {noPackets?.title ?? 'No packets yet'}
            </div>
            <p className="mt-1 text-[11.5px] text-ws-dim">
              {noPackets?.description ?? 'Start a capture to begin monitoring traffic on the interface.'}
            </p>
            <div className="mt-3 flex justify-center gap-2">
              {noPackets?.action}
              {!noPackets?.action && onStart ? (
                <button type="button" className="ws-btn ws-btn-primary" onClick={onStart}>
                  <Play className="size-3.5" aria-hidden />
                  Start Capture
                </button>
              ) : null}
            </div>
          </div>
        </td>
      </tr>
    )
  }

  if (filterError) {
    return (
      <tr>
        <td colSpan={8} className={cell}>
          <div className="mx-auto max-w-md">
            <div className="text-[13px] font-semibold text-ws-critical">That filter can’t be applied</div>
            <p className="mt-1 text-[11.5px] text-ws-dim">{filterError}</p>
            <button type="button" className="ws-btn ws-btn-primary mt-3" onClick={onReset}>
              <X className="size-3.5" aria-hidden />
              Clear filters
            </button>
          </div>
        </td>
      </tr>
    )
  }

  return (
    <tr>
      <td colSpan={8} className={cell}>
        <div className="mx-auto max-w-md">
          <div className="text-[13px] font-semibold text-ws-text">No packets match this filter</div>
          <p className="mt-1 text-[11.5px] text-ws-dim">
            Remove one or more conditions, or clear the filter to display every captured packet.
          </p>
          <div className="mt-3 flex justify-center gap-2">
            <button type="button" className="ws-btn ws-btn-primary" onClick={onReset}>
              <X className="size-3.5" aria-hidden />
              Clear filters
            </button>
            <button type="button" className="ws-btn" onClick={onOpenFilter}>
              Edit filter
            </button>
          </div>
        </div>
      </td>
    </tr>
  )
}
