import { useCallback, useMemo, useState } from 'react'
import { useCaptureFeed } from '@/hooks/useCaptureFeed'
import { formatSpi, toCaptureRows, type CaptureRow } from '@/lib/packetRows'
import { formatBytes, formatNumber } from '@/lib/format'
import { PacketInvestigation } from '@/components/packet/PacketInvestigation'

/**
 * LIVE SCREENING — the analyst's primary surface.
 *
 * The order of this page is the whole design: the packet stream comes first and
 * occupies the largest area, because a packet is what an analyst selects.
 *
 * Selecting a packet does not expand this page. It opens a centered Packet
 * Investigation window over the stream, so the stream stays visible and keeps
 * its full height for as long as the investigation lasts. Nothing here renders
 * a details card or a panel below the table — that inline flow was the previous
 * design and it made every selected packet permanently lengthen the page.
 *
 * Data rules that shape every binding below:
 *   - Packet rows come from `GET /api/v1/capture/events` and are never
 *     synthesised; the scope buttons filter that same list.
 *   - Risk is the backend's per-SPI assessment projection, verbatim.
 *   - Configuration is `bundle.expected` only, badged CONFIGURED.
 *   - Findings are the backend's own list for that assessment, with the score
 *     contribution the scoring engine recorded.
 *   - The analytics plane is read-only: there is no capture-stop endpoint, so
 *     the control that would stop a capture is present but disabled rather than
 *     pretending to work.
 */

type Scope = 'all' | 'ipsec'

/**
 * IPsec classifications, as the feed classifies them: bare ESP, AH, IKE, and
 * NAT-T's ESP-in-UDP encapsulation. `OTHER` and `UNKNOWN` are excluded because
 * neither asserts that the packet is IPsec, and the filter must never widen
 * itself on a guess.
 */
const IPSEC_CLASSIFICATIONS = new Set(['ESP', 'AH', 'IKE', 'ESP_IN_UDP'])

export function LiveScreening() {
  const feed = useCaptureFeed({})
  const [scope, setScope] = useState<Scope>('all')
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [investigationMinimized, setInvestigationMinimized] = useState(false)

  const rows = useMemo(() => {
    const all = toCaptureRows(feed.packets)
    return scope === 'ipsec' ? all.filter((row) => IPSEC_CLASSIFICATIONS.has(row.classification)) : all
  }, [feed.packets, scope])

  // The selected row is snapshotted as well as keyed. The feed is a bounded ring
  // buffer, so the packet an analyst is reading can be evicted by newer traffic;
  // resolving purely from the live buffer would silently change the context
  // under them. The snapshot is the fallback and the panel says when it is held.
  const liveRow = useMemo(
    () => (selectedKey ? (rows.find((row) => row.key === selectedKey) ?? null) : null),
    [rows, selectedKey],
  )
  const [snapshot, setSnapshot] = useState<CaptureRow | null>(null)
  const selected = liveRow ?? (selectedKey === null ? null : snapshot)

  const select = useCallback(
    (row: CaptureRow) => {
      setSelectedKey(row.key)
      setSnapshot(row)
      setInvestigationMinimized(false)
    },
    [],
  )

  const close = useCallback(() => {
    setSelectedKey(null)
    setSnapshot(null)
    setInvestigationMinimized(false)
  }, [])


  // Previous / Next walk the currently displayed rows without leaving the page.
  const step = useCallback(
    (delta: number) => {
      if (!selected) return
      const position = rows.findIndex((row) => row.key === selected.key)
      const next = rows[position + delta]
      if (next) select(next)
    },
    [rows, select, selected],
  )

  const position = selected ? rows.findIndex((row) => row.key === selected.key) : -1

  // The assessment whose configuration and findings apply to the selected
  // packet. This is the backend's own per-SPI match, taken from the first entry
  // of the ranked list the feed published for this packet — not a lookup the
  // browser performed.
  const assessmentId =
    selected && selected.packet.risk.present === true
      ? (selected.packet.risk.assessments[0]?.assessment_id ?? null)
      : null

  return (
    <div className="ls-root">
      <LiveHeader feed={feed} />

      <div className="ls-toolbar">
        <div className="ls-seg" role="group" aria-label="Traffic scope">
          <button
            type="button"
            className={`ls-seg-btn${scope === 'all' ? ' ls-seg-on' : ''}`}
            onClick={() => setScope('all')}
            aria-pressed={scope === 'all'}
          >
            All Traffic
          </button>
          <button
            type="button"
            className={`ls-seg-btn${scope === 'ipsec' ? ' ls-seg-on' : ''}`}
            onClick={() => setScope('ipsec')}
            aria-pressed={scope === 'ipsec'}
          >
            IPsec Only
          </button>
        </div>
        <div className="ls-seg" role="group" aria-label="Capture control">
          <button
            type="button"
            className="ls-seg-btn"
            onClick={feed.paused ? feed.resume : feed.pause}
            title={feed.paused ? 'Resume polling the capture feed' : 'Hold the rows already received'}
          >
            {feed.paused ? 'Resume' : 'Pause'}
          </button>
          <button type="button" className="ls-seg-btn" onClick={feed.clear} title="Clear the rows on screen">
            Clear
          </button>
        </div>

        <div className="ls-toolbar-right">
          <span
            className={`ls-live${feed.current && !feed.paused ? ' ls-live-on' : ''}`}
            title={
              feed.paused
                ? 'Polling is held by the analyst'
                : feed.current
                  ? 'The backend reports the journal is being written right now'
                  : feed.waitingReason ?? 'The backend is not reporting current traffic'
            }
          >
            <span className="ls-dot" aria-hidden="true" />
            Live capture {feed.paused ? 'held' : feed.current ? 'active' : 'inactive'}
          </span>
          <span className="ls-toolbar-fact">
            Last packet: <span className="ls-mono">{rows[0]?.time ?? '—'}</span>
          </span>
          <span className="ls-toolbar-fact">
            <span className="ls-mono">{formatNumber(rows.length)}</span> shown
          </span>
          <span className="ls-toolbar-fact">
            <span className="ls-mono">{formatNumber(feed.packets.length)}</span> buffered
          </span>
          <span
            className="ls-toolbar-fact"
            title="Server-side packet count for the whole journal, not the browser buffer"
          >
            <span className="ls-mono">{formatNumber(feed.serverTotal)}</span> in journal
          </span>
          {/* Surfaced only when it is true. A ring buffer that has dropped rows
              must say so, otherwise a gap in the stream reads as an absence of
              traffic rather than an absence of memory. */}
          {feed.evicted > 0 ? (
            <span
              className="ls-toolbar-fact"
              title="Older packets dropped from the browser's ring buffer. They are still in the journal."
            >
              <span className="ls-mono">{formatNumber(feed.evicted)}</span> evicted
            </span>
          ) : null}
        </div>
      </div>

      {feed.error ? (
        <div className="ls-banner ls-banner-bad" role="alert">
          The capture feed could not be read: {feed.error.message}
        </div>
      ) : null}

      <PacketStream
        rows={rows}
        selectedKey={selectedKey}
        onSelect={select}
        state={feed.state}
        waitingReason={feed.waitingReason}
        failed={feed.state === 'offline' || feed.state === 'degraded' || feed.state === 'unavailable' || feed.error !== null}
      />

      {selected ? (
        <PacketInvestigation
          row={selected}
          assessmentId={assessmentId}
          position={position}
          total={rows.length}
          onPrevious={() => step(-1)}
          onNext={() => step(1)}
          onClose={close}
          onMinimize={() => setInvestigationMinimized((v) => !v)}
          minimized={investigationMinimized}
        />
      ) : (
        <p className="ls-hint">
          Select a packet in the stream to open its investigation: the packet's own record, the
          configuration the assessment was run against, what the capture actually showed, and the
          findings that configuration produced.
        </p>
      )}
    </div>
  )
}

/* ------------------------------------------------------------- header */

function LiveHeader({ feed }: { feed: ReturnType<typeof useCaptureFeed> }) {
  const capturing = feed.current && !feed.paused && feed.state !== 'offline' && feed.state !== 'unavailable'

  // The capture feed envelope publishes no session id and no capture start
  // time. The only real identity it carries is the journal it is tailing, and
  // the only honest window it has is the span of packets the server has
  // published. Both are labelled with where they come from rather than being
  // dressed up as a session record.
  const span = feedSpan(feed)

  return (
    <header className="ls-head">
      <div className="ls-head-main">
        <div className="ls-head-titles">
          <h1 className="ls-title">Live Screening</h1>
          <p className="ls-subtitle">
            Real-time packet capture and analysis for the active IPsec session
          </p>
        </div>
        <span
          className={`ls-capture${capturing ? ' ls-capture-on' : ''}`}
          title={captureTitle(feed, capturing)}
        >
          <span className="ls-dot" aria-hidden="true" />
          {capturing ? 'Capturing' : captureWord(feed)}
        </span>
      </div>

      <div className="ls-head-right">
        <Fact label="Session" value={feed.feedSource ?? 'Not available'} title="The packet journal this feed is tailing" />
        <Fact
          label="Started at"
          value={span.startedAt ?? 'Not available'}
          title={
            span.startedAt
              ? 'Oldest packet the backend has published in this feed. The capture feed publishes no session start time.'
              : 'No packet has been published by the backend yet.'
          }
        />
        <Fact
          label="Duration"
          value={span.duration ?? 'Not available'}
          title="Span between the oldest and newest packets the backend has published in this feed."
        />
        {/* Read-only by design: the analytics plane exposes no capture control,
            so this states that rather than offering an action that would do
            nothing. */}
        <button
          type="button"
          className="ls-btn ls-btn-stop"
          disabled
          title="Not available: the analytics API is read-only and exposes no capture-stop endpoint. Stopping a capture is done in the testbed."
        >
          Stop Capture
        </button>
      </div>
    </header>
  )
}

function captureWord(feed: ReturnType<typeof useCaptureFeed>): string {
  if (feed.paused) return 'Paused'
  switch (feed.state) {
    case 'connecting':
      return 'Connecting'
    case 'waiting':
      return 'Waiting'
    case 'no_traffic':
      return 'No current traffic'
    case 'unavailable':
      return 'Feed unavailable'
    case 'offline':
      return 'Offline'
    case 'degraded':
      return 'Degraded'
    default:
      return 'Not capturing'
  }
}

function captureTitle(feed: ReturnType<typeof useCaptureFeed>, capturing: boolean): string {
  if (capturing) return 'The backend reports the journal is being written right now'
  return feed.waitingReason ?? feed.error?.message ?? 'The backend is not reporting current traffic'
}

/** Oldest/newest published packet times, or null when the feed is empty. */
function feedSpan(feed: ReturnType<typeof useCaptureFeed>): {
  startedAt: string | null
  duration: string | null
} {
  if (feed.packets.length === 0) return { startedAt: null, duration: null }
  let oldest = Infinity
  let newest = -Infinity
  for (const packet of feed.packets) {
    const ns = packet.timestamp_ns
    if (typeof ns !== 'number') continue
    if (ns < oldest) oldest = ns
    if (ns > newest) newest = ns
  }
  if (newest === -Infinity) return { startedAt: null, duration: null }
  return {
    startedAt: new Date(oldest / 1e6).toLocaleTimeString(),
    duration: formatDuration(newest - oldest),
  }
}

function formatDuration(ns: number): string {
  const seconds = ns / 1e9
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`
  if (seconds < 60) return `${seconds.toFixed(1)} s`
  const minutes = Math.floor(seconds / 60)
  return `${minutes}m ${Math.round(seconds - minutes * 60)}s`
}

function Fact({ label, value, title }: { label: string; value: string; title?: string }) {
  return (
    <div className="ls-fact" title={title}>
      <span className="ls-fact-label">{label}</span>
      <span className="ls-fact-value ls-mono">{value}</span>
    </div>
  )
}

/**
 * Why the stream is in the state it is in, in the hook's own terms. `paused` is
 * checked first because it is an analyst action, not a backend verdict, and the
 * two would otherwise be conflated.
 */
function streamNote(state: string, waitingReason: string | null): string {
  if (state === 'paused') return 'Held by the analyst — rows on screen are not growing'
  if (state === 'live') return 'Appending as the backend publishes packets'
  return waitingReason ?? 'Not receiving current packets'
}

/* ------------------------------------------------------- packet stream */

function PacketStream({
  rows,
  selectedKey,
  onSelect,
  state,
  waitingReason,
  failed,
}: {
  rows: CaptureRow[]
  selectedKey: string | null
  onSelect: (row: CaptureRow) => void
  state: string
  waitingReason: string | null
  /** The feed could not be read at all, as opposed to being read and empty. */
  failed: boolean
}) {
  return (
    <section className="ls-stream" aria-label="Live packet stream">
      <div className="ls-stream-head">
        <h2 className="ls-stream-title">Live Packet Stream</h2>
        <span className="ls-state ls-state-observed">observed</span>
        <span className="ls-stream-note">{streamNote(state, waitingReason)}</span>
      </div>

      <div className="ls-table-wrap">
        <table className="ls-table ls-stream-table">
          <thead>
            <tr>
              <th className="ls-th-num">No.</th>
              <th>Time</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th className="ls-th-num">Length</th>
              <th>Info</th>
              <th>SPI</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.key}
                className={row.key === selectedKey ? 'ls-row ls-row-sel' : 'ls-row'}
                onClick={() => onSelect(row)}
                tabIndex={0}
                aria-selected={row.key === selectedKey}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    onSelect(row)
                  }
                }}
              >
                <td className="ls-th-num ls-mono">{row.sequence}</td>
                <td className="ls-mono">{row.time}</td>
                <td className="ls-mono">{row.source}</td>
                <td className="ls-mono">{row.destination}</td>
                <td>
                  <span
                    className={
                      row.protocol ? 'ls-badge ls-badge-proto' : 'ls-badge ls-badge-none'
                    }
                  >
                    {row.protocol || 'No label'}
                  </span>
                </td>
                <td className="ls-th-num ls-mono">{formatBytes(row.length)}</td>
                <td className="ls-dim">{row.info}</td>
                <td className="ls-mono">{formatSpi(row.spi)}</td>
                <td>
                  <span className="ls-risk" data-risk={row.riskLabel}>
                    {row.riskLabel}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 ? (
          <p className="ls-empty">
            {/* "Nothing arrived" and "we could not ask" are different facts, and
                conflating them would let an unreachable backend read as a quiet
                link — the worst possible reading on this page. */}
            {failed
              ? 'The capture feed could not be read, so no packets are shown. This is not evidence that the link was quiet.'
              : (waitingReason ?? 'No packets received from the capture feed.')}
          </p>
        ) : null}
      </div>
    </section>
  )
}
