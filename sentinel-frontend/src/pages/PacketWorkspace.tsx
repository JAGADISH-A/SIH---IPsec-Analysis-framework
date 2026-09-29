import { useCallback, useMemo, useState } from 'react'
import { useCaptureFeed, type CaptureFeed } from '@/hooks/useCaptureFeed'
import { ErrorState, Spinner } from '@/components/states'
import { PacketInvestigation } from '@/components/packet/PacketInvestigation'
import { FindingFilterBar } from '@/components/packet/FindingFilterBar'
import { PacketDirectionBadge, PacketRiskBadge } from '@/components/packet/primitives'
import {
  anchorRowFor,
  DEFAULT_FILTERS,
  useFindingFilters,
  type FindingFilters,
  type FilteredFinding,
} from '@/hooks/useFindingFilters'
import { formatBytes, formatNumber } from '@/lib/format'
import {
  toCaptureRows,
  type CaptureRow,
} from '@/lib/packetRows'

type Scope = 'all' | 'ipsec'

const IPSEC_LABELS = new Set(['ESP', 'AH', 'IKE', 'ESP_IN_UDP'])

const FEED_STATE_LABEL: Record<CaptureFeed['state'], string> = {
  connecting: 'connecting',
  live: 'LIVE',
  paused: 'paused',
  waiting: 'LIVE',
  no_traffic: 'LIVE',
  unavailable: 'feed unavailable',
  offline: 'disconnected',
  degraded: 'reconnecting',
}

const FEED_STATE_COLOR: Record<CaptureFeed['state'], string> = {
  connecting: '#8b94a3',
  live: '#34d399',
  paused: '#d9a441',
  waiting: '#8b94a3',
  no_traffic: '#d9a441',
  unavailable: '#d9a441',
  offline: '#f87171',
  degraded: '#d9a441',
}

/**
 * The live cap. The surface is the *live* IPsec traffic view, so even while it
 * is waiting or the journal is currently quiet it reads "LIVE · 0 pkt/s" — the
 * honest label for a live source with no current traffic — rather than
 * switching to a non-live word.
 */
function FeedCap({ feed }: { feed: CaptureFeed }) {
  const label = FEED_STATE_LABEL[feed.state]
  const color = FEED_STATE_COLOR[feed.state]
  return (
    <span className="pw-cap" title={`Capture feed: ${label}`}>
      <span className="pw-dot" style={{ background: color }} aria-hidden="true" />
      <span className="pw-cap-label">
        {feed.state === 'live' || feed.state === 'waiting' || feed.state === 'no_traffic'
          ? `${label} · ${formatNumber(feed.pps ?? 0)} pkt/s`
          : label}
      </span>
    </span>
  )
}

function SegFilter({ scope, onChange }: { scope: Scope; onChange: (scope: Scope) => void }) {
  return (
    <div className="pw-seg" role="tablist" aria-label="Packet scope">
      <button
        type="button"
        role="tab"
        aria-selected={scope === 'all'}
        className={scope === 'all' ? 'pw-seg-on' : undefined}
        onClick={() => onChange('all')}
      >
        All traffic
      </button>
      <button
        type="button"
        role="tab"
        aria-selected={scope === 'ipsec'}
        className={scope === 'ipsec' ? 'pw-seg-on' : undefined}
        onClick={() => onChange('ipsec')}
      >
        IPsec only
      </button>
    </div>
  )
}

function PacketTable({
  models,
  selectedKey,
  onSelect,
  findingAssessmentIds,
}: {
  models: CaptureRow[]
  selectedKey: string | null
  onSelect: (model: CaptureRow) => void
  findingAssessmentIds: Set<string>
}) {
  return (
    <div className="pw-scroll">
      <table className="pw-table" aria-label="Captured packets">
        <thead>
          <tr>
            <th className="pw-th-num">No.</th>
            <th>Time</th>
            <th>Direction</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th className="pw-th-num">Length</th>
            <th>Info</th>
            <th>SPI</th>
            <th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {models.map((model) => {
            const selected = model.key === selectedKey
            const findingMatch =
              !selected &&
              findingAssessmentIds.size > 0 &&
              model.riskPresent &&
              model.assessmentIds.some((id) => findingAssessmentIds.has(id))
            return (
              <tr
                key={model.key}
                className={`${selected ? 'pw-rowsel' : ''}${findingMatch ? ' pw-row-finding' : ''}`}
                onClick={() => onSelect(model)}
                aria-selected={selected}
                title={
                  findingMatch
                    ? `${model.protocol} · assessment matches the filtered findings — click to open`
                    : `${model.protocol}${model.timeTitle ? ` · ${model.timeTitle}` : ''}`
                }
              >
                <td className="pw-num pw-mono">{model.sequence}</td>
                <td className="pw-mono pw-dim" style={{ whiteSpace: 'nowrap' }}>
                  {model.time}
                </td>
                <td>
                  <PacketDirectionBadge direction={model.directionLabel} />
                </td>
                <td className="pw-mono">{model.source}</td>
                <td className="pw-mono">{model.destination}</td>
                <td className="pw-mono">{model.protocol}</td>
                <td className="pw-num pw-mono">{formatBytes(model.length)}</td>
                <td className="pw-dim">{model.info}</td>
                <td className="pw-num pw-mono" title={model.spi === null ? undefined : `SPI 0x${model.spi.toString(16)}`}>
                  {model.spi === null ? <span className="pw-dim">—</span> : model.spi.toString(16).padStart(8, '0')}
                </td>
                <td>
                  <PacketRiskBadge
                    label={model.riskLabel}
                    score={model.riskScore}
                    present={model.riskPresent}
                    spi={model.spi}
                    assessments={model.packet.risk.present === true ? model.packet.risk.assessments : []}
                  />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function ListArea({
  feed,
  models,
  scope,
  selectedKey,
  onSelect,
  findingAssessmentIds,
}: {
  feed: CaptureFeed
  models: CaptureRow[]
  scope: Scope
  selectedKey: string | null
  onSelect: (model: CaptureRow) => void
  findingAssessmentIds: Set<string>
}) {
  if (feed.state === 'connecting' && feed.packets.length === 0) {
    return (
      <div className="pw-list">
        <div className="pw-empty">
          <Spinner />
          <span>Connecting to the capture feed…</span>
        </div>
      </div>
    )
  }

  if (feed.state === 'unavailable') {
    return (
      <div className="pw-list">
        <div className="pw-empty">
          <p className="pw-ink-strong">Capture feed unavailable</p>
          <p className="pw-empty-note">
            The analytics API reports that no capture feed is attached to this server.
            Nothing is shown here rather than inventing a packet list.
          </p>
          <button type="button" className="pw-btn" onClick={feed.reconnect}>
            Re-check
          </button>
        </div>
      </div>
    )
  }

  if (feed.state === 'offline' || feed.state === 'degraded') {
    return (
      <div className="pw-list">
        <div className="p-4">
          <ErrorState error={feed.error} onRetry={feed.reconnect} />
          {feed.packets.length > 0 && (
            <p className="mt-2 px-1 pw-cap">
              The {formatNumber(feed.packets.length)} rows below were received before the
              connection failed and are the last known state, not live.
            </p>
          )}
          {feed.packets.length > 0 && (
            <PacketTable models={models} selectedKey={selectedKey} onSelect={onSelect} findingAssessmentIds={findingAssessmentIds} />
          )}
        </div>
      </div>
    )
  }

  if (feed.state === 'waiting') {
    return (
      <div className="pw-list">
        <div className="pw-empty" data-no-traffic="true">
          <p className="pw-ink-strong">No current IPsec traffic observed.</p>
          <p className="pw-empty-note">
            {feed.waitingReason ??
              'The capture feed is attached but holds no packets yet. When the gateway monitor '
              +
                'sees traffic, the actual observed packets will appear here — nothing is fabricated to '
              +
                'fill the view.'}
          </p>
          <button type="button" className="pw-btn" onClick={feed.reconnect}>
            Re-check
          </button>
        </div>
      </div>
    )
  }

  if (feed.state === 'no_traffic') {
    // The journal exists but has stopped being written. Whatever rows it holds
    // are recorded history — present in the journal and the findings/evidence
    // surfaces, never as current live traffic. The live table stays empty.
    const ageSec =
      feed.lastWriteAgeMs === null ? null : Math.max(0, Math.round(feed.lastWriteAgeMs / 1000))
    const source = feed.feedSource ? ` ${feed.feedSource}` : ''
    return (
      <div className="pw-list">
        <div className="pw-empty" data-no-traffic="true">
          <p className="pw-ink-strong">No current IPsec traffic observed.</p>
          <p className="pw-empty-note">
            The journal{source} holds {formatNumber(feed.serverTotal)} recorded packet
            {feed.serverTotal === 1 ? '' : 's'} that were written {ageSec === null ? 'some time ago' : `${ageSec}s ago`}.
            Those rows are recorded history, not current traffic, so none are presented here. When the
            gateway monitor writes again, the live view shows the new packets.
          </p>
          <button type="button" className="pw-btn" onClick={feed.reconnect}>
            Re-check
          </button>
        </div>
      </div>
    )
  }

  if (models.length === 0) {
    return (
      <div className="pw-list">
        <div className="pw-empty">
          <p className="pw-ink-strong">{scope === 'ipsec' ? 'No IPsec packets' : 'No packets'}</p>
          <p className="pw-empty-note">
            {scope === 'ipsec'
              ? 'None of the buffered packets are classified ESP, AH, IKE or ESP-in-UDP.'
              : `${formatNumber(feed.packets.length)} packets are buffered, but none resolve to rows.`}
          </p>
        </div>
      </div>
    )
  }

  return <PacketTable models={models} selectedKey={selectedKey} onSelect={onSelect} findingAssessmentIds={findingAssessmentIds} />
}

export function PacketWorkspace() {
  const feed = useCaptureFeed({})

  const [scope, setScope] = useState<Scope>('all')
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [focusFindingId, setFocusFindingId] = useState<string | null>(null)
  const [snapshot, setSnapshot] = useState<CaptureRow | null>(null)
  const [filters, setFilters] = useState<FindingFilters>(DEFAULT_FILTERS)
  const findingStore = useFindingFilters(filters)

  const models = useMemo(() => {
    const packets =
      scope === 'ipsec'
        ? feed.packets.filter((packet) => IPSEC_LABELS.has(packet.packet.classification))
        : feed.packets
    return toCaptureRows(packets)
  }, [feed.packets, scope])

  const liveSelected = useMemo(
    () => (selectedKey ? (models.find((model) => model.key === selectedKey) ?? null) : null),
    [models, selectedKey],
  )
  const selectedModel = liveSelected ?? snapshot
  const selectedIsHeld = selectedModel !== null && liveSelected === null

  const selectModel = useCallback((model: CaptureRow) => {
    setSelectedKey(model.key)
    setSnapshot(model)
  }, [])

  // Clear is a view/buffer operation: it drops the buffered rows (and advances
  // the feed's watermark so they can never be re-read) and closes any open
  // investigation whose packet was just cleared. The journal is never touched.
  const clearFeed = useCallback(() => {
    feed.clear()
    setSelectedKey(null)
    setSnapshot(null)
    setFocusFindingId(null)
  }, [feed])

  // Assessment ids currently represented in the live packet buffer, so the
  // findings strip can say honestly whether a finding has a captured packet.
  const bufferedAssessmentIds = useMemo(() => {
    const ids = new Set<string>()
    for (const packet of feed.packets) {
      if (packet.risk.present === true) {
        for (const a of packet.risk.assessments) ids.add(a.assessment_id)
      }
    }
    return ids
  }, [feed.packets])

  // Assessment ids behind the *filtered* findings, for row highlighting.
  const findingAssessmentIds = useMemo(
    () => new Set(findingStore.findings.map((f) => f.finding.assessment_id)),
    [findingStore.findings],
  )

  const activeFilterCount = useMemo(
    () =>
      (filters.risk !== 'ALL' ? 1 : 0) +
      (filters.confidence !== 'ALL' ? 1 : 0) +
      (filters.traffic !== 'ALL' ? 1 : 0) +
      (filters.finding !== 'ALL' ? 1 : 0) +
      (filters.drift !== 'ALL' ? 1 : 0),
    [filters],
  )

  const openFinding = useCallback(
    (finding: FilteredFinding) => {
      const anchored = models.find((model) => model.assessmentIds.includes(finding.finding.assessment_id))
      // The clicked finding is passed on, so the investigation explains THAT
      // finding rather than defaulting to the most severe one.
      setFocusFindingId(finding.finding.finding_id)
      selectModel(anchored ?? anchorRowFor(finding))
    },
    [models, selectModel],
  )

  return (
    <section className="pw-root" aria-label="Packet capture workspace">
      <div className="pw-live" data-live-section="true">
        <div className="pw-live-head">
          <h2 className="pw-live-title">LIVE IPSEC TRAFFIC</h2>
          <FeedCap feed={feed} />
          {feed.feedSource && (
            <span className="pw-chip" title="Packet journal being tailed (read-only)">
              feed: {feed.feedSource}
            </span>
          )}
          <span className="pw-spacer" />
          <span className="pw-cap-label pw-dim-caption">
            passive XDP capture of the gateway traffic path · read-only tail
          </span>
        </div>

        <div className="pw-topbar">
          <SegFilter scope={scope} onChange={setScope} />
          <button
            type="button"
            className="pw-btn"
            onClick={() => (feed.paused ? feed.resume() : feed.pause())}
          >
            {feed.paused ? 'Resume' : 'Pause'}
          </button>
          <button type="button" className="pw-btn" onClick={clearFeed}>
            Clear
          </button>
        </div>

        <div className="pw-statusline">
          <span>
            Packets are the gateway&apos;s observed traffic (xdp_monitor), normalized by the streaming
            adapter and rendered by the feed. Direction and Risk are per-packet: direction from the
            capture adapter&apos;s observation context, risk from the assessment store by the SPI that
            store actually observed. UNASSESSED means no assessment classified that packet.
          </span>
          <span className="pw-spacer" />
          <span className="pw-mono">
            {formatNumber(models.length)} shown · {formatNumber(feed.packets.length)} buffered ·{' '}
            {formatNumber(feed.serverTotal)} in journal
          </span>
          {feed.evicted > 0 && (
            <span className="pw-warn">
              {formatNumber(feed.evicted)} older row{feed.evicted === 1 ? '' : 's'} dropped from the
              buffer
            </span>
          )}
          {!feed.current && (feed.state === 'waiting' || feed.state === 'no_traffic') && (
            <span className="pw-warn">
              no current live traffic — recorded journal rows are not shown as live
            </span>
          )}
          <span className="pw-dim-caption">
            {feed.lastPollAtMs
              ? `last poll ${new Date(feed.lastPollAtMs).toLocaleTimeString()}`
              : 'not polled yet'}
          </span>
        </div>

        <ListArea
          feed={feed}
          models={models}
          scope={scope}
          selectedKey={selectedKey}
          onSelect={selectModel}
          findingAssessmentIds={findingAssessmentIds}
        />

        <div className="pw-inspector">
          <PacketInvestigation
            model={selectedModel}
            held={selectedIsHeld}
            focusFindingId={focusFindingId}
          />
        </div>
      </div>

      <section className="pw-findings" data-findings-section="true" aria-label="Findings and assessment filters">
        <FindingFilterBar
          filters={filters}
          onChange={(patch) => setFilters((current) => ({ ...current, ...patch }))}
          onClear={() => setFilters(DEFAULT_FILTERS)}
          activeCount={activeFilterCount}
          findingStore={findingStore}
          findings={findingStore.findings}
          onOpenFinding={openFinding}
          bufferedAssessmentIds={bufferedAssessmentIds}
        />
      </section>
    </section>
  )
}