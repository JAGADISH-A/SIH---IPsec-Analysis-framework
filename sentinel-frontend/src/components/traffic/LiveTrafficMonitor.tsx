import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { LiveTraffic } from '@/hooks/useLiveTraffic'
import { EmptyState, ErrorState, Spinner } from '@/components/states'
import { Panel, SeverityBadge, StatusPill, Tag } from '@/components/ui'
import { filterTrafficRows, STAGE_ORDER, type TrafficFilters, type TrafficRow } from '@/lib/traffic'
import { formatNumber, formatUtc, humanize, severityHex } from '@/lib/format'
import type { Severity } from '@/types'

/** Fixed row height so the virtualizer can position rows without measuring. */
const ROW_HEIGHT = 34
const OVERSCAN = 8

const SEVERITY_FILTERS: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

type Props = {
  feed: LiveTraffic
  selectedKey: string | null
  onSelect: (row: TrafficRow) => void
  /** Set once the analyst has frozen a selection, so new rows cannot steal it. */
  frozen: boolean
  onFreezeChange: (frozen: boolean) => void
}

function FeedBadge({ feed }: { feed: LiveTraffic }) {
  const tone =
    feed.state === 'live'
      ? 'good'
      : feed.state === 'paused'
        ? 'warn'
        : feed.state === 'degraded' || feed.state === 'offline'
          ? 'bad'
          : 'neutral'
  const label = {
    connecting: 'connecting',
    live: 'live',
    paused: 'paused',
    empty: 'no events',
    unavailable: 'source unavailable',
    offline: 'disconnected',
    degraded: 'reconnecting',
  }[feed.state]
  return <StatusPill status={feed.state} tone={tone} label={label} />
}

function Field({
  label,
  value,
  onValue,
}: {
  label: string
  value: string
  onValue: (value: string) => void
}) {
  return (
    <label className="flex min-w-0 flex-col gap-1">
      <span className="label text-ink-faint">
        {label}
      </span>
      <input
        type="text"
        value={value}
        onChange={(event) => onValue(event.target.value)}
        className="mono w-full rounded-md border border-edge bg-panel px-2 py-1.5 text-sm text-ink outline-none transition-colors placeholder:text-ink-faint/60 focus:border-sentinel focus:ring-2 focus:ring-sentinel/15"
      />
    </label>
  )
}

function FilterControls({
  filters,
  setFilters,
  onReset,
}: {
  filters: TrafficFilters
  setFilters: (update: Partial<TrafficFilters>) => void
  onReset: () => void
}) {
  const [search, setSearch] = useState(filters.search)
  useEffect(() => setSearch(filters.search), [filters.search])

  useEffect(() => {
    // Debounced so a keystroke does not re-filter the whole buffer per character.
    if (search === filters.search) return
    const timer = setTimeout(() => setFilters({ search }), 160)
    return () => clearTimeout(timer)
  }, [search, filters.search, setFilters])

  const toggleStage = (stage: string) => {
    const stages = filters.stages.includes(stage)
      ? filters.stages.filter((value) => value !== stage)
      : [...filters.stages, stage]
    setFilters({ stages })
  }

  const toggleSeverity = (severity: string) => {
    const severities = filters.severities.includes(severity)
      ? filters.severities.filter((value) => value !== severity)
      : [...filters.severities, severity]
    setFilters({ severities })
  }

  const dirty =
    filters.search !== '' ||
    filters.stages.length > 0 ||
    filters.severities.length > 0 ||
    filters.onlyAuthoritative ||
    filters.onlyAnomalies ||
    filters.minRisk !== null

  return (
    <div className="space-y-2.5 border-b border-edge px-3 py-3">
      <div className="grid gap-2.5 sm:grid-cols-[1.6fr_1fr_1fr]">
        <Field label="Search" value={search} onValue={setSearch} />
        <label className="flex min-w-0 flex-col gap-1">
          <span className="label text-ink-faint">
            Min inherited risk
          </span>
          <select
            value={filters.minRisk ?? ''}
            onChange={(event) =>
              setFilters({ minRisk: event.target.value === '' ? null : Number(event.target.value) })
            }
            className="mono w-full rounded-md border border-edge bg-panel px-2 py-1.5 text-sm text-ink outline-none focus:border-sentinel focus:ring-2 focus:ring-sentinel/15"
          >
            <option value="">any</option>
            {[25, 40, 50, 70].map((score) => (
              <option key={score} value={score}>
                ≥ {score}
              </option>
            ))}
          </select>
        </label>
        <div className="flex min-w-0 flex-col gap-1">
          <span className="label text-ink-faint">
            Source
          </span>
          <button
            type="button"
            onClick={() => setFilters({ onlyAuthoritative: !filters.onlyAuthoritative })}
            className={`rounded border px-2 py-1.5 text-sm transition-colors ${
              filters.onlyAuthoritative
                ? 'border-sentinel/45 bg-sentinel/12 text-sentinel'
                : 'border-edge bg-panel text-ink-dim hover:text-ink'
            }`}
          >
            {filters.onlyAuthoritative ? 'authoritative only' : 'any authority'}
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="label text-ink-faint">
          Stage
        </span>
        {STAGE_ORDER.map((stage) => (
          <button
            key={stage}
            type="button"
            onClick={() => toggleStage(stage)}
            className={`rounded border px-1.5 py-0.5 text-xs transition-colors ${
              filters.stages.includes(stage)
                ? 'border-sentinel/45 bg-sentinel/12 text-sentinel'
                : 'border-edge bg-panel-2 text-ink-faint hover:text-ink-dim'
            }`}
          >
            {stage}
          </button>
        ))}
        <span className="mx-1 h-3 w-px bg-edge" aria-hidden="true" />
        <span className="label text-ink-faint">
          Inherited risk
        </span>
        {SEVERITY_FILTERS.map((severity) => (
          <button
            key={severity}
            type="button"
            onClick={() => toggleSeverity(severity)}
            className={`rounded border px-1.5 py-0.5 text-xs font-medium transition-colors ${
              filters.severities.includes(severity)
                ? 'text-ink'
                : 'border-edge bg-panel-2 text-ink-faint/70 hover:text-ink-dim'
            }`}
            style={
              filters.severities.includes(severity)
                ? { borderColor: `${severityHex(severity)}66`, background: `${severityHex(severity)}1f` }
                : undefined
            }
          >
            {severity}
          </button>
        ))}
        <button
          type="button"
          onClick={() => setFilters({ onlyAnomalies: !filters.onlyAnomalies })}
          className={`rounded border px-1.5 py-0.5 text-xs transition-colors ${
            filters.onlyAnomalies
              ? 'border-medium/45 bg-medium/12 text-medium'
              : 'border-edge bg-panel-2 text-ink-faint hover:text-ink-dim'
          }`}
        >
          anomalies only
        </button>
        {dirty && (
          <button
            type="button"
            onClick={onReset}
            className="ml-auto text-xs text-ink-faint underline-offset-2 transition-colors hover:text-sentinel hover:underline"
          >
            clear filters
          </button>
        )}
      </div>
    </div>
  )
}

/**
 * The table body, windowed.
 *
 * Only the visible slice is mounted, so a full 2,000-row buffer scrolls without
 * holding 2,000 rows of DOM. The window is a plain slice over a fixed-height
 * row; nothing here measures the DOM, so there is no layout feedback loop.
 */
function VirtualRows({
  rows,
  totalHeight,
  scrollTop,
  selectedKey,
  onSelect,
}: {
  rows: TrafficRow[]
  totalHeight: number
  scrollTop: number
  selectedKey: string | null
  onSelect: (row: TrafficRow) => void
}) {
  const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)
  const end = Math.min(rows.length, Math.ceil((scrollTop + 520) / ROW_HEIGHT) + OVERSCAN)
  const slice = rows.slice(start, end)

  return (
    <div style={{ height: totalHeight, position: 'relative' }}>
      <div style={{ transform: `translateY(${start * ROW_HEIGHT}px)` }}>
        <table className="data-table min-w-[1180px]">
          <tbody>
            {slice.map((row) => {
              const { event, assessment, inherited } = row
              const selected = row.key === selectedKey
              return (
                <tr
                  key={row.key}
                  onClick={() => onSelect(row)}
                  aria-selected={selected}
                  className={`cursor-pointer border-b border-edge/45 transition-colors ${
                    selected ? 'bg-sentinel/[0.11]' : 'hover:bg-panel-2/60'
                  }`}
                  style={{ height: ROW_HEIGHT }}
                >
                  <td className="w-[128px] px-3 py-0">
                    <span className="mono text-xs text-ink-dim">
                      {event.recorded_at ? formatUtc(event.recorded_at) : '—'}
                    </span>
                  </td>
                  <td className="px-2 py-0">
                    <span
                      className="inline-flex items-center gap-1.5 text-xs text-ink"
                      title={`${event.event_type} · recorded by ${event.source}`}
                    >
                      <span
                        className="h-1.5 w-1.5 shrink-0 rounded-full"
                        style={{
                          background: event.authoritative ? '#34d399' : '#64748b',
                        }}
                        aria-hidden="true"
                      />
                      {humanize(row.stage)}
                    </span>
                  </td>
                  <td className="px-2 py-0">
                    <span
                      className="mono block max-w-[190px] truncate text-xs text-ink-dim"
                      title={event.event_type}
                    >
                      {event.event_type}
                    </span>
                  </td>
                  <td className="px-2 py-0">
                    {event.authoritative ? (
                      <span className="text-xs text-good">authoritative</span>
                    ) : (
                      <span className="text-xs text-ink-faint">derived</span>
                    )}
                  </td>
                  <td className="px-2 py-0">
                    <span
                      className="mono block max-w-[150px] truncate text-xs text-ink-faint"
                      title={event.source}
                    >
                      {event.source}
                    </span>
                  </td>
                  <td className="px-2 py-0">
                    {assessment ? (
                      <>
                        <span
                          className="mono block max-w-[180px] truncate text-xs text-ink-dim"
                          title={assessment.assessment_id}
                        >
                          #{assessment.sequence} {assessment.slot}
                        </span>
                        <span className="mono block text-xs text-ink-faint">
                          w{event.window_index ?? '—'}
                        </span>
                      </>
                    ) : (
                      <span className="text-xs text-ink-faint" title="No stored assessment matches this event's run and sequence">
                        not in store
                      </span>
                    )}
                  </td>
                  <td className="px-2 py-0">
                    {assessment ? (
                      <span className="text-xs text-ink-dim">
                        {assessment.mode} · {assessment.address_family} · ESP{' '}
                        {assessment.esp_encryption}
                      </span>
                    ) : (
                      <span className="text-xs text-ink-faint">—</span>
                    )}
                  </td>
                  <td className="w-[74px] px-2 py-0">
                    {inherited.riskScore === null ? (
                      <span className="text-xs text-ink-faint">Not observable</span>
                    ) : (
                      <span className="mono tnum text-sm text-ink">
                        {inherited.riskScore}
                      </span>
                    )}
                  </td>
                  <td className="w-[96px] px-2 py-0">
                    {inherited.severity ? (
                      <SeverityBadge severity={inherited.severity} size="sm" />
                    ) : (
                      <span className="text-xs text-ink-faint">Not observable</span>
                    )}
                  </td>
                  <td className="w-[86px] px-2 py-0">
                    {inherited.anomaly === null ? (
                      <span className="text-xs text-ink-faint">—</span>
                    ) : inherited.anomaly ? (
                      <span className="text-xs font-medium text-medium">anomaly</span>
                    ) : (
                      <span className="text-xs text-ink-faint">normal</span>
                    )}
                  </td>
                  <td className="w-[132px] px-3 py-0">
                    <span
                      className="mono block max-w-[132px] truncate text-xs text-ink-faint/80"
                      title={event.event_id}
                    >
                      {event.event_id}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/**
 * The live traffic monitor.
 *
 * What this shows, stated plainly: the analysis audit journal, polled. The
 * rows are pipeline events, not packets — the read-only analytics plane serves
 * no frame data and decrypts nothing, so there is no source, destination,
 * length or payload column here that would imply otherwise. The columns are
 * the event's own identity and provenance, plus the risk and ML state of the
 * flow it belongs to, marked as inherited.
 */
export function LiveTrafficMonitor({
  feed,
  selectedKey,
  onSelect,
  frozen,
  onFreezeChange,
}: Props) {
  const [filters, setFiltersState] = useState<TrafficFilters>({
    search: '',
    stages: [],
    onlyAuthoritative: false,
    onlyAnomalies: false,
    minRisk: null,
    severities: [],
  })
  const [scrollTop, setScrollTop] = useState(0)
  const scrollerRef = useRef<HTMLDivElement | null>(null)

  const setFilters = useCallback(
    (update: Partial<TrafficFilters>) =>
      setFiltersState((current) => ({ ...current, ...update })),
    [],
  )
  const resetFilters = useCallback(
    () =>
      setFiltersState({
        search: '',
        stages: [],
        onlyAuthoritative: false,
        onlyAnomalies: false,
        minRisk: null,
        severities: [],
      }),
    [],
  )

  const visible = useMemo(() => filterTrafficRows(feed.rows, filters), [feed.rows, filters])

  const unavailable = feed.state === 'unavailable'
  const offline = feed.state === 'offline' || feed.state === 'degraded'
  const loading = feed.state === 'connecting' && feed.rows.length === 0

  return (
    <Panel
      title="Live Traffic Monitor"
      subtitle="analysis audit journal · polled · risk and ML are inherited from the enclosing flow, not measured per event"
      className="flex min-h-0 flex-col"
      bodyClassName="flex min-h-0 flex-1 flex-col"
      action={
        <div className="flex flex-wrap items-center justify-end gap-1.5">
          <FeedBadge feed={feed} />
          <button
            type="button"
            onClick={() => (feed.paused ? feed.resume() : feed.pause())}
            className="rounded border border-edge bg-panel-2 px-2 py-1 text-xs text-ink-dim transition-colors hover:text-ink"
          >
            {feed.paused ? 'Resume' : 'Pause'}
          </button>
          <button
            type="button"
            onClick={() => onFreezeChange(!frozen)}
            className={`rounded border px-2 py-1 text-xs transition-colors ${
              frozen
                ? 'border-medium/45 bg-medium/12 text-medium'
                : 'border-edge bg-panel-2 text-ink-dim hover:text-ink'
            }`}
            title="Freeze the current selection so incoming rows cannot change what is open"
          >
            {frozen ? 'Frozen' : 'Freeze'}
          </button>
          <button
            type="button"
            onClick={feed.clear}
            className="rounded border border-edge bg-panel-2 px-2 py-1 text-xs text-ink-dim transition-colors hover:text-ink"
          >
            Clear
          </button>
        </div>
      }
    >
      {/* The provenance disclaimer sits above the data, not in a tooltip. */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-edge-soft bg-panel-2 px-3 py-2 text-xs text-ink-faint">
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-good" aria-hidden="true" />
          authoritative
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-ink-faint" aria-hidden="true" />
          derived / not authoritative
        </span>
        <span>
          Risk, severity and anomaly are <span className="text-ink-dim">inherited</span> from the
          flow-level assessment and are not per-event measurements.
        </span>
        <span className="ml-auto mono">
          {formatNumber(visible.length)} shown · {formatNumber(feed.rows.length)} buffered ·{' '}
          {formatNumber(feed.serverTotal)} in journal
        </span>
      </div>

      {feed.evicted > 0 && (
        <p className="border-b border-edge bg-medium/[0.07] px-3 py-1.5 text-xs text-medium">
          {formatNumber(feed.evicted)} older event{feed.evicted === 1 ? '' : 's'} dropped from the
          view buffer. The journal still holds all {formatNumber(feed.serverTotal)}; raise
          VITE_TRAFFIC_BUFFER_LIMIT to widen the window.
        </p>
      )}

      {!unavailable && !offline && (
        <FilterControls filters={filters} setFilters={setFilters} onReset={resetFilters} />
      )}

      {loading ? (
        <div className="flex items-center justify-center gap-2.5 px-4 py-14 text-ink-dim">
          <Spinner />
          <span className="text-sm">Connecting to the audit journal…</span>
        </div>
      ) : unavailable ? (
        <EmptyState
          title="Live source unavailable"
          icon="filter"
          description={
            <>
              The analytics API reports that no analysis audit journal is attached to this store.
              The server was started without <span className="mono text-ink-dim">--phase10</span>{' '}
              or <span className="mono text-ink-dim">--audit-journal &lt;path&gt;</span>. Sentinel
              shows this state rather than an empty table, because an empty list here would read
              as &ldquo;no activity&rdquo; when in fact nothing is being watched.
            </>
          }
          action={
            <button
              type="button"
              onClick={feed.reconnect}
              className="rounded border border-edge bg-panel-2 px-3 py-1.5 text-sm text-ink-dim transition-colors hover:text-ink"
            >
              Re-check
            </button>
          }
        />
      ) : offline ? (
        <div className="p-3">
          <ErrorState error={feed.error} onRetry={feed.reconnect} />
          {feed.rows.length > 0 && (
            <p className="mt-2 px-1 text-xs text-ink-faint">
              The {formatNumber(feed.rows.length)} rows below were received before the connection
              failed and are the last known state, not live.
            </p>
          )}
        </div>
      ) : feed.state === 'empty' ? (
        <EmptyState
          title="The journal holds no events"
          icon="inbox"
          description="The analytics service answered successfully and the attached journal contains zero analysis events. Nothing is being fabricated to fill the view."
        />
      ) : visible.length === 0 ? (
        <EmptyState
          title="No events match these filters"
          icon="filter"
          description={`${formatNumber(feed.rows.length)} events are buffered, but none match the current filters.`}
          action={
            <button
              type="button"
              onClick={resetFilters}
              className="rounded border border-edge bg-panel-2 px-3 py-1.5 text-sm text-ink-dim transition-colors hover:text-ink"
            >
              Clear filters
            </button>
          }
        />
      ) : (
        <>
          <div className="overflow-x-auto border-b border-edge">
            <table className="data-table min-w-[1180px]">
              <thead>
                <tr className="text-left">
                  {[
                    'Recorded',
                    'Stage',
                    'Event type',
                    'Authority',
                    'Source',
                    'Flow / window',
                    'Flow configuration',
                    'Risk',
                    'Severity',
                    'ML',
                    'Event id',
                  ].map((heading) => (
                    <th
                      key={heading}
                      className="px-3 py-2 label text-ink-faint"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
            </table>
          </div>
          <div
            ref={scrollerRef}
            onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
            className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden"
            style={{ maxHeight: '460px' }}
          >
            <VirtualRows
              rows={visible}
              totalHeight={visible.length * ROW_HEIGHT}
              scrollTop={scrollTop}
              selectedKey={selectedKey}
              onSelect={onSelect}
            />
          </div>
        </>
      )}

      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-edge px-3 py-2 text-xs text-ink-faint">
        <span className="mono">
          {feed.lastPollAtMs
            ? `last poll ${new Date(feed.lastPollAtMs).toLocaleTimeString()}`
            : 'not polled yet'}
        </span>
        {feed.failures > 0 && (
          <span className="text-medium">
            {feed.failures} consecutive failed poll{feed.failures === 1 ? '' : 's'}
          </span>
        )}
        <span className="flex items-center gap-1.5">
          {feed.paused ? <Tag className="text-medium">paused</Tag> : null}
          {frozen ? <Tag className="text-medium">selection frozen</Tag> : null}
        </span>
        <span className="ml-auto">
          No packet contents, addresses or payloads are shown: the read-only analytics plane
          exposes analysis events, not decrypted frames.
        </span>
      </div>
    </Panel>
  )
}
