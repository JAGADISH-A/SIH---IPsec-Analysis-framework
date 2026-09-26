import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Pause, Play, Radio } from 'lucide-react'
import { Button } from '../../components/common/Button.tsx'
import { ConfidenceTag, SeverityTag } from '../../components/common/Evidence.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { ErrorPanel, LoadingPanel } from '../../components/common/QueryState.tsx'
import { Panel, PanelHeader } from '../../components/common/Panel.tsx'
import { StatusDot } from '../../components/common/StatusDot.tsx'
import { Tabs } from '../../components/common/Tabs.tsx'
import { AnalyzerPage } from '../analyzer/AnalyzerPage.tsx'
import { useSystemHealth } from '../../hooks/queries'
import { useLiveEvents, useLiveSnapshot } from '../../hooks/useLiveEvents'
import { cx } from '../../lib/cx'
import { services } from '../../services'
import { LIVE_EVENT_LABEL, MONITORING_STATUS_LABEL, type LiveEvent } from '../../types/events'
import { formatBytes } from '../sessions/SessionDetailPage.tsx'

/**
 * Live monitor.
 *
 * Two views share one route: the event feed (default) and the packet analyzer
 * workspace, which keeps its own full-height layout. The view lives in the URL
 * so a link always reopens the same surface.
 */
export function LiveMonitorPage() {
  const [params, setParams] = useSearchParams()
  const view = params.get('view') === 'analyzer' ? 'analyzer' : 'monitor'

  if (view === 'analyzer') {
    return (
      <div className="flex h-full min-h-0 flex-col">
        <div className="flex shrink-0 items-center gap-2 border-b border-edge bg-night-900/60 px-3 py-1.5">
          <Tabs
            items={[
              { id: 'monitor', label: 'Monitor' },
              { id: 'analyzer', label: 'Packet Analyzer' },
            ]}
            value={view}
            onChange={(id) => setParams(id === 'analyzer' ? { view: 'analyzer' } : {}, { replace: true })}
            ariaLabel="Live monitor views"
          />
        </div>
        <div className="min-h-0 flex-1">
          <AnalyzerPage />
        </div>
      </div>
    )
  }

  return (
    <PageScroll>
      <div className="border-b border-edge bg-night-900/60 px-4 pt-3 lg:px-6">
        <Tabs
          items={[
            { id: 'monitor', label: 'Monitor' },
            { id: 'analyzer', label: 'Packet Analyzer' },
          ]}
          value={view}
          onChange={(id) => setParams(id === 'analyzer' ? { view: 'analyzer' } : {}, { replace: true })}
          ariaLabel="Live monitor views"
        />
      </div>

      <LiveMonitorFeed />
    </PageScroll>
  )
}

function LiveMonitorFeed() {
  const events = useLiveEvents()
  const snapshot = useLiveSnapshot()
  const health = useSystemHealth()
  const [paused, setPaused] = useState(false)
  // The one-minute window has to age while no event arrives, so the clock is
  // state driven by an interval rather than read during render.
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 5_000)
    return () => window.clearInterval(timer)
  }, [])

  const visible = paused ? [] : events

  const rates = useMemo(() => {
    const recent = events.filter((event) => now - Date.parse(event.timestamp) < 60_000)
    return {
      perMinute: recent.length,
      critical: recent.filter((event) => event.severity === 'critical').length,
      failures: recent.filter((event) => event.type === 'IKE_NEGOTIATION_FAILED').length,
    }
  }, [events, now])

  if (snapshot.isLoading) {
    return (
      <>
        <PageHeader title="Live Monitor" description="Connecting to the analysis event stream…" />
        <LoadingPanel rows={8} />
      </>
    )
  }

  if (snapshot.isError || !snapshot.data) {
    return (
      <>
        <PageHeader title="Live Monitor" />
        <div className="p-4 lg:p-6">
          <ErrorPanel error={snapshot.error} onRetry={() => void snapshot.refetch()} />
        </div>
      </>
    )
  }

  return (
    <>
      <PageHeader
        title="Live Monitor"
        description="Protocol events as the analysis engine observes them. Every event is evidence, not notification."
        meta={
          <>
            <span className="font-mono">
              {snapshot.data.activeSessions} active session(s) · {snapshot.data.packetsPerSecond} pkt/s ·{' '}
              {formatBytes(snapshot.data.bytesPerSecond)}/s
            </span>
            <span className="font-mono">Interface {snapshot.data.interfaceName ?? 'unknown'}</span>
            {health.data ? <span>Source: {health.data.mockMode ? 'simulated event stream' : health.data.apiBaseUrl}</span> : null}
          </>
        }
        actions={
          <>
            <Button onClick={() => setPaused((value) => !value)} aria-pressed={paused}>
              {paused ? <Play className="size-3.5" aria-hidden /> : <Pause className="size-3.5" aria-hidden />}
              {paused ? 'Resume feed' : 'Pause feed'}
            </Button>
            <Link to="/vpn-sessions" className="btn btn-primary">
              Sessions
            </Link>
          </>
        }
      />

      <PageBody>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Stat
            label="Monitoring status"
            value={MONITORING_STATUS_LABEL[snapshot.data.monitoringStatus]}
            tone={snapshot.data.monitoringStatus === 'monitoring' ? 'success' : 'warning'}
            hint={paused ? 'Feed paused locally' : 'Receiving analysis events'}
          />
          <Stat
            label="Events / minute"
            value={String(paused ? 0 : rates.perMinute)}
            tone="accent"
            hint={`${snapshot.data.eventBreakdown.length} distinct event type(s) observed`}
          />
          <Stat
            label="Critical events / minute"
            value={String(paused ? 0 : rates.critical)}
            tone={rates.critical > 0 ? 'danger' : 'success'}
            hint="Events the platform rated critical"
          />
          <Stat
            label="Negotiation failures"
            value={String(paused ? 0 : rates.failures)}
            tone={rates.failures > 0 ? 'warning' : 'success'}
            hint="IKE handshakes that did not complete"
          />
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
          <Panel flush>
            <PanelHeader
              title="Event feed"
              subtitle={
                <span aria-live="polite">
                  {visible.length} event(s) buffered
                  {snapshot.data.lastEventAt
                    ? ` · last at ${new Date(snapshot.data.lastEventAt).toLocaleTimeString()}`
                    : ''}
                </span>
              }
            />
            {events.length === 0 ? (
              <p className="px-4 py-10 text-center text-xs text-mist-faint">
                Waiting for the first analysis event…
              </p>
            ) : (
              <ol className="max-h-[32rem] divide-y divide-edge/60 overflow-y-auto" aria-live="polite">
                {[...visible].reverse().map((event) => (
                  <EventRow key={event.id} event={event} />
                ))}
              </ol>
            )}
          </Panel>

          <div className="flex flex-col gap-4">
            <Panel flush>
              <PanelHeader title="Event mix" subtitle="Last minute by type" />
              <ul className="flex flex-col gap-1.5 p-4">
                {snapshot.data.eventBreakdown.map((entry) => (
                  <li key={entry.type} className="flex items-center gap-2 text-[11px]">
                    <span className="min-w-0 flex-1 truncate text-mist-dim">{LIVE_EVENT_LABEL[entry.type]}</span>
                    <span className="h-1.5 w-24 overflow-hidden rounded-full bg-night-800">
                      <span
                        className="block h-full rounded-full bg-accent-400"
                        style={{
                          width: `${(entry.count / Math.max(1, snapshot.data.eventBreakdown[0]?.count ?? 1)) * 100}%`,
                        }}
                      />
                    </span>
                    <span className="w-6 text-right font-mono text-mist-faint">{entry.count}</span>
                  </li>
                ))}
              </ul>
            </Panel>

            <Panel flush>
              <PanelHeader title="How to read this feed" />
              <ul className="flex flex-col gap-2 p-4 text-[11.5px] leading-relaxed text-mist-dim">
                <li>
                  Events are observations, not verdicts. A negotiation failure is a fact about the wire; what it means
                  is a finding.
                </li>
                <li>
                  Confidence is shown per event where the analyser had one. An event without a confidence estimate is
                  reported as unknown.
                </li>
                <li>
                  The feed is a live channel. It will be carried over WebSocket or SSE once the backend exists; this
                  page will not change.
                </li>
              </ul>
              <div className="border-t border-edge px-3 py-2 text-[10px] text-mist-faint">
                <Radio className="mr-1 inline size-3" aria-hidden />
                Currently subscribed to {services.liveEvents.constructor.name} via the LiveEventService interface.
              </div>
            </Panel>
          </div>
        </div>
      </PageBody>
    </>
  )
}

function EventRow({ event }: { event: LiveEvent }) {
  return (
    <li className="flex items-start gap-3 px-3 py-2">
      <span className="mt-1 w-16 shrink-0 text-right font-mono text-[10.5px] text-mist-faint">
        {new Date(event.timestamp).toLocaleTimeString()}
      </span>
      <span
        className={cx(
          'mt-1.5 size-2 shrink-0 rounded-full',
          event.severity === 'critical'
            ? 'bg-critical'
            : event.severity === 'high'
              ? 'bg-danger'
              : event.severity === 'medium'
                ? 'bg-warning'
                : event.severity === 'low'
                  ? 'bg-info'
                  : 'bg-mist-faint',
        )}
        aria-hidden
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[12.5px] font-medium text-mist">{LIVE_EVENT_LABEL[event.type]}</span>
          {event.severity !== 'informational' ? <SeverityTag severity={event.severity} /> : null}
          {event.confidence !== null ? <ConfidenceTag confidence={event.confidence} /> : null}
        </div>
        <p className="mt-0.5 text-[12px] leading-relaxed text-mist-dim">{event.description}</p>
        <p className="mt-0.5 font-mono text-[10.5px] text-mist-faint">
          {event.sessionId ? (
            <Link to={`/vpn-sessions/${event.sessionId}`} className="hover:text-accent-300">
              {event.sessionId}
            </Link>
          ) : (
            'no session'
          )}{' '}
          · {event.sessionLabel} · {event.peer} · {event.source}
        </p>
      </div>
      {event.findingId ? (
        <Link to={`/findings/${event.findingId}`} className="btn btn-sm shrink-0">
          Finding
        </Link>
      ) : null}
    </li>
  )
}

function Stat({
  label,
  value,
  hint,
  tone,
}: {
  label: string
  value: string
  hint: string
  tone: 'success' | 'warning' | 'danger' | 'accent'
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-edge bg-night-900 p-3">
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-wide text-mist-faint">
        <StatusDot tone={tone} />
        {label}
      </div>
      <span className="font-mono text-xl font-semibold text-mist">{value}</span>
      <span className="text-[10px] text-mist-faint">{hint}</span>
    </div>
  )
}
