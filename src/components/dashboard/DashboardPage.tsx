import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { ArrowDownRight, ArrowUpRight, Info, Minus, RefreshCw } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { ConfidenceTag, SeverityTag } from '../../components/common/Evidence.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { ErrorPanel, LoadingPanel } from '../../components/common/QueryState.tsx'
import { Panel, PanelHeader } from '../../components/common/Panel.tsx'
import { StatusDot } from '../../components/common/StatusDot.tsx'
import { BarChart, DonutChart, LineChart } from '../../components/charts/Charts.tsx'
import { ScoreDial } from '../../components/charts/ScoreDial.tsx'
import { useDashboard } from '../../hooks/queries'
import { cx } from '../../lib/cx'
import { ENVIRONMENT_LABEL, SESSION_STATUS_LABEL, type VpnSession } from '../../types/session'
import type { DashboardSummary, KpiMetric } from '../../types/dashboard'
import { SERVICE_STATUS_LABEL } from '../../types/health'

/**
 * Dashboard: the platform's security posture at a glance.
 *
 * The page is a projection, so every number links to the page that can explain
 * it, and anything the platform could not compute is rendered as Unknown rather
 * than as a zero.
 */
export function DashboardPage() {
  const { data, isLoading, isError, error, refetch, isFetching, dataUpdatedAt } = useDashboard()

  if (isLoading) {
    return (
      <PageScroll>
        <PageHeader title="Dashboard" description="Loading the current security posture…" />
        <LoadingPanel rows={6} />
      </PageScroll>
    )
  }

  if (isError || !data) {
    return (
      <PageScroll>
        <PageHeader title="Dashboard" />
        <div className="p-4 lg:p-6">
          <ErrorPanel error={error} onRetry={() => void refetch()} />
        </div>
      </PageScroll>
    )
  }

  return (
    <PageScroll>
      <PageHeader
        title="Dashboard"
        description="Aggregated posture, finding severity and analysis coverage across every assessed VPN session."
        meta={
          <>
            <span className="font-mono">Window {data.range.label}</span>
            <span>Generated {new Date(data.generatedAt).toLocaleString()}</span>
            {isFetching ? <span className="text-accent-300">Refreshing…</span> : null}
          </>
        }
        actions={
          <>
            <Link to="/findings" className="btn">
              Review findings
            </Link>
            <Link to="/reports/new" className="btn btn-primary">
              Generate report
            </Link>
          </>
        }
      />

      <PageBody>
        {data.partial ? (
          <div className="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning-dim/40 p-3">
            <Info className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden />
            <div className="text-xs text-mist-dim">
              <span className="font-semibold text-warning">Partial summary.</span>{' '}
              {data.partialReasons.join(' ')}
            </div>
          </div>
        ) : null}

        <div className="grid gap-4 xl:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
          <Panel className="flex flex-col items-center gap-3 p-4">
            <PanelHeader title="Security posture" subtitle="Weighted across correlated findings" className="w-full" />
            <ScoreDial posture={data.posture} />
            <p className="text-center text-[11px] leading-relaxed text-mist-faint">{data.posture.method}</p>
            <dl className="grid w-full grid-cols-2 gap-2 border-t border-edge pt-3 text-[11px]">
              <div>
                <dt className="text-mist-faint">Last assessed</dt>
                <dd className="font-mono text-mist">{new Date(data.posture.lastAssessmentAt).toLocaleTimeString()}</dd>
              </div>
              <div>
                <dt className="text-mist-faint">Sessions affected</dt>
                <dd className="font-mono text-mist">{data.posture.affectedSessions}</dd>
              </div>
            </dl>
          </Panel>

          <section aria-label="Key performance indicators" className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {data.kpis.map((kpi) => (
              <KpiCard key={kpi.id} kpi={kpi} />
            ))}
          </section>
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          <Panel className="lg:col-span-2" flush>
            <PanelHeader
              title="Security score trend"
              subtitle="Composite score per day — lower is better"
              actions={
                <Badge tone="muted" className="font-mono">
                  {data.securityScoreTrend.length} points
                </Badge>
              }
            />
            <div className="p-4">
              <LineChart
                label="Security score over time"
                points={data.securityScoreTrend}
                unit=""
                tone={data.posture.score !== null && data.posture.score >= 40 ? 'danger' : 'success'}
                height={200}
                zeroBased
              />
            </div>
          </Panel>

          <Panel flush>
            <PanelHeader title="Findings by severity" subtitle={`${data.findingTally.critical + data.findingTally.high} critical or high`} />
            <div className="p-4">
              <DonutChart
                label="Findings by severity"
                data={data.severityDistribution.map((entry) => ({
                  label: entry.label,
                  value: entry.value,
                  tone:
                    entry.label === 'critical'
                      ? ('critical' as const)
                      : entry.label === 'high'
                        ? ('danger' as const)
                        : entry.label === 'medium'
                          ? ('warning' as const)
                          : entry.label === 'low'
                            ? ('info' as const)
                            : ('success' as const),
                }))}
                centerLabel="Findings"
              />
            </div>
          </Panel>
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          <Panel flush>
            <PanelHeader title="Sessions by mode" />
            <div className="p-4">
              <BarChart label="Sessions by VPN mode" data={toBars(data.sessionsByMode)} horizontal />
            </div>
          </Panel>
          <Panel flush>
            <PanelHeader title="Encryption algorithms" />
            <div className="p-4">
              <BarChart label="Sessions by encryption algorithm" data={toBars(data.encryptionDistribution)} horizontal />
            </div>
          </Panel>
          <Panel flush>
            <PanelHeader
              title="AI confidence"
              subtitle="Self-reported by the analysis models"
            />
            <div className="p-4">
              <BarChart
                label="Sessions by confidence band"
                data={data.aiConfidenceDistribution.map((entry) => ({
                  label: entry.label,
                  value: entry.value,
                  tone: entry.label.startsWith('90') ? ('success' as const) : entry.label.startsWith('75') ? ('info' as const) : ('warning' as const),
                }))}
                horizontal
              />
            </div>
          </Panel>
        </div>

        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
          <RecentFindings findings={data.recentFindings} />
          <ActiveSessions sessions={data.activeSessions} />
        </div>

        <SystemStrip status={data.systemStatus} updatedAt={dataUpdatedAt} />
      </PageBody>
    </PageScroll>
  )
}

/* ------------------------------------------------------------------ */
/* Pieces                                                              */
/* ------------------------------------------------------------------ */

const TONE_CLASS: Record<KpiMetric['tone'], string> = {
  neutral: 'text-mist',
  positive: 'text-success',
  warning: 'text-warning',
  danger: 'text-critical',
  accent: 'text-accent-300',
}

function KpiCard({ kpi }: { kpi: KpiMetric }) {
  const DirectionIcon =
    kpi.deltaDirection === 'up' ? ArrowUpRight : kpi.deltaDirection === 'down' ? ArrowDownRight : Minus

  return (
    <div className="flex flex-col gap-1 rounded-lg border border-edge bg-night-900 p-3">
      <span className="text-[11px] uppercase tracking-wide text-mist-faint">{kpi.label}</span>
      <span className={cx('font-mono text-xl font-semibold', TONE_CLASS[kpi.tone])}>{kpi.display}</span>
      {kpi.delta === null ? (
        <span className="text-[10px] text-mist-faint">No comparison window</span>
      ) : (
        <span
          className={cx(
            'flex items-center gap-1 text-[10px]',
            kpi.delta === 0 ? 'text-mist-faint' : kpi.tone === 'danger' || kpi.tone === 'warning' ? 'text-warning' : 'text-mist-dim',
          )}
        >
          <DirectionIcon className="size-3" aria-hidden />
          {kpi.delta > 0 ? '+' : ''}
          {kpi.delta}% vs previous window
        </span>
      )}
      <span className="text-[10px] leading-snug text-mist-faint">{kpi.hint}</span>
    </div>
  )
}

function RecentFindings({ findings }: { findings: DashboardSummary['recentFindings'] }) {
  const columns = useMemo<ColumnDef<DashboardSummary['recentFindings'][number]>[]>(
    () => [
      {
        id: 'severity',
        header: 'Severity',
        width: '7rem',
        render: (row) => <SeverityTag severity={row.severity} />,
      },
      {
        id: 'title',
        header: 'Finding',
        render: (row) => (
          <Link to={`/findings/${row.id}`} className="text-mist hover:text-accent-300 hover:underline">
            {row.title}
          </Link>
        ),
      },
      {
        id: 'session',
        header: 'Session',
        width: '10rem',
        render: (row) =>
          row.sessionId ? (
            <Link to={`/vpn-sessions/${row.sessionId}`} className="font-mono text-xs text-mist-dim hover:text-accent-300">
              {row.sessionId}
            </Link>
          ) : (
            <span className="text-mist-faint">—</span>
          ),
      },
      {
        id: 'confidence',
        header: 'Confidence',
        width: '7rem',
        render: (row) => <ConfidenceTag confidence={row.confidence} />,
      },
      {
        id: 'detected',
        header: 'Detected',
        width: '9rem',
        align: 'right',
        render: (row) => (
          <span className="font-mono text-[11px] text-mist-faint">
            {new Date(row.detectedAt).toLocaleString()}
          </span>
        ),
      },
    ],
    [],
  )

  return (
    <Panel flush>
      <PanelHeader
        title="Recent findings"
        subtitle="Most recently detected across all sessions"
        actions={
          <Link to="/findings" className="btn btn-sm">
            View all
          </Link>
        }
      />
      <DataTable
        columns={columns}
        rows={findings}
        rowKey={(row) => row.id}
        empty="No findings have been produced yet."
      />
    </Panel>
  )
}

function ActiveSessions({ sessions }: { sessions: VpnSession[] }) {
  return (
    <Panel flush>
      <PanelHeader
        title="Active sessions"
        subtitle="Negotiating or carrying traffic"
        actions={
          <Link to="/vpn-sessions" className="btn btn-sm">
            All sessions
          </Link>
        }
      />
      <ul className="divide-y divide-edge/60">
        {sessions.length === 0 ? (
          <li className="px-4 py-8 text-center text-xs text-mist-faint">No active sessions.</li>
        ) : (
          sessions.map((session) => (
            <li key={session.id} className="flex items-center gap-3 px-3 py-2">
              <StatusDot
                tone={session.riskBand === 'critical' || session.riskBand === 'high' ? 'danger' : 'success'}
                pulse
              />
              <div className="min-w-0 flex-1">
                <Link to={`/vpn-sessions/${session.id}`} className="block truncate text-[13px] text-mist hover:text-accent-300">
                  {session.label}
                </Link>
                <span className="font-mono text-[11px] text-mist-faint">
                  {session.configuration.ikeVersion.value ?? 'Unknown'} · {session.configuration.encryption.value ?? 'Unknown'} ·{' '}
                  {ENVIRONMENT_LABEL[session.environment]}
                </span>
              </div>
              <div className="shrink-0 text-right">
                <Badge tone="muted">{SESSION_STATUS_LABEL[session.status]}</Badge>
                <div className="mt-0.5 font-mono text-[10px] text-mist-faint">risk {session.riskScore}</div>
              </div>
            </li>
          ))
        )}
      </ul>
    </Panel>
  )
}

function SystemStrip({ status, updatedAt }: { status: DashboardSummary['systemStatus']; updatedAt: number }) {
  return (
    <Panel flush>
      <PanelHeader
        title="Platform services"
        subtitle={`Last checked ${updatedAt ? new Date(updatedAt).toLocaleTimeString() : 'never'}`}
        actions={
          <Link to="/system-health" className="btn btn-sm">
            System health
          </Link>
        }
      />
      <ul className="grid gap-2 p-3 sm:grid-cols-2 lg:grid-cols-3">
        {status.map((service) => (
          <li key={service.label} className="flex items-start gap-2 rounded-md border border-edge bg-night-900 px-3 py-2">
            <StatusDot
              tone={
                service.status === 'operational'
                  ? 'success'
                  : service.status === 'degraded'
                    ? 'warning'
                    : service.status === 'offline'
                      ? 'danger'
                      : 'info'
              }
            />
            <div className="min-w-0">
              <div className="truncate text-[12px] text-mist">{service.label}</div>
              <div className="text-[11px] text-mist-faint">
                {SERVICE_STATUS_LABEL[service.status]} — {service.detail}
              </div>
            </div>
          </li>
        ))}
      </ul>
      <div className="flex items-center gap-2 border-t border-edge px-3 py-2 text-[10px] text-mist-faint">
        <RefreshCw className="size-3" aria-hidden />
        Simulated status: the platform is currently running on frontend mock services.
      </div>
    </Panel>
  )
}

function toBars(data: DashboardSummary['sessionsByMode']) {
  return data.slice(0, 6).map((entry) => ({ label: entry.label, value: entry.value }))
}
