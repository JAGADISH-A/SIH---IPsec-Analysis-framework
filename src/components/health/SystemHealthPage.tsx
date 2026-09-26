import { Activity, AlertTriangle, CheckCircle2, HelpCircle, ServerOff, XCircle } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { KeyValueList } from '../../components/common/Data.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { ErrorPanel, LoadingPanel } from '../../components/common/QueryState.tsx'
import { Panel } from '../../components/common/Panel.tsx'
import { StatusDot, StatusPill } from '../../components/common/StatusDot.tsx'
import { useSystemHealth } from '../../hooks/queries'
import { MISSING_BACKEND_WARNING } from '../../services'
import { cx } from '../../lib/cx'
import type { SeverityTone } from '../../types/common'
import {
  SERVICE_DESCRIPTION,
  SERVICE_STATUS_LABEL,
  type ServiceHealth,
  type ServiceStatus,
} from '../../types/health'
import { env } from '../../config/env'

const STATUS_TONE: Record<ServiceStatus, SeverityTone> = {
  operational: 'success',
  degraded: 'warning',
  offline: 'danger',
  unknown: 'info',
}

const STATUS_ICON = {
  operational: CheckCircle2,
  degraded: AlertTriangle,
  offline: XCircle,
  unknown: HelpCircle,
} as const

/**
 * System health.
 *
 * The page reports what it can actually observe. In mock mode it says so
 * explicitly rather than showing invented latencies as if they were measured.
 */
export function SystemHealthPage() {
  const health = useSystemHealth()

  return (
    <PageScroll>
      <PageHeader
        title="System Health"
        description="Dependency status as this client can observe it, including which of them are simulated."
        meta={
          health.data ? (
            <>
              <span>Checked {new Date(health.data.checkedAt).toLocaleTimeString()}</span>
              <span className="font-mono">{health.data.apiBaseUrl}</span>
            </>
          ) : null
        }
      />

      <PageBody>
        {health.isLoading ? <LoadingPanel rows={6} /> : null}
        {health.isError ? <ErrorPanel error={health.error} onRetry={() => void health.refetch()} /> : null}

        {health.data ? (
          <>
            {MISSING_BACKEND_WARNING ? (
              <div role="alert" className="flex items-start gap-2 rounded-lg border border-danger bg-danger-dim px-4 py-3">
                <ServerOff className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden />
                <div>
                  <div className="text-[12.5px] font-medium text-danger">
                    This build is configured to use HTTP services, but no HTTP implementations are wired yet.
                  </div>
                  <p className="mt-0.5 text-[11.5px] leading-relaxed text-mist-dim">
                    The figures below are still simulated. Set <code className="font-mono">VITE_USE_MOCK_DATA=true</code>{' '}
                    to acknowledge the simulated data source, or add the REST services to the composition root.
                  </p>
                </div>
              </div>
            ) : null}

            <div className="flex flex-wrap items-center gap-3 rounded-lg border border-edge bg-night-900 px-4 py-3">
              <StatusDot tone={STATUS_TONE[health.data.overall]} pulse={health.data.overall !== 'operational'} />
              <span className="text-[13px] font-medium text-mist">
                {SERVICE_STATUS_LABEL[health.data.overall]}
              </span>
              {health.data.mockMode ? (
                <Badge tone="warning">Mock mode — no live infrastructure is being contacted</Badge>
              ) : (
                <Badge tone="info">Connected to {health.data.apiBaseUrl}</Badge>
              )}
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              {health.data.services.map((service) => (
                <ServiceCard key={service.name} service={service} />
              ))}
            </div>

            <Panel padded>
              <h2 className="text-[13px] font-semibold tracking-wide text-mist">Client configuration</h2>
              <div className="mt-3">
                <KeyValueList
                  columns={2}
                  items={[
                    { label: 'Data source', value: env.useMockData ? 'Mock services' : 'HTTP services', mono: true },
                    { label: 'API base URL', value: env.apiBaseUrl, mono: true },
                    { label: 'Live event interval', value: `${env.liveEventIntervalMs} ms`, mono: true },
                    { label: 'Default refresh', value: `${env.refreshIntervalMs} ms`, mono: true },
                    { label: 'Application', value: env.appName, mono: true },
                  ]}
                />
              </div>
              <div className="mt-3">
                <RestrictedNote />
              </div>
            </Panel>

            <Panel padded>
              <h2 className="text-[13px] font-semibold tracking-wide text-mist">What this page cannot tell you</h2>
              <ul className="mt-2 flex list-disc flex-col gap-1 pl-5 text-[11.5px] leading-relaxed text-mist-dim">
                <li>Whether a dependency is reachable from another network vantage point.</li>
                <li>Whether the analysis pipeline is currently producing correct results, as opposed to running.</li>
                <li>Anything about infrastructure that this client has not been configured to contact.</li>
              </ul>
            </Panel>
          </>
        ) : null}
      </PageBody>
    </PageScroll>
  )
}

function ServiceCard({ service }: { service: ServiceHealth }) {
  const Icon = STATUS_ICON[service.status]
  return (
    <Panel padded>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Icon
              className={cx(
                'size-4 shrink-0',
                service.status === 'operational'
                  ? 'text-success'
                  : service.status === 'degraded'
                    ? 'text-warning'
                    : service.status === 'offline'
                      ? 'text-danger'
                      : 'text-mist-faint',
              )}
              aria-hidden
            />
            <span className="text-[13px] font-medium text-mist">{service.label}</span>
          </div>
          <p className="mt-1 text-[11.5px] leading-relaxed text-mist-dim">{SERVICE_DESCRIPTION[service.name]}</p>
        </div>
        <StatusPill tone={STATUS_TONE[service.status]} label={SERVICE_STATUS_LABEL[service.status]} />
      </div>

      <div className="mt-3">
        <KeyValueList
          items={[
            { label: 'Version', value: service.version || 'Not reported', mono: true },
            {
              label: 'Response time',
              value: service.responseTimeMs === null ? 'Not measurable' : `${service.responseTimeMs} ms`,
              mono: true,
            },
            { label: 'Last checked', value: new Date(service.lastChecked).toLocaleTimeString(), mono: true },
            { label: 'Detail', value: service.detail || '—' },
          ]}
        />
      </div>

      {service.error ? (
        <p role="status" className="mt-2 flex items-start gap-1.5 text-[11px] text-danger">
          <ServerOff className="mt-0.5 size-3 shrink-0" aria-hidden />
          {service.error}
        </p>
      ) : null}
    </Panel>
  )
}

function RestrictedNote() {
  return (
    <p className="flex items-start gap-2 rounded-md border border-edge bg-night-800 px-2.5 py-2 text-[10.5px] leading-relaxed text-mist-faint">
      <Activity className="mt-0.5 size-3 shrink-0" aria-hidden />
      All values above come from the browser. No credentials, tokens or hostnames of internal infrastructure are read
      into the frontend, and a service that cannot be probed is reported as unknown rather than as healthy.
    </p>
  )
}
