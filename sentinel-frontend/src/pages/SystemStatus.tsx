import { useMemo } from 'react'
import { getAnalyticsHealth, getAnalyticsV1Health, getAssessments } from '@/api/analytics'
import { getControlHealth } from '@/api/control'
import { aiHealth } from '@/api/ai'
import { useResource } from '@/hooks/useResource'
import { ErrorState, LoadingPanel, Spinner } from '@/components/states'
import { Button, LinkButton, Panel, StatusPill, Tag } from '@/components/ui'
import { PageHeader } from '@/layouts/AppLayout'
import { AI_API_URL, ANALYTICS_API_URL, CONTROL_API_URL } from '@/config'
import { formatNumber } from '@/lib/format'

type Reachability = 'checking' | 'connected' | 'unreachable'

function reach(resource: { loading: boolean; error: unknown; data: unknown }): Reachability {
  if (resource.loading) return 'checking'
  if (resource.error) return 'unreachable'
  if (resource.data) return 'connected'
  return 'unreachable'
}

const TONE: Record<Reachability, { dot: string; text: string; label: string }> = {
  checking: { dot: 'bg-medium', text: 'text-medium', label: 'checking' },
  connected: { dot: 'bg-good', text: 'text-good', label: 'connected' },
  unreachable: { dot: 'bg-critical', text: 'text-critical', label: 'unreachable' },
}

function EndpointRow({
  name,
  url,
  state,
  note,
  detail,
}: {
  name: string
  url: string
  state: Reachability
  note: string
  detail?: React.ReactNode
}) {
  const tone = TONE[state]
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-edge-soft px-4 py-3 last:border-0">
      <span className="flex items-center gap-2">
        <span
          className={`h-2 w-2 shrink-0 rounded-full ${tone.dot} ${state === 'checking' ? 'status-pending' : ''}`}
          aria-hidden="true"
        />
        <span className="text-sm font-medium text-ink">{name}</span>
      </span>
      <span className={`text-sm ${tone.text}`}>
        {state === 'checking' && <Spinner className="mr-1.5 h-3 w-3" />}
        {tone.label}
      </span>
      <span className="mono text-xs text-ink-faint">{url}</span>
      <span className="ml-auto text-xs text-ink-faint">{note}</span>
      {detail}
    </div>
  )
}

function ComponentGrid({
  components,
}: {
  components: Record<string, { status: string; detail?: string }> | undefined
}) {
  const entries = useMemo(() => Object.entries(components ?? {}), [components])
  if (entries.length === 0) {
    return (
      <p className="p-4 text-sm text-ink-faint">
        The analytics service reported no component breakdown.
      </p>
    )
  }
  return (
    <div className="grid gap-2 p-4 sm:grid-cols-2">
      {entries.map(([name, component]) => {
        const status = component.status.toLowerCase()
        const tone =
          status === 'healthy'
            ? 'good'
            : status === 'disabled'
              ? 'neutral'
              : status === 'degraded'
                ? 'warn'
                : 'bad'
        return (
          <div
            key={name}
            className="flex items-start gap-3 rounded-md border border-edge bg-panel-2 px-3 py-2.5"
          >
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium capitalize text-ink">
                {name.replace(/_/g, ' ')}
              </p>
              {component.detail && (
                <p className="mt-0.5 text-xs leading-snug text-ink-faint">
                  {component.detail}
                </p>
              )}
            </div>
            <StatusPill status={component.status} tone={tone} />
          </div>
        )
      })}
    </div>
  )
}

/**
 * System status.
 *
 * Every indicator is derived from a live call. The analytics plane is probed
 * with both `/api/health` and `/api/v1/health` because they report different
 * things: store-level readiness and per-component health. The control plane
 * has no component breakdown, so only its reachability and HTTP status are
 * shown.
 */
export function SystemStatus() {
  const analytics = useResource((signal) => getAnalyticsHealth(signal))
  const analyticsV1 = useResource((signal) => getAnalyticsV1Health(signal))
  const control = useResource((signal) => getControlHealth(signal))
  const ai = useResource((signal) => aiHealth().then((h) => {
    if (!h) throw new Error('no response')
    return h
  }))
  const store = useResource((signal) => getAssessments({ limit: 1 }, signal))

  const overview = store.data?.overview ?? null
  const analyticsState = reach(analytics)
  const controlState = reach(control)
  const storeState = reach(store)

  const allConnected = analyticsState === 'connected' && controlState === 'connected'

  return (
    <div className="space-y-5">
      <PageHeader
        title="System status"
        description="Live reachability for every backend this app depends on"
      />

      {/* Headline */}
      <div
        className={`panel p-4 ${
          allConnected
            ? 'border-good/25 bg-good/[0.04]'
            : 'border-critical/30 bg-critical/[0.05]'
        }`}
      >
        <div className="flex flex-wrap items-center gap-3">
          <span
            className={`flex h-9 w-9 items-center justify-center rounded-full border ${
              allConnected
                ? 'border-good/40 text-good'
                : 'border-critical/40 text-critical'
            }`}
            aria-hidden="true"
          >
            {allConnected ? (
              <svg viewBox="0 0 16 16" className="h-4.5 w-4.5" fill="none">
                <g stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="8" cy="8" r="6.2" />
                  <path d="m5.2 8.2 2 2 3.6-4" />
                </g>
              </svg>
            ) : (
              <svg viewBox="0 0 16 16" className="h-4.5 w-4.5" fill="none">
                <path
                  d="M8 1.5 15 14H1L8 1.5Z"
                  stroke="currentColor"
                  strokeWidth="1.4"
                  strokeLinejoin="round"
                />
                <path d="M8 6v4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                <circle cx="8" cy="12" r="0.9" fill="currentColor" />
              </svg>
            )}
          </span>
          <div>
            <h2 className="text-base font-semibold text-ink">
              {allConnected ? 'Both API planes are connected' : 'One or more API planes are unreachable'}
            </h2>
            <p className="mt-0.5 text-sm text-ink-faint">
              {allConnected
                ? 'Sentinel is showing live backend data. No value on any page is cached or synthesised.'
                : 'Start the missing service with scripts/serve-backend.sh, then retry.'}
            </p>
          </div>
          <Button
            variant="secondary"
            className="ml-auto"
            onClick={() => {
              analytics.reload()
              analyticsV1.reload()
              control.reload()
              store.reload()
            }}
          >
            Re-check
          </Button>
        </div>
      </div>

      {/* Endpoints */}
      <Panel title="API Planes" subtitle="live reachability, probed on every load">
        <EndpointRow
          name="Analytics API"
          url={`${ANALYTICS_API_URL}/api/health`}
          state={analyticsState}
          note={analytics.data?.service ?? 'phase-8 dashboard API'}
          detail={
            analytics.data ? (
              <span className="w-full pl-5 text-xs text-ink-faint sm:pl-0">
                {formatNumber(analytics.data.total_assessments)} assessments · store{' '}
                {analytics.data.store_version} · schema {analytics.data.api_schema_version} ·{' '}
                {analytics.data.read_only ? 'read-only' : 'writable'}
              </span>
            ) : null
          }
        />
        <EndpointRow
          name="Analytics components"
          url={`${ANALYTICS_API_URL}/api/v1/health`}
          state={reach(analyticsV1)}
          note={analyticsV1.data ? `overall ${analyticsV1.data.status}` : 'phase-10 components'}
        />
        <EndpointRow
          name="Control API"
          url={`${CONTROL_API_URL}/health`}
          state={controlState}
          note={
            control.data
              ? `status ${control.data.status} · configurations + experiments`
              : 'experiment control plane'
          }
        />
        {/*
          The explanation plane is optional, so it is reported separately and
          is deliberately excluded from `allConnected`: the app is fully
          functional without it, and a page that says "one or more planes are
          unreachable" because an optional helper is stopped would be crying
          wolf. The note says which of the two states this is, because "AI
          explanation: not configured" and "AI explanation: running, no model"
          call for different action.
        */}
        <EndpointRow
          name="AI explanation"
          url={`${AI_API_URL}/ai/health`}
          state={reach(ai)}
          note={
            ai.data
              ? ai.data.model.configured
                ? `read-only · model ${ai.data.model.model_version ?? 'configured'}`
                : 'read-only · no model configured; answers from recorded values'
              : 'optional · explains recorded assessments; start it to enable "Explain with AI"'
          }
        />
      </Panel>

      {/* Errors, if any */}
      {analytics.error && <ErrorState error={analytics.error} onRetry={analytics.reload} compact />}
      {control.error && <ErrorState error={control.error} onRetry={control.reload} compact />}

      {/* Dataset */}
      <Panel
        title="Assessment Store"
        subtitle="the dataset Sentinel reads; read-only"
      >
        {store.loading ? (
          <div className="p-4">
            <LoadingPanel label="Reading store" rows={3} />
          </div>
        ) : store.error ? (
          <div className="p-4">
            <ErrorState error={store.error} onRetry={store.reload} compact />
          </div>
        ) : overview ? (
          <div className="space-y-4 p-4">
            <div className="grid grid-cols-2 gap-x-5 gap-y-4 md:grid-cols-4">
              <div>
                <p className="label text-ink-faint">Available</p>
                <div className="mt-1">
                  <StatusPill
                    status={storeState}
                    tone={storeState === 'connected' ? 'good' : 'bad'}
                    label={storeState === 'connected' ? 'yes' : 'no'}
                  />
                </div>
              </div>
              <div>
                <p className="label text-ink-faint">
                  Assessments
                </p>
                <p className="mono tnum mt-1 text-xl text-ink">
                  {formatNumber(overview.total_assessments)}
                </p>
              </div>
              <div>
                <p className="label text-ink-faint">
                  Findings
                </p>
                <p className="mono tnum mt-1 text-xl text-ink">
                  {formatNumber(overview.findings_total)}
                </p>
              </div>
              <div>
                <p className="label text-ink-faint">
                  Dataset run
                </p>
                <p className="mono mt-1 break-all text-sm text-ink-dim">
                  {overview.dataset_run_id ?? '—'}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 border-t border-edge pt-3">
              <Tag>policy {overview.risk_policy_version}</Tag>
              <Tag>store {overview.store_version}</Tag>
              <Tag>xai {overview.xai_available ? 'available' : 'unavailable'}</Tag>
              <Tag>highest risk {overview.highest_risk ?? '—'}</Tag>
              <Tag>highest severity {overview.highest_severity ?? '—'}</Tag>
            </div>

            {overview.source && (
              <p className="border-t border-edge pt-3 text-xs leading-relaxed text-ink-faint">
                {overview.source}
              </p>
            )}
          </div>
        ) : null}
      </Panel>

      {/* Component breakdown */}
      <Panel
        title="Analytics Components"
        subtitle="reported by GET /api/v1/health"
      >
        <ComponentGrid components={analyticsV1.data?.components} />
      </Panel>

      {/* CORS / environment */}
      <Panel
        title="Client Configuration"
        subtitle="values this frontend was built with"
      >
        <dl className="grid grid-cols-1 gap-x-6 gap-y-3 p-4 md:grid-cols-2">
          <div>
            <dt className="label text-ink-faint">
              Analytics base URL
            </dt>
            <dd className="mono mt-0.5 text-sm text-ink">{ANALYTICS_API_URL}</dd>
          </div>
          <div>
            <dt className="label text-ink-faint">
              Control base URL
            </dt>
            <dd className="mono mt-0.5 text-sm text-ink">{CONTROL_API_URL}</dd>
          </div>
          {analyticsV1.data?.cors?.allowed_origins && (
            <div className="md:col-span-2">
              <dt className="label text-ink-faint">
                Origins the analytics API accepts
              </dt>
              <dd className="mt-1 flex flex-wrap gap-1.5">
                {analyticsV1.data.cors.allowed_origins.map((origin) => (
                  <span
                    key={origin}
                    className={`mono rounded border px-1.5 py-0.5 text-xs ${
                      typeof window !== 'undefined' && window.location.origin === origin
                        ? 'border-good/40 bg-good/10 text-good'
                        : 'border-edge text-ink-faint'
                    }`}
                  >
                    {origin}
                  </span>
                ))}
              </dd>
              {typeof window !== 'undefined' && (
                <p className="mt-1.5 text-xs text-ink-faint">
                  This page is served from{' '}
                  <span className="mono text-ink-dim">{window.location.origin}</span>. If it is
                  not in the list above, browser requests to the analytics API will be blocked
                  by CORS.
                </p>
              )}
            </div>
          )}
        </dl>
      </Panel>

      {/* Access model */}
      <div className="panel p-4">
        <p className="label text-ink-faint">
          Access model
        </p>
        <p className="mt-1.5 text-sm leading-relaxed text-ink-dim">
          Neither backend is configured with authentication, and both bind loopback by
          default. The analytics plane is read-only by construction — it exposes no route
          that resolves, dismisses, overrides or acknowledges a finding. The control plane is
          the only mutating surface, and it only orchestrates experiments. This prototype adds
          no login and no role model.
        </p>
        <div className="mt-2.5 flex flex-wrap gap-1.5">
          <Tag>no authentication</Tag>
          <Tag>loopback only</Tag>
          <Tag>read-only assessments</Tag>
          <Tag>mutating experiments</Tag>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <LinkButton to="/">← Back to overview</LinkButton>
        <LinkButton href={`${ANALYTICS_API_URL}/api/v1/docs`} external>
          Analytics API reference ↗
        </LinkButton>
        <LinkButton href={`${CONTROL_API_URL}/docs`} external>
          Control API reference ↗
        </LinkButton>
      </div>

      <p className="px-1 text-xs text-ink-faint">
        Nothing on this page is hardcoded: every indicator comes from a live response. If a
        service is down the page says so rather than showing a default that looks healthy.
      </p>
    </div>
  )
}
