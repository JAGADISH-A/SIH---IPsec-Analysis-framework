import { Monitor, RotateCcw, Server, ShieldCheck } from 'lucide-react'
import { Button } from '../../components/common/Button.tsx'
import { Select } from '../../components/common/Select.tsx'
import { KeyValueList } from '../../components/common/Data.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { Panel } from '../../components/common/Panel.tsx'
import { StatusDot } from '../../components/common/StatusDot.tsx'
import { useSystemHealth } from '../../hooks/queries'
import { env } from '../../config/env'
import { REFRESH_INTERVAL_OPTIONS, TIME_ZONE_OPTIONS, useSettings } from '../../state/settings'
import type { Settings } from '../../state/settings'
import type { ReactNode } from 'react'

/**
 * Settings.
 *
 * Everything on this page is a local display preference persisted in this
 * browser. There is no account, no server-side profile, and deliberately no
 * field that could hold a credential.
 */
export function SettingsPage() {
  const { settings, update, updateNotification, reset } = useSettings()
  const health = useSystemHealth()

  const toggle = <K extends keyof Settings>(key: K, label: string, hint: string) => (
    <label className="flex items-start justify-between gap-4 py-2">
      <span className="min-w-0">
        <span className="block text-[12.5px] text-mist">{label}</span>
        <span className="block text-[11px] text-mist-faint">{hint}</span>
      </span>
      <input
        type="checkbox"
        checked={Boolean(settings[key])}
        onChange={(event) => update(key, event.target.checked as Settings[K])}
        className="mt-0.5 shrink-0 accent-accent-500"
      />
    </label>
  )

  return (
    <PageScroll>
      <PageHeader
        title="Settings"
        description="Display and accessibility preferences for this browser. Nothing here leaves the device, and nothing here can hold a secret."
        actions={
          <Button onClick={reset}>
            <RotateCcw className="size-3.5" aria-hidden />
            Reset to defaults
          </Button>
        }
      />

      <PageBody>
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel padded>
            <SectionTitle icon={<Monitor className="size-3.5" aria-hidden />} title="Appearance" />
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              <Select
                label="Theme"
                value={settings.theme}
                onChange={(event) => update('theme', event.target.value as Settings['theme'])}
              >
                <option value="system">Follow system</option>
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </Select>
              <Select
                label="Table density"
                value={settings.tableDensity}
                onChange={(event) => update('tableDensity', event.target.value as Settings['tableDensity'])}
              >
                <option value="compact">Compact</option>
                <option value="default">Default</option>
                <option value="relaxed">Relaxed</option>
              </Select>
              <Select
                label="Default dashboard"
                value={settings.defaultDashboard}
                onChange={(event) => update('defaultDashboard', event.target.value as Settings['defaultDashboard'])}
              >
                <option value="overview">Overview</option>
                <option value="sessions">Sessions</option>
                <option value="findings">Findings</option>
              </Select>
              <Select
                label="Time zone"
                value={settings.timeZone}
                onChange={(event) => update('timeZone', event.target.value)}
              >
                {TIME_ZONE_OPTIONS.map((zone) => (
                  <option key={zone} value={zone}>
                    {zone}
                  </option>
                ))}
              </Select>
            </div>

            <div className="mt-3 divide-y divide-edge/60">
              {toggle('reduceMotion', 'Reduce motion', 'Disables chart animation and non-essential transitions.')}
              {toggle(
                'highContrastFocus',
                'Stronger focus outlines',
                'Increases focus ring contrast for keyboard navigation.',
              )}
            </div>
          </Panel>

          <Panel padded>
            <SectionTitle icon={<ShieldCheck className="size-3.5" aria-hidden />} title="Data and evidence display" />
            <div className="mt-3 flex flex-col gap-2">
              <Select
                label="Confidence display"
                hint="Confidence is always recorded. This controls only how prominently it is shown."
                value={settings.confidenceDisplay}
                onChange={(event) => update('confidenceDisplay', event.target.value as Settings['confidenceDisplay'])}
              >
                <option value="always">Always show</option>
                <option value="on-hover">On hover or focus</option>
                <option value="never">Hide (evidence still records it)</option>
              </Select>
              <div className="rounded-md border border-edge bg-night-800 px-2.5 py-2 text-[11px] leading-relaxed text-mist-faint">
                A null confidence is always rendered as <span className="text-mist">Unknown</span>. No setting can
                display it as a number.
              </div>
            </div>

            <SectionTitle icon={<Server className="size-3.5" aria-hidden />} title="Refresh cadence" />
            <div className="mt-3">
              <Select
                label="Dashboard and session refresh"
                value={settings.refreshIntervalMs}
                onChange={(event) => update('refreshIntervalMs', Number(event.target.value))}
              >
                {REFRESH_INTERVAL_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </Select>
              <p className="mt-1.5 text-[11px] text-mist-faint">
                Live events are not polled on this cadence; the event stream has its own interval (
                {env.liveEventIntervalMs} ms).
              </p>
            </div>
          </Panel>

          <Panel padded>
            <SectionTitle icon={<ShieldCheck className="size-3.5" aria-hidden />} title="Notifications" />
            <p className="mt-1 text-[11px] text-mist-faint">
              Which in-app notifications the operator wants to see. No email, SMS or push is configured in this build.
            </p>
            <div className="mt-2 divide-y divide-edge/60">
              <NotificationRow
                label="Critical findings"
                hint="A new finding is rated critical."
                checked={settings.notifications.criticalFindings}
                onChange={(value) => updateNotification('criticalFindings', value)}
              />
              <NotificationRow
                label="Session state changes"
                hint="A session is established, rekeyed or torn down."
                checked={settings.notifications.sessionStateChanges}
                onChange={(value) => updateNotification('sessionStateChanges', value)}
              />
              <NotificationRow
                label="Experiment state changes"
                hint="A controlled run starts, completes or fails."
                checked={settings.notifications.experimentStateChanges}
                onChange={(value) => updateNotification('experimentStateChanges', value)}
              />
              <NotificationRow
                label="Service degradation"
                hint="A dependency stops reporting as operational."
                checked={settings.notifications.serviceDegradation}
                onChange={(value) => updateNotification('serviceDegradation', value)}
              />
            </div>
          </Panel>

          <Panel padded>
            <SectionTitle icon={<Server className="size-3.5" aria-hidden />} title="Environment" />
            <div className="mt-3">
              <KeyValueList
                items={[
                  { label: 'Application', value: env.appName, mono: true },
                  { label: 'Data source', value: env.useMockData ? 'Mock services' : 'HTTP services', mono: true },
                  { label: 'API base URL', value: env.apiBaseUrl, mono: true },
                  { label: 'Build-time refresh default', value: `${env.refreshIntervalMs} ms`, mono: true },
                ]}
              />
            </div>

            <div className="mt-3 rounded-md border border-edge bg-night-800 px-2.5 py-2 text-[11px] leading-relaxed text-mist-faint">
              <p className="flex items-start gap-1.5">
                <StatusDot
                  tone={
                    health.data?.overall === 'operational'
                      ? 'success'
                      : health.data?.overall === 'offline'
                        ? 'danger'
                        : 'warning'
                  }
                />
                <span>
                  Build-time environment values are visible to the browser. Tokens, keys and credentials must never be
                  placed in a <code className="font-mono">VITE_</code> variable, and this application has no field
                  that accepts one.
                </span>
              </p>
            </div>

            <div className="mt-3">
              <KeyValueList
                items={[
                  { label: 'Theme', value: settings.theme },
                  { label: 'Time zone', value: settings.timeZone },
                  { label: 'Refresh', value: `${settings.refreshIntervalMs} ms` },
                  { label: 'Confidence', value: settings.confidenceDisplay },
                ]}
              />
            </div>
          </Panel>
        </div>
      </PageBody>
    </PageScroll>
  )
}

function SectionTitle({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <h2 className="flex items-center gap-1.5 text-[13px] font-semibold tracking-wide text-mist">
      <span className="text-mist-faint">{icon}</span>
      {title}
    </h2>
  )
}

function NotificationRow({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string
  hint: string
  checked: boolean
  onChange: (value: boolean) => void
}) {
  return (
    <label className="flex items-start justify-between gap-4 py-2">
      <span className="min-w-0">
        <span className="block text-[12.5px] text-mist">{label}</span>
        <span className="block text-[11px] text-mist-faint">{hint}</span>
      </span>
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-0.5 shrink-0 accent-accent-500"
      />
    </label>
  )
}
