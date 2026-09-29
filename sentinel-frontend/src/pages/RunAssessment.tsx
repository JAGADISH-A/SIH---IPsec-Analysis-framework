import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { createExperiment, getExperimentConfigurations } from '@/api/control'
import { ApiRequestError } from '@/api/client'
import { useResource } from '@/hooks/useResource'
import { ErrorState, LoadingPanel } from '@/components/states'
import { Button, Panel, Tag } from '@/components/ui'
import { PageHeader } from '@/layouts/AppLayout'
import { humanize } from '@/lib/format'
import type { ExperimentRequest } from '@/types'

type Draft = {
  mode: string
  address_family: string
  ike_encryption: string
  ike_integrity: string
  ike_dh_group: string
  esp_encryption: string
  esp_integrity: string
  esp_dh_group: string
  esp_pfs: boolean
  traffic_profile: string
  traffic_duration: number
}

/**
 * The stages a run moves through, in the order an analyst experiences them.
 *
 * `key` is the status the control plane reports; `label` is what the stage
 * means. Keeping the mapping in one place means the progress list and the
 * result page cannot disagree about what "CONNECTIVITY" was doing.
 */
export const STAGE_SEQUENCE = [
  { key: 'QUEUED', label: 'Accepted', detail: 'Request received and queued' },
  { key: 'DEPLOY', label: 'Deploying topology', detail: 'Starting the testbed lab' },
  { key: 'IPSEC', label: 'Establishing tunnel', detail: 'Loading the IPsec configuration' },
  { key: 'OBSERVATION', label: 'Preparing live observation', detail: 'Attaching the XDP live packet feed' },
  { key: 'CONNECTIVITY', label: 'Verifying connectivity', detail: 'Checking the security association' },
  { key: 'TRAFFIC', label: 'Generating traffic', detail: 'Running the selected traffic profile' },
  { key: 'COMPLETED', label: 'Analysing', detail: 'Scoring the capture into an assessment' },
] as const

/** A labelled select. All options come from the control plane. */
function Field({
  label,
  value,
  options,
  onChange,
  hint,
  render = humanize,
  emptyLabel = 'Not set',
}: {
  label: string
  value: string
  options: string[]
  onChange: (value: string) => void
  hint?: string
  render?: (value: string) => string
  emptyLabel?: string
}) {
  return (
    <label className="flex min-w-0 flex-col gap-1.5">
      <span className="label">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full rounded-md border border-edge bg-panel px-2.5 py-1.5 text-base text-ink transition-colors hover:border-ink-faint focus:border-sentinel focus:outline-none focus:ring-2 focus:ring-sentinel/15"
      >
        {options.length === 0 && <option value="">{emptyLabel}</option>}
        {options.map((option) => (
          <option key={option} value={option}>
            {render(option)}
          </option>
        ))}
      </select>
      {hint && <span className="text-xs text-ink-faint">{hint}</span>}
    </label>
  )
}

/** A two-state segmented control, for booleans where both options are valid. */
function Toggle({
  label,
  value,
  options,
  onChange,
  hint,
}: {
  label: string
  value: boolean
  options: readonly boolean[]
  onChange: (value: boolean) => void
  hint?: string
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <span className="label">{label}</span>
      <div className="flex gap-1.5">
        {options.map((option) => (
          <button
            key={String(option)}
            type="button"
            aria-pressed={value === option}
            onClick={() => onChange(option)}
            className={`flex-1 rounded-md border px-2.5 py-1.5 text-sm font-medium transition-colors ${
              value === option
                ? 'border-sentinel/40 bg-sentinel/8 text-sentinel-deep'
                : 'border-edge bg-panel text-ink-dim hover:bg-panel-2 hover:text-ink'
            }`}
          >
            {option ? 'Enabled' : 'Disabled'}
          </button>
        ))}
      </div>
      {hint && <span className="text-xs text-ink-faint">{hint}</span>}
    </div>
  )
}

/**
 * The "planned configuration" summary.
 *
 * This is the confirmation step, not a debug dump: it restates the choices in
 * the same words the form used, so an analyst can check intent against what
 * will actually be built. The exact request body is still available, but only
 * behind an explicit disclosure.
 */
function PlannedConfiguration({ draft }: { draft: Draft }) {
  return (
    <Panel title="Planned configuration" subtitle="What this assessment will test">
      <dl className="grid grid-cols-2 gap-x-5 gap-y-4 p-4 sm:grid-cols-3 lg:grid-cols-4">
        {(
          [
            ['Mode', draft.mode],
            ['Address family', draft.address_family],
            ['IKE encryption', draft.ike_encryption],
            ['IKE integrity', draft.ike_integrity],
            ['IKE DH group', draft.ike_dh_group],
            ['ESP encryption', draft.esp_encryption],
            ['ESP integrity', draft.esp_integrity],
            ['ESP DH group', draft.esp_dh_group],
            ['PFS', draft.esp_pfs ? 'Enabled' : 'Disabled'],
            ['Traffic profile', draft.traffic_profile],
            ['Duration', `${draft.traffic_duration}s`],
          ] as const
        ).map(([label, value]) => (
          <div key={label} className="min-w-0">
            <dt className="label">{label}</dt>
            <dd className="mono mt-0.5 truncate text-sm text-ink" title={value}>
              {value || 'none'}
            </dd>
          </div>
        ))}
      </dl>
    </Panel>
  )
}

/**
 * Run Assessment.
 *
 * Replaces the old Experiments console. The previous page led with a raw JSON
 * payload and a "POST experiment" mental model, which is the repository's
 * vocabulary, not the analyst's vocabulary — the person using this has a VPN
 * scenario in mind, not an HTTP request.
 *
 * The page is therefore a single form with a plain-language confirmation, and
 * the payload is demoted to a disclosure. Nothing about the request itself
 * changed: every option still comes from `GET /experiments/configurations`, and
 * the body still matches the `ExperimentConfig` model the backend validates.
 */
export function RunAssessment() {
  const navigate = useNavigate()
  const config = useResource((signal) => getExperimentConfigurations(signal))
  const [draft, setDraft] = useState<Draft | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<ApiRequestError | null>(null)

  const options = config.data

  const defaultsFor = useMemo(
    () =>
      (): Draft => ({
        mode: options?.modes[0] ?? 'tunnel',
        address_family: options?.address_families[0] ?? 'ipv4',
        ike_encryption: options?.ike.encryption[0] ?? '',
        ike_integrity: options?.ike.integrity[0] ?? '',
        ike_dh_group: options?.ike.dh_groups.at(-1) ?? '',
        esp_encryption: options?.esp.encryption[0] ?? '',
        esp_integrity: '',
        esp_dh_group: options?.esp.dh_groups.at(-1) ?? '',
        esp_pfs: true,
        traffic_profile: options?.traffic.profiles[0] ?? '',
        traffic_duration: options?.traffic.duration.default ?? 30,
      }),
    [options],
  )

  const active = draft ?? (options ? defaultsFor() : null)

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => {
    setDraft({ ...(draft ?? defaultsFor()), [key]: value })
    setSubmitError(null)
  }

  /** The exact body the control plane will validate. */
  const payload: ExperimentRequest | null =
    active && options
      ? {
          mode: active.mode,
          address_family: active.address_family,
          ike: {
            version: options.ike.version,
            encryption: active.ike_encryption,
            integrity: active.ike_integrity,
            dh_group: active.ike_dh_group,
          },
          esp: {
            encryption: active.esp_encryption,
            integrity: active.esp_integrity === '' ? null : active.esp_integrity,
            dh_group: active.esp_dh_group,
            pfs: active.esp_pfs,
          },
          traffic: {
            profile: active.traffic_profile,
            duration: active.traffic_duration,
          },
        }
      : null

  const run = async () => {
    if (!payload) return
    setSubmitting(true)
    setSubmitError(null)
    try {
      const job = await createExperiment(payload)
      navigate(`/run/${encodeURIComponent(job.job_id)}`)
    } catch (cause) {
      setSubmitError(
        cause instanceof ApiRequestError
          ? cause
          : new ApiRequestError({
              title: 'Unable to start the assessment',
              detail: 'The request failed for an unexpected reason.',
              status: 0,
              code: 'unexpected_error',
              service: 'control',
            }),
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title="Run Assessment"
        description="Configure an IPsec scenario, run it against the testbed, and review the resulting assessment."
      />

      {config.error && <ErrorState error={config.error} onRetry={config.reload} />}
      {config.loading && <LoadingPanel label="Loading available configurations" rows={5} />}

      {options && active && (
        <>
          {/* ---------------------------------------------------- configure */}
          <Panel title="Test scenario" subtitle="Every option is validated by the control plane">
            <div className="space-y-5 p-4">
              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <Field
                  label="Tunnel / transport mode"
                  value={active.mode}
                  options={options.modes}
                  onChange={(value) => set('mode', value)}
                />
                <Field
                  label="Address family"
                  value={active.address_family}
                  options={options.address_families}
                  onChange={(value) => set('address_family', value)}
                />
                <Field
                  label="Traffic profile"
                  value={active.traffic_profile}
                  options={options.traffic.profiles}
                  onChange={(value) => set('traffic_profile', value)}
                />
              </div>

              <div>
                <p className="label mb-2.5">Tunnel establishment (IKE)</p>
                <div className="grid gap-4 sm:grid-cols-3">
                  <Field
                    label="Encryption"
                    value={active.ike_encryption}
                    options={options.ike.encryption}
                    onChange={(value) => set('ike_encryption', value)}
                  />
                  <Field
                    label="Integrity"
                    value={active.ike_integrity}
                    options={options.ike.integrity}
                    onChange={(value) => set('ike_integrity', value)}
                  />
                  <Field
                    label="DH group"
                    value={active.ike_dh_group}
                    options={options.ike.dh_groups}
                    onChange={(value) => set('ike_dh_group', value)}
                  />
                </div>
              </div>

              <div>
                <p className="label mb-2.5">Data protection (ESP)</p>
                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                  <Field
                    label="Encryption"
                    value={active.esp_encryption}
                    options={options.esp.encryption}
                    onChange={(value) => set('esp_encryption', value)}
                  />
                  <Field
                    label="Integrity"
                    value={active.esp_integrity}
                    options={['', ...options.esp.integrity]}
                    onChange={(value) => set('esp_integrity', value)}
                    emptyLabel="None (AEAD)"
                    hint="Leave unset for AEAD ciphers, which authenticate as part of encryption."
                  />
                  <Field
                    label="DH / PFS group"
                    value={active.esp_dh_group}
                    options={options.esp.dh_groups}
                    onChange={(value) => set('esp_dh_group', value)}
                  />
                  <Toggle
                    label="Perfect forward secrecy"
                    value={active.esp_pfs}
                    options={options.esp.pfs}
                    onChange={(value) => set('esp_pfs', value)}
                  />
                </div>
              </div>

              <div className="grid gap-4 sm:grid-cols-3">
                <label className="flex min-w-0 flex-col gap-1.5">
                  <span className="label">Duration (seconds)</span>
                  <input
                    type="number"
                    min={options.traffic.duration.min}
                    max={options.traffic.duration.max}
                    value={active.traffic_duration}
                    onChange={(event) =>
                      set(
                        'traffic_duration',
                        Math.min(
                          options.traffic.duration.max,
                          Math.max(
                            options.traffic.duration.min,
                            Number(event.target.value) || options.traffic.duration.default,
                          ),
                        ),
                      )
                    }
                    className="tnum w-full rounded-md border border-edge bg-panel px-2.5 py-1.5 text-base text-ink transition-colors hover:border-ink-faint focus:border-sentinel focus:outline-none focus:ring-2 focus:ring-sentinel/15"
                  />
                  <span className="text-xs text-ink-faint">
                    {options.traffic.duration.min}–{options.traffic.duration.max}s
                  </span>
                </label>
              </div>
            </div>
          </Panel>

          <PlannedConfiguration draft={active} />

          {submitError && <ErrorState error={submitError} onRetry={() => void run()} />}

          {/* --------------------------------------------------------- run */}
          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={() => void run()} disabled={submitting} className="px-4 py-2">
              {submitting ? 'Starting…' : 'Run Assessment'}
            </Button>
            {draft && (
              <Button
                variant="ghost"
                onClick={() => {
                  setDraft(null)
                  setSubmitError(null)
                }}
              >
                Reset to defaults
              </Button>
            )}
            <span className="text-xs text-ink-faint">
              Runs against the containerlab testbed. Results are scored by the backend
              risk engine.
            </span>
          </div>

          {/* ------------------------------------------------------ what next */}
          <Panel title="What happens when you run this">
            <ol className="space-y-2.5 p-4">
              {STAGE_SEQUENCE.map((stage, index) => (
                <li key={stage.key} className="flex items-start gap-3">
                  <span className="tnum mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-panel-3 text-2xs font-semibold text-ink-dim">
                    {index + 1}
                  </span>
                  <span className="min-w-0">
                    <span className="text-base text-ink">{stage.label}</span>
                    <span className="ml-2 text-sm text-ink-faint">{stage.detail}</span>
                  </span>
                </li>
              ))}
              <li className="flex items-start gap-3">
                <span className="tnum mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-panel-3 text-2xs font-semibold text-ink-dim">
                  {STAGE_SEQUENCE.length + 1}
                </span>
                <span className="min-w-0">
                  <span className="text-base text-ink">Review findings</span>
                  <span className="ml-2 text-sm text-ink-faint">
                    Open the assessment to compare expected against observed
                  </span>
                </span>
              </li>
            </ol>
          </Panel>

          {/* ------------------------------------------------------ advanced */}
          <details className="group">
            <summary className="cursor-pointer list-none text-sm font-medium text-ink-dim transition-colors hover:text-ink">
              <span className="group-open:hidden">Advanced · show request payload</span>
              <span className="hidden group-open:inline">Advanced · hide request payload</span>
            </summary>
            <div className="mt-2">
              <p className="mb-2 text-xs text-ink-faint">
                The exact JSON body sent to the control plane. Provided for
                interoperability and debugging; the form above is the interface.
              </p>
              <pre className="code-block overflow-x-auto p-3">
                {JSON.stringify(payload, null, 2)}
              </pre>
            </div>
          </details>

          <div className="flex flex-wrap items-center gap-2">
            <Tag>The control plane performs this action; the analytics plane stays read-only</Tag>
          </div>
        </>
      )}
    </div>
  )
}
