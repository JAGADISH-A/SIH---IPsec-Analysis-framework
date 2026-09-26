import { useState } from 'react'
import { FlaskConical, X } from 'lucide-react'
import { Button } from '../common/Button.tsx'
import { Field } from '../common/Field.tsx'
import { Select } from '../common/Select.tsx'
import { Panel } from '../common/Panel.tsx'
import { useCreateExperiment } from '../../hooks/queries'
import { TRAFFIC_PROFILE_LABEL, type Experiment, type TrafficProfile } from '../../types/experiment'
import type { IkevVersion, IpVersion, VpnMode } from '../../types/session'

const ENCRYPTION = ['AES-CBC-128', 'AES-CBC-256', '3DES-CBC', 'AES-GCM-16', 'CHACHA20-POLY1305'] as const
const INTEGRITY = ['SHA-256', 'SHA-384', 'SHA-512', 'AES-CMAC-128', 'HMAC-SHA1-96'] as const
const DH_GROUPS = ['1 (MODP 768)', '2 (MODP 1024)', '5 (MODP 1536)', '14 (MODP 2048)', '19 (ECDH 256)'] as const
const PROFILES: TrafficProfile[] = [
  'interactive',
  'bulk-transfer',
  'streaming',
  'rekey-cycle',
  'idle',
  'malformed-probe',
]

/**
 * Experiment creation.
 *
 * Everything entered here becomes declared ground truth, which the detail page
 * later compares the observation against. That is why the form insists on an
 * explicit configuration and refuses to infer one.
 */
export function NewExperimentForm({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (experiment: Experiment) => void
}) {
  const create = useCreateExperiment()
  const [form, setForm] = useState({
    name: '',
    hypothesis: '',
    ikeVersion: 'IKEv2' as IkevVersion,
    vpnMode: 'tunnel' as VpnMode,
    encryption: 'AES-CBC-256' as string,
    integrity: 'AES-CMAC-128' as string,
    dhGroup: DH_GROUPS[3] as string,
    perfectForwardSecrecy: true,
    ipVersion: 'IPv4' as IpVersion,
    trafficProfile: 'interactive' as TrafficProfile,
    durationMinutes: 2,
  })

  const set = <K extends keyof typeof form>(key: K, value: (typeof form)[K]) =>
    setForm((previous) => ({ ...previous, [key]: value }))

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    create.mutate(
      {
        name: form.name,
        hypothesis: form.hypothesis,
        ikeVersion: form.ikeVersion,
        vpnMode: form.vpnMode,
        encryption: form.encryption,
        integrity: form.integrity,
        dhGroup: form.dhGroup,
        perfectForwardSecrecy: form.perfectForwardSecrecy,
        ipVersion: form.ipVersion,
        trafficProfile: form.trafficProfile,
        durationMinutes: form.durationMinutes,
      },
      { onSuccess: (experiment) => onCreated(experiment) },
    )
  }

  const invalid = form.name.trim().length === 0 || form.hypothesis.trim().length === 0

  return (
    <Panel padded>
      <div className="flex items-center justify-between gap-2">
        <h2 className="flex items-center gap-1.5 text-[13px] font-semibold tracking-wide text-mist">
          <FlaskConical className="size-3.5 text-mist-faint" aria-hidden />
          New experiment
        </h2>
        <Button size="icon-sm" onClick={onClose} aria-label="Close the experiment form">
          <X className="size-3.5" aria-hidden />
        </Button>
      </div>

      <p className="mt-1 text-[11px] leading-relaxed text-mist-faint">
        The values below are recorded as ground truth before the run starts. The platform will read the configuration
        back from the capture and compare it with what was declared here.
      </p>

      <form onSubmit={submit} className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <div className="sm:col-span-2 lg:col-span-3">
          <Field
            label="Name"
            value={form.name}
            onChange={(event) => set('name', event.target.value)}
            placeholder="e.g. DH group 2 downgrade probe"
            required
          />
        </div>
        <div className="sm:col-span-2 lg:col-span-3">
          <Field
            label="Hypothesis"
            value={form.hypothesis}
            onChange={(event) => set('hypothesis', event.target.value)}
            placeholder="What this run should demonstrate"
            required
          />
        </div>

        <Select
          label="IKE version"
          value={form.ikeVersion}
          onChange={(event) => set('ikeVersion', event.target.value as IkevVersion)}
        >
          <option value="IKEv1">IKEv1</option>
          <option value="IKEv2">IKEv2</option>
        </Select>
        <Select label="VPN mode" value={form.vpnMode} onChange={(event) => set('vpnMode', event.target.value as VpnMode)}>
          <option value="tunnel">Tunnel</option>
          <option value="transport">Transport</option>
        </Select>
        <Select label="IP version" value={form.ipVersion} onChange={(event) => set('ipVersion', event.target.value as IpVersion)}>
          <option value="IPv4">IPv4</option>
          <option value="IPv6">IPv6</option>
          <option value="Mixed">Mixed</option>
        </Select>

        <Select
          label="Encryption"
          value={form.encryption}
          onChange={(event) => set('encryption', event.target.value)}
        >
          {ENCRYPTION.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </Select>
        <Select label="Integrity" value={form.integrity} onChange={(event) => set('integrity', event.target.value)}>
          {INTEGRITY.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </Select>
        <Select label="DH group" value={form.dhGroup} onChange={(event) => set('dhGroup', event.target.value)}>
          {DH_GROUPS.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </Select>

        <Select
          label="Traffic profile"
          value={form.trafficProfile}
          onChange={(event) => set('trafficProfile', event.target.value as TrafficProfile)}
        >
          {PROFILES.map((value) => (
            <option key={value} value={value}>
              {TRAFFIC_PROFILE_LABEL[value]}
            </option>
          ))}
        </Select>
        <Field
          label="Duration (minutes)"
          type="number"
          min={1}
          max={60}
          value={form.durationMinutes}
          onChange={(event) => set('durationMinutes', Number(event.target.value))}
        />
        <label className="flex items-end gap-2 pb-1.5 text-[12px] text-mist-dim">
          <input
            type="checkbox"
            checked={form.perfectForwardSecrecy}
            onChange={(event) => set('perfectForwardSecrecy', event.target.checked)}
            className="mb-0.5 accent-accent-500"
          />
          Require perfect forward secrecy
        </label>

        {create.isError ? (
          <p role="alert" className="sm:col-span-2 lg:col-span-3 rounded-md border border-danger bg-danger-dim px-2.5 py-1.5 text-[12px] text-danger">
            {create.error.message}
          </p>
        ) : null}

        <div className="flex items-center gap-2 sm:col-span-2 lg:col-span-3">
          <Button type="submit" variant="primary" disabled={invalid || create.isPending}>
            {create.isPending ? 'Starting…' : 'Start run'}
          </Button>
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <span className="text-[10.5px] text-mist-faint">
            Runs are simulated in this build. The testbed driver will take this configuration unchanged.
          </span>
        </div>
      </form>
    </Panel>
  )
}
