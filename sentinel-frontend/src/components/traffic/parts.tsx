import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import type { EvidenceRef } from '@/types'
import type { Provenance } from '@/lib/traffic'
import { formatBytes, formatNumber, formatUtc, humanize } from '@/lib/format'
import { Tag } from '@/components/ui'

/* --------------------------------------------------------------- provenance */

/**
 * A labelled value whose provenance class is always visible.
 *
 * `OBSERVED` is a measurement from the capture, `CONFIGURED` is what the
 * planner asked for, `INFERRED` and `MODEL-DERIVED` are not measurements at
 * all. Collapsing those into one "value" column is the single easiest way to
 * turn a defensible assessment into an indefensible one, so the label is part
 * of the component rather than something callers remember to add.
 */
export function ProvenanceValue({
  provenance,
  label,
  children,
  mono = false,
  notObservable = false,
}: {
  provenance: Provenance
  label?: ReactNode
  children: ReactNode
  mono?: boolean
  /** Render the canonical "Not observable" state instead of a value. */
  notObservable?: boolean
}) {
  if (notObservable) {
    return (
      <div className="min-w-0">
        <span className="label text-ink-faint">
          {label}
        </span>
        <p className="mono text-sm text-ink-faint/80">Not observable</p>
      </div>
    )
  }
  return (
    <div className="min-w-0">
      <span className="flex items-center gap-1.5 label text-ink-faint">
        {label}
        <ProvenanceChip provenance={provenance} />
      </span>
      <p
        className={`break-words text-sm text-ink ${mono ? 'mono' : ''}`}
      >
        {children}
      </p>
    </div>
  )
}

const PROVENANCE_TONE: Record<Provenance, string> = {
  OBSERVED: 'border-good/35 bg-good/10 text-good',
  CONFIGURED: 'border-sentinel/35 bg-sentinel/10 text-sentinel',
  INFERRED: 'border-medium/35 bg-medium/10 text-medium',
  'MODEL-DERIVED': 'border-high/35 bg-high/10 text-high',
  REPORTED: 'border-edge bg-ink-faint/10 text-ink-dim',
}

export function ProvenanceChip({ provenance }: { provenance: Provenance }) {
  return (
    <span
      className={`rounded border px-1 py-px text-xs font-semibold tracking-[0.1em] ${PROVENANCE_TONE[provenance]}`}
    >
      {provenance}
    </span>
  )
}

/* --------------------------------------------------------------- risk block */

export function RiskBand({
  score,
  severity,
  policyVersion,
  contributions,
}: {
  score: number | null
  severity: string | null
  policyVersion?: string
  contributions?: { severity: string; weight: number; added: number; finding_id?: string }[]
}) {
  if (score === null) {
    return (
      <p className="text-sm text-ink-faint">
        Not observable — the backend risk engine produced no score for this entity.
      </p>
    )
  }
  return (
    <div className="space-y-3">
      <div className="flex items-end gap-4">
        <div>
          <p className="label text-ink-faint">
            Overall risk
          </p>
          <p className="mono tnum text-[30px] font-semibold leading-none text-ink">{score}</p>
        </div>
        <div className="pb-1">
          <p className="label text-ink-faint">
            Severity
          </p>
          <p className="text-base font-medium text-ink">{severity ?? 'UNRATED'}</p>
        </div>
        {policyVersion && (
          <div className="pb-1">
            <p className="label text-ink-faint">
              Policy
            </p>
            <p className="mono text-sm text-ink-dim">{policyVersion}</p>
          </div>
        )}
      </div>
      <p className="text-xs leading-relaxed text-ink-faint">
        This score is produced by the backend risk engine and is read verbatim. Sentinel does not
        recompute, adjust or re-weight it.
      </p>
      {contributions && contributions.length > 0 && (
        <div className="overflow-x-auto rounded-md border border-edge">
          <table className="data-table">
            <thead>
              <tr>
                {['Rule / finding', 'Severity', 'Weight', 'Added'].map((heading) => (
                  <th key={heading} scope="col">
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {contributions.map((contribution, index) => (
                <tr key={`${contribution.finding_id ?? 'c'}-${index}`}>
                  <td className="mono text-sm text-ink-dim">
                    {contribution.finding_id ?? '—'}
                  </td>
                  <td className="text-sm text-ink-dim">
                    {contribution.severity}
                  </td>
                  <td className="mono tnum px-2.5 py-1.5 text-xs text-ink-faint">
                    {contribution.weight}
                  </td>
                  <td className="mono tnum px-2.5 py-1.5 text-xs text-ink">
                    +{contribution.added}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/* --------------------------------------------------------------- evidence */

export function EvidenceList({
  refs,
  onSelect,
  selectedId,
}: {
  refs: EvidenceRef[]
  onSelect?: (ref: EvidenceRef) => void
  selectedId?: string | null
}) {
  if (refs.length === 0) {
    return (
      <p className="text-sm text-ink-faint">
        Not observable — no evidence reference is attached to this entity. An empty list means
        nothing was recorded, not that verification passed.
      </p>
    )
  }
  return (
    <ul className="space-y-1.5">
      {refs.map((ref, index) => {
        const id = ref.evidence_id ?? `${ref.pcap_path}-${index}`
        const selected = selectedId === id
        return (
          <li key={id}>
            <button
              type="button"
              onClick={() => onSelect?.(ref)}
              disabled={!onSelect}
              className={`w-full rounded border px-2.5 py-2 text-left transition-colors ${
                selected
                  ? 'border-sentinel/45 bg-sentinel/10'
                  : 'border-edge bg-panel-2 hover:border-ink-faint'
              } ${onSelect ? 'cursor-pointer' : 'cursor-default'}`}
            >
              <div className="flex flex-wrap items-center gap-1.5">
                <ProvenanceChip provenance="OBSERVED" />
                <span className="mono truncate text-xs text-ink-dim" title={ref.pcap_path}>
                  {ref.pcap_path || 'path not recorded'}
                </span>
              </div>
              <div className="mono mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-ink-faint">
                {ref.artifact_sha256 ? (
                  <span title={ref.artifact_sha256}>sha256 {ref.artifact_sha256.slice(0, 16)}…</span>
                ) : (
                  <span>sha256 Not observable</span>
                )}
                <span>{formatBytes(ref.byte_size)}</span>
                {ref.capture_start_ns !== null && ref.capture_start_ns !== undefined && (
                  <span>{formatUtc(ref.capture_start_ns)}</span>
                )}
                {ref.packet_start !== null && ref.packet_start !== undefined && (
                  <span>
                    packets {formatNumber(ref.packet_start)}–{formatNumber(ref.packet_end ?? ref.packet_start)}
                  </span>
                )}
              </div>
            </button>
          </li>
        )
      })}
    </ul>
  )
}

/* ------------------------------------------------------------------ custody */

export function CustodySteps({
  steps,
}: {
  steps: { index: number; stage: string; component: string; action: string; outcome: string; authoritative: boolean }[]
}) {
  if (steps.length === 0) {
    return (
      <p className="text-sm text-ink-faint">
        Not observable — no custody chain is recorded for this finding.
      </p>
    )
  }
  return (
    <ol className="space-y-0">
      {steps.map((step, index) => (
        <li key={step.index} className="flex gap-3">
          <div className="flex flex-col items-center">
            <span
              className={`mt-1 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-xs font-semibold ${
                step.authoritative
                  ? 'border-good/45 bg-good/10 text-good'
                  : 'border-edge bg-panel-2 text-ink-faint'
              }`}
            >
              {step.index}
            </span>
            {index < steps.length - 1 && (
              <span className="w-px flex-1 bg-edge" aria-hidden="true" />
            )}
          </div>
          <div className="min-w-0 flex-1 pb-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-sm font-medium text-ink">{humanize(step.stage)}</span>
              {step.authoritative ? (
                <ProvenanceChip provenance="OBSERVED" />
              ) : (
                <ProvenanceChip provenance="REPORTED" />
              )}
            </div>
            <p className="mt-0.5 text-sm leading-relaxed text-ink-dim">{step.action}</p>
            <p className="mono mt-0.5 text-xs text-ink-faint">
              {step.component} → {step.outcome}
            </p>
          </div>
        </li>
      ))}
    </ol>
  )
}

/* ------------------------------------------------------------------- misc */

export function NotObservable({ what }: { what: string }) {
  return (
    <p className="rounded-md border border-edge bg-panel-2 px-3 py-2.5 text-sm leading-relaxed text-ink-faint">
      <span className="mono text-ink-dim">Not observable</span> — {what}. Sentinel renders this
      state rather than substituting a default, because a plausible-looking value here would be
      read as something the backend actually measured.
    </p>
  )
}

export function DetailLink({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link
      to={to}
      className="text-xs text-sentinel underline-offset-2 transition-colors hover:underline"
    >
      {children}
    </Link>
  )
}

export { Tag }
