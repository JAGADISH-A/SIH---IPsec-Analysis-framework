import { useState, type ReactNode } from 'react'
import { cx } from '../../lib/cx'
import { ConfidenceBadge } from './ConfidenceLens'
import { ProvenanceValue } from './DataSourceBadge'
import { DATA_SOURCE_LABEL } from '../../types/evidence'
import {
  TUNNEL_STAGE_DESCRIPTION,
  TUNNEL_STAGE_LABEL,
  type TunnelDna,
  type TunnelIdentity,
  type TunnelStage,
} from '../../types/identity'

/**
 * Tunnel DNA.
 *
 * The platform's signature view: an IPsec tunnel reconstructed as a lifecycle
 * rather than a list of status lights. Five stages in negotiation order, each
 * marked with how the platform knows it — solid for a value read from packets,
 * ringed for one a model or the correlation engine concluded, hollow for a
 * stage that was not observed at all.
 *
 * It is deliberately information-dense and static. Nothing animates: the
 * uniqueness is in the model, not in the motion.
 */

function dotClass(stage: TunnelStage): string {
  if (stage.pending) return 'border-mist-faint bg-transparent'
  if (stage.state === 'observed') return 'border-accent-400 bg-accent-400'
  return 'border-info bg-night-900'
}

function stageTitle(stage: TunnelStage): string {
  const provenance = stage.pending ? 'Not observed' : DATA_SOURCE_LABEL[stage.state]
  const confidence = stage.confidence === null ? 'confidence unknown' : `confidence ${Math.round(stage.confidence * 100)}%`
  return `${TUNNEL_STAGE_LABEL[stage.id]} — ${stage.detail} (${provenance}, ${confidence})`
}

/** Compact horizontal lifecycle strip for list rows. */
export function TunnelDnaStrip({
  dna,
  className,
  onSelectStage,
}: {
  dna: TunnelDna
  className?: string
  onSelectStage?: (stage: TunnelStage) => void
}) {
  return (
    <ol className={cx('flex flex-wrap items-center gap-x-1 gap-y-1', className)} aria-label="Tunnel DNA">
      {dna.stages.map((stage, index) => {
        const node = (
          <>
            <span className={cx('size-1.5 shrink-0 rounded-full border', dotClass(stage))} aria-hidden />
            <span
              className={cx(
                'font-mono text-[9.5px] uppercase tracking-[0.04em]',
                stage.pending ? 'text-mist-faint' : 'text-mist-dim',
              )}
            >
              {TUNNEL_STAGE_LABEL[stage.id]}
            </span>
          </>
        )
        return (
          <li key={stage.id} className="flex items-center gap-1">
            {onSelectStage ? (
              <button
                type="button"
                onClick={() => onSelectStage(stage)}
                title={stageTitle(stage)}
                className="flex items-center gap-1 rounded px-0.5 py-px hover:bg-night-800"
              >
                {node}
              </button>
            ) : (
              <span className="flex items-center gap-1 px-0.5 py-px" title={stageTitle(stage)}>
                {node}
              </span>
            )}
            {index < dna.stages.length - 1 ? (
              <span
                className={cx('h-px w-3', dna.stages[index + 1].pending ? 'bg-edge' : 'bg-edge-strong')}
                aria-hidden
              />
            ) : null}
          </li>
        )
      })}
    </ol>
  )
}

/**
 * Full vertical lifecycle, for a page that has room to explain each stage:
 * what happened, how it was established and which packets show it.
 */
export function TunnelDnaStages({
  dna,
  className,
  onSelectStage,
  selectedId,
}: {
  dna: TunnelDna
  className?: string
  onSelectStage?: (stage: TunnelStage) => void
  selectedId?: TunnelStage['id'] | null
}) {
  return (
    <ol className={cx('flex flex-col', className)}>
      {dna.stages.map((stage, index) => {
        const last = index === dna.stages.length - 1
        const open = selectedId === stage.id
        return (
          <li key={stage.id} className="flex gap-3">
            <div className="flex flex-col items-center">
              <span
                className={cx(
                  'mt-1 size-2.5 shrink-0 rounded-full border',
                  dotClass(stage),
                  open && 'ring-2 ring-accent-400/40',
                )}
                aria-hidden
              />
              {!last ? <span className="w-px flex-1 bg-edge-strong" aria-hidden /> : null}
            </div>

            <div className={cx('min-w-0 flex-1', last ? 'pb-0' : 'pb-3')}>
              {onSelectStage ? (
                <button
                  type="button"
                  onClick={() => onSelectStage(stage)}
                  aria-expanded={open}
                  className="flex w-full flex-wrap items-center gap-2 rounded text-left hover:bg-night-800/60"
                >
                  <StageHeading stage={stage} />
                </button>
              ) : (
                <StageHeading stage={stage} />
              )}

              <p className={cx('mt-0.5 text-[11.5px]', stage.pending ? 'text-mist-faint' : 'text-mist-dim')}>
                {stage.detail}
              </p>

              {open ? (
                <div className="mt-1.5 flex flex-col gap-1 rounded border border-edge bg-night-800/60 px-2.5 py-2">
                  <span className="text-[11px] text-mist-dim">{TUNNEL_STAGE_DESCRIPTION[stage.id]}</span>
                  {stage.packetRange ? (
                    <span className="font-mono text-[10.5px] text-mist-faint">
                      Packets {stage.packetRange}
                    </span>
                  ) : null}
                  {stage.evidenceIds.length > 0 ? (
                    <span className="font-mono text-[10.5px] text-mist-faint">
                      {stage.evidenceIds.length} evidence record
                      {stage.evidenceIds.length === 1 ? '' : 's'}
                    </span>
                  ) : null}
                </div>
              ) : null}
            </div>
          </li>
        )
      })}
    </ol>
  )
}

function StageHeading({ stage }: { stage: TunnelStage }) {
  return (
    <>
      <span className="font-mono text-[12px] font-medium text-mist">{TUNNEL_STAGE_LABEL[stage.id]}</span>
      <span className="text-[10px] uppercase tracking-wide text-mist-faint">
        {stage.pending ? 'Not observed' : DATA_SOURCE_LABEL[stage.state]}
      </span>
      {stage.pending ? null : <ConfidenceBadge confidence={stage.confidence} prefix="" />}
    </>
  )
}

/** Lifecycle view with internal selection state, for a self-contained block. */
export function TunnelDNA({
  dna,
  variant = 'strip',
  className,
}: {
  dna: TunnelDna
  variant?: 'strip' | 'stages'
  className?: string
}) {
  const [selected, setSelected] = useState<TunnelStage['id'] | null>(null)
  if (variant === 'stages') {
    return <TunnelDnaStages dna={dna} className={className} selectedId={selected} onSelectStage={(stage) => setSelected(stage.id)} />
  }
  return <TunnelDnaStrip dna={dna} className={className} />
}

/* ------------------------------------------------------------------ */
/* Negotiated configuration                                             */
/* ------------------------------------------------------------------ */

/**
 * The tunnel's negotiated configuration, each value with its provenance.
 *
 * This is the answer to "how was this tunnel built?" and it is deliberately not
 * a second Tunnel DNA: the DNA is the lifecycle, this is the outcome of it.
 */
export function TunnelConfiguration({
  tunnel,
  className,
  children,
}: {
  tunnel: Pick<
    TunnelIdentity,
    | 'ikeVersion'
    | 'vpnMode'
    | 'encryption'
    | 'integrity'
    | 'dhGroup'
    | 'perfectForwardSecrecy'
    | 'replayProtection'
  >
  className?: string
  children?: ReactNode
}) {
  return (
    <div className={cx('flex flex-col gap-2.5', className)}>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3 lg:grid-cols-4">
        <ProvenanceValue field="IKE version" value={tunnel.ikeVersion} />
        <ProvenanceValue
          field="Mode"
          value={tunnel.vpnMode}
          format={(value: 'tunnel' | 'transport') => (value === 'tunnel' ? 'Tunnel mode' : 'Transport mode')}
        />
        <ProvenanceValue field="Encryption" value={tunnel.encryption} />
        <ProvenanceValue field="Integrity" value={tunnel.integrity} />
        <ProvenanceValue field="DH group" value={tunnel.dhGroup} />
        <ProvenanceValue
          field="PFS"
          value={tunnel.perfectForwardSecrecy}
          format={(value: boolean) => (value ? 'Enabled' : 'Disabled')}
        />
        <ProvenanceValue
          field="Replay protection"
          value={tunnel.replayProtection}
          format={(value: boolean) => (value ? 'Enabled' : 'Disabled')}
        />
      </div>
      {children}
    </div>
  )
}

/** One-line configuration read-out for dense rows. */
export function TunnelConfigLine({ tunnel, className }: { tunnel: TunnelIdentity; className?: string }) {
  const pfs = tunnel.perfectForwardSecrecy.value
  return (
    <span className={cx('flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[10.5px] text-mist-dim', className)}>
      <span>{tunnel.ikeVersion.value ?? 'IKE unknown'}</span>
      <span className="text-edge-strong">|</span>
      <span>{tunnel.vpnMode.value === 'tunnel' ? 'Tunnel mode' : (tunnel.vpnMode.value ?? 'Mode unknown')}</span>
      <span className="text-edge-strong">|</span>
      <span>{tunnel.encryption.value ?? 'Encryption unknown'}</span>
      <span className="text-edge-strong">|</span>
      <span>PFS</span>
      <span className={pfs === null ? 'text-mist-faint' : pfs ? 'text-success' : 'text-warning'}>
        {pfs === null ? 'unknown' : pfs ? 'on' : 'off'}
      </span>
    </span>
  )
}
