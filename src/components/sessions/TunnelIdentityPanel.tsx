import { EvidenceSpine } from '../../components/identity/EvidenceSpine'
import { ConfidencePopover } from '../../components/identity/ConfidenceLens'
import { RiskSignal } from '../../components/identity/RiskSignal'
import { TunnelConfigLine, TunnelDnaStrip, TunnelDnaStages } from '../../components/identity/TunnelDNA'
import { Panel } from '../../components/common/Panel'
import { Spinner } from '../../components/common/Spinner'
import { useEvidenceSpine, useTunnel } from '../../hooks/queries'
import { cx } from '../../lib/cx'
import { formatCompact } from '../../lib/format'
import { SESSION_STATUS_LABEL } from '../../types/session'
import { DetailSection } from './sessionBits'

/**
 * Tunnel identity, reconstructed.
 *
 * This is the identity block a session page leads with, because the tunnel —
 * not the packet and not the configuration table — is the thing the analyst is
 * actually investigating. It answers three questions in one place: what this
 * tunnel is, how it came up, and how sure the platform is about both.
 *
 * The data comes from the tunnel service, which reconstructs the lifecycle from
 * the session timeline and cites the evidence behind every stage. Nothing here
 * is recomputed in the view, so this block and the launchpad's tunnel rows can
 * never disagree about the same tunnel.
 */
export function TunnelIdentityPanel({ sessionId, className }: { sessionId: string; className?: string }) {
  const tunnel = useTunnel(sessionId)
  const spine = useEvidenceSpine(sessionId)

  if (tunnel.isLoading) {
    return (
      <div className={cx('flex items-center gap-2 text-[11.5px] text-mist-faint', className)}>
        <Spinner className="size-3.5" />
        Reconstructing the tunnel…
      </div>
    )
  }

  if (!tunnel.data) {
    // The session detail itself still renders; the reconstruction is an
    // addition, so its absence must not take the page down with it.
    return null
  }

  const identity = tunnel.data

  return (
    <div className={cx('flex flex-col gap-4', className)}>
      <Panel padded>
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex min-w-0 flex-col gap-1.5">
            <span className="text-[9.5px] font-semibold uppercase tracking-[0.08em] text-mist-faint">
              Session
            </span>
            <span className="mono-tab text-[15px] font-semibold text-mist">{identity.id}</span>
            <span className="flex flex-wrap items-center gap-2 font-mono text-[12.5px] text-mist-dim">
              <span>{identity.initiator.address}</span>
              <span aria-hidden className="text-edge-strong">
                ⇄
              </span>
              <span>{identity.responder.address}</span>
            </span>
            <span className="text-[11px] uppercase tracking-wide text-mist-faint">
              {SESSION_STATUS_LABEL[identity.status]} · {identity.environment} ·{' '}
              {formatCompact(identity.packetCount)} packets
            </span>
            <TunnelConfigLine tunnel={identity} className="mt-0.5" />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <RiskSignal severity={identity.severity} label={`risk ${identity.riskScore}/100`} />
            <ConfidencePopover
              confidence={identity.confidence}
              align="end"
              detail={{
                field: 'Overall assessment',
                value: identity.encryption.value ?? 'Unknown',
                source: 'calculated',
                evidence: identity.assessmentEvidence,
                explanation: 'Composite of the tunnel risk score and the findings raised against it.',
              }}
            />
          </div>
        </div>

        <div className="mt-4 border-t border-edge pt-3">
          <TunnelDnaStrip dna={identity.dna} />
        </div>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <DetailSection
          title="Tunnel DNA"
          description="The lifecycle, reconstructed from the capture. Select a stage to see what it rests on."
        >
          <Panel padded>
            <TunnelDnaStages dna={identity.dna} />
          </Panel>
        </DetailSection>

        <DetailSection
          title="Evidence spine"
          description="How the assessment was reached, from the exchanges to the risk."
          actions={
            spine.isLoading ? <Spinner className="size-3.5 text-mist-faint" /> : null
          }
        >
          <Panel padded>
            {spine.data ? (
              <EvidenceSpine steps={spine.data} />
            ) : (
              <p className="text-[11.5px] text-mist-faint">
                The evidence chain for this tunnel is not available.
              </p>
            )}
          </Panel>
        </DetailSection>
      </div>
    </div>
  )
}
