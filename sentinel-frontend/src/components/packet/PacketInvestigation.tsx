import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { usePacketInvestigation } from '@/hooks/usePacketInvestigation'
import { formatSpi, type CaptureRow } from '@/lib/packetRows'
import type { Finding, RiskContribution } from '@/types'
import { AskAiModal, type AiSubject } from '@/components/ai/AskAiModal'
import {
  ConfigurationFindings,
  ContextError,
  ContextLoading,
  IpsecConfiguration,
  ObservedTraffic,
  PacketDetailGrid,
  PanelUnavailable,
} from '@/components/packet/PacketContext'

/**
 * PACKET INVESTIGATION — the centered window a packet opens into.
 *
 * The stream stays on screen behind this, because the window is *about* a row in
 * it: an analyst comparing the detail grid against the rows around it is the
 * whole point. So this is a fixed overlay rather than a page section, and it
 * takes no vertical space from the stream.
 *
 * The window is deliberately small and its body scrolls. Three analyst panels
 * side by side, plus a findings list, is more content than fits any viewport —
 * so the constraint is the panels' *width*, not the page's height. Each panel is
 * a fixed-width column and the body scrolls inside the window, which keeps the
 * packet's identity visible in the header while the analyst reads the evidence.
 *
 * The three panels are strictly separated by provenance, and the separation is
 * the point of the layout rather than a stylistic choice:
 *
 *   IPsec Configuration  CONFIGURED — `bundle.expected`. How the tunnel was
 *                        built. Not evidence that anything was seen on the wire.
 *   Observed Traffic     OBSERVED / INFERRED — what the capture measured, plus
 *                        the one classifier output. No configured value is
 *                        repeated here, because `ObservedState` models no
 *                        cryptographic field to repeat.
 *   Configuration Findings
 *                        ASSESSED — the scoring engine's own findings, with its
 *                        own score contribution. Nothing here is computed in
 *                        the browser.
 *
 * Ask AI is a second, later overlay on top of this one, opened from either the
 * packet or a finding.
 */

export function PacketInvestigation({
  row,
  assessmentId,
  position,
  total,
  onPrevious,
  onNext,
  onClose,
  onMinimize,
  minimized,
}: {
  row: CaptureRow
  assessmentId: string | null
  position: number
  total: number
  onPrevious: () => void
  onNext: () => void
  onClose: () => void
  onMinimize: () => void
  minimized: boolean
}) {
  const bodyRef = useRef<HTMLDivElement>(null)

  // Selecting a different packet replaces the content of a scrollable panel; the
  // scroll offset belongs to the previous packet, so it is reset rather than
  // inherited.
  useEffect(() => {
    const body = bodyRef.current
    if (body) body.scrollTop = 0
  }, [row.key])

  // Escape closes, matching the Ask AI overlay so the two behave as one set of
  // layers. Bound to the document and removed with the window.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  // Minimizing releases the scroll lock: at that point there is no overlay.
  useEffect(() => {
    if (minimized) return
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previous
    }
  }, [minimized])

  if (minimized) {
    return (
      <button
        type="button"
        className="ls-inv-float"
        onClick={onMinimize}
        title="Restore the packet investigation window"
      >
        Investigation #{row.sequence}
      </button>
    )
  }

  return (
    <div className="ls-inv-overlay" role="dialog" aria-modal="true" aria-label="Packet investigation">
      <div className="ls-inv">
        <header className="ls-inv-head">
          <div className="ls-inv-titles">
            <h2 className="ls-inv-title">Packet Investigation</h2>
            <p className="ls-inv-identity">
              <span className="ls-inv-identity-part">{row.protocol || 'No label'}</span>
              <span className="ls-inv-identity-sep" aria-hidden="true">
                •
              </span>
              <span className="ls-mono">
                {row.source} → {row.destination}
              </span>
              {row.spi === null ? null : (
                <>
                  <span className="ls-inv-identity-sep" aria-hidden="true">
                    •
                  </span>
                  <span className="ls-mono">SPI {formatSpi(row.spi)}</span>
                </>
              )}
              <span className="ls-inv-identity-sep" aria-hidden="true">
                •
              </span>
              <span className="ls-mono">seq {row.sequence}</span>
            </p>
          </div>
          <div className="ls-inv-tools">
            <button
              type="button"
              className="ls-btn"
              onClick={onPrevious}
              disabled={position <= 0}
              title="Investigate the previous packet"
            >
              Previous
            </button>
            <button
              type="button"
              className="ls-btn"
              onClick={onNext}
              disabled={position >= total - 1}
              title="Investigate the next packet"
            >
              Next
            </button>
            <button
              type="button"
              className="ls-btn ls-btn-ghost"
              onClick={onMinimize}
              title="Collapse this window"
              aria-label="Minimize"
            >
              <span aria-hidden="true">–</span>
            </button>
            <button
              type="button"
              className="ls-btn ls-btn-ghost"
              onClick={onClose}
              title="Close and return to the packet stream"
              aria-label="Close"
            >
              <span aria-hidden="true">×</span>
            </button>
          </div>
        </header>

        <div className="ls-inv-body" ref={bodyRef}>
          <PacketDetailGrid row={row} />
          <InvestigationPanels row={row} assessmentId={assessmentId} />
        </div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------- panels */

function InvestigationPanels({ row, assessmentId }: { row: CaptureRow; assessmentId: string | null }) {
  const inv = usePacketInvestigation(assessmentId)
  const bundle = inv.bundle

  const [configCollapsed, setConfigCollapsed] = useState(false)
  const [findingsCollapsed, setFindingsCollapsed] = useState(false)

  const contributions = useMemo(() => {
    const map = new Map<string, RiskContribution>()
    for (const contribution of inv.bundle?.risk?.score_detail?.contributions ?? []) {
      map.set(contribution.finding_id, contribution)
    }
    return map
  }, [inv.bundle])

  // The Ask AI overlay is owned here because it needs the bundle and the
  // per-finding contributions, both already loaded for this packet. It renders
  // as a later layer (higher stacking), so it sits above this window.
  const [aiSubject, setAiSubject] = useState<AiSubject | null>(null)
  const [aiOpen, setAiOpen] = useState(false)
  const [aiMinimized, setAiMinimized] = useState(false)

  const openAi = useCallback(
    (finding: Finding | null) => {
      const subject: AiSubject =
        finding && assessmentId
          ? {
              kind: 'finding',
              row,
              assessmentId,
              bundle,
              contribution: contributions.get(finding.finding_id) ?? null,
              finding,
            }
          : { kind: 'packet', row, assessmentId, bundle, contribution: null, finding: null }
      setAiSubject(subject)
      setAiOpen(true)
      setAiMinimized(false)
    },
    [assessmentId, bundle, contributions, row],
  )

  // No assessment, still loading, or failed: the three-column grid is kept in
  // every case so the window does not resize under the analyst, and each column
  // says what is missing rather than collapsing.
  if (!assessmentId) {
    return (
      <div className="ls-inv-panels">
        <div className="ls-inv-panel-col">
          <PanelUnavailable title="IPsec Configuration" state="not assessed" stateClass="ls-state-na">
            Not assessed. No assessment in the store observed{' '}
            {row.spi === null ? 'this packet' : `SPI ${formatSpi(row.spi)}`}, so no configuration
            was published for it. The packet record above is still the captured one.
          </PanelUnavailable>
        </div>
        <div className="ls-inv-panel-col">
          <PanelUnavailable title="Observed Traffic" state="not available" stateClass="ls-state-na">
            Not available. Observation is an assessment-window property, and no assessment covers
            this packet. The packet's own fields above are still the captured ones.
          </PanelUnavailable>
        </div>
        <div className="ls-inv-panel-col">
          <PanelUnavailable title="Configuration Findings" state="not assessed" stateClass="ls-state-na">
            Not assessed. Findings belong to an assessment, and none covers this packet.
          </PanelUnavailable>
        </div>
      </div>
    )
  }

  if (inv.loading) return <ContextLoading />
  if (inv.error) return <ContextError error={inv.error} onRetry={inv.reload} />
  if (!inv.bundle) return null

  return (
    <>
      <div className="ls-inv-panels">
        <div className="ls-inv-panel-col">
          <IpsecConfiguration
            bundle={inv.bundle}
            observed={inv.bundle.observed}
            collapsed={configCollapsed}
            onToggle={() => setConfigCollapsed((v) => !v)}
          />
        </div>

        <div className="ls-inv-panel-col">
          <ObservedTraffic bundle={inv.bundle} />
        </div>

        <div className="ls-inv-panel-col">
          <ConfigurationFindings
            findings={inv.findings}
            contributions={contributions}
            assessmentId={assessmentId}
            // The scoring engine's own numbers, passed straight through. Nothing
            // in this file adds, weights, caps or re-derives them.
            score={inv.bundle.risk.overall_score ?? null}
            severity={inv.bundle.risk.severity ?? null}
            collapsed={findingsCollapsed}
            loading={inv.loading}
            error={inv.error}
            onRetry={inv.reload}
            onToggle={() => setFindingsCollapsed((v) => !v)}
            onAskAi={openAi}
          />
        </div>
      </div>

      {/* Layered above the investigation window. */}
      <AskAiModal
        subject={aiSubject}
        open={aiOpen}
        minimized={aiMinimized}
        onClose={() => {
          setAiOpen(false)
          setAiMinimized(false)
          setAiSubject(null)
        }}
        onMinimize={() => setAiMinimized(true)}
        onRestore={() => setAiMinimized(false)}
      />
    </>
  )
}
