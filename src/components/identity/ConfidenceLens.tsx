import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Info } from 'lucide-react'
import { Badge, type BadgeTone } from '../common/Badge'
import { confidenceBand } from '../common/Evidence'
import { cx } from '../../lib/cx'
import { formatPercent } from '../../lib/format'
import type { DataSource, EvidenceReference } from '../../types/evidence'
import { DATA_SOURCE_LABEL } from '../../types/evidence'

/**
 * The Confidence Lens.
 *
 * Every conclusion the platform states carries a confidence, and a number
 * without its basis is decoration. This lens makes the basis reachable: the
 * badge is the compact read-out, the popover is the source, the evidence and
 * the explanation behind it.
 *
 * A `null` confidence renders as an explicit Unknown. An absent estimate and a
 * zero estimate mean very different things, so the lens never collapses them.
 */

const BAND_TONE: Record<'high' | 'medium' | 'low' | 'unknown', BadgeTone> = {
  high: 'success',
  medium: 'info',
  low: 'warning',
  unknown: 'muted',
}

/** Compact confidence read-out, e.g. `99%`. */
export function ConfidenceBadge({
  confidence,
  className,
  prefix = 'Confidence',
}: {
  confidence: number | null
  className?: string
  prefix?: string
}) {
  const band = confidenceBand(confidence)
  const text = formatPercent(confidence)
  return (
    <Badge
      tone={BAND_TONE[band]}
      className={cx('font-mono', className)}
      title={
        confidence === null
          ? `${prefix}: unknown — no estimate was available for this value.`
          : `${prefix}: ${text} (${band} confidence)`
      }
    >
      {confidence === null ? text : `${prefix} ${text}`}
    </Badge>
  )
}

export interface ConfidenceDetail {
  /** Field the confidence is about, e.g. "IKE Version". */
  field?: string
  /** The value itself, e.g. "IKEv2". */
  value?: string
  /** Provenance of the value, e.g. `observed`. */
  source?: DataSource
  /** Verbatim evidence records behind the value. */
  evidence?: EvidenceReference[]
  /** Why the evidence supports the value. */
  explanation?: string
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 border-t border-edge px-3 py-2 first:border-t-0">
      <span className="w-24 shrink-0 text-[9.5px] font-semibold uppercase tracking-[0.07em] text-mist-faint">
        {label}
      </span>
      <div className="flex min-w-0 flex-1 flex-col gap-1 text-[11.5px] text-mist">{children}</div>
    </div>
  )
}

/**
 * Confidence badge that opens its basis in a popover: where the value came
 * from, which packets or fields support it, and how sure the platform is.
 *
 * Rendered in a portal with fixed positioning so it is never clipped by the
 * scroll containers these badges live inside.
 */
export function ConfidencePopover({
  confidence,
  detail,
  className,
  align = 'start',
}: {
  confidence: number | null
  detail: ConfidenceDetail
  className?: string
  align?: 'start' | 'end'
}) {
  const [open, setOpen] = useState(false)
  const [position, setPosition] = useState<{ top: number; left: number } | null>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const panelId = useId()

  useEffect(() => {
    if (!open) return
    const onPointerDown = (event: MouseEvent) => {
      const target = event.target as Node
      if (triggerRef.current?.contains(target) || panelRef.current?.contains(target)) return
      setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  useLayoutEffect(() => {
    if (!open || !triggerRef.current) return
    const rect = triggerRef.current.getBoundingClientRect()
    const width = 320
    const height = panelRef.current?.offsetHeight ?? 220
    const left =
      align === 'end' ? Math.min(rect.right - width, window.innerWidth - width - 12) : rect.left
    const flipUp = rect.bottom + height + 12 > window.innerHeight
    setPosition({
      top: flipUp ? Math.max(12, rect.top - height - 6) : rect.bottom + 6,
      left: Math.max(12, Math.min(left, window.innerWidth - width - 12)),
    })
  }, [open, align])

  const band = confidenceBand(confidence)
  const evidence = detail.evidence ?? []
  const first = evidence[0]

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        className={cx('inline-flex', className)}
      >
        <ConfidenceBadge confidence={confidence} />
      </button>
      {open && position
        ? createPortal(
            <div
              ref={panelRef}
              id={panelId}
              role="dialog"
              aria-label={detail.field ? `Confidence basis for ${detail.field}` : 'Confidence basis'}
              style={{ top: position.top, left: position.left, width: 320 }}
              className="fixed z-50 overflow-hidden rounded-lg border border-edge-strong bg-night-850 shadow-xl shadow-night-950/60"
            >
              <div className="flex items-center gap-2 border-b border-edge px-3 py-2">
                <Info className="size-3.5 shrink-0 text-accent-400" aria-hidden />
                <span className="flex min-w-0 flex-col">
                  <span className="truncate text-[12px] font-medium text-mist">
                    {detail.field ?? 'Value'}
                  </span>
                  {detail.value ? (
                    <span className="truncate font-mono text-[11px] text-mist-dim">{detail.value}</span>
                  ) : null}
                </span>
              </div>

              <Row label="Source">
                <span>
                  {detail.source ? DATA_SOURCE_LABEL[detail.source] : 'Not stated'}
                  {band === 'unknown' ? ' — no estimate available' : ''}
                </span>
                {detail.explanation ? (
                  <span className="text-mist-dim">{detail.explanation}</span>
                ) : null}
              </Row>

              <Row label="Evidence">
                {evidence.length === 0 ? (
                  <span className="text-mist-faint">No evidence record is attached to this value.</span>
                ) : (
                  <>
                    <span className="font-mono">
                      {first.packetRange ? `Packets ${first.packetRange}` : (first.exchange ?? first.id)}
                      {evidence.length > 1 ? ` + ${evidence.length - 1} more` : ''}
                    </span>
                    {first.field ? (
                      <span className="font-mono text-[10.5px] text-mist-faint">Field: {first.field}</span>
                    ) : null}
                    {first.ruleId ? (
                      <span className="font-mono text-[10.5px] text-mist-faint">Rule: {first.ruleId}</span>
                    ) : null}
                    <span className="text-mist-dim">{first.explanation}</span>
                  </>
                )}
              </Row>

              <Row label="Confidence">
                <span className="font-mono">
                  {formatPercent(confidence)}
                  {confidence === null ? ' — insufficient evidence' : ''}
                </span>
              </Row>
            </div>,
            document.body,
          )
        : null}
    </>
  )
}
