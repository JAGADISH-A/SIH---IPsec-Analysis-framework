import { Link } from 'react-router-dom'
import { HelpCircle } from 'lucide-react'
import { Badge } from '../common/Badge.tsx'
import { ConfidenceTag } from '../common/Evidence.tsx'
import { DataTable, type ColumnDef } from '../common/Table.tsx'
import { Panel } from '../common/Panel.tsx'
import { useClassifications } from '../../hooks/queries'
import { TRAFFIC_CLASS_LABEL, type TrafficClassification } from '../../types/trafficIntelligence'
import { formatBytes } from '../sessions/SessionDetailPage.tsx'

/**
 * Classification review queue.
 *
 * The classifier is allowed to be unsure, and this panel is where that shows up:
 * every flow whose effective class fell back to `unknown`, or that carries no
 * confidence at all, is listed with the class the model actually proposed. It is
 * the honest counterpart to the class distribution on the traffic page — the
 * flows the platform declined to label.
 */
export function ClassificationReview() {
  const query = useClassifications()
  const all = query.data ?? []

  const needsReview = all
    .filter(
      (item) =>
        item.label === 'unknown' || item.confidence === null || (item.confidence !== null && item.confidence < 0.6),
    )
    .sort((a, b) => (a.confidence ?? -1) - (b.confidence ?? -1))

  const columns: ColumnDef<TrafficClassification>[] = [
    {
      id: 'effective',
      header: 'Effective class',
      width: '10rem',
      render: (row) => (
        <span className="flex items-center gap-1.5">
          <span className="text-[12.5px] text-mist-dim">
            {row.label === 'unknown' ? <HelpCircle className="inline size-3 text-mist-faint" aria-hidden /> : null}{' '}
            {TRAFFIC_CLASS_LABEL[row.label]}
          </span>
        </span>
      ),
    },
    {
      id: 'proposed',
      header: 'Model proposed',
      width: '10rem',
      render: (row) =>
        row.proposedLabel === row.label ? (
          <span className="text-[11.5px] text-mist-faint">Same</span>
        ) : (
          <Badge tone="warning">{TRAFFIC_CLASS_LABEL[row.proposedLabel]}</Badge>
        ),
    },
    {
      id: 'confidence',
      header: 'Confidence',
      width: '7rem',
      render: (row) => <ConfidenceTag confidence={row.confidence} />,
    },
    {
      id: 'session',
      header: 'Session',
      width: '9rem',
      render: (row) =>
        row.sessionId ? (
          <Link
            to={`/vpn-sessions/${row.sessionId}`}
            className="font-mono text-[11px] text-mist-dim hover:text-accent-300"
          >
            {row.sessionId}
          </Link>
        ) : (
          <span className="text-[11px] text-mist-faint">Not session-scoped</span>
        ),
    },
    {
      id: 'volume',
      header: 'Volume',
      width: '9rem',
      align: 'right',
      render: (row) => (
        <span className="font-mono text-[11px] text-mist-dim">
          {row.packets.toLocaleString()} pkt · {formatBytes(row.bytes)}
        </span>
      ),
    },
    {
      id: 'hints',
      header: 'Hints used',
      width: '11rem',
      render: (row) =>
        row.hints.length === 0 ? (
          <span className="text-[11px] text-mist-faint">None</span>
        ) : (
          <span className="flex flex-wrap gap-1">
            {row.hints.slice(0, 3).map((hint) => (
              <span key={hint} className="rounded border border-edge bg-night-800 px-1 font-mono text-[10px] text-mist-dim">
                {hint}
              </span>
            ))}
          </span>
        ),
    },
    { id: 'basis', header: 'Basis', render: (row) => <span className="text-[12px] text-mist-dim">{row.basis}</span> },
  ]

  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 className="text-[13px] font-semibold tracking-wide text-mist">Classification review</h2>
          <p className="mt-0.5 text-[11px] text-mist-faint">
            {needsReview.length} of {all.length} flows were not classified confidently. A flow is never forced into a
            class: below the floor the effective label is Unknown and the model's proposal is kept alongside it.
          </p>
        </div>
      </div>
      <Panel flush>
        <DataTable
          columns={columns}
          rows={needsReview}
          rowKey={(row) => row.id}
          empty="Every flow was classified above the confidence floor."
        />
      </Panel>
    </section>
  )
}
