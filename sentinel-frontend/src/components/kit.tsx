import { useId, useState, type ReactNode } from 'react'
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { SeverityBadge, Tag } from '@/components/ui'
import { SEVERITY_ORDER, type Severity } from '@/types'
import { comparisonStyle, formatPercent, severityHex, severityStyle } from '@/lib/format'

/**
 * The shared visual system.
 *
 * Every screen is assembled from these primitives so hierarchy is identical
 * across the product: one metric strip per screen, sentence-case section
 * headings, collapsible deep evidence, and one expected/observed comparison.
 * The rule the whole file encodes is "one decision per surface, evidence
 * behind a disclosure" — pages never invent their own card language.
 */

/* ---------------------------------------------------------------- metrics */

export type MetricTone = Severity | 'good' | 'accent' | 'neutral'

export interface MetricItem {
  label: ReactNode
  value: ReactNode
  hint?: ReactNode
  tone?: MetricTone
  /** Optional id so a screen can deep-link / test a specific metric. */
  id?: string
}

function toneClass(tone: MetricTone | undefined): string {
  if (!tone || tone === 'neutral') return 'text-ink'
  if (tone === 'good') return 'text-good'
  if (tone === 'accent') return 'text-sentinel'
  return severityStyle(tone).text
}

/**
 * The one strip of primary figures at the top of a screen. A single panel with
 * hairline dividers, not a row of competing cards: the numbers are the subject,
 * the separators only group them.
 */
export function MetricStrip({
  items,
  className = '',
  ariaLabel,
}: {
  items: MetricItem[]
  className?: string
  ariaLabel?: string
}) {
  return (
    <dl
      aria-label={ariaLabel}
      data-metric-strip="true"
      className={`panel flex flex-wrap overflow-hidden ${className}`}
    >
      {items.map((item, index) => (
        <div
          key={item.id ?? `${index}-${String(item.label)}`}
          className="flex min-w-[8.5rem] flex-1 flex-col gap-1 px-4 py-3 [&:not(:first-child)]:border-l [&:not(:first-child)]:border-edge-soft"
        >
          <dt className="label">{item.label}</dt>
          <dd className={`tnum text-2xl font-semibold leading-none tracking-tight ${toneClass(item.tone)}`}>
            {item.value}
          </dd>
          {item.hint && <dd className="text-xs text-ink-faint">{item.hint}</dd>}
        </div>
      ))}
    </dl>
  )
}

/* --------------------------------------------------------------- headings */

export function SectionHeading({
  title,
  description,
  count,
  action,
  className = '',
  id,
}: {
  title: ReactNode
  description?: ReactNode
  count?: ReactNode
  action?: ReactNode
  className?: string
  id?: string
}) {
  return (
    <div className={`flex flex-wrap items-end justify-between gap-3 ${className}`}>
      <div className="min-w-0">
        <h3 id={id} className="flex items-center gap-2 text-lg font-semibold tracking-tight text-ink">
          {title}
          {count !== undefined && count !== null && (
            <span className="tnum text-sm font-normal text-ink-faint">{count}</span>
          )}
        </h3>
        {description && <p className="mt-0.5 max-w-3xl text-sm text-ink-dim">{description}</p>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  )
}

/* ------------------------------------------------------------ disclosure */

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 16 16"
      aria-hidden="true"
      className={`h-3.5 w-3.5 shrink-0 text-ink-faint transition-transform ${open ? 'rotate-90' : ''}`}
      fill="none"
    >
      <path d="m6 4 4 4-4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

/**
 * Deep evidence lives behind one of these. Native button semantics, a stable
 * region id, and a single level of nesting — no nested accordions, because
 * nesting is how progressive disclosure turns back into overload.
 */
export function CollapsibleSection({
  title,
  description,
  meta,
  defaultOpen = false,
  open: openProp,
  onToggle,
  children,
  className = '',
  bodyClassName = '',
  id,
}: {
  title: ReactNode
  description?: ReactNode
  meta?: ReactNode
  defaultOpen?: boolean
  /** Controlled open state. Omit for uncontrolled disclosure. */
  open?: boolean
  onToggle?: (open: boolean) => void
  children: ReactNode
  className?: string
  bodyClassName?: string
  id?: string
}) {
  const [internalOpen, setInternalOpen] = useState(defaultOpen)
  const controlled = openProp !== undefined
  const open = controlled ? openProp : internalOpen
  const regionId = useId()
  const toggle = () => {
    const next = !open
    if (!controlled) setInternalOpen(next)
    onToggle?.(next)
  }
  return (
    <section
      id={id}
      data-collapsible={String(title)}
      data-open={open ? 'true' : 'false'}
      className={`border-t border-edge-soft first:border-t-0 ${className}`}
    >
      <button
        type="button"
        aria-expanded={open}
        aria-controls={regionId}
        onClick={toggle}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-panel-2"
      >
        <Chevron open={open} />
        <span className="text-base font-semibold text-ink">{title}</span>
        {meta}
        <span className="flex-1" />
        {description && (
          <span className="hidden max-w-md truncate text-xs text-ink-faint sm:block">{description}</span>
        )}
      </button>
      {open && (
        <div id={regionId} className={`px-4 pb-4 ${bodyClassName}`}>
          {children}
        </div>
      )}
    </section>
  )
}

/* --------------------------------------------------------------- findings */

/**
 * The compact headline an analyst reads before any evidence: what was found,
 * how severe, its score, and the single sentence of why. Deep comparison and
 * custody are separate disclosures underneath this.
 */
export function FindingSummary({
  title,
  severity,
  score,
  category,
  ruleId,
  confidence,
  description,
  action,
  className = '',
}: {
  title: ReactNode
  severity: Severity | string | null
  score?: number | null
  category?: ReactNode
  ruleId?: ReactNode
  confidence?: number | null
  description?: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <div
      data-finding-summary="true"
      className={`panel flex flex-wrap items-start gap-x-6 gap-y-3 p-4 ${className}`}
    >
      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={severity} />
          <span className="text-base font-semibold text-ink">{title}</span>
        </div>
        {description && <p className="max-w-3xl text-sm leading-relaxed text-ink-dim">{description}</p>}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-faint">
          {category && <span>{category}</span>}
          {ruleId && <span className="mono">{ruleId}</span>}
          {confidence !== null && confidence !== undefined && (
            <span>Confidence {formatPercent(confidence, 0)}</span>
          )}
        </div>
      </div>
      {score !== null && score !== undefined && (
        <div className="flex shrink-0 flex-col items-end">
          <span className="label">Risk score</span>
          <span className={`tnum text-2xl font-semibold leading-none ${severityStyle(severity).text}`}>
            {score}
          </span>
        </div>
      )}
      {action && <div className="shrink-0 self-center">{action}</div>}
    </div>
  )
}

/* --------------------------------------------------- expected vs observed */

export interface ExpectedObservedRow {
  parameter: ReactNode
  expected: ReactNode
  observed: ReactNode
  status?: string | null
  note?: ReactNode
}

function StatusCell({ status }: { status?: string | null }) {
  if (!status) return <span className="text-ink-faint">—</span>
  const style = comparisonStyle(status)
  return (
    <span className={`text-xs font-semibold uppercase tracking-wide ${style.text}`}>
      {status.replace(/_/g, ' ')}
    </span>
  )
}

/**
 * Parameter | Expected | Observed | Status. The comparison the product exists
 * to make, as a table rather than prose: one row per configuration variable,
 * the difference and its verdict on a single line.
 */
export function ExpectedObservedTable({
  rows,
  className = '',
  emptyLabel = 'No comparable configuration was recorded.',
}: {
  rows: ExpectedObservedRow[]
  className?: string
  emptyLabel?: string
}) {
  if (rows.length === 0) {
    return <p className="px-1 py-2 text-sm text-ink-faint">{emptyLabel}</p>
  }
  return (
    <div className={`overflow-x-auto ${className}`} data-expected-observed="true">
      <table className="data-table min-w-[560px]">
        <thead>
          <tr>
            <th scope="col">Parameter</th>
            <th scope="col">Expected</th>
            <th scope="col">Observed</th>
            <th scope="col">Status</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              <td className="whitespace-nowrap text-ink-dim">{row.parameter}</td>
              <td className="mono text-ink">{row.expected ?? <span className="text-ink-faint">—</span>}</td>
              <td className={`mono ${row.status ? comparisonStyle(row.status).text : 'text-ink'}`}>
                {row.observed ?? <span className="text-ink-faint">—</span>}
              </td>
              <td>
                <StatusCell status={row.status} />
                {row.note && <span className="ml-2 text-xs text-ink-faint">{row.note}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* --------------------------------------------------------------- evidence */

export interface EvidenceRow {
  id: ReactNode
  finding?: ReactNode
  source?: ReactNode
  captured?: ReactNode
  assessment?: ReactNode
  onOpen?: () => void
}

export function EvidenceTable({
  rows,
  className = '',
  emptyLabel = 'No evidence references were recorded.',
}: {
  rows: EvidenceRow[]
  className?: string
  emptyLabel?: string
}) {
  if (rows.length === 0) {
    return <p className="px-1 py-2 text-sm text-ink-faint">{emptyLabel}</p>
  }
  return (
    <div className={`overflow-x-auto ${className}`} data-evidence-table="true">
      <table className="data-table min-w-[640px]">
        <thead>
          <tr>
            <th scope="col">Evidence</th>
            <th scope="col">Finding</th>
            <th scope="col">Source</th>
            <th scope="col">Captured</th>
            <th scope="col">Assessment</th>
            <th scope="col" />
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              <td className="mono text-ink">{row.id}</td>
              <td className="text-ink-dim">{row.finding ?? '—'}</td>
              <td className="text-ink-dim">{row.source ?? '—'}</td>
              <td className="whitespace-nowrap text-ink-dim">{row.captured ?? '—'}</td>
              <td>{row.assessment ?? '—'}</td>
              <td className="text-right">
                {row.onOpen && (
                  <button
                    type="button"
                    onClick={row.onOpen}
                    className="text-xs font-medium text-sentinel transition-colors hover:text-ink"
                  >
                    Open evidence
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* ------------------------------------------------------- severity summary */

export interface SeverityCount {
  severity: Severity
  count: number
}

export function severityCounts<T>(
  items: T[],
  getSeverity: (item: T) => string | null | undefined,
): SeverityCount[] {
  const tally = new Map<Severity, number>()
  for (const severity of SEVERITY_ORDER) tally.set(severity, 0)
  for (const item of items) {
    const key = (getSeverity(item) ?? '').toUpperCase() as Severity
    if (tally.has(key)) tally.set(key, (tally.get(key) ?? 0) + 1)
  }
  return SEVERITY_ORDER.map((severity) => ({ severity, count: tally.get(severity) ?? 0 }))
}

export function SeverityPieChart({
  counts,
  height = 220,
  title,
}: {
  counts: SeverityCount[]
  height?: number
  title?: string
}) {
  const total = counts.reduce((sum, entry) => sum + entry.count, 0)
  if (total === 0) {
    return <p className="py-4 text-sm text-ink-faint">No assessed items to summarise.</p>
  }
  const data = counts.map((entry) => ({
    name: entry.severity,
    value: entry.count,
    hex: severityHex(entry.severity),
  }))
  return (
    <div data-severity-pie="true">
      {title && <p className="sr-only">{title}</p>}
      <div className="flex flex-wrap items-center gap-5">
        <div style={{ width: 190, height }} className="shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                innerRadius="55%"
                outerRadius="85%"
                paddingAngle={1}
                stroke="#101722"
                strokeWidth={2}
              >
                {data.map((entry) => (
                  <Cell key={entry.name} fill={entry.hex} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: '#16202e',
                  border: '1px solid #26354a',
                  borderRadius: 6,
                  fontSize: 13,
                  color: '#d9e0ea',
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <dl className="min-w-[10rem] flex-1">
          {counts.map((entry) => (
            <div
              key={entry.severity}
              className="flex items-center justify-between gap-4 border-b border-edge-soft py-1.5 last:border-b-0"
            >
              <dt className="flex items-center gap-2">
                <span
                  className="h-2.5 w-2.5 shrink-0 rounded-sm"
                  style={{ background: severityHex(entry.severity) }}
                  aria-hidden="true"
                />
                <span className="text-sm text-ink-dim">{entry.severity}</span>
              </dt>
              <dd className="tnum flex items-center gap-3 text-sm">
                <span className="font-semibold text-ink">{entry.count}</span>
                <span className="w-12 text-right text-ink-faint">
                  {formatPercent((entry.count / total) * 100, 0)}
                </span>
              </dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  )
}

/* --------------------------------------------------------------- report */

export function ReportSection({
  index,
  title,
  description,
  action,
  children,
  className = '',
  id,
}: {
  index?: number | string
  title: ReactNode
  description?: ReactNode
  action?: ReactNode
  children: ReactNode
  className?: string
  id?: string
}) {
  return (
    <section id={id} className={`panel ${className}`} data-report-section={String(title)}>
      <header className="flex flex-wrap items-end justify-between gap-3 border-b border-edge-soft px-5 py-3">
        <div className="min-w-0">
          <h3 className="flex items-baseline gap-2 text-lg font-semibold tracking-tight text-ink">
            {index !== undefined && <span className="tnum text-sm text-ink-faint">{index}</span>}
            {title}
          </h3>
          {description && <p className="mt-0.5 max-w-3xl text-sm text-ink-dim">{description}</p>}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </header>
      <div className="p-5">{children}</div>
    </section>
  )
}

/** A small labelled chip used to distinguish fact / assessment / inference. */
export function ProvenanceTag({
  kind,
}: {
  kind: 'fact' | 'assessment' | 'ml' | 'ai'
}) {
  const map = {
    fact: { label: 'Observed fact', tone: 'neutral' as const },
    assessment: { label: 'Deterministic assessment', tone: 'accent' as const },
    ml: { label: 'ML inference', tone: 'warn' as const },
    ai: { label: 'AI explanation', tone: 'warn' as const },
  }
  const entry = map[kind]
  return <Tag tone={entry.tone}>{entry.label}</Tag>
}
