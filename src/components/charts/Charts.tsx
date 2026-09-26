import { useId, useMemo, useState } from 'react'
import { cx } from '../../lib/cx'

/**
 * Charts.
 *
 * Hand-rolled SVG rather than a charting library: the platform needs six small,
 * accessible visualisations and nothing more. Every chart degrades to a text
 * summary, exposes its data to assistive technology, and is driven by the same
 * theme variables as the rest of the interface.
 */

export interface SeriesPoint {
  timestamp: string
  value: number
  label?: string
}

const CHART_TONE: Record<string, string> = {
  accent: 'text-accent-400',
  info: 'text-info',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
  critical: 'text-critical',
}

export interface LineChartProps {
  points: SeriesPoint[]
  height?: number
  tone?: keyof typeof CHART_TONE
  /** Suffix for the tooltip value, e.g. " pkts". */
  unit?: string
  label: string
  className?: string
  /** Force the y-axis to include zero. */
  zeroBased?: boolean
  formatValue?: (value: number) => string
}

/** Time-series line with a soft area fill and a focusable point readout. */
export function LineChart({
  points,
  height = 180,
  tone = 'accent',
  unit = '',
  label,
  className,
  zeroBased = false,
  formatValue,
}: LineChartProps) {
  const gradientId = useId().replace(/:/g, '')
  const [active, setActive] = useState<number | null>(null)

  const geometry = useMemo(() => {
    const width = 600
    const padX = 8
    const padTop = 12
    const padBottom = 22
    if (points.length === 0) return null
    const values = points.map((point) => point.value)
    const rawMax = Math.max(...values)
    const rawMin = zeroBased ? 0 : Math.min(...values)
    const max = rawMax === rawMin ? rawMax + 1 : rawMax
    const min = rawMax === rawMin ? 0 : rawMin
    const span = max - min || 1
    const innerW = width - padX * 2
    const innerH = height - padTop - padBottom
    const x = (index: number): number =>
      padX + (points.length === 1 ? innerW / 2 : (index / (points.length - 1)) * innerW)
    const y = (value: number): number => padTop + innerH - ((value - min) / span) * innerH
    const line = points.map((point, index) => `${index === 0 ? 'M' : 'L'}${x(index).toFixed(1)},${y(point.value).toFixed(1)}`).join(' ')
    const area = `${line} L${x(points.length - 1).toFixed(1)},${(padTop + innerH).toFixed(1)} L${x(0).toFixed(1)},${(padTop + innerH).toFixed(1)} Z`
    return { width, padX, padTop, padBottom, innerW, innerH, min, max, x, y, line, area }
  }, [points, height, zeroBased])

  if (!geometry || points.length === 0) {
    return <ChartEmpty label={label} className={className} height={height} />
  }

  const { x, y, line, area, innerH, padTop, width } = geometry
  const formatter = formatValue ?? ((value: number) => value.toLocaleString('en-US'))
  const first = points[0]
  const last = points[points.length - 1]
  const activePoint = active === null ? null : points[active]

  return (
    <figure className={cx('flex flex-col gap-1.5', className)}>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="h-auto w-full"
        role="img"
        aria-label={`${label}. ${points.length} points from ${first?.timestamp ?? ''} to ${last?.timestamp ?? ''}, ranging ${formatter(geometry.min)}${unit} to ${formatter(geometry.max)}${unit}.`}
        onMouseLeave={() => setActive(null)}
      >
        <defs>
          <linearGradient id={`grad-${gradientId}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" className={CHART_TONE[tone]} stopOpacity="0.28" />
            <stop offset="100%" className={CHART_TONE[tone]} stopOpacity="0" />
          </linearGradient>
        </defs>

        {[0, 0.5, 1].map((ratio) => {
          const gy = padTop + innerH * ratio
          return (
            <line
              key={ratio}
              x1={0}
              x2={width}
              y1={gy}
              y2={gy}
              className="stroke-edge"
              strokeWidth="1"
              vectorEffect="non-scaling-stroke"
            />
          )
        })}

        <path d={area} fill={`url(#grad-${gradientId})`} />
        <path
          d={line}
          fill="none"
          className={CHART_TONE[tone]}
          strokeWidth="1.75"
          strokeLinejoin="round"
          strokeLinecap="round"
          vectorEffect="non-scaling-stroke"
        />

        {activePoint && active !== null ? (
          <g>
            <line
              x1={x(active)}
              x2={x(active)}
              y1={padTop}
              y2={padTop + innerH}
              className="stroke-edge-strong"
              strokeWidth="1"
              vectorEffect="non-scaling-stroke"
            />
            <circle cx={x(active)} cy={y(activePoint.value)} r="3.5" className={CHART_TONE[tone]} />
          </g>
        ) : null}
      </svg>

      {/* Invisible hit targets: keeps the chart keyboard- and pointer-navigable. */}
      <div className="flex" style={{ marginTop: -height, height: 0 }}>
        {points.map((point, index) => (
          <button
            key={point.timestamp + index}
            type="button"
            className="flex-1 cursor-crosshair bg-transparent"
            style={{ height }}
            onMouseEnter={() => setActive(index)}
            onFocus={() => setActive(index)}
            onBlur={() => setActive(null)}
            aria-label={`${point.label ?? point.timestamp}: ${formatter(point.value)}${unit}`}
          />
        ))}
      </div>

      <div className="flex items-center justify-between text-[10px] text-mist-faint">
        <span className="font-mono">{first?.label ?? first?.timestamp.slice(0, 10)}</span>
        <span className="font-mono text-mist-dim">
          {activePoint
            ? `${activePoint.label ?? activePoint.timestamp} · ${formatter(activePoint.value)}${unit}`
            : `${points.length} points · ${formatter(geometry.min)}–${formatter(geometry.max)}${unit}`}
        </span>
        <span className="font-mono">{last?.label ?? last?.timestamp.slice(0, 10)}</span>
      </div>
    </figure>
  )
}

/* ------------------------------------------------------------------ */
/* Bar chart                                                            */
/* ------------------------------------------------------------------ */

export interface BarDatum {
  label: string
  value: number
  tone?: keyof typeof CHART_TONE
  hint?: string
}

export function BarChart({
  data,
  height = 160,
  unit = '',
  label,
  className,
  horizontal = false,
  formatValue,
}: {
  data: BarDatum[]
  height?: number
  unit?: string
  label: string
  className?: string
  horizontal?: boolean
  formatValue?: (value: number) => string
}) {
  const formatter = formatValue ?? ((value: number) => value.toLocaleString('en-US'))
  if (data.length === 0) return <ChartEmpty label={label} className={className} height={height} />
  const max = Math.max(...data.map((datum) => datum.value), 1)

  if (horizontal) {
    return (
      <figure className={cx('flex flex-col gap-1.5', className)}>
        <ul className="flex flex-col gap-2" aria-label={label}>
          {data.map((datum) => (
            <li key={datum.label} className="grid grid-cols-[minmax(0,7rem)_1fr_auto] items-center gap-2">
              <span className="truncate text-[11px] text-mist-dim" title={datum.label}>
                {datum.label}
              </span>
              <span className="h-2.5 overflow-hidden rounded-sm bg-night-800">
                <span
                  className={cx('block h-full rounded-sm', CHART_TONE[datum.tone ?? 'accent'])}
                  style={{ width: `${(datum.value / max) * 100}%` }}
                />
              </span>
              <span className="w-16 text-right font-mono text-[11px] text-mist-faint">
                {formatter(datum.value)}
                {unit}
              </span>
            </li>
          ))}
        </ul>
        <figcaption className="sr-only">{label}</figcaption>
      </figure>
    )
  }

  return (
    <figure className={cx('flex flex-col gap-1.5', className)}>
      <div
        className="flex items-end gap-1.5"
        style={{ height }}
        role="img"
        aria-label={`${label}. ${data.map((datum) => `${datum.label}: ${formatter(datum.value)}${unit}`).join(', ')}`}
      >
        {data.map((datum) => (
          <div key={datum.label} className="group flex min-w-0 flex-1 flex-col items-center justify-end gap-1">
            <span className="font-mono text-[10px] text-mist-faint opacity-0 transition-opacity group-hover:opacity-100">
              {formatter(datum.value)}
            </span>
            <span
              className={cx('w-full rounded-t-sm', CHART_TONE[datum.tone ?? 'accent'])}
              style={{ height: `${Math.max(2, (datum.value / max) * (height - 24))}px` }}
              title={datum.hint ?? `${datum.label}: ${formatter(datum.value)}${unit}`}
            />
          </div>
        ))}
      </div>
      <div className="flex gap-1.5">
        {data.map((datum) => (
          <span key={datum.label} className="min-w-0 flex-1 truncate text-center text-[10px] text-mist-faint">
            {datum.label}
          </span>
        ))}
      </div>
    </figure>
  )
}

/* ------------------------------------------------------------------ */
/* Donut                                                               */
/* ------------------------------------------------------------------ */

export interface DonutDatum {
  label: string
  value: number
  tone?: keyof typeof CHART_TONE
}

const DONUT_TONES: Array<keyof typeof CHART_TONE> = [
  'accent',
  'info',
  'success',
  'warning',
  'danger',
  'critical',
]

export function DonutChart({
  data,
  size = 168,
  thickness = 18,
  label,
  centerLabel = 'Total',
  className,
  formatValue,
}: {
  data: DonutDatum[]
  size?: number
  thickness?: number
  label: string
  centerLabel?: string
  className?: string
  formatValue?: (value: number) => string
}) {
  const formatter = formatValue ?? ((value: number) => value.toLocaleString('en-US'))
  const total = data.reduce((sum, datum) => sum + datum.value, 0)
  if (total === 0) return <ChartEmpty label={label} className={className} height={size} />

  const radius = (size - thickness) / 2
  const circumference = 2 * Math.PI * radius
  // Segment start offsets are pure data, derived before render rather than
  // accumulated while the elements are being created.
  const segments = data.map((datum) => {
    const dash = (datum.value / total) * circumference
    return { datum, dash, offset: 0 }
  })
  segments.reduce((accumulated, segment) => {
    segment.offset = accumulated
    return accumulated + segment.dash
  }, 0)

  return (
    <div className={cx('flex flex-wrap items-center gap-4', className)}>
      <figure className="relative shrink-0" style={{ width: size, height: size }}>
        <svg width={size} height={size} role="img" aria-label={`${label}. ${data.map((datum) => `${datum.label}: ${formatter(datum.value)}`).join(', ')}`}>
          <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              strokeWidth={thickness}
              className="stroke-night-800"
            />
            {segments.map((segment, index) => (
              <circle
                key={segment.datum.label}
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="none"
                strokeWidth={thickness}
                className={CHART_TONE[segment.datum.tone ?? DONUT_TONES[index % DONUT_TONES.length]]}
                strokeDasharray={`${segment.dash} ${circumference - segment.dash}`}
                strokeDashoffset={-segment.offset}
              />
            ))}
          </g>
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-base font-semibold text-mist">{formatter(total)}</span>
          <span className="text-[10px] uppercase tracking-wide text-mist-faint">{centerLabel}</span>
        </div>
      </figure>

      <ul className="flex min-w-0 flex-1 flex-col gap-1.5">
        {data.map((datum, index) => (
          <li key={datum.label} className="flex items-center gap-2 text-[11px]">
            <span
              aria-hidden
              className={cx('size-2 shrink-0 rounded-sm', CHART_TONE[datum.tone ?? DONUT_TONES[index % DONUT_TONES.length]])}
            />
            <span className="min-w-0 flex-1 truncate text-mist-dim">{datum.label}</span>
            <span className="font-mono text-mist-faint">{formatter(datum.value)}</span>
            <span className="w-10 text-right font-mono text-mist-faint">
              {Math.round((datum.value / total) * 100)}%
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Histogram                                                            */
/* ------------------------------------------------------------------ */

export interface HistogramBin {
  from: number
  to: number
  count: number
}

export function Histogram({
  bins,
  label,
  unit = '',
  className,
  formatValue,
}: {
  bins: HistogramBin[]
  label: string
  unit?: string
  className?: string
  formatValue?: (value: number) => string
}) {
  const formatter = formatValue ?? ((value: number) => value.toLocaleString('en-US'))
  if (bins.length === 0) return <ChartEmpty label={label} className={className} height={120} />
  return (
    <BarChart
      label={label}
      className={className}
      unit={unit}
      data={bins.map((bin) => ({
        label: `${formatter(bin.from)}–${formatter(bin.to)}`,
        value: bin.count,
        tone: 'info' as const,
        hint: `${formatter(bin.from)}${unit} to ${formatter(bin.to)}${unit}: ${formatter(bin.count)} packets`,
      }))}
    />
  )
}

function ChartEmpty({ label, className, height = 120 }: { label: string; className?: string; height?: number }) {
  return (
    <div
      className={cx('flex items-center justify-center rounded-lg border border-dashed border-edge text-[11px] text-mist-faint', className)}
      style={{ height }}
    >
      {label}: no data available
    </div>
  )
}
