import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowUpRight, Check, CheckCircle2, RotateCcw, X } from 'lucide-react'
import { cx } from '../../lib/cx'
import { formatCompact } from '../../lib/format'
import { Skeleton } from '../common/Skeleton.tsx'
import { Spinner } from '../common/Spinner.tsx'
import { PIPELINE_STEPS, stepIndex } from '../../hooks/usePcapUpload'
import type {
  PCAPAnalysis,
  PcapUploadState,
} from '../../types/pcap'

const STAT_TONES: Record<string, string> = {
  mist: 'text-mist',
  accent: 'text-accent-300',
  info: 'text-info',
  warning: 'text-warning',
  danger: 'text-danger',
}

export function Stat({ label, value, tone }: { label: string; value: number; tone: keyof typeof STAT_TONES }) {
  return (
    <div className="rounded-lg border border-edge bg-night-800/60 px-3 py-2.5">
      <div className={cx('mono-tab text-lg font-semibold leading-tight', STAT_TONES[tone])}>
        {formatCompact(value)}
      </div>
      <div className="mt-0.5 text-[10px] uppercase tracking-wide text-mist-faint">{label}</div>
    </div>
  )
}

export function StepRow({ label, state }: { label: string; state: 'done' | 'active' | 'pending' }) {
  return (
    <li className="flex items-center gap-2.5 text-[13px]">
      {state === 'done' ? (
        <CheckCircle2 className="size-4 shrink-0 text-info" aria-hidden />
      ) : state === 'active' ? (
        <Spinner className="size-4 shrink-0 text-accent-300" />
      ) : (
        <span className="size-4 shrink-0 rounded-full border border-edge" aria-hidden />
      )}
      <span
        className={cx(
          state === 'done'
            ? 'text-mist-dim'
            : state === 'active'
              ? 'font-medium text-mist'
              : 'text-mist-faint/70',
        )}
      >
        {label}
      </span>
    </li>
  )
}

export function ProcessingView({ state, onCancel }: { state: PcapUploadState; onCancel: () => void }) {
  const current = stepIndex(state.stage, state.percent)
  return (
    <div className="flex flex-col gap-4 px-6 py-8">
      <div className="flex items-center gap-2">
        <Spinner className="size-4 text-accent-300" />
        <span className="truncate text-[13px] font-medium text-mist">Analyzing {state.file.name}</span>
      </div>

      <ol className="space-y-2.5">
        {PIPELINE_STEPS.map((step, index) => (
          <StepRow
            key={step.key}
            label={step.label}
            state={current > index ? 'done' : current === index ? 'active' : 'pending'}
          />
        ))}
      </ol>

      <div className="h-1.5 overflow-hidden rounded-full bg-night-800">
        <div
          className="h-full rounded-full bg-accent-400 transition-[width] duration-300 ease-out"
          style={{ width: `${state.percent}%` }}
        />
      </div>

      <div className="flex items-center justify-between gap-2 text-[11px]">
        <span className="min-w-0 truncate text-mist-dim">{state.message}</span>
        <span className="mono-tab shrink-0 text-mist-faint">{state.percent}%</span>
      </div>

      <div className="mt-2">
        <div className="flex items-center gap-2 text-[11px] text-mist-faint">
          <Spinner className="size-3 text-accent-300" />
          Building analysis summary…
        </div>
        <div className="mt-2.5 grid grid-cols-2 gap-2 sm:grid-cols-3" aria-busy="true" aria-label="Analysis summary loading">
          {Array.from({ length: 7 }).map((_, index) => (
            <div key={index} className="rounded-lg border border-edge bg-night-800/60 px-3 py-2.5">
              <Skeleton className="h-4 w-12" />
              <Skeleton className="mt-1.5 h-2.5 w-2/3" />
            </div>
          ))}
        </div>
      </div>

      <div className="mt-1">
        <button type="button" onClick={onCancel} className="btn btn-ghost btn-sm">
          <X className="size-3.5" aria-hidden />
          Cancel analysis
        </button>
      </div>
    </div>
  )
}

export function CompletedView({ result, onReset }: { result?: PCAPAnalysis; onReset: () => void }) {
  if (!result) return null
  return (
    <div className="flex flex-col gap-5 px-6 py-8">
      <div className="flex items-center gap-3">
        <div className="flex size-11 shrink-0 items-center justify-center rounded-full border border-success/40 bg-success-dim text-success">
          <Check className="size-5" aria-hidden />
        </div>
        <div className="min-w-0">
          <div className="text-[15px] font-semibold text-mist">Analysis complete</div>
          <div className="truncate text-xs text-mist-faint">
            {result.fileName} — ready for review
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        <Stat label="Packets analyzed" value={result.packetsAnalyzed} tone="mist" />
        <Stat label="IPsec packets" value={result.ipsecPackets} tone="accent" />
        <Stat label="IKEv2" value={result.ikev2} tone="info" />
        <Stat label="ESP" value={result.esp} tone="accent" />
        <Stat label="AH" value={result.ah} tone="warning" />
        <Stat label="High risk" value={result.highRisk} tone="danger" />
        <Stat label="Medium risk" value={result.mediumRisk} tone="warning" />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Link to="/live" className="btn btn-primary">
          Open Analysis
          <ArrowUpRight className="size-4" aria-hidden />
        </Link>
        <button type="button" onClick={onReset} className="btn btn-ghost">
          Analyze another file
        </button>
      </div>
    </div>
  )
}

export function ErrorView({
  message,
  onRestart,
  onReset,
}: {
  message: string
  onRestart: () => void
  onReset: () => void
}) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
      <div className="flex size-12 items-center justify-center rounded-full border border-danger/40 bg-danger-dim text-danger">
        <AlertTriangle className="size-5" aria-hidden />
      </div>
      <div className="text-[15px] font-semibold text-mist">Analysis could not complete</div>
      <p className="max-w-sm text-xs text-mist-faint">{message}</p>
      <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
        <button type="button" onClick={onRestart} className="btn btn-primary">
          <RotateCcw className="size-4" aria-hidden />
          Try again
        </button>
        <button type="button" onClick={onReset} className="btn btn-ghost">
          New file
        </button>
      </div>
    </div>
  )
}