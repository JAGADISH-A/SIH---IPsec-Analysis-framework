import { useRef, useState, type DragEvent } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, Check, FileUp, Upload } from 'lucide-react'
import { Spinner } from '../../components/common/Spinner'
import { cx } from '../../lib/cx'
import { formatBytes } from '../../lib/format'
import { useUploadCapture } from '../../hooks/queries'
import { ACCEPTED_EXTENSIONS, extensionOf } from '../../hooks/usePcapUpload'
import { LauncherPanel } from './LauncherPanel'
import type { CaptureUploadOptions } from '../../services/api/datasetService'

/**
 * Ingest options recorded with a capture dropped here.
 *
 * The welcome screen is a launcher, not a form: it registers the file and sends
 * the analyst to the archive, where the same options can be corrected and the
 * capture dissected. Unlabelled is the honest default — the platform records
 * what it was told and never guesses from a file name.
 */
const INGEST_DEFAULTS: CaptureUploadOptions = {
  label: 'unlabelled',
  ikeVersion: 'IKEv2',
  vpnMode: 'tunnel',
  trafficType: 'mixed',
  metadataOnly: false,
}

/**
 * The second way to start work: open a capture file.
 *
 * A drop target rather than a link, because opening a file is a local act —
 * the file is validated by extension here and by the ingest service itself, and
 * the capture lands in the archive where every other page can reach it.
 */
export function PcapLauncher() {
  const inputRef = useRef<HTMLInputElement>(null)
  const upload = useUploadCapture()
  const [dragActive, setDragActive] = useState(false)
  const [rejected, setRejected] = useState<string | null>(null)

  const file = upload.variables?.file ?? null

  function ingest(candidate: File) {
    if (!ACCEPTED_EXTENSIONS.includes(extensionOf(candidate.name))) {
      setRejected(
        `“${candidate.name}” is not a capture file. Only .pcap and .pcapng are accepted.`,
      )
      return
    }
    setRejected(null)
    upload.reset()
    upload.mutate({ file: candidate, options: INGEST_DEFAULTS })
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setDragActive(false)
    if (upload.isPending) return
    const dropped = event.dataTransfer.files?.[0]
    if (dropped) ingest(dropped)
  }

  const notice = rejected ?? (upload.isError ? upload.error.message : null)

  return (
    <LauncherPanel
      title="Open PCAP"
      description="Analyze an existing PCAP or PCAPNG capture."
      icon={FileUp}
      aside={
        <span className="font-mono text-[10.5px] uppercase tracking-[0.07em] text-mist-faint">
          {ACCEPTED_EXTENSIONS.join(' · ')}
        </span>
      }
      footer={
        <>
          {upload.isSuccess ? (
            <span className="flex min-w-0 items-center gap-1.5 text-[11.5px] text-success">
              <Check className="size-3.5 shrink-0" aria-hidden />
              <span className="truncate">
                Registered <span className="font-mono">{upload.data.id}</span> — ready to dissect
              </span>
            </span>
          ) : (
            <span className="truncate text-[10.5px] text-mist-faint">
              Ingest is a server-side job; this client never parses the file.
            </span>
          )}
          <Link to="/pcap" className="btn btn-sm ml-auto">
            Open PCAP
            <ArrowRight className="size-3.5" aria-hidden />
          </Link>
        </>
      }
    >
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng"
        className="sr-only"
        onChange={(event) => {
          const chosen = event.target.files?.[0]
          if (chosen) ingest(chosen)
          event.target.value = ''
        }}
      />

      {notice ? (
        <div
          role="alert"
          className="mb-2 flex shrink-0 items-start gap-2 rounded border border-danger/40 bg-danger-dim/40 px-2.5 py-1.5 text-[11px] leading-snug text-danger"
        >
          <AlertTriangle className="mt-px size-3.5 shrink-0" aria-hidden />
          <span className="min-w-0 flex-1">{notice}</span>
          <button
            type="button"
            className="shrink-0 text-mist-faint hover:text-mist"
            onClick={() => {
              setRejected(null)
              upload.reset()
            }}
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      ) : null}

      <div
        onClick={() => {
          if (!upload.isPending) inputRef.current?.click()
        }}
        onDragOver={(event) => {
          event.preventDefault()
          event.dataTransfer.dropEffect = 'copy'
          if (!upload.isPending) setDragActive(true)
        }}
        onDragLeave={(event) => {
          if (event.currentTarget.contains(event.relatedTarget as Node | null)) return
          setDragActive(false)
        }}
        onDrop={onDrop}
        className={cx(
          'flex min-h-[132px] flex-1 cursor-pointer flex-col items-center justify-center gap-1.5 rounded border border-dashed px-4 py-5 text-center transition-colors',
          dragActive
            ? 'border-accent-400 bg-accent-dim/20'
            : 'border-edge-strong bg-night-850/60 hover:border-accent-500/60',
        )}
      >
        {upload.isPending ? (
          <>
            <Spinner className="size-4 text-accent-300" />
            <span className="text-[12.5px] font-medium text-mist">Registering capture…</span>
            <span className="truncate font-mono text-[10.5px] text-mist-faint" title={file?.name}>
              {file ? `${file.name} · ${formatBytes(file.size)}` : ''}
            </span>
          </>
        ) : (
          <>
            <Upload className="size-4 text-accent-300" aria-hidden />
            <span className="text-[12.5px] font-medium text-mist">
              {dragActive ? 'Release to open' : 'Drop PCAP / PCAPNG here'}
            </span>
            <span className="text-[10.5px] uppercase tracking-[0.08em] text-mist-faint">or</span>
            <button
              type="button"
              className="btn btn-sm"
              onClick={(event) => {
                // The whole zone is clickable; this keeps one dialog trigger.
                event.stopPropagation()
                inputRef.current?.click()
              }}
            >
              Choose file
            </button>
          </>
        )}
      </div>
    </LauncherPanel>
  )
}
