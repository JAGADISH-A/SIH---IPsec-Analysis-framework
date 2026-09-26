import { AlertTriangle, FileStack, Sparkles, Upload, X } from 'lucide-react'
import { cx } from '../../lib/cx'
import { formatBytes } from '../../lib/format'
import { usePcapUpload, ACCEPT_ATTR, extensionOf } from '../../hooks/usePcapUpload'
import { CompletedView, ErrorView, ProcessingView } from './pcapViews'

/**
 * PCAP Upload workspace. Pure presentation: file selection, the analysis
 * pipeline lifecycle and drag & drop state come from the `usePcapUpload` hook,
 * which talks to the `PcapService` interface — a real parsing backend can
 * replace the mock pipeline without touching this view.
 */
export function PcapUploadPage() {
  const {
    file,
    session,
    dragActive,
    banner,
    isSelectionError,
    isProcessing,
    isCompleted,
    stageError,
    inputRef,
    acceptFile,
    browse,
    analyze,
    cancel,
    restart,
    reset,
    dismissSelectionError,
    onDragOver,
    onDragLeave,
    onDrop,
  } = usePcapUpload()

  return (
    <div className="mx-auto flex h-full w-full max-w-3xl flex-col gap-3 overflow-y-auto p-6 lg:p-8">
      <header>
        <h1 className="text-lg font-semibold text-mist">Upload PCAP</h1>
        <p className="mt-0.5 text-[13px] text-mist-faint">
          Drop a capture file to run a simulated IPsec security analysis. Processing is mocked — a real parser
          connects behind the same service contract.
        </p>
      </header>

      <div
        role="region"
        aria-label="PCAP upload drop zone"
        className={cx(
          'panel w-full overflow-hidden transition-colors',
          dragActive && 'border-accent-400/70 bg-accent-dim/10',
        )}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
      >
        <input
          ref={inputRef}
          type="file"
          accept={ACCEPT_ATTR}
          className="hidden"
          onChange={(event) => {
            const chosen = event.target.files?.[0]
            if (chosen) acceptFile(chosen)
            event.target.value = ''
          }}
        />

        {banner ? (
          <div className="flex items-center gap-2 border-b border-danger/30 bg-danger-dim/40 px-4 py-2 text-xs text-danger">
            <AlertTriangle className="size-3.5 shrink-0" aria-hidden />
            <span className="min-w-0 flex-1">{banner}</span>
            {isSelectionError ? (
              <button
                type="button"
                aria-label="Dismiss error"
                onClick={dismissSelectionError}
                className="btn btn-ghost btn-icon btn-sm"
              >
                <X className="size-3.5" aria-hidden />
              </button>
            ) : null}
          </div>
        ) : null}

        {isCompleted ? (
          <CompletedView result={session?.result} onReset={reset} />
        ) : isProcessing ? (
          <ProcessingView state={session!} onCancel={cancel} />
        ) : session?.stage === 'error' ? (
          <ErrorView message={stageError ?? 'The analysis could not be completed.'} onRestart={restart} onReset={reset} />
        ) : file ? (
          <div className="flex flex-col gap-4 px-6 py-8">
            <div className="flex items-center gap-3 rounded-lg border border-edge bg-night-800/50 p-3">
              <div className="flex size-10 shrink-0 items-center justify-center rounded-md border border-edge bg-night-900 text-accent-300">
                <FileStack className="size-5" aria-hidden />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-[13px] font-medium text-mist" title={file.name}>
                    {file.name}
                  </span>
                  <span className="chip">.{extensionOf(file.name)}</span>
                </div>
                <div className="mt-0.5 truncate text-[11px] text-mist-faint">
                  {formatBytes(file.size)}
                  {file.type ? ` · ${file.type}` : ''} · PCAP capture
                </div>
              </div>
              <button
                type="button"
                aria-label="Remove file"
                title="Remove file"
                onClick={reset}
                className="btn btn-ghost btn-icon btn-sm"
              >
                <X className="size-4" aria-hidden />
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button type="button" onClick={analyze} className="btn btn-primary">
                <Sparkles className="size-4" aria-hidden />
                Analyze PCAP
              </button>
              <button type="button" onClick={browse} className="btn btn-ghost">
                Browse files
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center px-6 py-14 text-center">
            <div
              className={cx(
                'mb-4 flex size-14 items-center justify-center rounded-xl border transition-colors',
                dragActive
                  ? 'border-accent-400/60 bg-accent-dim text-accent-300'
                  : 'border-accent-500/30 bg-accent-dim text-accent-300',
              )}
            >
              <Upload className="size-6" aria-hidden />
            </div>
            <h2 className="text-lg font-semibold text-mist">
              {dragActive ? 'Release to analyze' : 'Drop your capture file here'}
            </h2>
            <p className="mt-1 max-w-sm text-[13px] text-mist-faint">
              {dragActive
                ? 'We accept .pcap and .pcapng captures for IPsec traffic analysis.'
                : 'Upload a .pcap or .pcapng capture to inspect IKEv2, ESP and AH traffic.'}
            </p>
            <div className="my-5 flex w-full max-w-[240px] items-center gap-3 text-[10px] uppercase tracking-wider text-mist-faint">
              <span className="h-px flex-1 bg-edge" aria-hidden />
              or
              <span className="h-px flex-1 bg-edge" aria-hidden />
            </div>
            <button type="button" onClick={browse} className="btn btn-primary">
              <Upload className="size-4" aria-hidden />
              Browse files
            </button>
            <p className="mt-4 text-[11px] text-mist-faint">Accepted formats: .pcap · .pcapng</p>
          </div>
        )}
      </div>
    </div>
  )
}