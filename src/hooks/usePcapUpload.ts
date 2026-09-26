import { useCallback, useEffect, useRef, useState, type DragEvent } from 'react'
import { services } from '../services'
import type { PcapService } from '../services/api/pcapService'
import type { PcapProcessingStage, PcapUploadHandle, PcapUploadState } from '../types/pcap'

export const ACCEPTED_EXTENSIONS = ['pcap', 'pcapng']
export const ACCEPT_ATTR = '.pcap,.pcapng'

/** Ordered pipeline steps surfaced by the processing view. */
export const PIPELINE_STEPS = [
  { key: 'upload', label: 'Uploading' },
  { key: 'parse', label: 'Parsing packets' },
  { key: 'extract', label: 'Extracting IPsec protocols' },
  { key: 'analyze', label: 'Running security analysis' },
]

/** Maps a pipeline stage/progress onto an index over PIPELINE_STEPS. */
export function stepIndex(stage: PcapProcessingStage, percent: number): number {
  switch (stage) {
    case 'uploading':
    case 'validating':
      return 0
    case 'parsing':
      return 1
    case 'analyzing':
      return percent <= 81 ? 2 : 3
    case 'complete':
      return 4
    default:
      return -1
  }
}

export function extensionOf(name: string): string {
  const index = name.lastIndexOf('.')
  return index >= 0 ? name.slice(index + 1).toLowerCase() : ''
}

/**
 * PCAP upload workflow bound to the `PcapService` interface (mock pipeline
 * today, a real parsing backend later — zero UI changes). Owns file
 * selection/validation, the upload session lifecycle and drag & drop state.
 */
export function usePcapUpload(pcapService: PcapService = services.pcap) {
  const [file, setFile] = useState<File | null>(null)
  const [session, setSession] = useState<PcapUploadState | null>(null)
  const [dragActive, setDragActive] = useState(false)
  const [selectionError, setSelectionError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const handleRef = useRef<PcapUploadHandle | null>(null)
  const unsubRef = useRef<(() => void) | null>(null)

  const stage = session?.stage ?? 'idle'
  const isProcessing = ['uploading', 'validating', 'parsing', 'analyzing'].includes(stage)
  const isCompleted = stage === 'complete'
  const stageError = stage === 'error' ? session?.message : null
  const banner = selectionError
  const isSelectionError = selectionError !== null

  useEffect(() => {
    return () => {
      unsubRef.current?.()
      handleRef.current?.cancel()
    }
  }, [])

  const acceptFile = useCallback((candidate: File) => {
    if (!ACCEPTED_EXTENSIONS.includes(extensionOf(candidate.name))) {
      setSelectionError(
        `Unsupported file type “${extensionOf(candidate.name) || 'unknown'}”. Only .pcap and .pcapng captures are accepted.`,
      )
      return
    }
    setSelectionError(null)
    unsubRef.current?.()
    unsubRef.current = null
    handleRef.current = null
    setSession(null)
    setFile(candidate)
  }, [])

  const browse = useCallback(() => inputRef.current?.click(), [])

  const analyze = useCallback(() => {
    if (!file) return
    unsubRef.current?.()
    const handle = pcapService.startUpload(file)
    handleRef.current = handle
    setSession(handle.getSnapshot())
    unsubRef.current = handle.subscribe(setSession)
  }, [file, pcapService])

  const cancel = useCallback(() => handleRef.current?.cancel(), [])

  const restart = useCallback(() => {
    unsubRef.current?.()
    unsubRef.current = null
    handleRef.current = null
    setSession(null)
    setSelectionError(null)
  }, [])

  const reset = useCallback(() => {
    restart()
    setFile(null)
  }, [restart])

  const dismissSelectionError = useCallback(() => setSelectionError(null), [])

  const onDragOver = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      if (isProcessing) return
      event.preventDefault()
      event.dataTransfer.dropEffect = 'copy'
      setDragActive(true)
    },
    [isProcessing],
  )

  const onDragLeave = useCallback((event: DragEvent<HTMLDivElement>) => {
    if (event.currentTarget.contains(event.relatedTarget as Node | null)) return
    setDragActive(false)
  }, [])

  const onDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault()
      setDragActive(false)
      if (isProcessing) return
      const dropped = event.dataTransfer.files?.[0]
      if (dropped) acceptFile(dropped)
    },
    [isProcessing, acceptFile],
  )

  return {
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
  }
}