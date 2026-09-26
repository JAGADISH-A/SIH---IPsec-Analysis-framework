import type { Unsubscribe } from './common'

/** Pipeline stage of a PCAP analysis job as surfaced to the UI. */
export type PcapProcessingStage =
  | 'idle'
  | 'uploading'
  | 'validating'
  | 'parsing'
  | 'analyzing'
  | 'complete'
  | 'error'

/** Minimal file metadata used by the PCAP pipeline. */
export interface PcapFileInfo {
  name: string
  sizeBytes: number
  /** MIME type when the browser exposes one (often empty for pcap files). */
  type?: string
}

/** Summary result of an analysis pass over a capture. */
export interface PCAPAnalysis {
  fileName: string
  packetsAnalyzed: number
  ipsecPackets: number
  ikev2: number
  esp: number
  ah: number
  highRisk: number
  mediumRisk: number
}

/** Observable snapshot of an in-flight (or completed) PCAP analysis. */
export interface PcapUploadState {
  file: PcapFileInfo
  stage: PcapProcessingStage
  /** 0..100 overall completion. */
  percent: number
  message: string
  /** Populated when stage reaches `complete`. */
  result?: PCAPAnalysis
}

/** Handle returned when a PCAP upload starts; observable + cancellable. */
export interface PcapUploadHandle {
  subscribe(listener: (state: PcapUploadState) => void): Unsubscribe
  getSnapshot(): PcapUploadState
  cancel(): void
}