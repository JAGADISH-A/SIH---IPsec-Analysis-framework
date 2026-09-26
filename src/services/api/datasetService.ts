import type {
  CaptureMetadata,
  CaptureRecord,
  DatasetPage,
  DatasetQuery,
  DatasetStats,
} from '../../types/dataset'

export interface CaptureUploadOptions {
  label: CaptureRecord['label']
  ikeVersion: CaptureRecord['ikeVersion']
  vpnMode: CaptureRecord['vpnMode']
  trafficType: CaptureRecord['trafficType']
  /** Skip dissection and store metadata only. */
  metadataOnly: boolean
}

/** Progress callback for a running ingest. */
export type UploadProgress = (percent: number, stage: string) => void

/**
 * Capture archive: browse, upload and fetch artefacts.
 *
 * Ingest is a backend job even in mock mode — the frontend shows stage
 * progress and never parses a capture file itself. Raw payload access is
 * gated by `payloadAccess` on the record, not by the client.
 */
export interface DatasetService {
  query(query?: DatasetQuery): Promise<DatasetPage>
  getStats(): Promise<DatasetStats>
  getMetadata(id: string): Promise<CaptureMetadata>
  upload(file: File, options: CaptureUploadOptions, onProgress?: UploadProgress): Promise<CaptureRecord>
  remove(id: string): Promise<void>
  /** Resolve the capture artefact URL for download. */
  getDownloadUrl(id: string): Promise<string>
}
