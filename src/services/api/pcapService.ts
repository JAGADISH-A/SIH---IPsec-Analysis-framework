import type { PcapUploadHandle } from '../../types/pcap'

/**
 * Frontend-only PCAP processing contract. Today the mock simulates the full
 * upload → validate → parse → analyze pipeline and fabricates a plausible
 * result; a real PCAP backend implements the same contract without any UI
 * changes.
 */
export interface PcapService {
  startUpload(file: File): PcapUploadHandle
}