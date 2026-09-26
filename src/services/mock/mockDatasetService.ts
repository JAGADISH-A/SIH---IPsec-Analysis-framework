import type { CaptureUploadOptions, DatasetService, UploadProgress } from '../api/datasetService'
import type {
  CaptureLabel,
  CaptureMetadata,
  CaptureRecord,
  DatasetPage,
  DatasetQuery,
  DatasetStats,
} from '../../types/dataset'
import { CAPTURE_LABEL_LABEL } from '../../types/dataset'
import { mockDataset } from './mockData'
import { inFilter, invalid, latency, matchesSearch, notFound, paginate, withinRange } from './mockSupport'

/** Ingest stages, mirroring the backend's dissect → index → summarise job. */
const INGEST_STAGES: { percent: number; stage: string }[] = [
  { percent: 8, stage: 'Validating file' },
  { percent: 22, stage: 'Reading packets' },
  { percent: 45, stage: 'Dissecting IKE and ESP' },
  { percent: 68, stage: 'Extracting sessions' },
  { percent: 86, stage: 'Indexing' },
  { percent: 96, stage: 'Summarising' },
]

/** PCAP/PCAPNG magic bytes, so the frontend can reject the obvious case early. */
const MAGIC = new Set(['d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d', '0a0d0d0a'])

function readMagic(file: File): Promise<boolean> {
  return file
    .slice(0, 4)
    .arrayBuffer()
    .then((buffer) => {
      const bytes = [...new Uint8Array(buffer)]
      const hex = bytes
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('')
      return MAGIC.has(hex)
    })
    .catch(() => false)
}

export class MockDatasetService implements DatasetService {
  private readonly captures: CaptureRecord[] = [...mockDataset.captures]
  private nextId = 1

  async query(query: DatasetQuery = {}): Promise<DatasetPage> {
    const matched = this.captures
      .filter(
        (capture) =>
          matchesSearch(query.search, capture.id, capture.fileName, capture.testbed, capture.encryption) &&
          inFilter(capture.label, query.labels) &&
          inFilter(capture.ikeVersion, query.ikeVersions) &&
          inFilter(capture.ipVersion, query.ipVersions) &&
          inFilter(capture.trafficType, query.trafficTypes) &&
          inFilter(
            capture.perfectForwardSecrecy ? 'enabled' : 'disabled',
            query.pfs,
          ) &&
          withinRange(capture.createdAt, query.from, query.to),
      )
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0))
    const page = paginate(matched, query.page, query.pageSize)
    return latency({ items: page.items, total: page.total, page: page.page, pageSize: page.pageSize }, 140)
  }

  async getStats(): Promise<DatasetStats> {
    const total = this.captures.length || 1
    const share = (value: number): number => value / total
    const countBy = (pick: (capture: CaptureRecord) => string): { label: string; value: number; share: number }[] => {
      const counts = new Map<string, number>()
      for (const capture of this.captures) {
        const key = pick(capture)
        counts.set(key, (counts.get(key) ?? 0) + 1)
      }
      return [...counts.entries()]
        .map(([label, value]) => ({ label, value, share: share(value) }))
        .sort((a, b) => b.value - a.value)
    }

    return latency(
      {
        totalCaptures: this.captures.length,
        totalPackets: this.captures.reduce((sum, capture) => sum + capture.packetCount, 0),
        totalBytes: this.captures.reduce((sum, capture) => sum + capture.byteCount, 0),
        totalDurationMs: this.captures.reduce((sum, capture) => sum + capture.durationMs, 0),
        labelledCaptures: this.captures.filter((capture) => capture.label !== 'unlabelled').length,
        byLabel: countBy((capture) => capture.label).map((entry) => ({
          label: entry.label as CaptureLabel,
          labelText: CAPTURE_LABEL_LABEL[entry.label as CaptureLabel],
          count: entry.value,
          share: entry.share,
        })),
        byIkeVersion: countBy((capture) => capture.ikeVersion),
        byEncryption: countBy((capture) => capture.encryption),
        byIpVersion: countBy((capture) => capture.ipVersion),
        byMode: countBy((capture) => capture.vpnMode),
        byPfs: countBy((capture) => (capture.perfectForwardSecrecy ? 'PFS enabled' : 'PFS disabled')),
      },
      120,
    )
  }

  async getMetadata(id: string): Promise<CaptureMetadata> {
    const capture = this.captures.find((entry) => entry.id === id)
    if (!capture) throw notFound('Capture', id)
    return latency(
      {
        capture,
        generator: 'IPsec Sentinel testbed capture agent',
        snaplen: 262_144,
        linkType: 'LINKTYPE_ETHERNET (1)',
        firstPacketAt: capture.createdAt,
        lastPacketAt: new Date(Date.parse(capture.createdAt) + capture.durationMs).toISOString(),
        filters: ['ip proto 50 or ip proto 51', 'udp port 500 or udp port 4500'],
        notes: capture.payloadAccess
          ? 'Raw payload access is authorised for this capture.'
          : 'Raw payload access is not authorised for this capture.',
      },
      110,
    )
  }

  async upload(
    file: File,
    options: CaptureUploadOptions,
    onProgress?: UploadProgress,
  ): Promise<CaptureRecord> {
    if (file.size === 0) throw invalid('The selected file is empty.')
    if (!/\.(pcap|pcapng|cap)$/i.test(file.name)) {
      throw invalid('Select a .pcap or .pcapng file.')
    }
    if (!(await readMagic(file))) {
      throw invalid('The file does not start with a PCAP or PCAPNG magic number.')
    }

    for (const stage of INGEST_STAGES) {
      onProgress?.(stage.percent, stage.stage)
      await new Promise((resolve) => window.setTimeout(resolve, 220))
    }

    const id = `CAP-NEW-${String(this.nextId).padStart(3, '0')}`
    this.nextId += 1
    const packets = Math.max(1, Math.floor(file.size / 420))
    const capture: CaptureRecord = {
      id,
      experimentId: null,
      fileName: file.name,
      sizeBytes: file.size,
      ikeVersion: options.ikeVersion,
      vpnMode: options.vpnMode,
      encryption: 'Pending dissection',
      dhGroup: 'Pending dissection',
      perfectForwardSecrecy: false,
      ipVersion: 'IPv4',
      trafficType: options.trafficType,
      packetCount: options.metadataOnly ? 0 : packets,
      byteCount: options.metadataOnly ? 0 : file.size,
      durationMs: 0,
      label: options.label,
      createdAt: new Date().toISOString(),
      sessionCount: 0,
      findingCount: 0,
      checksum: 'pending',
      testbed: 'uploaded',
      payloadAccess: false,
    }
    this.captures.unshift(capture)
    onProgress?.(100, 'Stored')
    return latency(capture, 100)
  }

  async remove(id: string): Promise<void> {
    const index = this.captures.findIndex((entry) => entry.id === id)
    if (index < 0) throw notFound('Capture', id)
    this.captures.splice(index, 1)
    return latency(undefined, 80)
  }

  async getDownloadUrl(id: string): Promise<string> {
    const capture = this.captures.find((entry) => entry.id === id)
    if (!capture) throw notFound('Capture', id)
    const body = `# ${capture.fileName}\n# mock artefact for ${capture.id}\n`
    return latency(URL.createObjectURL(new Blob([body], { type: 'text/plain' })), 60)
  }
}
