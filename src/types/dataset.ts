import type { IkevVersion, IpVersion, VpnMode } from './session'

export type CaptureLabel =
  | 'benign'
  | 'weak-crypto'
  | 'weak-dh'
  | 'no-pfs'
  | 'replay-probe'
  | 'lifetime-abuse'
  | 'downgrade-probe'
  | 'traffic-anomaly'
  | 'unlabelled'

export const CAPTURE_LABEL_LABEL: Record<CaptureLabel, string> = {
  benign: 'Benign',
  'weak-crypto': 'Weak crypto',
  'weak-dh': 'Weak DH',
  'no-pfs': 'No PFS',
  'replay-probe': 'Replay probe',
  'lifetime-abuse': 'Lifetime abuse',
  'downgrade-probe': 'Downgrade probe',
  'traffic-anomaly': 'Traffic anomaly',
  unlabelled: 'Unlabelled',
}

export type CaptureTrafficType =
  | 'interactive'
  | 'bulk'
  | 'streaming'
  | 'rekey-cycle'
  | 'idle'
  | 'mixed'

export interface CaptureRecord {
  id: string
  experimentId: string | null
  fileName: string
  sizeBytes: number
  ikeVersion: IkevVersion
  vpnMode: VpnMode
  encryption: string
  dhGroup: string
  perfectForwardSecrecy: boolean
  ipVersion: IpVersion
  trafficType: CaptureTrafficType
  packetCount: number
  byteCount: number
  durationMs: number
  label: CaptureLabel
  createdAt: string
  /** Sessions extracted from this capture. */
  sessionCount: number
  findingCount: number
  /** sha256 of the capture file, as recorded by the ingest service. */
  checksum: string
  testbed: string
  /** Whether raw payloads may be rendered; false requires authorisation. */
  payloadAccess: boolean
}

export interface DatasetStats {
  totalCaptures: number
  totalPackets: number
  totalBytes: number
  totalDurationMs: number
  labelledCaptures: number
  byLabel: { label: CaptureLabel; labelText: string; count: number; share: number }[]
  byIkeVersion: { label: string; value: number; share: number }[]
  byEncryption: { label: string; value: number; share: number }[]
  byIpVersion: { label: string; value: number; share: number }[]
  byMode: { label: string; value: number; share: number }[]
  byPfs: { label: string; value: number; share: number }[]
}

export interface DatasetQuery {
  search?: string
  labels?: CaptureLabel[]
  ikeVersions?: IkevVersion[]
  ipVersions?: IpVersion[]
  trafficTypes?: CaptureTrafficType[]
  pfs?: ('enabled' | 'disabled')[]
  from?: string
  to?: string
  page?: number
  pageSize?: number
}

export interface DatasetPage {
  items: CaptureRecord[]
  total: number
  page: number
  pageSize: number
}

/** Capture metadata as served by the metadata download endpoint. */
export interface CaptureMetadata {
  capture: CaptureRecord
  generator: string
  snaplen: number
  linkType: string
  firstPacketAt: string
  lastPacketAt: string
  filters: string[]
  notes: string
}
