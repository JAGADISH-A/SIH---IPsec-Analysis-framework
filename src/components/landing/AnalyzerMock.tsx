import { Fragment } from 'react'
import { Filter, Play, Radio, Square, Trash2 } from 'lucide-react'
import { riskStyle, protocolStyle } from '../analyzer/workspaceTheme.ts'
import type { RiskLevel } from '../../types/security'

/* ------------------------------------------------------------------ */
/* Static preview of the Live Analyzer, rendered in the same light     */
/* workspace language as the real thing: capture toolbar, display     */
/* filter, dense packet table, and one row expanded inline.           */
/* Presentation only — no packet logic, no state.                      */
/* ------------------------------------------------------------------ */

interface PreviewRow {
  no: number
  time: string
  proto: 'IKEv2' | 'ESP' | 'AH' | 'DNS' | 'TCP'
  src: string
  dst: string
  len: number
  info: string
  risk: RiskLevel | null
  /** Row shown expanded, with its detail block. */
  detail?: {
    kind: string
    rows: [string, string][]
    finding?: { severity: RiskLevel; title: string; body: string; fix: string }
  }
}

const ROWS: PreviewRow[] = [
  {
    no: 1021,
    time: '20:31:03.012',
    proto: 'IKEv2',
    src: '10.8.0.2',
    dst: '10.8.0.1',
    len: 428,
    info: 'IKE_SA_INIT request · proposing AES-GCM-16 / SHA2-256',
    risk: null,
  },
  {
    no: 1022,
    time: '20:31:03.125',
    proto: 'IKEv2',
    src: '10.8.0.1',
    dst: '10.8.0.2',
    len: 356,
    info: 'IKE_SA_INIT response · accepted proposal 1',
    risk: null,
  },
  {
    no: 1023,
    time: '20:31:03.226',
    proto: 'ESP',
    src: '10.8.0.2',
    dst: '10.8.0.1',
    len: 512,
    info: 'ESP (SPI 0x8f2c1a44) · ENCR_3DES_CBC',
    risk: 'medium',
    detail: {
      kind: 'ESP Header',
      rows: [
        ['SPI', '0x8f2c1a44'],
        ['Sequence Number', '441'],
        ['Payload Length', '458 bytes'],
        ['Encryption Algorithm', 'ENCR_3DES_CBC'],
        ['Integrity Algorithm', 'HMAC-SHA1-96'],
        ['Mode', 'Tunnel mode'],
      ],
      finding: {
        severity: 'medium',
        title: 'Legacy cryptographic configuration detected',
        body: 'ESP is using 3DES-CBC with HMAC-SHA1-96. RFC 8247 deprecates ENCR_3DES_CBC for new security associations.',
        fix: 'Re-negotiate the child SA with ENCR_AES_GCM_16 and HMAC-SHA2-256-128.',
      },
    },
  },
  {
    no: 1024,
    time: '20:31:03.521',
    proto: 'ESP',
    src: '10.8.0.1',
    dst: '10.8.0.2',
    len: 512,
    info: 'ESP (SPI 0x8f2c1a45) · ENCR_AES_GCM_16',
    risk: null,
  },
  {
    no: 1025,
    time: '20:31:03.884',
    proto: 'AH',
    src: '10.4.8.15',
    dst: '10.4.8.16',
    len: 96,
    info: 'AH (SPI 0x2b7d0910) · HMAC-MD5-96',
    risk: 'high',
  },
  {
    no: 1026,
    time: '20:31:04.010',
    proto: 'DNS',
    src: '10.20.1.5',
    dst: '8.8.8.8',
    len: 74,
    info: 'Standard query 0x1f3a A resolver.dc1.example',
    risk: null,
  },
]

function Toolbar() {
  return (
    <div className="ws-bar ws-bar-raised">
      <span className="ws-btn ws-btn-primary">
        <Play className="size-3.5" aria-hidden />
        Start Capture
      </span>
      <span className="ws-btn">
        <Trash2 className="size-3.5" aria-hidden />
        Clear
      </span>
      <span className="ws-select !flex w-[104px] items-center">eth0</span>

      <span className="flex items-center gap-1.5">
        <span className="inline-block size-2 animate-pulse-dot rounded-full bg-ws-esp" aria-hidden />
        <span className="text-[12px] font-semibold text-ws-esp">Capturing packets…</span>
        <span className="ws-chip mono-tab">00:01:24</span>
      </span>

      <span className="ml-auto flex items-center">
        {[
          ['Packets', '1,248'],
          ['Rate', '2.4 Gbps'],
          ['IPsec', '1,203'],
          ['High', '7'],
          ['Medium', '21'],
        ].map(([label, value]) => (
          <span key={label} className="ws-stat">
            <span className="ws-stat-label">{label}</span>
            <span className="ws-stat-value">{value}</span>
          </span>
        ))}
      </span>
    </div>
  )
}

function FilterStrip() {
  return (
    <div className="ws-bar ws-bar-tight">
      <span className="ws-bar-title flex items-center gap-1.5">
        <Filter className="size-3" aria-hidden />
        Display Filter
      </span>
      <span className="ws-input !flex flex-1 items-center text-ws-faint">ip.addr == 10.8.0.2 &amp;&amp; esp</span>
      <span className="ws-btn ws-btn-primary">Apply</span>
      <span className="ws-btn">Clear</span>
    </div>
  )
}

function DetailBlock({ row }: { row: NonNullable<PreviewRow['detail']> }) {
  const finding = row.finding
  return (
    <div className="ws">
      <div className="flex flex-wrap items-center gap-2 border-b border-ws-line bg-ws-panel px-2.5 py-1.5">
        <span className="ws-bar-title">Packet 1023 Details</span>
        <span
          className="ws-proto"
          style={{ ...protocolStyle('ESP'), borderColor: protocolStyle('ESP').color }}
        >
          ESP
        </span>
        {finding ? (
          <span
            className="ws-risk"
            style={{ ...riskStyle(finding.severity), borderColor: riskStyle(finding.severity).color }}
          >
            Medium Risk
          </span>
        ) : null}
        <span className="mono-tab text-[11px] text-ws-dim">10.8.0.2 → 10.8.0.1</span>
        <span className="mono-tab text-[10.5px] text-ws-faint">20:31:03.226 · 512 bytes</span>
        <span className="ws-btn ws-btn-ghost ml-auto">Ask AI</span>
      </div>

      <div className="ws-tabs border-b border-ws-line">
        {['Overview', 'Protocol Details', 'Security Analysis', 'Raw Packet'].map((tab) => (
          <span key={tab} className="ws-tab" aria-selected={tab === 'Overview'} role="presentation">
            {tab}
          </span>
        ))}
      </div>

      <div className="grid gap-2 p-2 lg:grid-cols-2">
        <section className="ws-section">
          <div className="ws-section-head">{row.kind}</div>
          <div className="ws-section-body">
            <dl className="ws-kv" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
              {row.rows.map(([label, value]) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>

        <section className="ws-section">
          <div className="ws-section-head">Security Assessment</div>
          <div className="ws-section-body">
            {finding ? (
              <div
                className="ws-finding"
                style={{ borderLeftColor: riskStyle(finding.severity).color }}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-[12px] font-bold text-ws-text">{finding.title}</span>
                  <span
                    className="ws-risk"
                    style={{ ...riskStyle(finding.severity), borderColor: riskStyle(finding.severity).color }}
                  >
                    Medium
                  </span>
                </div>
                <p className="mt-1 text-[11px] leading-snug text-ws-dim">{finding.body}</p>
                <p className="mt-1 text-[11px] leading-snug text-ws-accent-ink">
                  <span className="font-semibold">Recommendation · </span>
                  {finding.fix}
                </p>
              </div>
            ) : null}
          </div>
        </section>
      </div>
    </div>
  )
}

export function AnalyzerMock({ className }: { className?: string }) {
  return (
    <div
      className={`ws overflow-hidden rounded-[4px] border border-ws-line-strong shadow-[0_24px_60px_-24px_rgb(0_0_0/0.75)] ${className ?? ''}`}
    >
      <div className="flex items-center gap-2 border-b border-ws-line bg-night-900 px-3 py-2">
        <Radio className="size-3.5 text-accent-400" aria-hidden />
        <span className="text-[12px] font-semibold text-mist">Live Analyzer</span>
        <span className="chip">
          <span className="size-1.5 animate-pulse-dot rounded-full bg-accent-400" aria-hidden />
          live · 1.24k pkt/s
        </span>
        <span className="ml-auto flex items-center gap-1.5">
          <span className="ws-btn ws-btn-ghost">
            <Square className="size-3" aria-hidden />
            Stop
          </span>
        </span>
      </div>

      <Toolbar />
      <FilterStrip />

      <div className="ws-scroll max-h-[340px] overflow-auto">
        <table className="ws-table min-w-[820px]">
          <thead>
            <tr>
              <th className="w-[62px] text-right">No.</th>
              <th className="w-[104px] text-right">Time</th>
              <th className="w-[132px]">Source</th>
              <th className="w-[132px]">Destination</th>
              <th className="w-[72px]">Protocol</th>
              <th className="w-[62px] text-right">Length</th>
              <th>Info</th>
              <th className="w-[74px] text-right">Risk</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((row) => (
              <Fragment key={row.no}>
                <tr className="ws-row" data-selected={row.detail ? 'true' : undefined}>
                  <td className="mono-tab text-right text-[10.5px] text-ws-faint">{row.no}</td>
                  <td className="mono-tab text-right text-[10.5px] text-ws-dim">{row.time}</td>
                  <td className="mono-tab text-[11px] text-ws-dim">{row.src}</td>
                  <td className="mono-tab text-[11px] text-ws-dim">{row.dst}</td>
                  <td>
                    <span
                      className="ws-proto"
                      style={{ ...protocolStyle(row.proto), borderColor: protocolStyle(row.proto).color }}
                    >
                      {row.proto}
                    </span>
                  </td>
                  <td className="mono-tab text-right text-[11px] text-ws-dim">{row.len}</td>
                  <td className="truncate text-[11px] text-ws-dim">{row.info}</td>
                  <td className="text-right">
                    {row.risk ? (
                      <span
                        className="ws-risk"
                        style={{ ...riskStyle(row.risk), borderColor: riskStyle(row.risk).color }}
                      >
                        {riskStyle(row.risk).label}
                      </span>
                    ) : (
                      <span className="text-[10px] text-ws-faint">—</span>
                    )}
                  </td>
                </tr>
                {row.detail ? (
                  <tr className="ws-detail-row">
                    <td colSpan={8}>
                      <DetailBlock row={row.detail} />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>

      <div className="ws-bar ws-bar-tight justify-between">
        <span className="text-[10.5px] text-ws-faint">
          No. · Time · Source · Destination · Protocol · Length · Info · Risk
        </span>
        <span className="mono-tab text-[10.5px] text-ws-faint">
          1,248 of 4,096 shown · 8,192 packet ring buffer
        </span>
      </div>
    </div>
  )
}
