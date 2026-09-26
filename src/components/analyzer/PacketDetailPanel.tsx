import { useMemo, useState } from 'react'
import { ChevronUp, ListTree, ShieldCheck, Sparkles, TriangleAlert } from 'lucide-react'
import { formatArrivalTime } from '../../lib/format'
import { buildPacketDetails } from '../../lib/packetDetails'
import { packetIpsecSummary } from '../../lib/ipsecSummary'
import { useAiAssistant } from '../../state/aiAssistant.tsx'
import { findingEdge, protocolStyle, riskStyle } from './workspaceTheme.ts'
import type { Packet } from '../../types/packet'
import type { DetailRow, HexLine } from '../../types/packetDetails'

interface PacketDetailPanelProps {
  packet: Packet
  interfaceName?: string
  /** Called when the analyst collapses the block (usually deselects the row). */
  onCollapse?(): void
}

type TabId = 'overview' | 'protocol' | 'security' | 'raw'

const TABS: { id: TabId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'protocol', label: 'Protocol Details' },
  { id: 'security', label: 'Security Analysis' },
  { id: 'raw', label: 'Raw Packet' },
]

/** Compact key/value grid — the workhorse of every tab. */
function KV({ rows, columns }: { rows: DetailRow[]; columns?: number }) {
  return (
    <dl
      className="ws-kv"
      style={columns ? { gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` } : undefined}
    >
      {rows.map((row) => (
        <div key={row.title}>
          <dt>{row.title}</dt>
          <dd title={row.value}>{row.value}</dd>
          {row.note ? <dd className="ws-kv-note" data-tone="muted">{row.note}</dd> : null}
        </div>
      ))}
    </dl>
  )
}

function Section({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="ws-section">
      <div className="ws-section-head">
        <span>{title}</span>
        {action ? <span className="ml-auto">{action}</span> : null}
      </div>
      <div className="ws-section-body">{children}</div>
    </section>
  )
}

function EmptyHint({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return (
    <div className="flex flex-col items-center gap-1.5 py-6 text-center">
      <span className="text-ws-faint">{icon}</span>
      <span className="text-[12px] font-semibold text-ws-text">{title}</span>
      <span className="max-w-sm text-[11px] text-ws-dim">{description}</span>
    </div>
  )
}

function RiskPill({ packet }: { packet: Packet }) {
  const style = riskStyle(packet.risk ?? 'none')
  return (
    <span
      className="ws-risk"
      style={{ color: style.color, background: style.background, borderColor: style.color }}
    >
      {packet.risk ? `${style.label} Risk` : 'No Risk'}
    </span>
  )
}

/* ------------------------------------------------------------------ */
/* Tabs                                                                */
/* ------------------------------------------------------------------ */

function OverviewTab({ packet, interfaceName }: { packet: Packet; interfaceName: string }) {
  const details = useMemo(() => buildPacketDetails(packet, interfaceName), [packet, interfaceName])
  const ipsecRows = details.protocols
  const summary = packet.ipsec ? packetIpsecSummary(packet) : null
  const finding = packet.findings[0]

  return (
    <div className="grid gap-2 xl:grid-cols-2">
      <Section title="Frame">
        <KV
          rows={[
            { title: 'Frame number', value: String(packet.number) },
            { title: 'Frame length', value: `${packet.length} bytes` },
            { title: 'Interface', value: interfaceName },
            { title: 'Arrival time', value: formatArrivalTime(packet.timestamp) },
            { title: 'Source', value: packet.source },
            { title: 'Destination', value: packet.destination },
            { title: 'Protocol', value: packet.protocol },
            { title: 'Length', value: `${packet.length} bytes` },
          ]}
          columns={2}
        />
      </Section>

      <Section title={`${packet.protocol} Header`}>
        {ipsecRows.length > 0 ? (
          <KV rows={ipsecRows} columns={2} />
        ) : (
          <p className="text-[11.5px] text-ws-dim">
            This frame carries no IPsec header. Its protocol stack is{' '}
            <span className="mono-tab text-ws-text">{packet.protocolStack.join(' → ') || 'unknown'}</span>.
          </p>
        )}
      </Section>

      {summary ? (
        <Section title="Security Assessment">
          <div className="flex flex-wrap items-center gap-2">
            <RiskPill packet={packet} />
            {summary.securityProtocols.map((protocol) => {
              const style = protocolStyle(protocol)
              return (
                <span
                  key={protocol}
                  className="ws-proto"
                  style={{ color: style.color, background: style.background, borderColor: style.color }}
                >
                  {protocol}
                </span>
              )
            })}
            {summary.encryption ? <span className="ws-chip mono-tab">{summary.encryption}</span> : null}
            {summary.integrity ? <span className="ws-chip mono-tab">{summary.integrity}</span> : null}
          </div>

          {finding ? (
            <div className="mt-2 flex gap-2">
              <TriangleAlert className="mt-0.5 size-3.5 shrink-0" style={{ color: findingEdge(finding.severity) }} aria-hidden />
              <div className="min-w-0">
                <div className="text-[11.5px] font-semibold text-ws-text">Finding: {finding.title}</div>
                <p className="mt-0.5 text-[11px] leading-snug text-ws-dim">{finding.description}</p>
                {finding.recommendation ? (
                  <p className="mt-1 text-[11px] leading-snug text-ws-accent-ink">
                    Recommendation: {finding.recommendation}
                  </p>
                ) : null}
              </div>
            </div>
          ) : (
            <p className="mt-2 text-[11px] text-ws-dim">
              No security finding on this frame — the negotiated parameters meet the current rule set.
            </p>
          )}
        </Section>
      ) : null}

      <Section title="Protocol Stack">
        <div className="flex flex-wrap items-center gap-1.5">
          {packet.protocolStack.length > 0 ? (
            packet.protocolStack.map((layer, index) => (
              <span key={`${layer}-${index}`} className="flex items-center gap-1.5">
                <span className="ws-layer-abbr">{layer}</span>
                {index < packet.protocolStack.length - 1 ? (
                  <span className="text-ws-faint" aria-hidden>
                    ›
                  </span>
                ) : null}
              </span>
            ))
          ) : (
            <span className="text-[11px] text-ws-faint">Not dissected</span>
          )}
        </div>
      </Section>
    </div>
  )
}

function ProtocolTab({ packet, interfaceName }: { packet: Packet; interfaceName: string }) {
  const details = useMemo(() => buildPacketDetails(packet, interfaceName), [packet, interfaceName])

  if (packet.layers.length === 0 && details.protocols.length === 0) {
    return (
      <EmptyHint
        icon={<ListTree className="size-4" aria-hidden />}
        title="No protocol details available"
        description={`The dissection tree for frame ${packet.number} is empty — no decodable layers were produced.`}
      />
    )
  }

  return (
    <div className="grid gap-2">
      <Section title="Dissection Tree">
        <div className="grid gap-2.5">
          {packet.layers.map((layer, index) => (
            <div
              key={layer.id}
              className="ws-layer"
              style={{ borderLeftColor: index % 2 === 0 ? 'var(--color-ws-line)' : 'var(--color-ws-line-strong)' }}
            >
              <div className="ws-layer-head">
                <span className="ws-layer-abbr">{layer.abbreviation}</span>
                <span className="ws-layer-name">{layer.name}</span>
                {layer.summary ? <span className="ws-layer-sum">{layer.summary}</span> : null}
              </div>
              {layer.fields.length > 0 ? (
                <div className="mt-1.5">
                  <KV
                    rows={layer.fields.map((field) => ({
                      title: field.title,
                      value: field.value || '—',
                      note: field.note,
                    }))}
                  />
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </Section>

      {details.protocols.length > 0 ? (
        <Section title="IPsec Security Association">
          <KV rows={details.protocols} />
        </Section>
      ) : null}
    </div>
  )
}

function SecurityTab({ packet }: { packet: Packet }) {
  if (packet.findings.length === 0) {
    return (
      <EmptyHint
        icon={<ShieldCheck className="size-4" aria-hidden />}
        title="No security findings"
        description="This packet passed the analysis engine cleanly. No tuning is recommended."
      />
    )
  }

  return (
    <div className="grid gap-2">
      {packet.findings.map((finding) => (
        <article
          key={finding.id}
          className="ws-finding"
          style={{ borderLeftColor: findingEdge(finding.severity) }}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[12px] font-bold text-ws-text">{finding.title}</span>
            <span
              className="ws-risk"
              style={{
                color: riskStyle(finding.severity).color,
                background: riskStyle(finding.severity).background,
                borderColor: riskStyle(finding.severity).color,
              }}
            >
              {riskStyle(finding.severity).label}
            </span>
            <span className="ws-chip">{finding.category}</span>
            {finding.ruleId ? <span className="mono-tab text-[10.5px] text-ws-faint">{finding.ruleId}</span> : null}
          </div>

          <p className="mt-1.5 text-[11.5px] leading-snug text-ws-dim">{finding.description}</p>

          {finding.recommendation ? (
            <p className="mt-1.5 text-[11.5px] leading-snug text-ws-accent-ink">
              <span className="font-semibold">Recommendation · </span>
              {finding.recommendation}
            </p>
          ) : null}

          {finding.affectedFields.length > 0 ? (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="ws-bar-title">Affected fields</span>
              {finding.affectedFields.map((field) => (
                <span key={field} className="ws-chip mono-tab">
                  {field}
                </span>
              ))}
            </div>
          ) : null}

          {finding.references && finding.references.length > 0 ? (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="ws-bar-title">References</span>
              {finding.references.map((reference) => (
                <span key={reference} className="mono-tab text-[10.5px] text-ws-faint">
                  {reference}
                </span>
              ))}
            </div>
          ) : null}
        </article>
      ))}
    </div>
  )
}

function RawTab({ packet, lines }: { packet: Packet; lines: HexLine[] }) {
  // Keep the viewer compact: a long jumbo frame is trimmed to the first blocks.
  const MAX_LINES = 24
  const shown = lines.slice(0, MAX_LINES)
  const hidden = lines.length - shown.length

  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-ws-dim">
        <span className="ws-chip mono-tab">{packet.length} bytes</span>
        <span className="ws-chip mono-tab">{lines.length} lines</span>
        <span className="text-ws-faint">Hexadecimal packet bytes · synthesized locally</span>
      </div>

      <div className="ws-hex ws-scroll max-h-[260px]">
        {shown.map((line) => (
          <div key={line.offset} className="ws-hex-row">
            <span className="ws-hex-offset">{line.offset}</span>
            <span className="ws-hex-bytes">{line.hex}</span>
            <span className="ws-hex-ascii">{line.ascii}</span>
          </div>
        ))}
        {hidden > 0 ? (
          <div className="px-2.5 pt-1 text-[10.5px] text-ws-faint">
            … {hidden} more line{hidden === 1 ? '' : 's'} not shown
          </div>
        ) : null}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Panel                                                               */
/* ------------------------------------------------------------------ */

/**
 * The expanded packet detail, rendered **inside** the table row directly below
 * the packet it describes. Selecting a different packet collapses this one and
 * opens the new one in place — the analyst never scrolls to a separate
 * detail page, and nothing opens in a modal.
 */
export function PacketDetailPanel({ packet, interfaceName = 'eth0', onCollapse }: PacketDetailPanelProps) {
  const [activeTab, setActiveTab] = useState<TabId>('overview')
  const { openAssistant } = useAiAssistant()
  const details = useMemo(() => buildPacketDetails(packet, interfaceName), [packet, interfaceName])
  const protoStyle = protocolStyle(packet.protocol)

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return
    event.preventDefault()
    const index = TABS.findIndex((tab) => tab.id === activeTab)
    const delta = event.key === 'ArrowRight' ? 1 : -1
    const next = (index + delta + TABS.length) % TABS.length
    setActiveTab(TABS[next].id)
  }

  return (
    <div className="ws">
      {/* Header strip */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-ws-line bg-ws-panel px-2.5 py-1.5">
        <span className="ws-bar-title">Packet {packet.number} Details</span>
        <span
          className="ws-proto"
          style={{ color: protoStyle.color, background: protoStyle.background, borderColor: protoStyle.color }}
        >
          {packet.protocol}
        </span>
        <RiskPill packet={packet} />
        <span className="mono-tab text-[11px] text-ws-dim">
          {packet.source} → {packet.destination}
        </span>
        <span className="mono-tab text-[10.5px] text-ws-faint">
          {formatArrivalTime(packet.timestamp)} · {packet.length} bytes
        </span>

        <div className="ml-auto flex items-center gap-1.5">
          <button
            type="button"
            className="ws-btn"
            onClick={() => openAssistant({ source: 'packet', packetId: packet.id })}
            title="Ask the AI assistant about this packet"
          >
            <Sparkles className="size-3.5 text-ws-accent" aria-hidden />
            Ask AI
          </button>
          {onCollapse ? (
            <button
              type="button"
              className="ws-btn ws-btn-ghost ws-btn-icon"
              onClick={onCollapse}
              aria-label="Collapse packet details"
              title="Collapse"
            >
              <ChevronUp className="size-3.5" aria-hidden />
            </button>
          ) : null}
        </div>
      </div>

      {/* Tabs */}
      <div
        role="tablist"
        aria-label="Packet detail sections"
        onKeyDown={onKeyDown}
        className="ws-tabs border-b border-ws-line bg-ws-sunken"
      >
        {TABS.map((tab) => {
          const selected = tab.id === activeTab
          const count =
            tab.id === 'security' && packet.findings.length > 0 ? packet.findings.length : undefined
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              id={`packet-tab-${tab.id}`}
              aria-selected={selected}
              aria-controls={`packet-panel-${tab.id}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => setActiveTab(tab.id)}
              className="ws-tab"
            >
              {tab.label}
              {count ? (
                <span className="mono-tab ml-1.5 rounded-[2px] bg-ws-medium-dim px-1 text-[9.5px] text-ws-medium">
                  {count}
                </span>
              ) : null}
            </button>
          )
        })}
      </div>

      {/* Panel body */}
      <div
        id={`packet-panel-${activeTab}`}
        role="tabpanel"
        aria-labelledby={`packet-tab-${activeTab}`}
        className="p-2"
      >
        {activeTab === 'overview' ? <OverviewTab packet={packet} interfaceName={interfaceName} /> : null}
        {activeTab === 'protocol' ? <ProtocolTab packet={packet} interfaceName={interfaceName} /> : null}
        {activeTab === 'security' ? <SecurityTab packet={packet} /> : null}
        {activeTab === 'raw' ? <RawTab packet={packet} lines={details.hex} /> : null}
      </div>
    </div>
  )
}
