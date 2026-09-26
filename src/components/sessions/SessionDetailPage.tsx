import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { ConfidenceMeter, ConfidenceTag, ProtocolValueDisplay, SourceTag } from '../../components/common/Evidence.tsx'
import { JsonBlock, KeyValueList } from '../../components/common/Data.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { Tabs } from '../../components/common/Tabs.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { Panel } from '../../components/common/Panel.tsx'
import { BarChart } from '../../components/charts/Charts.tsx'
import { useFindings, useSessionDetail } from '../../hooks/queries'
import { cx } from '../../lib/cx'
import { SEVERITY_LABEL, type EvidenceReference } from '../../types/evidence'
import type { SecurityFinding } from '../../types/analysis'
import {
  ENVIRONMENT_LABEL,
  SESSION_STATUS_LABEL,
  type SecurityAssociation,
  type SessionCorrelation,
  type SessionDetail,
  type SessionModelOutput,
  type SessionTimelineEvent,
} from '../../types/session'
import { TRAFFIC_CLASS_LABEL, CLASSIFICATION_DISCLAIMER } from '../../types/trafficIntelligence'
import { DetailSection, RiskTag } from './sessionBits.tsx'
import { TunnelIdentityPanel } from './TunnelIdentityPanel.tsx'

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'associations', label: 'Security Associations' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'traffic', label: 'Traffic' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'models', label: 'Models' },
  { id: 'raw', label: 'Raw Data' },
] as const

type TabId = (typeof TABS)[number]['id']

/**
 * Session detail: the composite record behind every conclusion about a
 * session. Each tab answers a different question — what was negotiated, when,
 * what traffic it carried, what proves it, what the models said, and what the
 * backend actually returned.
 */
export function SessionDetailPage() {
  const { sessionId } = useParams<{ sessionId: string }>()
  const detail = useSessionDetail(sessionId)
  const [tab, setTab] = useState<TabId>('overview')

  return (
    <PageScroll>
      <PageHeader
        breadcrumb={[{ label: 'Sessions', to: '/vpn-sessions' }, { label: detail.data?.session.id ?? sessionId ?? '' }]}
        title={detail.data?.session.label ?? sessionId ?? 'Session'}
        description={
          detail.data ? (
            <span className="font-mono text-xs">
              {detail.data.session.initiator.address} → {detail.data.session.responder.address} ·{' '}
              {detail.data.session.configuration.ikeVersion.value ?? 'Unknown IKE'} ·{' '}
              {detail.data.session.configuration.vpnMode.value ?? 'Unknown mode'}
            </span>
          ) : undefined
        }
        meta={
          detail.data ? (
            <>
              <span>Started {new Date(detail.data.session.startedAt).toLocaleString()}</span>
              <span className="font-mono">
                {detail.data.session.packetCount.toLocaleString()} packets ·{' '}
                {formatBytes(detail.data.session.byteCount)}
              </span>
              <span className="font-mono">{detail.data.session.rekeyCount} rekeys</span>
            </>
          ) : null
        }
        actions={
          <>
            <Link to="/vpn-sessions" className="btn">
              <ArrowLeft className="size-3.5" aria-hidden />
              All sessions
            </Link>
            <Link to="/live-monitor?view=analyzer" className="btn btn-primary">
              Open in analyzer
            </Link>
          </>
        }
      />

      <QueryBoundary
        isLoading={detail.isLoading}
        isError={detail.isError}
        error={detail.error}
        onRetry={() => void detail.refetch()}
        isEmpty={!detail.isLoading && !detail.data}
        emptyTitle="Session not found"
        emptyDescription="The record does not exist in the current dataset. It may have been removed, or the id may be incorrect."
        loadingRows={8}
      >
        {detail.data ? <SessionWorkspace data={detail.data} tab={tab} onTab={setTab} /> : null}
      </QueryBoundary>
    </PageScroll>
  )
}

function SessionWorkspace({
  data,
  tab,
  onTab,
}: {
  data: SessionDetail
  tab: TabId
  onTab: (id: TabId) => void
}) {
  const { session } = data
  const findings = useFindings({ sessionId: session.id })

  return (
    <>
      {/* The reconstructed tunnel leads the page: it is the thing under
          investigation, and the tabs below are views onto it. */}
      <div className="px-4 pt-4 lg:px-6">
        <TunnelIdentityPanel sessionId={session.id} />
      </div>

      <div className="border-b border-edge bg-night-900/40 px-4 lg:px-6">
        <Tabs
          items={TABS.map((entry) => ({ id: entry.id, label: entry.label }))}
          value={tab}
          onChange={(id) => onTab(id as TabId)}
          ariaLabel="Session detail sections"
          panelIdPrefix={`session-${session.id}`}
        />
      </div>

      <PageBody>
        <div className="flex flex-wrap items-center gap-2">
          <Badge
            tone={
              session.status === 'active'
                ? 'success'
                : session.status === 'rekeying'
                  ? 'info'
                  : session.status === 'failed'
                    ? 'danger'
                    : 'muted'
            }
            dot
          >
            {SESSION_STATUS_LABEL[session.status]}
          </Badge>
          <RiskTag band={session.riskBand} score={session.riskScore} />
          <ConfidenceTag confidence={session.confidence} showLabel />
          <Badge tone="muted">{ENVIRONMENT_LABEL[session.environment]}</Badge>
          {session.testbed ? <Badge tone="muted">Testbed {session.testbed}</Badge> : null}
          <span className="text-[11px] text-mist-faint">
            Assessment confidence is self-reported by the analysis engine, not a measured quantity.
          </span>
        </div>

        {tab === 'overview' ? <Overview data={data} /> : null}
        {tab === 'associations' ? <Associations associations={data.securityAssociations} /> : null}
        {tab === 'timeline' ? <Timeline events={data.timeline} /> : null}
        {tab === 'traffic' ? <Traffic data={data} /> : null}
        {tab === 'evidence' ? <EvidenceTable evidence={data.evidence} /> : null}
        {tab === 'models' ? <Models models={data.models} correlation={data.correlation} /> : null}
        {tab === 'raw' ? <JsonBlock value={data.raw} label="Verbatim backend payload" maxHeight={640} /> : null}

        {tab === 'overview' ? (
          <DetailSection
            title="Findings for this session"
            description={`${findings.data?.length ?? 0} finding(s) reference this session`}
            actions={
              <Link to={`/findings?session=${session.id}`} className="btn btn-sm">
                Open in findings
              </Link>
            }
          >
            <Panel flush>
              <DataTable
                columns={findingColumns}
                rows={findings.data ?? []}
                rowKey={(row) => row.id}
                empty="No findings reference this session."
              />
            </Panel>
          </DetailSection>
        ) : null}
      </PageBody>
    </>
  )
}

/* ------------------------------------------------------------------ */
/* Tabs                                                                */
/* ------------------------------------------------------------------ */

function Overview({ data }: { data: SessionDetail }) {
  const config = data.session.configuration
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
      <div className="flex flex-col gap-4">
        <DetailSection title="Negotiated configuration" description="Every value carries its provenance and evidence.">
          <Panel padded>
            <div className="grid gap-4 md:grid-cols-2">
              <ProtocolValueDisplay field="IKE version" value={config.ikeVersion} />
              <ProtocolValueDisplay field="VPN mode" value={config.vpnMode} />
              <ProtocolValueDisplay field="IP version" value={config.ipVersion} />
              <ProtocolValueDisplay field="Encryption" value={config.encryption} />
              <ProtocolValueDisplay field="Integrity" value={config.integrity} />
              <ProtocolValueDisplay field="Diffie-Hellman group" value={config.dhGroup} />
              <ProtocolValueDisplay field="PRF" value={config.prf} />
              <ProtocolValueDisplay
                field="Perfect forward secrecy"
                value={config.perfectForwardSecrecy}
                format={(value) => (value ? 'Enabled' : 'Disabled')}
              />
              <ProtocolValueDisplay
                field="Replay protection"
                value={config.replayProtection}
                format={(value) => (value ? `Enabled (window ${config.replayWindowSize.value ?? 'unknown'})` : 'Disabled')}
              />
              <ProtocolValueDisplay
                field="NAT traversal"
                value={config.natTraversal}
                format={(value) => (value ? 'Detected' : 'Not detected')}
              />
              <ProtocolValueDisplay
                field="Key lifetime"
                value={config.keyLifetimeSeconds}
                format={(value) => `${Math.round(value / 3600)}h`}
              />
              <ProtocolValueDisplay
                field="SA lifetime"
                value={config.lifetimeSeconds}
                format={(value) => `${Math.round(value / 3600)}h`}
              />
              <ProtocolValueDisplay field="Authentication" value={config.authenticationMethod} />
              <ProtocolValueDisplay field="Traffic selectors" value={config.trafficSelectors} />
              <ProtocolValueDisplay
                field="ESP"
                value={config.esp}
                format={(value) => (value ? 'Present' : 'Absent')}
              />
              <ProtocolValueDisplay field="AH" value={config.ah} format={(value) => (value ? 'Present' : 'Absent')} />
            </div>
          </Panel>
        </DetailSection>

        <DetailSection title="Session metrics">
          <Panel padded>
            <KeyValueList
              columns={2}
              items={[
                { label: 'Packets', value: data.session.packetCount.toLocaleString(), mono: true },
                { label: 'Bytes', value: formatBytes(data.session.byteCount), mono: true },
                { label: 'Rekeys', value: String(data.session.rekeyCount), mono: true },
                { label: 'Retransmissions', value: String(data.session.retransmissions), mono: true },
                { label: 'First seen', value: new Date(data.session.startedAt).toLocaleString() },
                {
                  label: 'Last activity',
                  value: new Date(data.session.lastActivityAt).toLocaleString(),
                },
                {
                  label: 'Ended',
                  value: data.session.endedAt ? new Date(data.session.endedAt).toLocaleString() : 'Still active',
                },
                {
                  label: 'Source captures',
                  value: data.session.captureIds.length > 0 ? data.session.captureIds.join(', ') : 'None linked',
                  mono: true,
                },
              ]}
            />
          </Panel>
        </DetailSection>
      </div>

      <div className="flex flex-col gap-4">
        <DetailSection title="Correlation narrative" description={data.correlation.engine}>
          <Panel padded>
            <p className="text-[12.5px] leading-relaxed text-mist-dim">{data.correlation.narrative}</p>
            <div className="mt-3 flex items-center gap-3">
              <span className="text-[11px] text-mist-faint">Composite score</span>
              <span className="font-mono text-lg text-mist">{data.correlation.score}</span>
              <RiskTag band={data.session.riskBand} />
            </div>
            {data.correlation.contributingFindingIds.length > 0 ? (
              <p className="mt-2 text-[11px] text-mist-faint">
                Contributing findings:{' '}
                <span className="font-mono text-mist-dim">{data.correlation.contributingFindingIds.join(', ')}</span>
              </p>
            ) : null}
          </Panel>
        </DetailSection>

        <DetailSection title="Assessment confidence">
          <Panel padded>
            <ConfidenceMeter confidence={data.session.confidence} />
            <p className="mt-2 text-[11px] leading-relaxed text-mist-faint">
              Confidence reflects the analyser's certainty in its own conclusions. A high score does not mean the
              configuration is safe — only that the platform is sure about what it observed.
            </p>
          </Panel>
        </DetailSection>
      </div>
    </div>
  )
}

function Associations({ associations }: { associations: SecurityAssociation[] }) {
  const columns: ColumnDef<SecurityAssociation>[] = [
    { id: 'protocol', header: 'Protocol', width: '6rem', render: (row) => <Badge tone="muted">{row.protocol}</Badge> },
    { id: 'direction', header: 'Direction', width: '7rem', render: (row) => <span className="text-xs text-mist-dim">{row.direction}</span> },
    { id: 'spi', header: 'SPI', width: '10rem', render: (row) => <span className="font-mono text-xs text-mist">{row.spi}</span> },
    { id: 'encryption', header: 'Encryption', render: (row) => <span className="font-mono text-xs text-mist-dim">{row.encryption ?? '—'}</span> },
    { id: 'integrity', header: 'Integrity', render: (row) => <span className="font-mono text-xs text-mist-dim">{row.integrity ?? '—'}</span> },
    {
      id: 'lifetime',
      header: 'Lifetime',
      width: '8rem',
      render: (row) => (
        <span className="font-mono text-[11px] text-mist-dim">
          {row.keyLifetimeSeconds ? `${Math.round(row.keyLifetimeSeconds / 3600)}h` : '—'}
        </span>
      ),
    },
    {
      id: 'expires',
      header: 'Expires',
      width: '10rem',
      render: (row) => (
        <span className="font-mono text-[11px] text-mist-faint">
          {row.expiresAt ? new Date(row.expiresAt).toLocaleString() : 'Not bounded'}
        </span>
      ),
    },
    {
      id: 'rekey',
      header: 'Rekey',
      width: '8rem',
      render: (row) => (
        <Badge tone={row.rekeyStatus === 'completed' ? 'success' : row.rekeyStatus === 'failed' ? 'danger' : 'muted'}>
          {row.rekeyStatus}
        </Badge>
      ),
    },
    {
      id: 'source',
      header: 'Source',
      width: '8rem',
      render: (row) => <SourceTag source={row.source} />,
    },
  ]

  return (
    <DetailSection
      title="Security associations"
      description="Each SA is read from the capture, with the SPI that identifies it on the wire."
    >
      <Panel flush>
        <DataTable columns={columns} rows={associations} rowKey={(row) => row.id} empty="No security associations were extracted." />
      </Panel>
    </DetailSection>
  )
}

function Timeline({ events }: { events: SessionTimelineEvent[] }) {
  return (
    <DetailSection title="Session timeline" description="Protocol exchanges in the order they were observed.">
      <Panel flush>
        <ol className="divide-y divide-edge/60">
          {events.length === 0 ? (
            <li className="px-4 py-8 text-center text-xs text-mist-faint">No timeline events were recorded.</li>
          ) : (
            events.map((event) => (
              <li key={event.id} className="flex gap-3 px-3 py-2">
                <div className="w-24 shrink-0 text-right">
                  <div className="font-mono text-[11px] text-mist-faint">
                    +{(event.relativeTimeMs / 1000).toFixed(1)}s
                  </div>
                  <div className="font-mono text-[10px] text-mist-faint">{new Date(event.timestamp).toLocaleTimeString()}</div>
                </div>
                <div className="flex flex-col items-center">
                  <span
                    className={cx(
                      'mt-1 size-2 rounded-full',
                      event.type === 'NEGOTIATION_FAILURE' || event.type === 'ERROR'
                        ? 'bg-critical'
                        : event.type === 'RETRANSMISSION'
                          ? 'bg-warning'
                          : 'bg-accent-400',
                    )}
                    aria-hidden
                  />
                  <span className="w-px flex-1 bg-edge" aria-hidden />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[12.5px] font-medium text-mist">{event.type}</span>
                    <Badge tone="muted">{event.source}</Badge>
                    {event.confidence !== null ? <ConfidenceTag confidence={event.confidence} /> : null}
                  </div>
                  <p className="mt-0.5 text-[12px] leading-relaxed text-mist-dim">{event.description}</p>
                  {event.relatedFindingIds.length > 0 ? (
                    <p className="mt-1 text-[11px] text-mist-faint">
                      Linked findings:{' '}
                      {event.relatedFindingIds.map((id) => (
                        <Link key={id} to={`/findings/${id}`} className="mr-2 font-mono text-mist-dim hover:text-accent-300">
                          {id}
                        </Link>
                      ))}
                    </p>
                  ) : null}
                </div>
              </li>
            ))
          )}
        </ol>
      </Panel>
    </DetailSection>
  )
}

function Traffic({ data }: { data: SessionDetail }) {
  const { traffic } = data
  const classification = traffic.classification
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
      <DetailSection title="Traffic classification" description={CLASSIFICATION_DISCLAIMER}>
        <Panel padded>
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-lg font-semibold text-mist">
              {classification ? TRAFFIC_CLASS_LABEL[classification.label] : 'Unknown'}
            </span>
            {classification?.confidence != null ? <ConfidenceTag confidence={classification.confidence} showLabel /> : null}
          </div>
          {classification ? (
            <>
              <p className="mt-2 text-[12px] leading-relaxed text-mist-dim">{classification.basis}</p>
              {classification.label === 'unknown' && classification.proposedLabel !== 'unknown' ? (
                <p className="mt-2 rounded-md border border-warning/40 bg-warning-dim/40 p-2 text-[11px] text-mist-dim">
                  The model proposed <span className="font-mono">{TRAFFIC_CLASS_LABEL[classification.proposedLabel]}</span> but
                  its confidence fell below the reporting floor, so the platform reports Unknown rather than a guess.
                </p>
              ) : null}
              <div className="mt-3">
                <KeyValueList
                  columns={2}
                  items={[
                    { label: 'Packets', value: classification.packets.toLocaleString(), mono: true },
                    { label: 'Bytes', value: formatBytes(classification.bytes), mono: true },
                    { label: 'First seen', value: new Date(classification.firstSeen).toLocaleString() },
                    { label: 'Last seen', value: new Date(classification.lastSeen).toLocaleString() },
                    { label: 'Peer', value: classification.peer, mono: true },
                    {
                      label: 'Classifier hints',
                      value:
                        classification.hints.length > 0 ? (
                          <span className="flex flex-wrap gap-1">
                            {classification.hints.map((hint) => (
                              <Badge key={hint} tone="muted">
                                {hint}
                              </Badge>
                            ))}
                          </span>
                        ) : (
                          'None'
                        ),
                    },
                  ]}
                />
              </div>
            </>
          ) : (
            <p className="mt-2 text-[12px] text-mist-faint">No classification was computed for this session.</p>
          )}
        </Panel>
      </DetailSection>

      <DetailSection title="Flow profile">
        <Panel padded>
          <BarChart
            label="Flow metrics"
            horizontal
            data={[
              { label: 'Packets', value: traffic.packets ?? 0, tone: 'info' },
              { label: 'Bytes (KB)', value: Math.round((traffic.bytes ?? 0) / 1024), tone: 'accent' },
              { label: 'Avg packet (B)', value: traffic.averagePacketSize ?? 0, tone: 'success' },
              { label: 'Avg inter-arrival (ms)', value: traffic.averageInterArrivalMs ?? 0, tone: 'warning' },
            ]}
          />
        </Panel>
      </DetailSection>
    </div>
  )
}

function EvidenceTable({ evidence }: { evidence: EvidenceReference[] }) {
  const columns: ColumnDef<EvidenceReference>[] = [
    { id: 'id', header: 'Evidence ID', width: '14rem', render: (row) => <span className="font-mono text-[11px] text-mist-dim">{row.id}</span> },
    { id: 'field', header: 'Field', width: '14rem', render: (row) => <span className="font-mono text-[11px] text-mist-dim">{row.field ?? '—'}</span> },
    { id: 'range', header: 'Packets', width: '9rem', render: (row) => <span className="font-mono text-[11px] text-mist-dim">{row.packetRange ?? '—'}</span> },
    { id: 'exchange', header: 'Exchange', width: '9rem', render: (row) => <span className="text-[11px] text-mist-dim">{row.exchange ?? '—'}</span> },
    { id: 'value', header: 'Raw value', width: '10rem', render: (row) => <span className="font-mono text-[11px] text-mist">{row.rawValue}</span> },
    { id: 'source', header: 'Source', width: '7rem', render: (row) => <SourceTag source={row.source} /> },
    { id: 'confidence', header: 'Confidence', width: '7rem', render: (row) => <ConfidenceTag confidence={row.confidence} /> },
    { id: 'explanation', header: 'Why it supports the conclusion', render: (row) => <span className="text-[12px] text-mist-dim">{row.explanation}</span> },
  ]

  return (
    <DetailSection
      title="Evidence"
      description="Every value on this page traces back to one of these artefacts."
    >
      <Panel flush>
        <DataTable columns={columns} rows={evidence} rowKey={(row) => row.id} empty="No evidence was recorded for this session." />
      </Panel>
    </DetailSection>
  )
}

function Models({ models, correlation }: { models: SessionModelOutput[]; correlation: SessionCorrelation }) {
  return (
    <div className="flex flex-col gap-4">
      <DetailSection
        title="Model outputs"
        description="What each model contributed — shown with its own confidence, never merged into a single claim."
      >
        <div className="grid gap-3 lg:grid-cols-2">
          {models.length === 0 ? (
            <Panel padded>
              <p className="text-[12px] text-mist-faint">No model produced an output for this session.</p>
            </Panel>
          ) : (
            models.map((model) => (
              <Panel key={model.id} padded>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-[13px] font-semibold text-mist">{model.name}</div>
                    <div className="font-mono text-[11px] text-mist-faint">
                      {model.version} · {model.task}
                    </div>
                  </div>
                  <ConfidenceTag confidence={model.confidence} showLabel />
                </div>
                <p className="mt-2 text-[12.5px] text-mist">{model.output}</p>
                <p className="mt-1.5 text-[11px] leading-relaxed text-mist-faint">{model.explanation}</p>
              </Panel>
            ))
          )}
        </div>
      </DetailSection>

      <DetailSection title="Correlation engine" description={correlation.engine}>
        <Panel padded>
          <p className="text-[12.5px] leading-relaxed text-mist-dim">{correlation.narrative}</p>
        </Panel>
      </DetailSection>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Shared column sets and formatters                                    */
/* ------------------------------------------------------------------ */

const findingColumns: ColumnDef<SecurityFinding>[] = [
  {
    id: 'severity',
    header: 'Severity',
    width: '7rem',
    render: (row) => <span className="text-[11px] text-mist-dim">{SEVERITY_LABEL[row.severity]}</span>,
  },
  {
    id: 'title',
    header: 'Finding',
    render: (row) => (
      <Link to={`/findings/${row.id}`} className="text-mist hover:text-accent-300 hover:underline">
        {row.title}
      </Link>
    ),
  },
  {
    id: 'status',
    header: 'Status',
    width: '8rem',
    render: (row) => <span className="text-[11px] text-mist-dim">{row.status}</span>,
  },
  {
    id: 'confidence',
    header: 'Confidence',
    width: '7rem',
    render: (row) => <ConfidenceTag confidence={row.confidence} />,
  },
]

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`
}
