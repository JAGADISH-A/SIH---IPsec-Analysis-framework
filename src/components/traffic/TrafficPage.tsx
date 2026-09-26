import { Link } from 'react-router-dom'
import { Info } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { ConfidenceTag } from '../../components/common/Evidence.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { Panel, PanelHeader } from '../../components/common/Panel.tsx'
import { BarChart, DonutChart, Histogram, LineChart } from '../../components/charts/Charts.tsx'
import { useTrafficOverview } from '../../hooks/queries'
import { ClassificationReview } from './ClassificationReview.tsx'
import { formatBytes } from '../sessions/SessionDetailPage.tsx'
import {
  CLASSIFICATION_DISCLAIMER,
  TRAFFIC_CLASS_LABEL,
  type TrafficClassification,
  type TrafficOverview,
} from '../../types/trafficIntelligence'

/**
 * Traffic intelligence.
 *
 * Classification is an inference from observable metadata, and the page says so
 * wherever a class appears. Anything below the confidence floor is reported as
 * Unknown rather than as a guess.
 */
export function TrafficPage() {
  const overview = useTrafficOverview()
  const data = overview.data

  return (
    <PageScroll>
      <PageHeader
        title="Traffic Intelligence"
        description="Volume, direction and flow classification across every analysed session."
        meta={
          data ? (
            <>
              <span className="font-mono">{data.totalPackets.toLocaleString()} packets</span>
              <span className="font-mono">{formatBytes(data.totalBytes)}</span>
              <span className="font-mono">
                {data.classifiedFlows}/{data.totalFlows} flows classified
              </span>
              <span>
                Average confidence{' '}
                {data.averageConfidence === null ? 'unknown' : `${Math.round(data.averageConfidence * 100)}%`}
              </span>
            </>
          ) : null
        }
      />

      <QueryBoundary
        isLoading={overview.isLoading}
        isError={overview.isError}
        error={overview.error}
        onRetry={() => void overview.refetch()}
        isEmpty={!data}
        loadingRows={8}
      >
        {data ? (
          <PageBody>
            <div className="flex items-start gap-2 rounded-lg border border-edge bg-night-900 px-3 py-2">
              <Info className="mt-0.5 size-4 shrink-0 text-mist-faint" aria-hidden />
              <p className="text-[11.5px] leading-relaxed text-mist-dim">{CLASSIFICATION_DISCLAIMER}</p>
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <Panel flush className="lg:col-span-2">
                <PanelHeader title="Traffic volume" subtitle="Bytes observed per hour" />
                <div className="p-4">
                  <LineChart label="Traffic volume" points={data.volume} unit=" B" height={200} tone="info" />
                </div>
              </Panel>

              <Panel flush>
                <PanelHeader title="Direction split" />
                <div className="p-4">
                  <DonutChart
                    label="Bytes by direction"
                    centerLabel="Bytes"
                    data={[
                      { label: 'Outbound', value: data.outboundBytes, tone: 'accent' },
                      { label: 'Inbound', value: data.inboundBytes, tone: 'info' },
                    ]}
                  />
                </div>
              </Panel>
            </div>

            <div className="grid gap-4 lg:grid-cols-3">
              <Panel flush>
                <PanelHeader title="Flow classes" subtitle="By observed volume" />
                <div className="p-4">
                  <DonutChart
                    label="Traffic by class"
                    centerLabel="Bytes"
                    data={data.classDistribution.slice(0, 7).map((entry, index) => ({
                      label: entry.label,
                      value: entry.value,
                      tone: (['accent', 'info', 'success', 'warning', 'danger', 'critical', 'accent'] as const)[index % 7],
                    }))}
                  />
                </div>
              </Panel>

              <Panel flush>
                <PanelHeader title="Protocol mix" subtitle="IKE, ESP and AH packets" />
                <div className="p-4">
                  <BarChart
                    label="Packets by protocol"
                    data={data.protocolDistribution.map((entry) => ({
                      label: entry.label,
                      value: entry.value,
                      tone: entry.label === 'IKE' ? ('info' as const) : entry.label === 'ESP' ? ('accent' as const) : ('warning' as const),
                    }))}
                    horizontal
                  />
                </div>
              </Panel>

              <Panel flush>
                <PanelHeader title="IP versions" />
                <div className="p-4">
                  <BarChart
                    label="Sessions by IP version"
                    data={data.ipVersionDistribution.map((entry) => ({ label: entry.label, value: entry.value }))}
                    horizontal
                  />
                </div>
              </Panel>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <Panel flush>
                <PanelHeader title="Packet size distribution" subtitle="Bytes on the wire" />
                <div className="p-4">
                  <Histogram bins={data.packetSizeHistogram} label="Packet size distribution" unit=" B" />
                </div>
              </Panel>
              <Panel flush>
                <PanelHeader title="Inter-arrival time" subtitle="Milliseconds between packets" />
                <div className="p-4">
                  <Histogram bins={data.interArrivalHistogram} label="Inter-arrival histogram" unit=" ms" />
                </div>
              </Panel>
            </div>

            <ClassifiedFlows classifications={data.classifications} />

            <ClassificationReview />
          </PageBody>
        ) : null}
      </QueryBoundary>
    </PageScroll>
  )
}

function ClassifiedFlows({ classifications }: { classifications: TrafficClassification[] }) {
  const columns: ColumnDef<TrafficClassification>[] = [
    {
      id: 'class',
      header: 'Class',
      width: '10rem',
      render: (row) => (
        <span className="flex items-center gap-1.5">
          <span className="text-[12.5px] text-mist">{TRAFFIC_CLASS_LABEL[row.label]}</span>
          {row.label === 'unknown' && row.proposedLabel !== 'unknown' ? (
            <Badge tone="muted">below floor</Badge>
          ) : null}
        </span>
      ),
    },
    {
      id: 'session',
      header: 'Session',
      width: '10rem',
      render: (row) =>
        row.sessionId ? (
          <Link to={`/vpn-sessions/${row.sessionId}`} className="font-mono text-[11px] text-mist-dim hover:text-accent-300">
            {row.sessionId}
          </Link>
        ) : (
          <span className="text-[11px] text-mist-faint">Not session-scoped</span>
        ),
    },
    {
      id: 'confidence',
      header: 'Confidence',
      width: '8rem',
      render: (row) => <ConfidenceTag confidence={row.confidence} />,
    },
    {
      id: 'packets',
      header: 'Packets',
      width: '8rem',
      align: 'right',
      render: (row) => <span className="font-mono text-xs text-mist-dim">{row.packets.toLocaleString()}</span>,
    },
    {
      id: 'bytes',
      header: 'Bytes',
      width: '8rem',
      align: 'right',
      render: (row) => <span className="font-mono text-xs text-mist-dim">{formatBytes(row.bytes)}</span>,
    },
    { id: 'basis', header: 'Classification basis', render: (row) => <span className="text-[12px] text-mist-dim">{row.basis}</span> },
  ]

  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Classified flows</h2>
        <p className="mt-0.5 text-[11px] text-mist-faint">
          Every flow the classifier examined, including the ones it refused to label.
        </p>
      </div>
      <Panel flush>
        <DataTable
          columns={columns}
          rows={classifications}
          rowKey={(row) => row.id}
          empty="No flows have been classified yet."
        />
      </Panel>
    </section>
  )
}

export type { TrafficOverview }
