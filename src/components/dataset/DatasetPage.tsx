import { useRef, useState } from 'react'
import { Database, Search, Upload } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { Button } from '../../components/common/Button.tsx'
import { Field } from '../../components/common/Field.tsx'
import { Select } from '../../components/common/Select.tsx'
import { KeyValueList, Pagination, Toolbar } from '../../components/common/Data.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { Panel, PanelHeader } from '../../components/common/Panel.tsx'
import { BarChart, DonutChart } from '../../components/charts/Charts.tsx'
import { useDataset, useDatasetStats, useUploadCapture } from '../../hooks/queries'
import { CaptureDetail } from './CaptureDetail.tsx'
import type { CaptureLabel, CaptureRecord, CaptureTrafficType } from '../../types/dataset'
import { CAPTURE_LABEL_LABEL } from '../../types/dataset'
import type { IkevVersion, VpnMode } from '../../types/session'
import { formatBytes } from '../sessions/SessionDetailPage.tsx'

/**
 * Capture dataset.
 *
 * Every capture carries a checksum, a label and a link to the sessions extracted
 * from it, so a claim can be walked back to the bytes it came from.
 */
export function DatasetPage() {
  const [search, setSearch] = useState('')
  const [label, setLabel] = useState<CaptureLabel | 'all'>('all')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  // The whole record is kept so the detail panel survives a page change or a
  // refetch that moves the capture off this page.
  const [selected, setSelected] = useState<CaptureRecord | null>(null)

  const dataset = useDataset({
    search: search.trim() || undefined,
    labels: label === 'all' ? undefined : [label],
    page,
    pageSize,
  })
  const stats = useDatasetStats()
  const items = dataset.data?.items ?? []

  const columns: ColumnDef<CaptureRecord>[] = [
    {
      id: 'file',
      header: 'Capture',
      render: (row) => (
        <div className="min-w-0">
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation()
              setSelected(row)
            }}
            className="block truncate text-left font-mono text-[11.5px] text-mist hover:text-accent-300"
          >
            {row.fileName}
          </button>
          <span className="block truncate font-mono text-[10.5px] text-mist-faint">{row.id}</span>
        </div>
      ),
    },
    {
      id: 'label',
      header: 'Label',
      width: '9rem',
      render: (row) => (
        <Badge tone={row.label === 'benign' ? 'success' : row.label === 'unlabelled' ? 'muted' : 'warning'}>
          {CAPTURE_LABEL_LABEL[row.label]}
        </Badge>
      ),
    },
    {
      id: 'config',
      header: 'Configuration',
      width: '14rem',
      render: (row) => (
        <div className="font-mono text-[10.5px] leading-relaxed text-mist-faint">
          <div>
            {row.ikeVersion} · {row.vpnMode} · {row.ipVersion}
          </div>
          <div>
            {row.encryption} · DH{row.dhGroup.replace(/\D/g, '')} · {row.perfectForwardSecrecy ? 'PFS' : 'no PFS'}
          </div>
        </div>
      ),
    },
    {
      id: 'size',
      header: 'Size',
      width: '7rem',
      align: 'right',
      render: (row) => <span className="font-mono text-[11px] text-mist-dim">{formatBytes(row.sizeBytes)}</span>,
    },
    {
      id: 'packets',
      header: 'Packets',
      width: '7rem',
      align: 'right',
      render: (row) => <span className="font-mono text-[11px] text-mist-dim">{row.packetCount.toLocaleString()}</span>,
    },
    {
      id: 'sessions',
      header: 'Sessions',
      width: '6rem',
      align: 'right',
      render: (row) => <span className="font-mono text-[11px] text-mist-dim">{row.sessionCount}</span>,
    },
    {
      id: 'findings',
      header: 'Findings',
      width: '6rem',
      align: 'right',
      render: (row) => <span className="font-mono text-[11px] text-mist-dim">{row.findingCount}</span>,
    },
    {
      id: 'traffic',
      header: 'Traffic',
      width: '7rem',
      render: (row) => <span className="text-[11px] text-mist-faint">{row.trafficType}</span>,
    },
    {
      id: 'created',
      header: 'Ingested',
      width: '9rem',
      render: (row) => (
        <span className="text-[11px] text-mist-faint">{new Date(row.createdAt).toLocaleDateString()}</span>
      ),
    },
  ]

  return (
    <PageScroll>
      <PageHeader
        title="Capture Dataset"
        description="Every capture that has been ingested, with the configuration it recorded and the sessions extracted from it."
        meta={
          stats.data ? (
            <>
              <span className="font-mono">{stats.data.totalCaptures} captures</span>
              <span className="font-mono">{stats.data.totalPackets.toLocaleString()} packets</span>
              <span className="font-mono">{formatBytes(stats.data.totalBytes)}</span>
              <span className="font-mono">
                {stats.data.labelledCaptures}/{stats.data.totalCaptures} labelled
              </span>
            </>
          ) : null
        }
        actions={<UploadCapture />}
      />

      <PageBody>
        {stats.data ? (
          <div className="grid gap-4 lg:grid-cols-3">
            <Panel flush className="lg:col-span-2">
              <PanelHeader title="Dataset composition" subtitle="Captures by label and configuration" />
              <div className="grid gap-4 p-4 sm:grid-cols-2">
                <DonutChart
                  label="Captures by label"
                  centerLabel="Captures"
                  data={stats.data.byLabel.map((entry, index) => ({
                    label: entry.labelText,
                    value: entry.count,
                    tone: (['accent', 'warning', 'danger', 'info', 'success', 'critical', 'muted'] as const)[index % 7],
                  }))}
                />
                <BarChart
                  label="Captures by encryption algorithm"
                  data={stats.data.byEncryption.map((entry) => ({ label: entry.label, value: entry.value }))}
                  horizontal
                />
              </div>
            </Panel>
            <Panel flush>
              <PanelHeader title="Breakdown" />
              <div className="p-4 text-[11.5px] text-mist-dim">
                <KeyValueList
                  items={[
                    { label: 'IKEv1 / IKEv2', value: stats.data.byIkeVersion.map((e) => `${e.label} ${e.value}`).join(' · ') },
                    { label: 'IP version', value: stats.data.byIpVersion.map((e) => `${e.label} ${e.value}`).join(' · ') },
                    { label: 'Mode', value: stats.data.byMode.map((e) => `${e.label} ${e.value}`).join(' · ') },
                    { label: 'Forward secrecy', value: stats.data.byPfs.map((e) => `${e.label} ${e.value}`).join(' · ') },
                    {
                      label: 'Total duration',
                      value: `${Math.round(stats.data.totalDurationMs / 3_600_000)} h`,
                    },
                  ]}
                />
              </div>
            </Panel>
          </div>
        ) : null}

        <Panel padded>
          <Toolbar>
            <Field
              label="Search"
              leading={<Search className="size-3.5" aria-hidden />}
              value={search}
              onChange={(event) => {
                setSearch(event.target.value)
                setPage(1)
              }}
              placeholder="File name, capture id or testbed"
            />
            <Select
              label="Label"
              value={label}
              onChange={(event) => {
                setLabel(event.target.value as CaptureLabel | 'all')
                setPage(1)
              }}
            >
              <option value="all">All labels</option>
              {(Object.keys(CAPTURE_LABEL_LABEL) as CaptureLabel[]).map((value) => (
                <option key={value} value={value}>
                  {CAPTURE_LABEL_LABEL[value]}
                </option>
              ))}
            </Select>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                setSearch('')
                setLabel('all')
                setPage(1)
              }}
            >
              Reset
            </button>
          </Toolbar>
        </Panel>

        <QueryBoundary
          isLoading={dataset.isLoading}
          isError={dataset.isError}
          error={dataset.error}
          onRetry={() => void dataset.refetch()}
          isEmpty={items.length === 0}
          emptyTitle="No captures match these filters"
          emptyDescription="Upload a pcap to add it to the dataset."
          loadingRows={10}
        >
          <Panel flush>
            <DataTable
              columns={columns}
              rows={items}
              rowKey={(row) => row.id}
              selectedKey={selected?.id}
              onRowClick={(row) => setSelected(row.id === selected?.id ? null : row)}
              empty="No captures on this page."
            />
          </Panel>

          {dataset.data ? (
            <Panel flush>
              <Pagination
                page={dataset.data.page}
                pageSize={dataset.data.pageSize}
                total={dataset.data.total}
                label="captures"
                onPageChange={setPage}
                onPageSizeChange={(value) => {
                  setPageSize(value)
                  setPage(1)
                }}
              />
            </Panel>
          ) : null}
        </QueryBoundary>

        {selected ? (
          <CaptureDetail
            capture={selected}
            onClose={() => setSelected(null)}
            onDeleted={() => setSelected(null)}
          />
        ) : null}

        <p className="flex items-start gap-2 text-[11px] leading-relaxed text-mist-faint">
          <Database className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          Uploading registers a capture and its checksum. It does not by itself produce findings: the analyzer has to
          dissect the capture, and any resulting finding will cite this capture as its evidence source.
        </p>
      </PageBody>
    </PageScroll>
  )
}

function UploadCapture() {
  const input = useRef<HTMLInputElement>(null)
  const upload = useUploadCapture()
  const [label, setLabel] = useState<CaptureLabel>('unlabelled')
  const [ikeVersion, setIkeVersion] = useState<IkevVersion>('IKEv2')
  const [vpnMode, setVpnMode] = useState<VpnMode>('tunnel')
  const [trafficType, setTrafficType] = useState<CaptureTrafficType>('mixed')
  const [open, setOpen] = useState(false)

  return (
    <div className="flex flex-col items-end gap-2">
      <div className="flex items-center gap-2">
        <Button onClick={() => setOpen((value) => !value)} active={open} aria-expanded={open}>
          <Upload className="size-3.5" aria-hidden />
          {upload.isPending ? 'Uploading…' : 'Upload capture'}
        </Button>
        {upload.isSuccess ? <span className="text-[11px] text-success">Ingested</span> : null}
        {upload.isError ? <span className="text-[11px] text-danger">{upload.error.message}</span> : null}
      </div>

      {open ? (
        <Panel padded className="w-80">
          <p className="text-[11px] leading-relaxed text-mist-faint">
            Ingest options are recorded with the capture. The platform does not guess them from the file name.
          </p>
          <div className="mt-3 grid grid-cols-2 gap-2">
            <Select label="Label" value={label} onChange={(event) => setLabel(event.target.value as CaptureLabel)}>
              {(Object.keys(CAPTURE_LABEL_LABEL) as CaptureLabel[]).map((value) => (
                <option key={value} value={value}>
                  {CAPTURE_LABEL_LABEL[value]}
                </option>
              ))}
            </Select>
            <Select label="IKE" value={ikeVersion} onChange={(event) => setIkeVersion(event.target.value as IkevVersion)}>
              <option value="IKEv1">IKEv1</option>
              <option value="IKEv2">IKEv2</option>
            </Select>
            <Select label="Mode" value={vpnMode} onChange={(event) => setVpnMode(event.target.value as VpnMode)}>
              <option value="tunnel">Tunnel</option>
              <option value="transport">Transport</option>
            </Select>
            <Select
              label="Traffic"
              value={trafficType}
              onChange={(event) => setTrafficType(event.target.value as CaptureTrafficType)}
            >
              <option value="mixed">Mixed</option>
              <option value="interactive">Interactive</option>
              <option value="bulk">Bulk</option>
              <option value="streaming">Streaming</option>
              <option value="rekey-cycle">Rekey cycle</option>
              <option value="idle">Idle</option>
            </Select>
          </div>
          <input
            ref={input}
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="sr-only"
            onChange={(event) => {
              const file = event.target.files?.[0]
              if (file) {
                upload.mutate({ file, options: { label, ikeVersion, vpnMode, trafficType, metadataOnly: false } })
                event.target.value = ''
                setOpen(false)
              }
            }}
          />
          <Button variant="primary" className="mt-3 w-full" onClick={() => input.current?.click()} disabled={upload.isPending}>
            Choose file…
          </Button>
        </Panel>
      ) : null}
    </div>
  )
}
