import { useState } from 'react'
import { Link } from 'react-router-dom'
import { FileText, HardDriveDownload, Trash2, X } from 'lucide-react'
import { Badge } from '../common/Badge.tsx'
import { Button } from '../common/Button.tsx'
import { JsonBlock, KeyValueList } from '../common/Data.tsx'
import { ErrorPanel, LoadingPanel } from '../common/QueryState.tsx'
import { Panel } from '../common/Panel.tsx'
import { StatusDot } from '../common/StatusDot.tsx'
import { useCaptureMetadata, useDeleteCapture } from '../../hooks/queries'
import { services } from '../../services'
import { CAPTURE_LABEL_LABEL, type CaptureRecord } from '../../types/dataset'
import { formatBytes } from '../sessions/SessionDetailPage.tsx'

/**
 * Capture detail.
 *
 * The capture is the root of every evidence chain, so this panel shows the
 * provenance metadata the ingest service recorded — generator, snaplen, link
 * type, filters, first and last packet — next to the checksum that identifies
 * the file.
 */
export function CaptureDetail({
  capture,
  onClose,
  onDeleted,
}: {
  capture: CaptureRecord
  onClose: () => void
  onDeleted: (id: string) => void
}) {
  const metadata = useCaptureMetadata(capture.id)
  const remove = useDeleteCapture()
  const [downloadError, setDownloadError] = useState<string | null>(null)
  const [confirming, setConfirming] = useState(false)

  return (
    <Panel flush>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-edge px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <FileText className="size-4 shrink-0 text-mist-faint" aria-hidden />
          <span className="truncate font-mono text-[12px] text-mist">{capture.fileName}</span>
          <Badge tone={capture.label === 'benign' ? 'success' : 'muted'}>
            {CAPTURE_LABEL_LABEL[capture.label]}
          </Badge>
        </div>
        <div className="flex items-center gap-1.5">
          <Button
            size="sm"
            onClick={async () => {
              try {
                const url = await services.dataset.getDownloadUrl(capture.id)
                setDownloadError(null)
                window.open(url, '_blank', 'noopener')
              } catch (cause) {
                setDownloadError(cause instanceof Error ? cause.message : 'Download failed')
              }
            }}
          >
            <HardDriveDownload className="size-3.5" aria-hidden />
            Download
          </Button>
          {confirming ? (
            <>
              <Button
                size="sm"
                variant="danger"
                onClick={() =>
                  remove.mutate(capture.id, {
                    onSuccess: () => {
                      onDeleted(capture.id)
                      onClose()
                    },
                  })
                }
                disabled={remove.isPending}
              >
                {remove.isPending ? 'Deleting…' : 'Confirm delete'}
              </Button>
              <Button size="sm" onClick={() => setConfirming(false)}>
                Keep
              </Button>
            </>
          ) : (
            <Button size="sm" variant="danger" onClick={() => setConfirming(true)}>
              <Trash2 className="size-3.5" aria-hidden />
              Delete
            </Button>
          )}
          <Button size="icon-sm" onClick={onClose} aria-label="Close capture details">
            <X className="size-3.5" aria-hidden />
          </Button>
        </div>
      </div>

      {downloadError ? (
        <p role="alert" className="border-b border-edge bg-danger-dim px-4 py-1.5 text-[11.5px] text-danger">
          {downloadError}
        </p>
      ) : null}
      {remove.isError ? (
        <p role="alert" className="border-b border-edge bg-danger-dim px-4 py-1.5 text-[11.5px] text-danger">
          {remove.error.message}
        </p>
      ) : null}

      {metadata.isLoading ? <LoadingPanel rows={4} className="m-4" /> : null}
      {metadata.isError ? (
        <div className="p-4">
          <ErrorPanel error={metadata.error} onRetry={() => void metadata.refetch()} compact />
        </div>
      ) : null}

      {metadata.data ? (
        <div className="grid gap-4 p-4 lg:grid-cols-2">
          <div className="flex flex-col gap-4">
            <div>
              <h3 className="text-[12.5px] font-semibold text-mist">Ingest record</h3>
              <div className="mt-2">
                <KeyValueList
                  items={[
                    { label: 'Capture id', value: metadata.data.capture.id, mono: true },
                    { label: 'File name', value: metadata.data.capture.fileName, mono: true },
                    { label: 'Size', value: formatBytes(metadata.data.capture.sizeBytes), mono: true },
                    { label: 'Checksum (sha256)', value: metadata.data.capture.checksum, mono: true },
                    { label: 'Generator', value: metadata.data.generator || 'Not reported', mono: true },
                    { label: 'Snaplen', value: String(metadata.data.snaplen), mono: true },
                    { label: 'Link type', value: metadata.data.linkType, mono: true },
                    { label: 'Testbed', value: metadata.data.capture.testbed },
                    { label: 'Ingested', value: new Date(metadata.data.capture.createdAt).toLocaleString() },
                  ]}
                />
              </div>
            </div>

            <div>
              <h3 className="text-[12.5px] font-semibold text-mist">Observed content</h3>
              <div className="mt-2">
                <KeyValueList
                  items={[
                    { label: 'Packets', value: metadata.data.capture.packetCount.toLocaleString(), mono: true },
                    { label: 'Bytes on the wire', value: formatBytes(metadata.data.capture.byteCount), mono: true },
                    { label: 'Duration', value: `${Math.round(metadata.data.capture.durationMs / 1000)}s`, mono: true },
                    {
                      label: 'First packet',
                      value: new Date(metadata.data.firstPacketAt).toLocaleTimeString(),
                      mono: true,
                    },
                    {
                      label: 'Last packet',
                      value: new Date(metadata.data.lastPacketAt).toLocaleTimeString(),
                      mono: true,
                    },
                    { label: 'Sessions extracted', value: String(metadata.data.capture.sessionCount), mono: true },
                    { label: 'Findings raised', value: String(metadata.data.capture.findingCount), mono: true },
                  ]}
                />
              </div>
            </div>

            <div>
              <h3 className="text-[12.5px] font-semibold text-mist">Dissector filters</h3>
              {metadata.data.filters.length === 0 ? (
                <p className="mt-1 text-[11.5px] text-mist-faint">No filters were recorded for this capture.</p>
              ) : (
                <ul className="mt-1.5 flex flex-wrap gap-1.5">
                  {metadata.data.filters.map((filter) => (
                    <li key={filter} className="rounded border border-edge bg-night-800 px-1.5 py-0.5 font-mono text-[10.5px] text-mist-dim">
                      {filter}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          <div className="flex flex-col gap-4">
            <div>
              <h3 className="text-[12.5px] font-semibold text-mist">Payload access</h3>
              <p className="mt-1 flex items-start gap-1.5 text-[11.5px] leading-relaxed text-mist-dim">
                <StatusDot tone={metadata.data.capture.payloadAccess ? 'warning' : 'info'} />
                {metadata.data.capture.payloadAccess
                  ? 'Payload rendering is permitted for this capture. ESP payloads are still encrypted on the wire, so only headers are available.'
                  : 'Payload rendering is not permitted for this capture. Only metadata and dissected headers are available.'}
              </p>
            </div>

            {metadata.data.notes ? (
              <p className="rounded-md border border-edge bg-night-800 px-2.5 py-2 text-[11.5px] leading-relaxed text-mist-dim">
                {metadata.data.notes}
              </p>
            ) : null}

            <div>
              <h3 className="text-[12.5px] font-semibold text-mist">Linked sessions</h3>
              {metadata.data.capture.experimentId ? (
                <Link
                  to={`/experiments/${metadata.data.capture.experimentId}`}
                  className="mt-1 block font-mono text-[11.5px] text-mist-dim hover:text-accent-300"
                >
                  {metadata.data.capture.experimentId}
                </Link>
              ) : (
                <p className="mt-1 text-[11.5px] text-mist-faint">
                  This capture is not linked to an experiment; it was ingested standalone.
                </p>
              )}
            </div>

            <JsonBlock
              label="Capture record"
              maxHeight={280}
              value={{
                id: metadata.data.capture.id,
                label: metadata.data.capture.label,
                ikeVersion: metadata.data.capture.ikeVersion,
                vpnMode: metadata.data.capture.vpnMode,
                encryption: metadata.data.capture.encryption,
                dhGroup: metadata.data.capture.dhGroup,
                perfectForwardSecrecy: metadata.data.capture.perfectForwardSecrecy,
                ipVersion: metadata.data.capture.ipVersion,
                trafficType: metadata.data.capture.trafficType,
                checksum: metadata.data.capture.checksum,
                generator: metadata.data.generator,
                snaplen: metadata.data.snaplen,
                linkType: metadata.data.linkType,
                filters: metadata.data.filters,
              }}
            />
          </div>
        </div>
      ) : null}
    </Panel>
  )
}
