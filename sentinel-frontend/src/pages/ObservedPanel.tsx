import { Panel, HashChip, Metric, Tag } from '@/components/ui'
import { EmptyState } from '@/components/states'
import {
  formatDateTime,
  formatNumber,
  formatUtc,
  artifactName,
} from '@/lib/format'
import type { AssessmentBundle } from '@/types'

function Flag({ on, label }: { on: boolean | undefined; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs ${
        on === undefined
          ? 'border-edge text-ink-faint'
          : on
            ? 'border-good/30 bg-good/10 text-good'
            : 'border-edge bg-ink-faint/5 text-ink-faint'
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          on === undefined ? 'bg-ink-faint' : on ? 'bg-good' : 'bg-ink-faint/60'
        }`}
        aria-hidden="true"
      />
      {label}
      {on !== undefined && (
        <span className="mono text-xs opacity-70">{on ? 'seen' : 'not seen'}</span>
      )}
    </span>
  )
}

/**
 * The authoritative observation: the IPsec state the pipeline derived from the
 * captured traffic. Deliberately separated from the "Expected" panel so planned
 * configuration is never presented as observed evidence.
 */
export function ObservedPanel({ bundle }: { bundle: AssessmentBundle }) {
  const observed = bundle.observed
  const present = observed?.present === true

  return (
    <Panel
      title="Observed"
      subtitle="authoritative IPsec state derived from the capture"
      className="border-good/20"
      bodyClassName="border-t border-good/15"
    >
      <div className="flex items-start gap-2.5 border-b border-good/15 bg-good/[0.04] px-4 py-2.5">
        <span className="mt-[3px] h-1.5 w-1.5 shrink-0 rounded-full bg-good" aria-hidden="true" />
        <p className="text-xs leading-relaxed text-ink-dim">
          What the captured traffic actually shows.{' '}
          {present ? (
            <>
              Snapshot taken{' '}
              <span className="mono text-ink">{formatUtc(observed.timestamp_ns)}</span>.
            </>
          ) : (
            'No observation was supplied for this assessment, so every observed value is absent by construction.'
          )}
        </p>
      </div>

      {!present ? (
        <EmptyState
          title="No observed state"
          description="The pipeline recorded no authoritative observation for this assessment. Observed values are not inferred."
          icon="inbox"
        />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-x-5 gap-y-4 p-4 md:grid-cols-4">
            <Metric
              label="Endpoints"
              value={
                <span className="text-base">
                  {observed.endpoints?.a ?? '—'}
                  <span className="mx-1.5 text-ink-faint">↔</span>
                  {observed.endpoints?.b ?? '—'}
                </span>
              }
            />
            <Metric label="Packets" value={formatNumber(observed.packets_seen)} hint={`${formatNumber(observed.bytes_seen)} bytes`} />
            <Metric
              label="A → B"
              value={formatNumber(observed.packets_a_to_b)}
              hint={`${formatNumber(observed.bytes_a_to_b)} B`}
            />
            <Metric
              label="B → A"
              value={formatNumber(observed.packets_b_to_a)}
              hint={`${formatNumber(observed.bytes_b_to_a)} B`}
            />
          </div>

          <div className="flex flex-wrap gap-2 border-t border-edge px-4 py-3">
            <Flag on={observed.tunnel_seen} label="Tunnel" />
            <Flag on={observed.esp_seen} label="ESP" />
            <Flag on={observed.ah_seen} label="AH" />
            <Flag on={observed.ike_seen} label="IKE" />
            <Flag on={observed.ike_nat_t_seen} label="IKE NAT-T" />
            <Flag on={observed.active} label="SA active" />
          </div>

          <div className="grid grid-cols-2 gap-x-5 gap-y-3 border-t border-edge px-4 py-3 md:grid-cols-4">
            <div>
              <p className="label text-ink-faint">Last ESP</p>
              <p className="mono text-xs text-ink-dim">
                {formatDateTime(observed.last_esp_timestamp_ns)}
              </p>
            </div>
            <div>
              <p className="label text-ink-faint">Last IKE</p>
              <p className="mono text-xs text-ink-dim">
                {formatDateTime(observed.last_ike_timestamp_ns)}
              </p>
            </div>
            <div>
              <p className="label text-ink-faint">
                Last NAT-T
              </p>
              <p className="mono text-xs text-ink-dim">
                {formatDateTime(observed.last_ike_nat_t_timestamp_ns)}
              </p>
            </div>
            <div>
              <p className="label text-ink-faint">Last AH</p>
              <p className="mono text-xs text-ink-dim">
                {formatDateTime(observed.last_ah_timestamp_ns)}
              </p>
            </div>
          </div>

          {observed.spis && observed.spis.length > 0 && (
            <div className="border-t border-edge">
              <p className="px-4 pb-1.5 pt-3 label text-ink-faint">
                Security Associations
              </p>
              <div className="overflow-x-auto">
                <table className="data-table min-w-[620px]">
                  <thead>
                    <tr className="text-left">
                      {['SPI', 'Direction', 'Packets', 'Seq range', 'First seen', 'Last seen', 'State'].map(
                        (heading) => (
                          <th
                            key={heading}
                            className="px-4 py-1.5 label text-ink-faint"
                          >
                            {heading}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {observed.spis.map((spi) => (
                      <tr
                        key={`${spi.spi}-${spi.direction}`}
                        className="border-t border-edge-soft"
                      >
                        <td className="mono text-sm text-sentinel">{spi.spi}</td>
                        <td className="text-sm text-ink-dim">{spi.direction}</td>
                        <td className="mono tnum text-sm text-ink-dim">
                          {formatNumber(spi.packet_count)}
                        </td>
                        <td className="mono tnum text-sm text-ink-dim">
                          {spi.first_sequence}–{spi.highest_sequence}
                        </td>
                        <td className="mono text-xs text-ink-faint">
                          {formatDateTime(spi.first_seen_ns)}
                        </td>
                        <td className="mono text-xs text-ink-faint">
                          {formatDateTime(spi.last_seen_ns)}
                        </td>
                        <td className="px-4 py-2">
                          <span
                            className={`text-xs ${spi.active ? 'text-good' : 'text-ink-faint'}`}
                          >
                            {spi.active ? 'active' : 'inactive'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {observed.transitions && observed.transitions.length > 0 && (
            <div className="border-t border-edge px-4 py-3">
              <p className="mb-2 label text-ink-faint">
                State transitions
              </p>
              <ol className="space-y-1.5">
                {observed.transitions.map((transition, index) => (
                  <li key={`${transition.name}-${index}`} className="flex items-start gap-2.5">
                    <span
                      className="mt-[5px] h-1.5 w-1.5 shrink-0 rounded-full border border-sentinel/60"
                      aria-hidden="true"
                    />
                    <span className="min-w-0">
                      <span className="mono text-xs text-ink-dim">{transition.name}</span>
                      <span className="mono ml-2 text-xs text-ink-faint">
                        {formatUtc(transition.timestamp_ns)}
                      </span>
                      {Object.keys(transition.details ?? {}).length > 0 && (
                        <span className="mono block truncate text-xs text-ink-faint">
                          {Object.entries(transition.details)
                            .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
                            .join('  ')}
                        </span>
                      )}
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </>
      )}
    </Panel>
  )
}

/** Evidence refs rendered as a provenance table, shared by several pages. */
export function EvidenceRefTable({
  refs,
  title = 'Evidence References',
}: {
  refs: AssessmentBundle['evidence']['refs'] | undefined
  title?: string
}) {
  if (!refs || refs.length === 0) {
    return (
      <Panel title={title}>
        <EmptyState
          title="No evidence references"
          description="The backend attached no evidence reference to this record."
          icon="inbox"
        />
      </Panel>
    )
  }

  return (
    <Panel title={title} subtitle={`${refs.length} reference${refs.length === 1 ? '' : 's'}`} bodyClassName="overflow-x-auto">
      <table className="data-table min-w-[820px]">
        <thead>
          <tr className="border-b border-edge text-left">
            {['Evidence ID', 'Artifact', 'Source', 'Type', 'Size', 'Digest'].map((heading) => (
              <th
                key={heading}
                className="px-4 py-2.5 label text-ink-faint"
              >
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {refs.map((ref, index) => (
            <tr
              key={ref.evidence_id ?? `${ref.pcap_path}-${index}`}
              className="border-b border-edge-soft last:border-0"
            >
              <td className="px-4 py-2.5">
                <span className="mono block text-xs text-sentinel" title={ref.evidence_id}>
                  {ref.evidence_id ?? '—'}
                </span>
                {ref.run_id && (
                  <span className="mono block text-xs text-ink-faint">run {ref.run_id}</span>
                )}
              </td>
              <td className="px-4 py-2.5">
                <span
                  className="mono block max-w-[280px] truncate text-xs text-ink-dim"
                  title={ref.pcap_path}
                >
                  {ref.pcap_path}
                </span>
                <span className="block text-xs text-ink-faint">
                  {artifactName(ref.pcap_path)}
                </span>
              </td>
              <td className="px-4 py-2.5">
                <Tag>{ref.source ?? '—'}</Tag>
              </td>
              <td className="text-sm text-ink-dim">
                {ref.artifact_type ?? '—'}
              </td>
              <td className="mono tnum text-sm text-ink-dim">
                {ref.byte_size !== undefined ? `${formatNumber(ref.byte_size)} B` : '—'}
              </td>
              <td className="px-4 py-2.5">
                <HashChip hash={ref.artifact_sha256} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  )
}
