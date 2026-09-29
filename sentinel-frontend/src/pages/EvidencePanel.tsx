import { Panel, Tag, StatusPill } from '@/components/ui'
import { EmptyState } from '@/components/states'
import { EvidenceRefTable } from './ObservedPanel'
import { artifactName, formatBytes, formatNumber, formatUtc, humanize } from '@/lib/format'
import type { AssessmentBundle } from '@/types'

/**
 * Evidence for one assessment: the refs the risk engine attached, the block the
 * assessment carries, and the XAI evidence summary. Provenance is always visible
 * — path, source, digest and size — because a finding without a traceable
 * artifact is not evidence.
 */
export function EvidencePanel({ bundle }: { bundle: AssessmentBundle }) {
  const evidence = bundle.evidence
  const findingRefs =
    bundle.risk?.findings?.flatMap((finding) =>
      (finding.evidence_refs ?? []).map((ref) => ({ ref, finding })),
    ) ?? []
  const summary = bundle.xai?.evidence_summary

  return (
    <div className="space-y-4">
      <Panel
        title="Evidence Provenance"
        subtitle="what the pipeline read to produce this assessment"
      >
        <div className="grid grid-cols-2 gap-x-5 gap-y-4 p-4 md:grid-cols-4">
          <div>
            <p className="label text-ink-faint">Total refs</p>
            <p className="mono tnum mt-0.5 text-xl text-ink">
              {formatNumber(evidence?.total_refs ?? 0)}
            </p>
          </div>
          <div>
            <p className="label text-ink-faint">Sources</p>
            <div className="mt-1 flex flex-wrap gap-1">
              {(evidence?.sources ?? []).length === 0 ? (
                <span className="text-sm text-ink-faint">—</span>
              ) : (
                (evidence?.sources ?? []).map((source, index) => (
                  <Tag key={`${source}-${index}`}>{source}</Tag>
                ))
              )}
            </div>
          </div>
          <div>
            <p className="label text-ink-faint">
              Refs on findings
            </p>
            <p className="mono tnum mt-0.5 text-xl text-ink">{findingRefs.length}</p>
          </div>
          <div>
            <p className="label text-ink-faint">
              Fabricated
            </p>
            <div className="mt-1">
              <StatusPill
                status={summary?.fabricated === false ? 'no' : 'unknown'}
                tone={summary?.fabricated === false ? 'good' : 'neutral'}
                label={summary?.fabricated === false ? 'none' : 'not reported'}
              />
            </div>
          </div>
        </div>
        {evidence?.limitation && (
          <p className="border-t border-edge px-4 py-2.5 text-sm text-medium">
            <span className="text-medium">Limitation: </span>
            <span className="text-ink-dim">{evidence.limitation}</span>
          </p>
        )}
        {summary?.limitation && !evidence?.limitation && (
          <p className="border-t border-edge px-4 py-2.5 text-sm text-ink-dim">
            {summary.limitation}
          </p>
        )}
      </Panel>

      <EvidenceRefTable refs={evidence?.refs} title="Assessment Evidence References" />

      {findingRefs.length > 0 && (
        <Panel
          title="Evidence by Finding"
          subtitle="every reference the risk engine attached, with the finding that cited it"
          bodyClassName="overflow-x-auto"
        >
          <table className="data-table min-w-[900px]">
            <thead>
              <tr className="border-b border-edge text-left">
                {['Finding', 'Severity', 'Evidence ID', 'Artifact', 'Captured', 'Size', 'Digest'].map(
                  (heading) => (
                    <th
                      key={heading}
                      className="px-4 py-2.5 label text-ink-faint"
                    >
                      {heading}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {findingRefs.map(({ ref, finding }, index) => (
                <tr
                  key={`${finding.finding_id}-${ref.evidence_id ?? index}`}
                  className="row-hover border-b border-edge-soft last:border-0"
                >
                  <td className="px-4 py-2.5">
                    <span className="block max-w-[200px] truncate text-sm text-ink" title={finding.title}>
                      {finding.title}
                    </span>
                    <span className="mono text-xs text-ink-faint">{finding.finding_id}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs text-ink-dim">{finding.severity}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="mono text-xs text-sentinel">{ref.evidence_id ?? '—'}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className="mono block max-w-[240px] truncate text-xs text-ink-dim"
                      title={ref.pcap_path}
                    >
                      {artifactName(ref.pcap_path)}
                    </span>
                    <span className="text-xs text-ink-faint">{ref.source ?? '—'}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="mono text-xs text-ink-dim">
                      {ref.packet_start !== null && ref.packet_start !== undefined
                        ? `${formatNumber(ref.packet_start)}–${formatNumber(ref.packet_end)}`
                        : (ref.capture_sequence ?? '—')}
                    </span>
                    <span className="mono block text-xs text-ink-faint">
                      {formatUtc(ref.capture_start_ns ?? ref.timestamp)}
                    </span>
                  </td>
                  <td className="mono tnum text-xs text-ink-dim">
                    {formatBytes(ref.byte_size)}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="mono text-xs text-ink-faint" title={ref.artifact_sha256}>
                      {ref.artifact_sha256 ? `${ref.artifact_sha256.slice(0, 10)}…` : '—'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {bundle.sources && bundle.sources.length > 0 && (
        <Panel
          title="Artifact Capture Detail"
          subtitle="what each recorded artifact actually contains"
          bodyClassName="overflow-x-auto"
        >
          <div className="divide-y divide-edge">
            {bundle.sources.map((source, index) => (
              <div key={`${source.path}-${index}`} className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono text-sm text-ink">{artifactName(source.path)}</span>
                  {source.feature_schema_version && (
                    <Tag>schema {source.feature_schema_version}</Tag>
                  )}
                  <Tag>{formatNumber(source.record_count ?? 0)} records</Tag>
                  <Tag>{formatBytes(source.byte_size)}</Tag>
                </div>
                <p className="mono mt-1 break-all text-xs text-ink-faint">{source.path}</p>
                <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1.5 md:grid-cols-4">
                  {source.endpoints?.a && (
                    <div>
                      <dt className="label text-ink-faint">
                        Endpoints
                      </dt>
                      <dd className="mono text-xs text-ink-dim">
                        {source.endpoints.a} ↔ {source.endpoints.b}
                      </dd>
                    </div>
                  )}
                  {source.packets_seen !== undefined && (
                    <div>
                      <dt className="label text-ink-faint">
                        Packets
                      </dt>
                      <dd className="mono tnum text-xs text-ink-dim">
                        {formatNumber(source.packets_seen)}
                      </dd>
                    </div>
                  )}
                  {source.esp_seen !== undefined && (
                    <div>
                      <dt className="label text-ink-faint">ESP</dt>
                      <dd className="text-xs text-ink-dim">
                        {source.esp_seen ? 'seen' : 'not seen'}
                      </dd>
                    </div>
                  )}
                  {source.spi_count !== undefined && (
                    <div>
                      <dt className="label text-ink-faint">SAs</dt>
                      <dd className="mono tnum text-xs text-ink-dim">
                        {formatNumber(source.spi_count)}
                      </dd>
                    </div>
                  )}
                  {source.window_start_ns !== undefined && (
                    <div className="col-span-2 md:col-span-4">
                      <dt className="label text-ink-faint">
                        Window
                      </dt>
                      <dd className="mono text-xs text-ink-dim">
                        {formatUtc(source.window_start_ns)} → {formatUtc(source.window_end_ns)}
                      </dd>
                    </div>
                  )}
                </dl>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {(evidence?.refs ?? []).length === 0 && findingRefs.length === 0 && (
        <Panel title="No evidence recorded">
          <EmptyState
            title="This assessment carries no evidence"
            description="Neither the assessment block nor its findings reference a capture artifact."
            icon="inbox"
          />
        </Panel>
      )}

      <p className="px-1 text-xs leading-relaxed text-ink-faint">
        Provenance fields are shown exactly as recorded.{' '}
        {summary?.fabricated === false
          ? 'The explainability layer reports that it fabricated no evidence reference.'
          : ''}{' '}
        Every source is a {humanize(bundle.dataset_run_id ? 'recorded dataset artifact' : 'recorded artifact')} from run{' '}
        <span className="mono text-ink-dim">{bundle.dataset_run_id}</span>.
      </p>
    </div>
  )
}
