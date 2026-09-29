import { useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { getAssessments, getFindings } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { EmptyState, ErrorState, LoadingPanel } from '@/components/states'
import { Panel, SeverityBadge, Tag } from '@/components/ui'
import { PageHeader } from '@/layouts/AppLayout'
import { artifactName, formatBytes, formatNumber, formatUtc } from '@/lib/format'
import type { AssessmentHeader, EvidenceRef, Severity } from '@/types'

type Row = EvidenceRef & {
  key: string
  findingId: string
  findingTitle: string
  findingSeverity: string
  assessmentId: string
}

/**
 * Cross-assessment evidence browser.
 *
 * The analytics API exposes evidence two ways: per assessment
 * (`/api/assessments/{id}/evidence`) and per finding
 * (`/api/v1/findings`). This page builds the index from the findings endpoint —
 * which already carries every evidence reference the risk engine attached — so
 * provenance is browsable across the whole store. The v1 evidence registry
 * returns zero rows on this deployment, and no reference is fabricated to fill
 * the gap.
 */
export function Evidence() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [query, setQuery] = useState('')

  const findings = useResource((signal) => getFindings({ limit: 1000 }, signal))
  const assessments = useResource((signal) => getAssessments({ limit: 200 }, signal))

  const assessmentFilter = searchParams.get('assessment') ?? 'ALL'

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = []
    for (const finding of findings.data?.findings ?? []) {
      for (const ref of finding.evidence_refs ?? []) {
        out.push({
          ...ref,
          key: `${finding.assessment_id}-${finding.finding_id}-${ref.evidence_id ?? ref.pcap_path}`,
          findingId: finding.finding_id,
          findingTitle: finding.title,
          findingSeverity: finding.severity,
          assessmentId: finding.assessment_id,
        })
      }
    }
    return out
  }, [findings.data])

  const headers = useMemo(() => assessments.data?.headers ?? [], [assessments.data])

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return rows.filter((row) => {
      if (assessmentFilter !== 'ALL' && row.assessmentId !== assessmentFilter) return false
      if (needle === '') return true
      return (
        row.evidence_id?.toLowerCase().includes(needle) ||
        row.pcap_path?.toLowerCase().includes(needle) ||
        row.findingId?.toLowerCase().includes(needle) ||
        row.findingTitle?.toLowerCase().includes(needle) ||
        row.source?.toLowerCase().includes(needle) ||
        row.artifact_sha256?.toLowerCase().includes(needle)
      )
    })
  }, [rows, query, assessmentFilter])

  /**
   * Deduplicated artifact view: the same file is usually cited many times. The
   * dedupe key is the evidence id when the backend supplied one, because the
   * same artifact path can legitimately appear with different ids across
   * captures — collapsing on path alone would hide those.
   */
  const artifacts = useMemo(() => {
    const map = new Map<
      string,
      {
        key: string
        path: string
        sha?: string
        bytes?: number
        type?: string
        source?: string
        count: number
        assessments: Set<string>
      }
    >()
    for (const row of rows) {
      const key = row.evidence_id ?? row.pcap_path
      const existing = map.get(key)
      if (existing) {
        existing.count += 1
        existing.assessments.add(row.assessmentId)
      } else {
        map.set(key, {
          key,
          path: row.pcap_path,
          sha: row.artifact_sha256,
          bytes: row.byte_size,
          type: row.artifact_type,
          source: row.source,
          count: 1,
          assessments: new Set([row.assessmentId]),
        })
      }
    }
    return [...map.values()].sort((a, b) => b.count - a.count)
  }, [rows])

  const totalBytes = useMemo(
    () => artifacts.reduce((sum, artifact) => sum + (artifact.bytes ?? 0), 0),
    [artifacts],
  )

  return (
    <div className="space-y-4">
      <PageHeader
        title="Evidence"
        description="Read-only evidence records, their digests, and the chain back to the assessment."
      />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-ink-faint">
          {findings.loading
            ? 'Loading evidence references…'
            : `${formatNumber(artifacts.length)} artifacts · ${formatNumber(rows.length)} references`}
          {totalBytes > 0 && (
            <span className="ml-2">· {formatBytes(totalBytes)} referenced</span>
          )}
        </p>
        <button
          type="button"
          onClick={() => {
            findings.reload()
            assessments.reload()
          }}
          className="rounded-md border border-edge bg-panel px-2.5 py-1.5 text-sm text-ink-dim transition-colors hover:bg-panel-2 hover:text-ink"
        >
          Refresh
        </button>
      </div>

      <div className="panel flex flex-wrap items-end gap-3 p-3">
        <label className="flex min-w-[240px] flex-1 flex-col gap-1">
          <span className="label text-ink-faint">
            Search
          </span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="evidence id, path, digest, finding…"
            className="rounded-md border border-edge bg-panel px-2.5 py-1.5 text-sm text-ink placeholder:text-ink-faint/70 focus:border-sentinel focus:ring-2 focus:ring-sentinel/15 focus:outline-none"
          />
        </label>
        <label className="flex min-w-[240px] flex-col gap-1">
          <span className="label text-ink-faint">
            Assessment
          </span>
          <select
            value={assessmentFilter}
            onChange={(event) => {
              const next = new URLSearchParams(searchParams)
              if (event.target.value === 'ALL') next.delete('assessment')
              else next.set('assessment', event.target.value)
              setSearchParams(next, { replace: true })
            }}
            className="w-full rounded-md border border-edge bg-panel px-2.5 py-1.5 text-base text-ink transition-colors hover:border-ink-faint focus:border-sentinel focus:outline-none focus:ring-2 focus:ring-sentinel/15"
          >
            <option value="ALL">All assessments</option>
            {headers.map((header: AssessmentHeader) => (
              <option key={header.assessment_id} value={header.assessment_id}>
                {header.assessment_id}
              </option>
            ))}
          </select>
        </label>
        {(query || assessmentFilter !== 'ALL') && (
          <button
            type="button"
            onClick={() => {
              setQuery('')
              setSearchParams(new URLSearchParams(), { replace: true })
            }}
            className="rounded-md px-2.5 py-1.5 text-sm text-ink-faint transition-colors hover:bg-panel-2 hover:text-ink"
          >
            Clear
          </button>
        )}
      </div>

      {findings.error && <ErrorState error={findings.error} onRetry={findings.reload} />}

      {/* Artifact catalogue */}
      <Panel
        title="Artifact Catalogue"
        subtitle="unique recorded files behind the findings in this store"
        bodyClassName="overflow-x-auto"
      >
        {findings.loading ? (
          <div className="p-4">
            <LoadingPanel label="Loading artifacts" rows={5} />
          </div>
        ) : artifacts.length === 0 ? (
          <EmptyState
            title="No evidence artifacts"
            description="No finding in the store references a capture artifact. The assessment store may be empty, or the captures were recorded without registered evidence."
            icon="inbox"
          />
        ) : (
          <table className="data-table min-w-[860px]">
            <thead>
              <tr className="border-b border-edge text-left">
                {['Artifact', 'Type', 'Source', 'Size', 'Cited by', 'Digest'].map((heading) => (
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
              {artifacts.map((artifact) => (
                <tr key={artifact.key} className="border-b border-edge-soft last:border-0">
                  <td className="px-4 py-2.5">
                    <span className="mono block text-sm text-ink">
                      {artifactName(artifact.path)}
                    </span>
                    <span
                      className="mono block max-w-[300px] truncate text-xs text-ink-faint"
                      title={artifact.path}
                    >
                      {artifact.path}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <Tag>{artifact.type ?? '—'}</Tag>
                  </td>
                  <td className="text-sm text-ink-dim">
                    {artifact.source ?? '—'}
                  </td>
                  <td className="mono tnum text-sm text-ink-dim">
                    {formatBytes(artifact.bytes)}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="mono tnum text-sm text-ink">
                      {artifact.count}
                    </span>
                    <span className="block text-xs text-ink-faint">
                      {artifact.assessments.size} assessment
                      {artifact.assessments.size === 1 ? '' : 's'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="mono text-xs text-sentinel" title={artifact.sha}>
                      {artifact.sha ? `${artifact.sha.slice(0, 12)}…` : '—'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {/* Reference list */}
      <Panel
        title="Evidence References"
        subtitle="every citation, with the finding and assessment that made it"
        bodyClassName="overflow-x-auto"
      >
        {findings.loading ? (
          <div className="p-4">
            <LoadingPanel label="Loading references" rows={6} />
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            title={rows.length === 0 ? 'No references' : 'No references match'}
            description={
              rows.length === 0
                ? 'The risk engine attached no evidence reference to any finding.'
                : 'Try a different search term or assessment.'
            }
            icon={rows.length === 0 ? 'inbox' : 'search'}
          />
        ) : (
          <table className="data-table min-w-[1080px]">
            <thead>
              <tr className="border-b border-edge text-left">
                {['Evidence ID', 'Artifact', 'Source', 'Cited by', 'Captured', 'Assessment'].map(
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
              {filtered.map((row) => (
                <tr
                  key={row.key}
                  onClick={() =>
                    navigate(
                      `/findings/${encodeURIComponent(row.assessmentId)}/${encodeURIComponent(row.findingId)}`,
                    )
                  }
                  className="row-hover cursor-pointer border-b border-edge-soft align-top last:border-0"
                >
                  <td className="px-4 py-2.5">
                    <span className="mono block text-xs text-sentinel">
                      {row.evidence_id ?? '—'}
                    </span>
                    {row.run_id && (
                      <span className="mono block text-xs text-ink-faint">
                        run {row.run_id}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className="mono block max-w-[260px] truncate text-xs text-ink-dim"
                      title={row.pcap_path}
                    >
                      {row.pcap_path}
                    </span>
                    <span className="text-xs text-ink-faint">
                      {formatBytes(row.byte_size)}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <Tag>{row.source ?? '—'}</Tag>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <SeverityBadge severity={row.findingSeverity as Severity} size="sm" />
                      <span className="mono text-xs text-ink-dim">{row.findingId}</span>
                    </div>
                    <span className="mt-0.5 block max-w-[280px] truncate text-xs text-ink-faint">
                      {row.findingTitle}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="mono text-xs text-ink-dim">
                      {row.capture_sequence ?? row.sequence ?? '—'}
                    </span>
                    <span className="mono block text-xs text-ink-faint">
                      {formatUtc(row.capture_start_ns ?? row.capture_end_ns)}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className="mono block max-w-[220px] truncate text-xs text-ink-dim"
                      title={row.assessmentId}
                    >
                      {row.assessmentId}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <p className="px-1 text-xs leading-relaxed text-ink-faint">
        Provenance is shown exactly as recorded by the analysis pipeline: artifact path,
        source, SHA-256 digest and byte size. Where a field is not present in the backend
        response it is omitted rather than filled in.
      </p>

      <div className="flex flex-wrap gap-2">
        <Link
          to="/assessments"
          className="rounded border border-edge bg-panel-2 px-3 py-1.5 text-sm text-ink-dim transition-colors hover:text-ink"
        >
          Browse assessments →
        </Link>
        <Link
          to="/findings"
          className="rounded border border-edge bg-panel-2 px-3 py-1.5 text-sm text-ink-dim transition-colors hover:text-ink"
        >
          Browse findings →
        </Link>
      </div>
    </div>
  )
}
