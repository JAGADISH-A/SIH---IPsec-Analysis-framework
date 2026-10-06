import { useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { getAssessments, getFindings } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { EmptyState, ErrorState, LoadingPanel } from '@/components/states'
import { IdRow, ProvenanceDetails } from '@/components/kit'
import { Panel, SeverityBadge } from '@/components/ui'
import { PageHeader } from '@/layouts/AppLayout'
import { artifactName, formatBytes, formatNumber, formatUtc } from '@/lib/format'
import {
  assessmentLabel,
  evidenceSourceLabel,
  evidenceTypeLabel,
  evidenceTypeMeaning,
} from '@/lib/labels'
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
 *
 * ## Two layers
 *
 * The page is ordered around the two questions an analyst asks in sequence:
 *
 * 1. "What evidence do I have, and why does it matter?" — the primary layer.
 *    Every row leads with the kind of evidence, what that kind is, the finding
 *    that cited it with its severity, and the assessment it belongs to, all in
 *    readable labels.
 * 2. "Where exactly did this come from?" — the secondary layer, behind a
 *    `ProvenanceDetails` disclosure on each row: full artifact paths, digests,
 *    capture-feed names, internal evidence/finding/assessment ids, packet
 *    offsets and storage metadata.
 *
 * Nothing was dropped in the move: every field the backend sends is still
 * rendered, and the raw tokens stay reachable. Only the reading order changed.
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

  /* Assessments are referred to by scenario and slot everywhere they are named,
     with the raw id kept one column away for anyone reconciling against the
     store. Headers may be absent or truncated, so the id is the fallback rather
     than a blank cell. */
  const headerById = useMemo(
    () => new Map(headers.map((header) => [header.assessment_id, header])),
    [headers],
  )
  const assessmentIdLabel = (id: string): string => assessmentLabel(headerById.get(id) ?? { assessment_id: id })

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

  /**
   * The distinct kinds of evidence in the store, with a count and the one
   * sentence that says what each kind is. This is the answer to "what evidence
   * do I have and what does it mean" in one place, so the catalogue below can
   * stay a list of artifacts rather than repeating the explanation per row.
   *
   * Built from the `artifact_type` the backend actually sent. A kind the
   * product has no description for still appears, by its raw token, with the
   * count that was observed.
   */
  const kinds = useMemo(() => {
    const counts = new Map<string, { refs: number; artifacts: Set<string> }>()
    for (const row of rows) {
      const key = row.artifact_type ?? ''
      const entry = counts.get(key) ?? { refs: 0, artifacts: new Set<string>() }
      entry.refs += 1
      entry.artifacts.add(row.key)
      counts.set(key, entry)
    }
    return [...counts.entries()]
      .map(([type, entry]) => ({
        type,
        label: evidenceTypeLabel(type),
        meaning: evidenceTypeMeaning(type),
        refs: entry.refs,
        artifacts: entry.artifacts.size,
      }))
      .sort((a, b) => b.refs - a.refs)
  }, [rows])

  return (
    <div className="space-y-4">
      <PageHeader
        title="Evidence"
        description="What evidence the findings in this store rest on, and what each kind is. Paths, digests, capture feeds and record ids are behind the Provenance disclosure on every row."
      />

      {/* Primary layer, stated once at the top: what kinds of evidence exist and
          what each one is. An analyst should be able to answer "what do I have
          and why does it matter" without expanding anything. */}
      {findings.loading ? (
        <Panel title="Evidence kinds" bodyClassName="p-4">
          <LoadingPanel label="Loading evidence kinds" rows={2} />
        </Panel>
      ) : kinds.length > 0 ? (
        <Panel
          title="Evidence kinds"
          subtitle="what this store's evidence is, before any individual citation"
          bodyClassName="p-4"
        >
          <ul className="grid gap-3 sm:grid-cols-2">
            {kinds.map((kind) => (
              <li
                key={kind.type || 'untyped'}
                data-evidence-kind={kind.type || 'untyped'}
                className="rounded border border-edge-soft bg-panel-2/40 p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-ink">{kind.label}</span>
                  <span className="tnum text-xs text-ink-faint">
                    {formatNumber(kind.refs)} reference{kind.refs === 1 ? '' : 's'} ·{' '}
                    {formatNumber(kind.artifacts)} artifact{kind.artifacts === 1 ? '' : 's'}
                  </span>
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-ink-dim">{kind.meaning}</p>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

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
                {assessmentLabel(header)}
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
        subtitle="the distinct recorded files behind the findings in this store"
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
          <table className="data-table min-w-[720px]">
            <thead>
              {/* Primary layer leads: what the artifact is, which file, and how
                  much it is used for. Storage details sit behind the disclosure. */}
              <tr className="border-b border-edge text-left">
                {['Evidence', 'Artifact', 'Used by', 'Provenance'].map((heading) => (
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
                <tr key={artifact.key} className="border-b border-edge-soft align-top last:border-0">
                  <td className="px-4 py-2.5">
                    <span className="block text-sm font-medium text-ink">
                      {evidenceTypeLabel(artifact.type)}
                    </span>
                    <span className="mt-0.5 block max-w-[280px] text-xs leading-relaxed text-ink-faint">
                      {evidenceTypeMeaning(artifact.type)}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="mono block text-sm text-ink-dim">
                      {artifactName(artifact.path)}
                    </span>
                    <span className="tnum block text-xs text-ink-faint">
                      {formatBytes(artifact.bytes)}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="tnum block text-sm text-ink">
                      {formatNumber(artifact.count)} finding{artifact.count === 1 ? '' : 's'}
                    </span>
                    <span className="block text-xs text-ink-faint">
                      across {artifact.assessments.size} assessment
                      {artifact.assessments.size === 1 ? '' : 's'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <ProvenanceDetails title="Provenance">
                      <IdRow
                        label="Path"
                        value={artifact.path}
                        title={artifact.path}
                      />
                      <IdRow
                        label="File"
                        value={artifactName(artifact.path)}
                      />
                      <IdRow label="sha256" value={artifact.sha ?? '—'} title={artifact.sha ?? undefined} />
                      <IdRow
                        label="Capture feed"
                        value={evidenceSourceLabel(artifact.source)}
                        title={artifact.source ?? undefined}
                      />
                      <IdRow
                        label="source"
                        value={artifact.source ?? '—'}
                        title={artifact.source ?? undefined}
                      />
                      <IdRow
                        label="artifact_type"
                        value={artifact.type ?? '—'}
                        title={artifact.type ?? undefined}
                      />
                      <IdRow label="Bytes" value={formatBytes(artifact.bytes)} />
                    </ProvenanceDetails>
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
        subtitle="every citation, with the finding that made it and the evidence it rests on"
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
              {/* The finding that cited the evidence leads, then the kind of
                  evidence and the assessment it belongs to. Capture-feed names
                  and record ids trail behind one disclosure. */}
              <tr className="border-b border-edge text-left">
                {['Finding', 'Evidence', 'Assessment', 'Provenance'].map((heading) => (
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
                    <div className="flex flex-wrap items-center gap-1.5">
                      <SeverityBadge severity={row.findingSeverity as Severity} size="sm" />
                      <span className="text-sm font-medium text-ink">{row.findingTitle}</span>
                    </div>
                    <span className="mt-0.5 block text-xs text-ink-faint">
                      {row.findingSeverity}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="block text-sm text-ink-dim">
                      {evidenceTypeLabel(row.artifact_type)}
                    </span>
                    <span className="mono block text-xs text-ink-faint">
                      {artifactName(row.pcap_path)} · {formatBytes(row.byte_size)}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="block max-w-[220px] truncate text-sm text-ink-dim">
                      {assessmentIdLabel(row.assessmentId)}
                    </span>
                    <span className="block text-xs text-ink-faint">
                      {row.capture_sequence !== undefined
                        ? `capture ${formatNumber(row.capture_sequence)}`
                        : 'capture not numbered'}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <ProvenanceDetails title="Provenance">
                      <IdRow
                        label="Artifact path"
                        value={row.pcap_path}
                        title={row.pcap_path}
                      />
                      <IdRow
                        label="Capture feed"
                        value={evidenceSourceLabel(row.source)}
                        title={row.source ?? undefined}
                      />
                      <IdRow
                        label="source"
                        value={row.source ?? '—'}
                        title={row.source ?? undefined}
                      />
                      <IdRow label="sha256" value={row.artifact_sha256 ?? '—'} title={row.artifact_sha256 ?? undefined} />
                      <IdRow
                        label="Evidence id"
                        value={row.evidence_id ?? '—'}
                        title={row.evidence_id ?? undefined}
                      />
                      <IdRow label="Finding id" value={row.findingId} title={row.findingId} />
                      <IdRow label="Assessment id" value={row.assessmentId} title={row.assessmentId} />
                      {row.run_id && <IdRow label="Run id" value={row.run_id} title={row.run_id} />}
                      {row.experiment_id && (
                        <IdRow label="Experiment id" value={row.experiment_id} title={row.experiment_id} />
                      )}
                      <IdRow
                        label="artifact_type"
                        value={row.artifact_type ?? '—'}
                        title={row.artifact_type ?? undefined}
                      />
                      <IdRow label="Bytes" value={formatBytes(row.byte_size)} />
                      <IdRow
                        label="capture_sequence"
                        value={row.capture_sequence ?? '—'}
                      />
                      <IdRow label="sequence" value={row.sequence ?? '—'} />
                      <IdRow label="window_index" value={row.window_index ?? '—'} />
                      <IdRow
                        label="packet_start"
                        value={row.packet_start ?? 'not reported'}
                      />
                      <IdRow label="packet_end" value={row.packet_end ?? 'not reported'} />
                      <IdRow
                        label="Captured"
                        value={
                          row.capture_start_ns || row.capture_end_ns
                            ? formatUtc(row.capture_start_ns ?? row.capture_end_ns)
                            : 'no capture time recorded'
                        }
                      />
                      <IdRow
                        label="Audit event"
                        value={row.audit_event_reference ?? '—'}
                        title={row.audit_event_reference ?? undefined}
                      />
                    </ProvenanceDetails>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

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
