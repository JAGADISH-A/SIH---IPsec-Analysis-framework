import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, ExternalLink } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { ConfidenceMeter, ConfidenceTag, RestrictedNotice, SeverityTag, SourceTag } from '../../components/common/Evidence.tsx'
import { KeyValueList } from '../../components/common/Data.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { PageBody, PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { Panel } from '../../components/common/Panel.tsx'
import { FINDING_STATUSES, FINDING_STATUS_LABEL } from '../../types/analysis'
import type { FindingStatus, SecurityFinding } from '../../types/analysis'
import type { SessionReference } from '../../types/session'
import { useFinding, useSessionReferences, useSetFindingStatus } from '../../hooks/queries'
import type { EvidenceReference } from '../../types/evidence'

/**
 * Finding detail: the audit record.
 *
 * The page is written so a reviewer can answer, without leaving it: what was
 * observed, what was expected, why it matters, how to fix it, why the platform
 * believes it, and what evidence proves it.
 */
export function FindingDetailPage() {
  const { findingId } = useParams<{ findingId: string }>()
  const finding = useFinding(findingId)
  const sessions = useSessionReferences(finding.data?.sessionIds ?? [])
  const setStatus = useSetFindingStatus()

  return (
    <PageScroll>
      <PageHeader
        breadcrumb={[{ label: 'Findings', to: '/findings' }, { label: findingId ?? '' }]}
        title={finding.data?.title ?? findingId ?? 'Finding'}
        description={finding.data?.summary}
        meta={
          finding.data ? (
            <>
              <span className="font-mono">{finding.data.id}</span>
              <span>Detected {new Date(finding.data.detectedAt).toLocaleString()}</span>
              <span className="font-mono">Risk contribution {finding.data.riskScore}</span>
            </>
          ) : null
        }
        actions={
          <Link to="/findings" className="btn">
            <ArrowLeft className="size-3.5" aria-hidden />
            All findings
          </Link>
        }
      />

      <QueryBoundary
        isLoading={finding.isLoading}
        isError={finding.isError}
        error={finding.error}
        onRetry={() => void finding.refetch()}
        isEmpty={!finding.isLoading && !finding.data}
        emptyTitle="Finding not found"
        emptyDescription="No finding with this id exists in the current dataset."
        loadingRows={8}
      >
        {finding.data ? (
          <PageBody>
            <FindingSummaryBar finding={finding.data} />

            <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
              <div className="flex flex-col gap-4">
                <Narrative finding={finding.data} />
                <EvidenceTable evidence={finding.data.evidence} />
                <SessionsTable
                  sessionIds={finding.data.sessionIds}
                  references={sessions.data ?? []}
                />
              </div>

              <div className="flex flex-col gap-4">
                <TriagePanel finding={finding.data} pending={setStatus.isPending} onChange={(status) =>
                  setStatus.mutate({ id: finding.data!.id, status })
                } />
                <ProvenancePanel finding={finding.data} />
                <ReferencesPanel finding={finding.data} />
              </div>
            </div>
          </PageBody>
        ) : null}
      </QueryBoundary>
    </PageScroll>
  )
}

function FindingSummaryBar({ finding }: { finding: SecurityFinding }) {
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-edge bg-night-900 px-4 py-3">
      <SeverityTag severity={finding.severity} />
      <Badge tone={finding.status === 'open' ? 'warning' : finding.status === 'resolved' ? 'success' : 'muted'}>
        {FINDING_STATUS_LABEL[finding.status]}
      </Badge>
      <ConfidenceTag confidence={finding.confidence} showLabel />
      <SourceTag source={finding.source} />
      {finding.ruleId ? <span className="font-mono text-[11px] text-mist-faint">rule {finding.ruleId}</span> : null}
      {finding.model ? <span className="font-mono text-[11px] text-mist-faint">model {finding.model}</span> : null}
    </div>
  )
}

/** Observed / expected / impact / recommendation / rationale. */
function Narrative({ finding }: { finding: SecurityFinding }) {
  const rows: { label: string; body: string }[] = [
    { label: 'What was observed', body: finding.observedBehavior },
    { label: 'What was expected', body: finding.expectedBehavior },
    { label: 'Why it matters', body: finding.impact },
    { label: 'Recommended remediation', body: finding.recommendation },
    { label: 'Why the platform believes this', body: finding.rationale },
  ]
  return (
    <Panel padded>
      <dl className="flex flex-col gap-3">
        {rows.map((row) => (
          <div key={row.label}>
            <dt className="text-[11px] font-semibold uppercase tracking-wide text-mist-faint">{row.label}</dt>
            <dd className="mt-1 text-[12.5px] leading-relaxed text-mist-dim">{row.body}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  )
}

function EvidenceTable({ evidence }: { evidence: EvidenceReference[] }) {
  const columns: ColumnDef<EvidenceReference>[] = [
    {
      id: 'id',
      header: 'Evidence ID',
      width: '13rem',
      render: (row) => <span className="font-mono text-[11px] text-mist-dim">{row.id}</span>,
    },
    {
      id: 'artifact',
      header: 'Artefact',
      width: '14rem',
      render: (row) => (
        <div className="min-w-0">
          <div className="font-mono text-[11px] text-mist-dim">{row.field ?? '—'}</div>
          <div className="text-[10px] text-mist-faint">{row.packetRange ?? row.exchange ?? '—'}</div>
        </div>
      ),
    },
    {
      id: 'value',
      header: 'Raw value',
      width: '9rem',
      render: (row) => <span className="font-mono text-[11px] text-mist">{row.rawValue}</span>,
    },
    {
      id: 'source',
      header: 'Source',
      width: '7rem',
      render: (row) => <SourceTag source={row.source} />,
    },
    {
      id: 'confidence',
      header: 'Confidence',
      width: '7rem',
      render: (row) => <ConfidenceTag confidence={row.confidence} />,
    },
    {
      id: 'explanation',
      header: 'Why it supports the conclusion',
      render: (row) => <span className="text-[12px] text-mist-dim">{row.explanation}</span>,
    },
  ]

  return (
    <section className="flex flex-col gap-3">
      <div className="flex items-end justify-between gap-2">
        <div>
          <h2 className="text-[13px] font-semibold tracking-wide text-mist">Evidence</h2>
          <p className="mt-0.5 text-[11px] text-mist-faint">
            {evidence.length} artefact(s) support this conclusion.
          </p>
        </div>
      </div>
      <Panel flush>
        <DataTable columns={columns} rows={evidence} rowKey={(row) => row.id} empty="No evidence is attached to this finding." />
      </Panel>
    </section>
  )
}

function SessionsTable({
  sessionIds,
  references,
}: {
  sessionIds: string[]
  references: SessionReference[]
}) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Affected sessions</h2>
        <p className="mt-0.5 text-[11px] text-mist-faint">
          {sessionIds.length} session(s) exhibit this behaviour.
        </p>
      </div>
      <Panel flush>
        {sessionIds.length === 0 ? (
          <p className="px-4 py-6 text-center text-xs text-mist-faint">No sessions are linked to this finding.</p>
        ) : (
          <ul className="divide-y divide-edge/60">
            {sessionIds.map((id) => {
              const reference = references.find((entry) => entry.id === id)
              return (
                <li key={id} className="flex items-center justify-between gap-3 px-3 py-2">
                  <Link to={`/vpn-sessions/${id}`} className="font-mono text-xs text-mist hover:text-accent-300">
                    {id}
                  </Link>
                  <span className="truncate text-[12px] text-mist-dim">{reference?.label ?? 'Loading session label…'}</span>
                </li>
              )
            })}
          </ul>
        )}
      </Panel>
    </section>
  )
}

function TriagePanel({
  finding,
  pending,
  onChange,
}: {
  finding: SecurityFinding
  pending: boolean
  onChange: (status: FindingStatus) => void
}) {
  const [note, setNote] = useState('')
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Triage</h2>
        <p className="mt-0.5 text-[11px] text-mist-faint">Operator annotation only.</p>
      </div>
      <Panel padded>
        <fieldset disabled={pending} className="flex flex-col gap-1.5">
          <legend className="sr-only">Set finding status</legend>
          {FINDING_STATUSES.map((status) => (
            <label
              key={status}
              className="flex cursor-pointer items-center gap-2 rounded-md border border-edge bg-night-900 px-2.5 py-1.5 text-[12px] text-mist-dim has-checked:border-accent-500 has-checked:bg-accent-dim has-checked:text-mist"
            >
              <input
                type="radio"
                name="finding-status"
                value={status}
                checked={finding.status === status}
                onChange={() => onChange(status)}
                className="accent-accent-500"
              />
              {FINDING_STATUS_LABEL[status]}
            </label>
          ))}
        </fieldset>
        <label className="mt-3 block text-[11px] text-mist-faint">
          Note (kept locally in this session)
          <textarea
            value={note}
            onChange={(event) => setNote(event.target.value)}
            rows={2}
            className="field mt-1 w-full resize-y text-[12px]"
            placeholder="Why this triage decision was made…"
          />
        </label>
        {pending ? <p className="mt-2 text-[11px] text-mist-faint">Saving annotation…</p> : null}
        <p className="mt-2 text-[10px] leading-relaxed text-mist-faint">
          Marking a finding as a false positive does not remove the evidence. The record stays auditable.
        </p>
      </Panel>
    </section>
  )
}

function ProvenancePanel({ finding }: { finding: SecurityFinding }) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Confidence and provenance</h2>
      </div>
      <Panel padded>
        <ConfidenceMeter confidence={finding.confidence} />
        <div className="mt-3">
          <KeyValueList
            items={[
              { label: 'Produced by', value: finding.model ?? finding.ruleId ?? 'Rule engine', mono: true },
              { label: 'Source', value: <SourceTag source={finding.source} /> },
              { label: 'Detected', value: new Date(finding.detectedAt).toLocaleString() },
              { label: 'Last updated', value: new Date(finding.updatedAt).toLocaleString() },
              {
                label: 'Related events',
                value:
                  finding.relatedEventIds.length > 0 ? (
                    <span className="font-mono text-[11px]">{finding.relatedEventIds.join(', ')}</span>
                  ) : (
                    'None'
                  ),
              },
            ]}
          />
        </div>
      </Panel>
    </section>
  )
}

function ReferencesPanel({ finding }: { finding: SecurityFinding }) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-[13px] font-semibold tracking-wide text-mist">Standards references</h2>
      </div>
      <Panel padded>
        {finding.references.length === 0 ? (
          <p className="text-[12px] text-mist-faint">No standard references are attached to this finding.</p>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {finding.references.map((reference) => (
              <li key={reference} className="flex items-start gap-2 text-[12px] text-mist-dim">
                <ExternalLink className="mt-0.5 size-3 shrink-0 text-mist-faint" aria-hidden />
                <span className="font-mono text-[11px]">{reference}</span>
              </li>
            ))}
          </ul>
        )}
        <div className="mt-3">
          <RestrictedNotice>
            Reference links resolve to the standards library once the documentation service is connected. The
            identifiers above are the canonical ones.
          </RestrictedNotice>
        </div>
      </Panel>
      <div className="flex justify-end">
        <Link to="/documentation" className="btn btn-sm">
          Read the methodology
        </Link>
      </div>
    </section>
  )
}
