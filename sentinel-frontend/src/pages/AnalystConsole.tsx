import { useCallback, useEffect, useMemo, useState } from 'react'
import { getAssessments, getFindings, getFindingExplanation } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { useLiveTraffic } from '@/hooks/useLiveTraffic'
import { ErrorState, LoadingCards, LoadingPanel } from '@/components/states'
import { LiveTrafficMonitor } from '@/components/traffic/LiveTrafficMonitor'
import { EntityDetailDrawer } from '@/components/traffic/EntityDetailDrawer'
import {
  AssetPriorityPanel,
  DriftPanel,
  IntegrityPanel,
  ReportsPanel,
  StatisticsPanel,
  ThreatMatrix,
  Kpi,
} from '@/components/traffic/panels'
import { formatNumber, severityHex } from '@/lib/format'
import { PageHeader } from '@/layouts/AppLayout'
import { selectionForRow, type TrafficRow } from '@/lib/traffic'
import type { CustodyExplanation } from '@/types'

/**
 * Live activity.
 *
 * A contextual view rather than the product's front door. An analyst arrives
 * here to watch the analysis pipeline as it works — the audit event stream, the
 * entity currently under observation, and the store-wide context needed to judge
 * it — not to start their day. That job belongs to the Overview.
 *
 * Nothing here is a separate product: the same assessments, findings, drift,
 * integrity and custody data the rest of the console shows, organised by time
 * rather than by entity.
 */
export function Activity() {
  const assessments = useResource((signal) => getAssessments({ limit: 200 }, signal))
  const findings = useResource((signal) => getFindings({ limit: 500 }, signal))

  const headers = useMemo(() => assessments.data?.headers ?? [], [assessments.data])
  const allFindings = useMemo(() => findings.data?.findings ?? [], [findings.data])
  const overview = assessments.data?.overview ?? null

  const feed = useLiveTraffic({
    headers,
    findings: allFindings,
  })

  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [frozen, setFrozen] = useState(false)
  // The clicked row is snapshotted alongside its key. The feed is a bounded
  // ring buffer, so a row the analyst is mid-way through reading can be
  // evicted by newer events; resolving the drawer purely from the live buffer
  // would silently close it under them. The snapshot is the fallback, and the
  // drawer says when it is showing a held row rather than a live one.
  const [snapshot, setSnapshot] = useState<TrafficRow | null>(null)

  const liveRow = useMemo(
    () => (selectedKey ? (feed.rows.find((row) => row.key === selectedKey) ?? null) : null),
    [feed.rows, selectedKey],
  )
  const selectedRow = liveRow ?? snapshot
  const selectedIsHeld = selectedRow !== null && liveRow === null

  /**
   * Selection follows the newest matching row while it is unfrozen.
   *
   * Freezing pins the drawer to the row the analyst clicked, so clicking
   * through to a different event does not replace the panel being read.
   */
  const selectRow = useCallback(
    (row: TrafficRow) => {
      if (frozen) return
      const key = selectionForRow(row).rowKey
      setSelectedKey(key)
      setSnapshot(row)
    },
    [frozen],
  )

  // One custody chain per distinct finding, for the mission-context panel.
  const explanations = useCustodyExplanations(allFindings)

  if (assessments.error) {
    return (
      <div className="space-y-4">
        <ErrorState error={assessments.error} onRetry={assessments.reload} />
        <LoadingPanel label="Reconnecting to the analytics API" />
      </div>
    )
  }

  if (assessments.loading) {
    return (
      <div className="space-y-4">
        <LoadingCards count={4} />
        <LoadingPanel label="Loading the assessment store" rows={6} />
      </div>
    )
  }

  const highCount = (overview?.severity_counts?.CRITICAL ?? 0) + (overview?.severity_counts?.HIGH ?? 0)
  const mlAnomalies = headers.filter((header) => header.ml_anomaly === true).length
  const topSeverity = overview?.highest_severity ?? null

  return (
    <div className="space-y-5">
      <PageHeader
        title="Live activity"
        description="The analysis audit stream, the entity currently under observation, and the store-wide context for judging it."
      />

      {/* KPI strip */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Kpi
          label="Assessments"
          value={formatNumber(overview?.total_assessments ?? headers.length)}
          sub={<span className="mono">{overview?.dataset_run_id ?? '—'}</span>}
          accent="var(--color-ink)"
        />
        <Kpi
          label="Findings"
          value={formatNumber(overview?.findings_total ?? 0)}
          sub={`raised by the risk engine`}
          accent="var(--color-good)"
        />
        <Kpi
          label="High severity"
          value={formatNumber(highCount)}
          sub={
            <span style={{ color: topSeverity ? severityHex(String(topSeverity)) : undefined }}>
              peak {overview?.highest_risk ?? '—'}
            </span>
          }
          accent={severityHex('HIGH')}
        />
        <Kpi
          label="Live events"
          value={formatNumber(feed.rows.length)}
          sub={`${formatNumber(feed.serverTotal)} in journal`}
          accent="var(--color-sentinel)"
        />
        <Kpi
          label="ML anomalies"
          value={formatNumber(overview?.ml_anomalies ?? mlAnomalies)}
          sub="flow-scope, model-derived"
          accent="var(--color-medium)"
        />
      </div>

      {/* Traffic + selected entity */}
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <LiveTrafficMonitor
          feed={feed}
          selectedKey={selectedKey}
          onSelect={selectRow}
          frozen={frozen}
          onFreezeChange={setFrozen}
        />
        {/* Narrow screens get a full-screen overlay, because a 520px column
            under a horizontally scrolling event table is unusable on a phone.
            Wide screens keep it as the second grid column, always present so
            the "select a row" prompt is discoverable. */}
        <div
          className={
            selectedRow
              ? 'fixed inset-0 z-30 overflow-y-auto bg-canvas p-4 xl:static xl:z-auto xl:min-h-[520px] xl:overflow-visible xl:bg-transparent xl:p-0'
              : 'hidden xl:block xl:min-h-[520px]'
          }
        >
          <EntityDetailDrawer
            row={selectedRow}
            frozen={frozen}
            held={selectedIsHeld}
            onClose={() => {
              setSelectedKey(null)
              setSnapshot(null)
              setFrozen(false)
            }}
          />
        </div>
      </div>

      {/* Drift + integrity */}
      <div className="grid gap-4 lg:grid-cols-2">
        <DriftPanel />
        <IntegrityPanel findings={allFindings} />
      </div>

      {/* Statistics + threat matrix */}
      <div className="grid gap-4 lg:grid-cols-2">
        <StatisticsPanel overview={overview} headers={headers} findings={allFindings} />
        <ThreatMatrix headers={headers} />
      </div>

      {/* Priority + reports */}
      <div className="grid gap-4 lg:grid-cols-2">
        <AssetPriorityPanel explanations={explanations} />
        <ReportsPanel runId={overview?.dataset_run_id ?? null} />
      </div>

      {findings.error && <ErrorState error={findings.error} onRetry={findings.reload} compact />}

      <p className="text-xs leading-relaxed text-ink-faint">
        Every score, severity, comparison and finding on this page is produced by the backend and
        read verbatim. Sentinel recomputes nothing, and shows &ldquo;Not observable&rdquo; rather
        than a substituted value wherever the store did not record one.
      </p>
    </div>
  )
}

/**
 * Mission context, read from custody explanations.
 *
 * The custody endpoint is the only place the backend publishes mission
 * context, so it is the only source consulted for asset priority. The fetch is
 * bounded to the first few findings that actually carry a chain — the panel
 * needs a representative sample, not the whole store, and a fan-out of one
 * request per finding would be a lot of traffic for a display-only field.
 */
function useCustodyExplanations(findings: { assessment_id: string; finding_id: string }[]): CustodyExplanation[] {
  const [explanations, setExplanations] = useState<CustodyExplanation[]>([])

  const targets = useMemo(
    () =>
      [...findings]
        .filter((finding, index, all) =>
          all.findIndex((other) => other.assessment_id === finding.assessment_id) === index,
        )
        .slice(0, 6),
    [findings],
  )

  const key = targets.map((target) => `${target.assessment_id}/${target.finding_id}`).join('|')

  useEffect(() => {
    if (targets.length === 0) {
      setExplanations([])
      return
    }
    let cancelled = false
    const controller = new AbortController()
    setExplanations([])
    void Promise.all(
      targets.map((target) =>
        getFindingExplanation(target.assessment_id, target.finding_id, controller.signal).catch(
          () => null,
        ),
      ),
    ).then((results) => {
      if (cancelled) return
      setExplanations(results.filter((entry): entry is CustodyExplanation => entry !== null))
    })
    return () => {
      cancelled = true
      controller.abort()
    }
    // `key` is the stable identity of this request set.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  return explanations
}
