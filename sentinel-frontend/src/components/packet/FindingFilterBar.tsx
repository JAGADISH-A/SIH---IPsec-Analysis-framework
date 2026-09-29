import { useState } from 'react'
import { ErrorState, Spinner } from '@/components/states'
import { ApiRequestError } from '@/api/client'
import { formatNumber, formatPercent, humanize } from '@/lib/format'
import { RiskChip } from './primitives'
import {
  CONFIDENCE_OPTIONS,
  RISK_OPTIONS,
  trafficLabel,
  type FilteredFinding,
  type FindingFilters,
} from '@/hooks/useFindingFilters'

/**
 * The FINDINGS / assessment-filter section of the Packet Analysis workspace —
 * secondary to (and below) the LIVE IPSEC TRAFFIC view.
 *
 * It is a collapsible strip: hidden by default so the live capture stays the
 * primary surface. Expanding it reveals the five dropdowns (Risk, Confidence,
 * Traffic, Finding, Drift) + Clear Filters, then the compact findings-results
 * strip: one row per matching finding (severity chip + title + provenance +
 * traffic + drift), clickable into the Packet Investigation panel. Zero matches
 * render the explicit empty state — never a fabricated finding, packet or risk
 * value.
 *
 * These filters narrow the *findings* an analyst can triage — never the live
 * packet stream above, and never the investigation-scoped assessments.
 * Each dropdown carries only option values derived from the analytics store,
 * and matching is client-side and deterministic on the loaded store data.
 */

export type FilterKey = 'risk' | 'confidence' | 'traffic' | 'finding' | 'drift'

const FILTER_LABEL: Record<FilterKey, string> = {
  risk: 'Risk',
  confidence: 'Confidence',
  traffic: 'Traffic',
  finding: 'Finding',
  drift: 'Drift',
}

const DRIFT_LABEL: Record<string, string> = {
  ALL: 'All',
  with: 'With drift',
  without: 'Without drift',
}

const ALL_LABEL = 'All'

function optionLabel(key: FilterKey, value: string | number): string {
  if (value === 'ALL') return ALL_LABEL
  if (key === 'confidence') return `≥${value}%`
  if (key === 'drift') return DRIFT_LABEL[String(value)]
  if (key === 'traffic') return trafficLabel(String(value))
  return String(value)
}

function Dropdown({
  label,
  filterKey,
  options,
  activeValue,
  chosen,
  onSelect,
  hint,
}: {
  label: string
  filterKey: FilterKey
  options: { value: string | number; label: string }[]
  activeValue: string | number
  chosen: boolean
  onSelect: (value: string | number) => void
  hint?: string
}) {
  const [open, setOpen] = useState(false)
  return (
    <div className="pw-filter-dd" data-filter={filterKey}>
      <button
        type="button"
        className={`pw-filter-select${chosen ? ' pw-filter-on' : ''}`}
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label={`${FILTER_LABEL[filterKey]} filter: ${optionLabel(filterKey, activeValue)}`}
        data-filter={filterKey}
        onClick={() => setOpen((value) => !value)}
      >
        <span>
          {label}
          {hint && (
            <span
              className="pw-filter-hint"
              role="img"
              data-filter-hint={filterKey}
              aria-label={hint}
              title={hint}
            >
              ?
            </span>
          )}
        </span>
        <span className="pw-filter-value">{optionLabel(filterKey, activeValue)}</span>
        <span className="pw-filter-caret" aria-hidden="true">
          ▾
        </span>
      </button>
      {open && (
        <div className="pw-filter-menu" role="menu" data-filter-menu={filterKey}>
          {options.map((option) => {
            const isActive = String(option.value) === String(activeValue)
            return (
              <button
                key={String(option.value)}
                type="button"
                role="menuitemradio"
                aria-checked={isActive}
                className={`pw-filter-opt${isActive ? ' pw-filter-opt-on' : ''}`}
                onClick={() => {
                  onSelect(option.value)
                  setOpen(false)
                }}
              >
                {option.label}
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

/**
 * The full bar: label + the five dropdowns + Clear Filters + the live summary
 * counts, then the findings-results strip.
 */
export function FindingFilterBar({
  filters,
  onChange,
  onClear,
  activeCount,
  findingStore,
  findings,
  onOpenFinding,
  bufferedAssessmentIds,
}: {
  filters: FindingFilters
  onChange: (patch: Partial<FindingFilters>) => void
  onClear: () => void
  activeCount: number
  findingStore: {
    loading: boolean
    error: ApiRequestError | null
    reload: () => void
    totalFindings: number
    filteredFindings: number
    assessmentCount: number
    countBySeverity: { severity: string; count: number }[]
    findingOptions: string[]
    trafficOptions: string[]
  }
  findings: FilteredFinding[]
  onOpenFinding: (finding: FilteredFinding) => void
  bufferedAssessmentIds: Set<string>
}) {
  const { loading, error, reload } = findingStore
  const [stripOpen, setStripOpen] = useState(false)

  const activeLabel =
    activeCount === 0 ? '' : `${activeCount} active filter${activeCount === 1 ? '' : 's'}`

  const summary =
    activeCount === 0
      ? `${formatNumber(findingStore.filteredFindings)} findings`
      : `${formatNumber(findingStore.filteredFindings)} of ${formatNumber(findingStore.totalFindings)} findings`
  const severityText =
    findingStore.countBySeverity.map((c) => `${formatNumber(c.count)} ${c.severity}`).join(' · ') || '0 findings'

  const riskOptions = [
    { value: 'ALL', label: ALL_LABEL },
    ...RISK_OPTIONS.map((severity) => ({ value: severity, label: severity })),
  ]
  const confidenceOptions = CONFIDENCE_OPTIONS.map((option) => ({
    value: option.value,
    label: option.label,
  }))
  const trafficOptions = [
    { value: 'ALL', label: ALL_LABEL },
    ...findingStore.trafficOptions.map((tag) => ({ value: tag, label: trafficLabel(tag) })),
  ]
  const findingOptions = [
    { value: 'ALL', label: ALL_LABEL },
    ...findingStore.findingOptions.map((id) => ({ value: id, label: id })),
  ]
  const driftOptions = [
    { value: 'ALL', label: ALL_LABEL },
    { value: 'with', label: DRIFT_LABEL.with },
    { value: 'without', label: DRIFT_LABEL.without },
  ]

  return (
    <div data-findings-bar="true">
      <button
        type="button"
        className="pw-findings-toggle"
        aria-expanded={stripOpen}
        data-findings-toggle="true"
        onClick={() => setStripOpen((value) => !value)}
        title={
          stripOpen
            ? 'Collapse the findings section'
            : 'Expand the findings section (assessment filters narrow the findings list only — never the live capture)'
        }
      >
        <span className="pw-findings-label">FINDINGS</span>
        {activeLabel && (
          <span className="pw-findings-count" data-findings-count="true">
            {activeLabel}
          </span>
        )}
        <span className="pw-spacer" />
        <span className="pw-dim-caption">
          assessment filters narrow findings an analyst can triage — never the live IPsec capture
        </span>
        <span className="pw-filter-caret" aria-hidden="true">
          {stripOpen ? '▴' : '▾'}
        </span>
      </button>

      {stripOpen && (
        <>
          <div className="pw-filter-bar">
            <Dropdown
          label="Risk"
          filterKey="risk"
          options={riskOptions}
          activeValue={filters.risk}
          chosen={filters.risk !== 'ALL'}
          onSelect={(value) => onChange({ risk: String(value) })}
          hint="Filters findings by their backend finding severity. Packet risk reflects the highest severity associated with the packet's assessment."
        />
        <Dropdown
          label="Confidence"
          filterKey="confidence"
          options={confidenceOptions}
          activeValue={filters.confidence}
          chosen={filters.confidence !== 'ALL'}
          onSelect={(value) => onChange({ confidence: value === 'ALL' ? 'ALL' : (value as number) })}
        />
        <Dropdown
          label="Traffic"
          filterKey="traffic"
          options={trafficOptions}
          activeValue={filters.traffic}
          chosen={filters.traffic !== 'ALL'}
          onSelect={(value) => onChange({ traffic: value === 'ALL' ? 'ALL' : String(value) })}
        />
        <Dropdown
          label="Finding"
          filterKey="finding"
          options={findingOptions}
          activeValue={filters.finding}
          chosen={filters.finding !== 'ALL'}
          onSelect={(value) => onChange({ finding: value === 'ALL' ? 'ALL' : String(value) })}
        />
        <Dropdown
          label="Drift"
          filterKey="drift"
          options={driftOptions}
          activeValue={filters.drift}
          chosen={filters.drift !== 'ALL'}
          onSelect={(value) => onChange({ drift: value === 'ALL' ? ('ALL' as const) : (String(value) as 'with' | 'without') })}
        />

        <button
          type="button"
          className="pw-btn"
          disabled={activeCount === 0}
          data-action="clear-filters"
          onClick={onClear}
          title={activeCount === 0 ? 'No filters are active' : 'Clear all findings filters'}
        >
          Clear Filters
        </button>

        <span className="pw-spacer" />
        <span className="pw-findings-summary" data-findings-summary="true">
          {summary}
          {severityText ? ` · ${severityText}` : ''}
          <span className="pw-dim-caption"> · {formatNumber(findingStore.assessmentCount)} assessments</span>
        </span>
      </div>

      <FindingsStrip
        loading={loading}
        error={error}
        onRetry={reload}
        findings={findings}
        filteredCount={findingStore.filteredFindings}
        storeEmpty={findingStore.totalFindings === 0}
        onOpenFinding={onOpenFinding}
        bufferedAssessmentIds={bufferedAssessmentIds}
        onClear={onClear}
      />
        </>
      )}
    </div>
  )
}

function FindingsStrip({
  loading,
  error,
  onRetry,
  findings,
  filteredCount,
  storeEmpty,
  onOpenFinding,
  bufferedAssessmentIds,
  onClear,
}: {
  loading: boolean
  error: ApiRequestError | null
  onRetry: () => void
  findings: FilteredFinding[]
  filteredCount: number
  storeEmpty: boolean
  onOpenFinding: (finding: FilteredFinding) => void
  bufferedAssessmentIds: Set<string>
  onClear: () => void
}) {
  return (
    <div className="pw-findings-strip" data-findings-strip="true">
      {loading ? (
        <div className="pw-strip-state">
          <Spinner />
          <span>Loading findings index…</span>
        </div>
      ) : error ? (
        <div className="pw-strip-state">
          <ErrorState error={error} onRetry={onRetry} />
        </div>
      ) : storeEmpty ? (
        <div className="pw-strip-state" data-store-empty="true">
          <span className="pw-ink-strong">The assessment store contains no findings yet.</span>
          <p className="pw-empty-note">
            Nothing is rendered here rather than inventing findings — re-check the store or return later.
          </p>
        </div>
      ) : filteredCount === 0 ? (
        <div className="pw-strip-state" data-empty-state="true">
          <span className="pw-ink-strong">No findings match the selected filters.</span>
          <button type="button" className="pw-btn" data-action="clear-filters" onClick={onClear}>
            Clear Filters
          </button>
        </div>
      ) : (
        <ul className="pw-finding-list">
          {findings.map((f) => (
            <li key={`${f.finding.assessment_id}:${f.finding.finding_id}`}>
              <button type="button" className="pw-finding-row" data-finding-row="true" onClick={() => onOpenFinding(f)}>
                <RiskChip severity={f.severity} score={null} />
                <span className="pw-finding-name" title={f.finding.title}>
                  {f.finding.finding_id}
                </span>
                <span className="pw-finding-meta">
                  {f.finding.category} · {humanize(f.finding.source)}
                  {f.confidence === null
                    ? ' · no confidence score'
                    : ` · ${formatPercent(f.confidence)}`}
                </span>
                <span className="pw-finding-traffic">
                  {f.trafficTags.map((tag) => (
                    <span key={tag} className="pw-chip">
                      {trafficLabel(tag)}
                    </span>
                  ))}
                </span>
                <span className="pw-finding-drift">{f.driftStatus}</span>
                {!bufferedAssessmentIds.has(f.finding.assessment_id) && (
                  <span
                    className="pw-finding-nocap"
                    title="No current live packet is in the capture buffer for this assessment — the investigation opens from the finding itself."
                  >
                    no current live packet
                  </span>
                )}
                <span className="pw-finding-open" aria-hidden="true">
                  open ↗
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}