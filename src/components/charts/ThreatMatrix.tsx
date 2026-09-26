import { useMemo, useState } from 'react'
import { cx } from '../../lib/cx'
import type { Threat } from '../../types/analysis'
import { SEVERITY_LABEL } from '../../types/evidence'

/**
 * Likelihood × impact threat matrix.
 *
 * Each cell holds the threats observed at that coordinate. Opacity encodes how
 * confident the platform is: a threat with no confidence estimate is drawn as
 * a hollow marker rather than being silently treated as certain.
 */

const LIKELIHOOD_LABEL = ['Rare', 'Unlikely', 'Possible', 'Likely', 'Expected']
const IMPACT_LABEL = ['Negligible', 'Minor', 'Moderate', 'Major', 'Severe']

const FILL: Record<Threat['severity'], string> = {
  critical: 'bg-critical/70',
  high: 'bg-danger/65',
  medium: 'bg-warning/60',
  low: 'bg-info/55',
  informational: 'bg-mist-faint/50',
  unknown: 'bg-night-700',
}

export interface ThreatMatrixProps {
  threats: Threat[]
  selectedId?: string | null
  onSelect?: (threat: Threat) => void
  className?: string
}

export function ThreatMatrix({ threats, selectedId, onSelect, className }: ThreatMatrixProps) {
  const [hovered, setHovered] = useState<Threat | null>(null)

  const grid = useMemo(() => {
    const cells = new Map<string, Threat[]>()
    for (const threat of threats) {
      const key = `${threat.impact}-${threat.likelihood}`
      const bucket = cells.get(key) ?? []
      bucket.push(threat)
      cells.set(key, bucket)
    }
    return cells
  }, [threats])

  const detail = hovered ?? threats.find((threat) => threat.id === selectedId) ?? null

  return (
    <div className={cx('flex flex-col gap-3 lg:flex-row', className)}>
      <div className="flex flex-1 flex-col gap-1">
        <div className="flex">
          <div className="flex w-24 shrink-0 flex-col justify-center pr-2 text-right text-[10px] uppercase tracking-wide text-mist-faint">
            Impact
          </div>
          <div className="grid flex-1 grid-cols-5 gap-1">
            {[...LIKELIHOOD_LABEL].reverse().map((label) => (
              <div key={label} className="pb-1 text-center text-[10px] uppercase tracking-wide text-mist-faint">
                {label}
              </div>
            ))}
          </div>
        </div>

        <div className="flex">
          <div className="flex w-24 shrink-0 flex-col gap-1 pr-2">
            {[5, 4, 3, 2, 1].map((impact) => (
              <div
                key={impact}
                className="flex h-16 items-center justify-end text-right text-[10px] text-mist-dim"
              >
                {IMPACT_LABEL[impact - 1]}
              </div>
            ))}
          </div>

          <div
            className="grid flex-1 grid-cols-5 gap-1"
            role="group"
            aria-label="Threat matrix, likelihood by impact"
          >
            {[5, 4, 3, 2, 1].flatMap((impact) =>
              [1, 2, 3, 4, 5].map((likelihood) => {
                const cell = grid.get(`${impact}-${likelihood}`) ?? []
                const worst = cell.reduce<SeverityRank | null>((acc, threat) => {
                  if (acc === null) return threat.severity
                  return RANK[threat.severity] < RANK[acc] ? threat.severity : acc
                }, null)
                return (
                  <div
                    key={`${impact}-${likelihood}`}
                    className={cx(
                      'relative flex h-16 flex-col items-center justify-center gap-0.5 rounded-md border p-1 transition-colors',
                      cell.length > 0
                        ? cx('border-transparent', FILL[worst ?? 'unknown'])
                        : 'border-dashed border-edge bg-night-900/40',
                    )}
                    onMouseEnter={() => setHovered(cell[0] ?? null)}
                    onMouseLeave={() => setHovered(null)}
                  >
                    {cell.length === 0 ? (
                      <span className="text-[10px] text-mist-faint/60">—</span>
                    ) : (
                      cell.map((threat) => (
                        <button
                          key={threat.id}
                          type="button"
                          onClick={() => onSelect?.(threat)}
                          onFocus={() => setHovered(threat)}
                          onBlur={() => setHovered(null)}
                          aria-label={`${threat.name}, severity ${SEVERITY_LABEL[threat.severity]}, likelihood ${likelihood} of 5, impact ${impact} of 5`}
                          className={cx(
                            'max-w-full truncate rounded-sm px-1 py-0.5 text-[10px] font-semibold leading-tight text-night-950',
                            threat.confidence === null && 'bg-night-900/85 text-mist-dim ring-1 ring-inset ring-edge-strong',
                            selectedId === threat.id && 'ring-2 ring-accent-400',
                          )}
                          style={{ opacity: threat.confidence === null ? 1 : 0.4 + 0.6 * threat.confidence }}
                        >
                          {threat.name}
                        </button>
                      ))
                    )}
                    {cell.length > 1 ? (
                      <span className="text-[9px] font-mono text-night-950/80">+{cell.length - 1}</span>
                    ) : null}
                  </div>
                )
              }),
            )}
          </div>
        </div>

        <div className="flex">
          <div className="w-24 shrink-0" />
          <div className="flex flex-1 items-center justify-between text-[10px] text-mist-faint">
            <span>Likelihood →</span>
            <span>Marker opacity reflects confidence; hollow markers have no estimate.</span>
          </div>
        </div>
      </div>

      <aside className="w-full shrink-0 lg:w-72">
        {detail ? (
          <ThreatDetail threat={detail} />
        ) : (
          <div className="flex h-full min-h-40 flex-col justify-center rounded-lg border border-dashed border-edge p-4 text-[11px] text-mist-faint">
            Select a threat on the matrix to see its evidence and affected sessions.
          </div>
        )}
      </aside>
    </div>
  )
}

type SeverityRank = Threat['severity']

const RANK: Record<Threat['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
  unknown: 5,
}

function ThreatDetail({ threat }: { threat: Threat }) {
  return (
    <div className="flex flex-col gap-2.5 rounded-lg border border-edge bg-night-900 p-3">
      <div>
        <h3 className="text-[13px] font-semibold text-mist">{threat.name}</h3>
        <p className="mt-0.5 text-[11px] text-mist-faint">
          Severity {SEVERITY_LABEL[threat.severity]} · likelihood {threat.likelihood}/5 · impact {threat.impact}/5
        </p>
      </div>
      <p className="text-xs leading-relaxed text-mist-dim">{threat.description}</p>
      <dl className="grid grid-cols-2 gap-2 text-[11px]">
        <div>
          <dt className="text-mist-faint">Affected sessions</dt>
          <dd className="font-mono text-mist">{threat.affectedSessions}</dd>
        </div>
        <div>
          <dt className="text-mist-faint">Confidence</dt>
          <dd className="font-mono text-mist">
            {threat.confidence === null ? 'Unknown' : `${Math.round(threat.confidence * 100)}%`}
          </dd>
        </div>
        <div>
          <dt className="text-mist-faint">First detected</dt>
          <dd className="font-mono text-mist">{threat.firstDetected.slice(0, 10)}</dd>
        </div>
        <div>
          <dt className="text-mist-faint">Last observed</dt>
          <dd className="font-mono text-mist">{threat.lastObserved.slice(0, 10)}</dd>
        </div>
      </dl>
      {threat.relatedFindingIds.length > 0 ? (
        <p className="text-[11px] text-mist-faint">
          Supported by {threat.relatedFindingIds.length} finding(s):{' '}
          <span className="font-mono text-mist-dim">{threat.relatedFindingIds.join(', ')}</span>
        </p>
      ) : (
        <p className="text-[11px] text-mist-faint">No finding currently supports this threat.</p>
      )}
    </div>
  )
}
