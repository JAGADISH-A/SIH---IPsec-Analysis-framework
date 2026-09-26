import { useQueries } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { Badge } from '../common/Badge.tsx'
import { Button } from '../common/Button.tsx'
import { ConfidenceTag } from '../common/Evidence.tsx'
import { Panel } from '../common/Panel.tsx'
import { StatusDot } from '../common/StatusDot.tsx'
import { queryKeys } from '../../hooks/queries'
import { services } from '../../services'
import { cx } from '../../lib/cx'
import type { ExperimentDetail } from '../../types/experiment'

const MAX_COMPARISON = 4

/**
 * Side-by-side comparison of pinned experiments.
 *
 * The grid is deliberately configured-versus-observed: the point of running a
 * controlled experiment is to be able to say what was asked for and what was
 * actually seen, in the same column, for the same field.
 */
export function ExperimentCompare({ ids, onClear }: { ids: string[]; onClear: () => void }) {
  const details = useQueries({
    queries: ids.map((id) => ({
      queryKey: queryKeys.experiment(id),
      queryFn: () => services.experiments.getById(id),
      staleTime: 10_000,
    })),
  })
  const loaded = details
    .map((result) => result.data)
    .filter((detail): detail is ExperimentDetail => Boolean(detail))

  if (ids.length === 0) return null

  return (
    <Panel flush>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-edge px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className="text-[13px] font-semibold text-mist">Comparison</span>
          <Badge tone="muted">
            {ids.length} of {MAX_COMPARISON} pinned
          </Badge>
        </div>
        <Button size="sm" onClick={onClear}>
          <X className="size-3.5" aria-hidden />
          Clear
        </Button>
      </div>

      {loaded.length < ids.length ? (
        <p className="px-4 py-3 text-xs text-mist-faint">Loading experiment details…</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[44rem] text-left text-[12px]">
            <thead className="border-b border-edge text-[10.5px] uppercase tracking-wide text-mist-faint">
              <tr>
                <th scope="col" className="w-44 px-3 py-2 font-medium">Field</th>
                {loaded.map((detail) => (
                  <th key={detail.experiment.id} scope="col" className="px-3 py-2 font-medium">
                    <span className="block max-w-40 truncate normal-case text-mist">{detail.experiment.name}</span>
                    <span className="mt-0.5 flex items-center gap-1 normal-case">
                      <StatusDot
                        tone={
                          detail.experiment.status === 'completed'
                            ? 'success'
                            : detail.experiment.status === 'failed'
                              ? 'danger'
                              : 'accent'
                        }
                        size="sm"
                      />
                      <span className="font-mono text-[10px]">{detail.experiment.riskScore}</span>
                      <ConfidenceTag confidence={detail.experiment.confidence} />
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-edge/60">
              {COMPARISON_FIELDS.map((field) => {
                const values = loaded.map((detail) => {
                  const observation = detail.observations.find((row) => row.field === field.observation)
                  return { detail, observation }
                })
                const allAgree = values.every((entry) => entry.observation?.agrees !== false)
                return (
                  <tr key={field.label}>
                    <th scope="row" className="px-3 py-2 font-normal text-mist-faint">
                      {field.label}
                    </th>
                    {values.map(({ detail, observation }) => {
                      const configured = field.read(detail)
                      const observed = observation?.observed
                      const disagree = observation?.agrees === false
                      return (
                        <td
                          key={detail.experiment.id}
                          className={cx('px-3 py-2', disagree && 'bg-danger-dim/20')}
                        >
                          <span className="block font-mono text-[11px] text-mist-dim">{configured}</span>
                          {observation ? (
                            <span
                              className={cx(
                                'mt-0.5 block font-mono text-[11px]',
                                disagree ? 'text-danger' : 'text-mist',
                              )}
                            >
                              → {observed}
                              {observation.agrees === null ? (
                                <span className="ml-1 font-sans text-[10px] text-mist-faint">not determinable</span>
                              ) : null}
                            </span>
                          ) : (
                            <span className="mt-0.5 block text-[10.5px] text-mist-faint">no observation</span>
                          )}
                        </td>
                      )
                    })}
                    {!allAgree ? (
                      <td className="px-3 py-2 text-right text-[10.5px] text-danger">divergence</td>
                    ) : null}
                  </tr>
                )
              })}
              <tr>
                <th scope="row" className="px-3 py-2 font-normal text-mist-faint">Findings</th>
                {loaded.map((detail) => (
                  <td key={detail.experiment.id} className="px-3 py-2 font-mono text-[11px] text-mist-dim">
                    {detail.findings.length}
                  </td>
                ))}
              </tr>
              <tr>
                <th scope="row" className="px-3 py-2 font-normal text-mist-faint">Packets</th>
                {loaded.map((detail) => (
                  <td key={detail.experiment.id} className="px-3 py-2 font-mono text-[11px] text-mist-dim">
                    {detail.traffic.packets.toLocaleString()}
                  </td>
                ))}
              </tr>
            </tbody>
          </table>
        </div>
      )}

      <p className="border-t border-edge px-4 py-2 text-[10.5px] leading-relaxed text-mist-faint">
        Each cell shows the configured value on top and what the platform observed on the wire below. A red row means
        the observation contradicts the declared configuration, which is a fact to explain — not automatically a
        finding.
      </p>
    </Panel>
  )
}

const COMPARISON_FIELDS: {
  label: string
  observation: string
  read: (detail: ExperimentDetail) => string
}[] = [
  { label: 'IKE version', observation: 'IKE version', read: (d) => d.experiment.groundTruth.ikeVersion },
  { label: 'VPN mode', observation: 'Mode', read: (d) => d.experiment.groundTruth.vpnMode },
  { label: 'Encryption', observation: 'Encryption', read: (d) => d.experiment.groundTruth.encryption },
  { label: 'Integrity', observation: 'Integrity', read: (d) => d.experiment.groundTruth.integrity },
  { label: 'DH group', observation: 'DH group', read: (d) => `Group ${d.experiment.groundTruth.dhGroup}` },
  {
    label: 'Forward secrecy',
    observation: 'Perfect forward secrecy',
    read: (d) => (d.experiment.groundTruth.perfectForwardSecrecy ? 'Required' : 'Not required'),
  },
  { label: 'IP version', observation: 'IP version', read: (d) => d.experiment.groundTruth.ipVersion },
  { label: 'Traffic profile', observation: 'Traffic profile', read: (d) => d.experiment.trafficProfile },
]
