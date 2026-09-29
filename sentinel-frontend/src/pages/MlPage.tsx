import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { getAssessments } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { EmptyState, ErrorState, LoadingPanel } from '@/components/states'
import { Panel, StatusPill, Tag } from '@/components/ui'
import { PageHeader } from '@/layouts/AppLayout'
import { formatNumber } from '@/lib/format'

/**
 * Fleet view of the ML layer.
 *
 * The list endpoint carries only two ML signals per assessment — whether ML ran
 * and whether the model flagged an anomaly. Confidence, traffic class and
 * feature vectors are not in the list payload, so they are not shown here; the
 * per-assessment ML tab renders whatever the bundle actually carries.
 */
export function MlPage() {
  const resource = useResource((signal) => getAssessments({ limit: 200 }, signal))
  const headers = useMemo(() => resource.data?.headers ?? [], [resource.data])
  const overview = resource.data?.overview ?? null

  const withMl = useMemo(
    () => headers.filter((header) => header.ml_present),
    [headers],
  )
  const anomalies = useMemo(
    () => headers.filter((header) => header.ml_anomaly === true),
    [headers],
  )

  const classDistribution = useMemo(() => {
    const counts = new Map<string, number>()
    for (const header of withMl) {
      const profile = header.traffic_profile || 'unknown'
      counts.set(profile, (counts.get(profile) ?? 0) + 1)
    }
    return [...counts.entries()]
      .map(([profile, count]) => ({ profile, count }))
      .sort((a, b) => b.count - a.count)
  }, [withMl])

  return (
    <div className="space-y-4">
      <PageHeader
        title="Model analysis"
        description="Machine-learned verdicts are labelled as inference; the risk engine stays the authority."
      />

      <div className="panel border-low/25 bg-low/[0.03] p-4">
        <h2 className="text-sm font-semibold text-low">Model-derived inference</h2>
        <p className="mt-1 text-sm leading-relaxed text-ink-dim">
          Traffic classification comes from a trained model. The backend treats it as{' '}
          <span className="text-low">evidence about traffic</span>, never as an authoritative
          protocol observation, and the risk policy never scores a disagreement as a
          vulnerability on its own.
        </p>
      </div>

      {resource.error && <ErrorState error={resource.error} onRetry={resource.reload} />}
      {resource.loading && <LoadingPanel label="Loading assessments" rows={5} />}

      {overview && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[
            { label: 'ML anomalies', value: overview.ml_anomalies, tone: 'text-critical' },
            {
              label: 'Classification disagreements',
              value: overview.ml_classification_disagreements,
              tone: 'text-medium',
            },
            { label: 'Assessments with ML', value: withMl.length, tone: 'text-low' },
            { label: 'Total assessments', value: overview.total_assessments, tone: 'text-ink' },
          ].map((card) => (
            <div key={card.label} className="panel p-3.5">
              <p className="label text-ink-faint">
                {card.label}
              </p>
              <p className={`mono tnum mt-1 text-2xl leading-none ${card.tone}`}>
                {formatNumber(card.value)}
              </p>
            </div>
          ))}
        </div>
      )}

      {overview && (
        <>
          <div className="grid gap-4 lg:grid-cols-2">
            <Panel
              title="Planned Traffic Profile"
              subtitle="distribution across assessments that ran ML"
            >
              {classDistribution.length === 0 ? (
                <EmptyState
                  title="No ML results"
                  description="No assessment in this store carried an ML result."
                  icon="inbox"
                />
              ) : (
                <div className="h-[196px] px-1 py-3">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={classDistribution} margin={{ top: 4, right: 12, bottom: 0, left: -20 }}>
                      <XAxis
                        dataKey="profile"
                        tick={{ fill: '#5d6d85', fontSize: 10 }}
                        axisLine={{ stroke: '#1b2537' }}
                        tickLine={false}
                      />
                      <YAxis
                        tick={{ fill: '#5d6d85', fontSize: 10 }}
                        axisLine={false}
                        tickLine={false}
                        allowDecimals={false}
                        width={40}
                      />
                      <Tooltip
                        cursor={{ fill: 'rgba(34,211,238,0.05)' }}
                        contentStyle={{
                          background: 'rgba(5,7,12,0.96)',
                          border: '1px solid #1b2537',
                          borderRadius: 6,
                          fontSize: 11.5,
                        }}
                      />
                      <Bar dataKey="count" name="assessments" radius={[3, 3, 0, 0]} maxBarSize={34}>
                        {classDistribution.map((entry) => (
                          <Cell key={entry.profile} fill="#38bdf8" />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </Panel>

            <Panel
              title="ML Scope"
              subtitle="what the backend reports about the model layer"
            >
              <div className="space-y-3 p-4">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm text-ink-dim">ML anomalies</span>
                  <StatusPill
                    status={String(overview.ml_anomalies)}
                    tone={overview.ml_anomalies > 0 ? 'bad' : 'good'}
                  />
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm text-ink-dim">Disagreements</span>
                  <StatusPill
                    status={String(overview.ml_classification_disagreements)}
                    tone={overview.ml_classification_disagreements > 0 ? 'warn' : 'good'}
                  />
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm text-ink-dim">Anomaly list</span>
                  {anomalies.length === 0 ? (
                    <span className="text-sm text-ink-faint">no assessment flagged</span>
                  ) : (
                    <span className="mono tnum text-sm text-ink">
                      {anomalies.length}
                    </span>
                  )}
                </div>
                <div className="border-t border-edge pt-3">
                  <p className="label text-ink-faint">
                    Assessment coverage
                  </p>
                  <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-panel-2">
                    <div
                      className="h-full rounded-full bg-low"
                      style={{
                        width: `${
                          overview.total_assessments
                            ? (withMl.length / overview.total_assessments) * 100
                            : 0
                        }%`,
                      }}
                    />
                  </div>
                  <p className="mt-1.5 text-xs text-ink-faint">
                    {formatNumber(withMl.length)} of {formatNumber(overview.total_assessments)}{' '}
                    assessments ran ML
                    {withMl.length === 0 && ' — the remaining assessments record no ML result'}
                  </p>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  <Tag>model version per assessment</Tag>
                  <Tag>confidence from the bundle only</Tag>
                </div>
              </div>
            </Panel>
          </div>

          <Panel
            title="Assessments with ML"
            subtitle="select a row to open its ML tab"
            bodyClassName="overflow-x-auto"
          >
            {withMl.length === 0 ? (
              <EmptyState
                title="No assessment ran ML"
                description="The store contains no ML result. Open an assessment to confirm what its ML block reports."
                icon="inbox"
              />
            ) : (
              <table className="data-table min-w-[820px]">
                <thead>
                  <tr className="border-b border-edge text-left">
                    {['Assessment', 'Planned profile', 'ML present', 'Anomaly', 'Risk', ''].map(
                      (heading, index) => (
                        <th
                          key={heading || index}
                          className="px-4 py-2.5 label text-ink-faint"
                        >
                          {heading}
                        </th>
                      ),
                    )}
                </tr>
                </thead>
                <tbody>
                  {withMl.map((header) => (
                    <tr
                      key={header.assessment_id}
                      className="row-hover border-b border-edge-soft last:border-0"
                    >
                      <td className="px-4 py-2.5">
                        <span className="mono block text-sm text-ink">{header.slot}</span>
                        <span className="mono block max-w-[260px] truncate text-xs text-ink-faint">
                          {header.assessment_id}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <Tag>{header.traffic_profile}</Tag>
                      </td>
                      <td className="px-4 py-2.5">
                        <StatusPill status="yes" tone="info" />
                      </td>
                      <td className="px-4 py-2.5">
                        {header.ml_anomaly === true ? (
                          <StatusPill status="true" tone="bad" />
                        ) : (
                          <span className="text-sm text-ink-faint">not reported</span>
                        )}
                      </td>
                      <td className="mono tnum text-sm text-ink-dim">
                        {header.risk_score}
                      </td>
                      <td className="px-4 py-2.5">
                        <Link
                          to={`/assessments/${encodeURIComponent(header.assessment_id)}?tab=ml`}
                          className="text-sm text-ink-faint transition-colors hover:text-sentinel"
                        >
                          Open ML →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>

          <p className="px-1 text-xs leading-relaxed text-ink-faint">
            The assessment list endpoint carries only presence and anomaly flags, so the
            predicted class and its confidence are shown per assessment in its ML tab rather
            than estimated here. No value is inferred from data the backend did not send.
          </p>
        </>
      )}
    </div>
  )
}
