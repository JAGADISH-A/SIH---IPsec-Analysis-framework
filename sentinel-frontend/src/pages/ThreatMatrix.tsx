import { getAssessments } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { ErrorState, LoadingPanel } from '@/components/states'
import { ThreatMatrix as ThreatMatrixPanel } from '@/components/traffic/panels'
import { PageHeader } from '@/layouts/AppLayout'

/**
 * The threat matrix as a destination.
 *
 * The same cross-tabulation the overview shows, given its own route because
 * it is a product concept an analyst can name and navigate to directly. Both
 * axes are backend-recorded facts — severity from the risk engine, posture
 * from the planner — so the page fetches the assessment index and hands it to
 * the existing panel unchanged. Nothing here is computed: a score, ranking or
 * invented matrix would be a second, weaker source of truth next to the risk
 * engine, and the panel says so where the counts are.
 */
export function ThreatMatrix() {
  const assessments = useResource((signal) => getAssessments({ limit: 200 }, signal))
  const headers = assessments.data?.headers ?? []

  return (
    <div>
      <PageHeader
        title="Threat Matrix"
        description="Assessments on record, cross-tabulated by two backend-recorded axes."
      />

      {assessments.loading && !assessments.data ? (
        <LoadingPanel label="Loading assessments" />
      ) : assessments.error ? (
        <ErrorState error={assessments.error} onRetry={assessments.reload} />
      ) : (
        <ThreatMatrixPanel headers={headers} />
      )}
    </div>
  )
}
