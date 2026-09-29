import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { getAssessment } from '@/api/analytics'
import { useResource } from '@/hooks/useResource'
import { ErrorState, LoadingPanel } from '@/components/states'
import { LinkButton } from '@/components/ui'
import { Breadcrumbs } from '@/layouts/AppLayout'
import { AssessmentDetailBody, DETAIL_TABS, type DetailTab } from './AssessmentDetail'
import { ApiRequestError } from '@/api/client'

function isTab(value: string | null): value is DetailTab {
  return DETAIL_TABS.some((tab) => tab.id === value)
}

/**
 * Route wrapper for one assessment: resolves the id, owns the tab state, and
 * maps the four request states onto the shared primitives. The tab content
 * itself lives in `AssessmentDetailBody` so the same panels are reused by the
 * global Evidence / XAI / ML pages.
 */
export function AssessmentDetailRoute() {
  // The route param name is `assessmentId`; see `router.tsx`.
  const { assessmentId: id = '' } = useParams()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const tabParam = searchParams.get('tab')
  const tab: DetailTab = isTab(tabParam) ? tabParam : 'overview'

  const resource = useResource(
    (signal) => getAssessment(id, signal),
    { enabled: id !== '', deps: [id] },
  )

  const setTab = (next: DetailTab) => {
    const params = new URLSearchParams(searchParams)
    params.set('tab', next)
    setSearchParams(params, { replace: true })
  }

  if (id === '') {
    return (
      <ErrorState
        error={
          new ApiRequestError({
            title: 'No assessment selected',
            detail: 'The route did not include an assessment id.',
            status: 404,
            code: 'missing_assessment_id',
            service: 'analytics',
          })
        }
        onRetry={() => navigate('/assessments')}
      />
    )
  }

  return (
    <div>
      <Breadcrumbs
        trail={[
          { to: '/assessments', label: 'Assessments' },
          { label: id },
        ]}
      />

      {resource.loading && <LoadingPanel label="Loading assessment" rows={7} />}

      {resource.error && (
        <div className="space-y-3">
          <ErrorState error={resource.error} onRetry={resource.reload} />
          <LinkButton to="/assessments" variant="ghost">
            ← Back to assessments
          </LinkButton>
        </div>
      )}

      {resource.data && (
        <>
          <nav
            className="mb-4 flex flex-wrap gap-1 border-b border-edge"
            aria-label="Assessment sections"
          >
            {DETAIL_TABS.map((item) => {
              const active = tab === item.id
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setTab(item.id)}
                  aria-current={active ? 'page' : undefined}
                  className={`-mb-px border-b-2 px-3.5 py-2 text-sm transition-colors ${
                    active
                      ? 'border-sentinel font-medium text-sentinel'
                      : 'border-transparent text-ink-faint hover:text-ink'
                  }`}
                >
                  {item.label}
                </button>
              )
            })}
          </nav>

          <AssessmentDetailBody bundle={resource.data} tab={tab} />
        </>
      )}
    </div>
  )
}
