import { lazy, Suspense } from 'react'
import { createBrowserRouter, Navigate, RouterProvider, useRouteError } from 'react-router-dom'
import { AppLayout } from '@/layouts/AppLayout'
import { LoadingPanel } from '@/components/states'

/**
 * Routing.
 *
 * Two ideas govern this table.
 *
 * First, canonical URLs name the *product's* concepts, not the modules that
 * implement them. `/run` is what an analyst does; `/experiments` was how the
 * repository calls it. `/explainability` and `/analysis` read as subjects;
 * `/xai` and `/ml` read as acronyms. The old paths still work, as redirects, so
 * bookmarks and anything already written against them keep functioning.
 *
 * Second, the deep-dive routes are deliberately kept. Evidence, explainability
 * and ML are reached *from* an assessment in normal use, but a cross-cutting
 * view over the whole store is genuinely useful, and removing a working route
 * to tidy a sidebar would be the wrong trade.
 */
const Activity = lazy(() => import('@/pages/AnalystConsole').then((m) => ({ default: m.Activity })))
const PacketWorkspace = lazy(() =>
  import('@/pages/PacketWorkspace').then((m) => ({ default: m.PacketWorkspace })),
)
const Assessments = lazy(() => import('@/pages/Assessments').then((m) => ({ default: m.Assessments })))
const AssessmentDetailRoute = lazy(() =>
  import('@/pages/AssessmentDetailRoute').then((m) => ({ default: m.AssessmentDetailRoute })),
)
const Findings = lazy(() => import('@/pages/Findings').then((m) => ({ default: m.Findings })))
const Reports = lazy(() => import('@/pages/Reports').then((m) => ({ default: m.Reports })))
const FindingDetail = lazy(() =>
  import('@/pages/FindingDetail').then((m) => ({ default: m.FindingDetail })),
)
const EvidencePage = lazy(() => import('@/pages/EvidencePage').then((m) => ({ default: m.Evidence })))
const XaiPage = lazy(() => import('@/pages/XaiPage').then((m) => ({ default: m.XaiPage })))
const MlPage = lazy(() => import('@/pages/MlPage').then((m) => ({ default: m.MlPage })))
const RunAssessment = lazy(() =>
  import('@/pages/RunAssessment').then((m) => ({ default: m.RunAssessment })),
)
const ExperimentResult = lazy(() =>
  import('@/pages/ExperimentResult').then((m) => ({ default: m.ExperimentResult })),
)
const SystemStatus = lazy(() => import('@/pages/SystemStatus').then((m) => ({ default: m.SystemStatus })))
const NotFound = lazy(() => import('@/pages/NotFound').then((m) => ({ default: m.NotFound })))

const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    errorElement: <RouteErrorBoundary />,
    children: [
      /* ------------------------------------------------------- primary */
      { index: true, element: <PacketWorkspace /> },
      { path: 'assessments', element: <Assessments /> },
      { path: 'assessments/:assessmentId', element: <AssessmentDetailRoute /> },
      { path: 'reports', element: <Reports /> },
      { path: 'findings', element: <Findings /> },
      { path: 'findings/:assessmentId/:findingId', element: <FindingDetail /> },
      { path: 'run', element: <RunAssessment /> },
      { path: 'run/:jobId', element: <ExperimentResult /> },

      /* --------------------------------- reference / cross-cutting views */
      { path: 'activity', element: <Activity /> },
      { path: 'evidence', element: <EvidencePage /> },
      { path: 'explainability', element: <XaiPage /> },
      { path: 'analysis', element: <MlPage /> },
      { path: 'system', element: <SystemStatus /> },

      /* ------------------------------------------------------ redirects
         Legacy implementation-shaped URLs. Kept working so nothing that
         already points at them breaks; they simply land on the canonical
         page. */
      { path: 'console', element: <Navigate to="/activity" replace /> },
      { path: 'overview', element: <Navigate to="/" replace /> },
      { path: 'xai', element: <Navigate to="/explainability" replace /> },
      { path: 'ml', element: <Navigate to="/analysis" replace /> },
      { path: 'experiments', element: <Navigate to="/run" replace /> },
      { path: 'experiments/:jobId', element: <ExperimentResult /> },

      { path: '*', element: <NotFound /> },
    ],
  },
])

/**
 * Catches render-time failures inside the layout subtree. The message is
 * shown, but nothing is invented and no stack trace is dumped into the UI.
 */
function RouteErrorBoundary() {
  const error = useRouteError()
  const message = error instanceof Error ? error.message : 'An unexpected error occurred.'
  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas p-6">
      <div className="panel max-w-md p-6 text-center">
        <h1 className="text-lg font-semibold tracking-tight text-ink">
          Something went wrong
        </h1>
        <p className="mt-2 text-base leading-relaxed text-ink-dim">{message}</p>
        <a
          href="/"
          className="mt-4 inline-block rounded-md border border-edge bg-panel px-3 py-1.5 text-sm font-medium text-ink transition-colors hover:bg-panel-2"
        >
          Back to overview
        </a>
      </div>
    </div>
  )
}

export function App() {
  return (
    <Suspense fallback={<LoadingPanel label="Loading view" rows={6} fullPage />}>
      <RouterProvider router={router} />
    </Suspense>
  )
}
