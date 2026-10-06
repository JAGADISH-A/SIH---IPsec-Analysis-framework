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
const LiveScreening = lazy(() => import('@/pages/LiveScreening').then((m) => ({ default: m.LiveScreening })))
const ConfigurationIndex = lazy(() =>
  import('@/pages/ConfigurationIndex').then((m) => ({ default: m.ConfigurationIndex })),
)
const NotAvailable = lazy(() => import('@/pages/NotAvailable').then((m) => ({ default: m.NotAvailable })))
const Assessments = lazy(() => import('@/pages/Assessments').then((m) => ({ default: m.Assessments })))
const AssessmentDetailRoute = lazy(() =>
  import('@/pages/AssessmentDetailRoute').then((m) => ({ default: m.AssessmentDetailRoute })),
)
const Findings = lazy(() => import('@/pages/Findings').then((m) => ({ default: m.Findings })))
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
const ThreatMatrix = lazy(() => import('@/pages/ThreatMatrix').then((m) => ({ default: m.ThreatMatrix })))
const NotFound = lazy(() => import('@/pages/NotFound').then((m) => ({ default: m.NotFound })))

const router = createBrowserRouter([
  {
    path: '/',
    element: <AppLayout />,
    errorElement: <RouteErrorBoundary />,
    children: [
      /* ------------------------------------------------------- primary
         These are the destinations the sidebar names, in the order it names
         them. Overview and Settings have real pages of their own; the routes
         the implementation used to call them (/activity, /system) are kept
         below as redirects. */
      { index: true, element: <LiveScreening /> },
      { path: 'overview', element: <Activity /> },
      { path: 'configuration', element: <ConfigurationIndex /> },
      { path: 'analysis', element: <MlPage /> },
      { path: 'assessments', element: <Assessments /> },
      { path: 'reports', element: <NotAvailable kind="report documents" /> },
      { path: 'threat-matrix', element: <ThreatMatrix /> },
      { path: 'settings', element: <SystemStatus /> },
      { path: 'assessments/:assessmentId', element: <AssessmentDetailRoute /> },
      { path: 'run', element: <RunAssessment /> },
      { path: 'run/:jobId', element: <ExperimentResult /> },

      /* --------------------------------- reference / cross-cutting views
         Deliberately not in the sidebar. These are reached from an assessment
         in normal use — an analyst follows a finding to its evidence, not the
         other way round — so a route that only ever makes sense in that context
         does not need a permanent navigation entry to stay reachable. */
      { path: 'findings', element: <Findings /> },
      { path: 'findings/:assessmentId/:findingId', element: <FindingDetail /> },
      { path: 'evidence', element: <EvidencePage /> },
      { path: 'explainability', element: <XaiPage /> },

      /* ------------------------------------------------------ redirects
         Legacy implementation-shaped URLs. Kept working so nothing that
         already points at them breaks; they simply land on the canonical
         page. */
      { path: 'activity', element: <Navigate to="/overview" replace /> },
      { path: 'system', element: <Navigate to="/settings" replace /> },
      { path: 'live', element: <Navigate to="/" replace /> },
      { path: 'console', element: <Navigate to="/" replace /> },
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
