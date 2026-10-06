/**
 * Temporary server-render smoke test (not part of the shipped app).
 *
 * Renders every route in one pass with no DOM, to catch import cycles, missing
 * exports and invalid hook usage before anything is mounted for real.
 */
import { StrictMode, createElement, type ReactElement } from 'react'
import { renderToString } from 'react-dom/server'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AppLayout } from '@/layouts/AppLayout'
import { LiveScreening } from '@/pages/LiveScreening'
import { Assessments } from '@/pages/Assessments'
import { AssessmentDetailRoute } from '@/pages/AssessmentDetailRoute'
import { Findings } from '@/pages/Findings'
import { FindingDetail } from '@/pages/FindingDetail'
import { Evidence } from '@/pages/EvidencePage'
import { XaiPage } from '@/pages/XaiPage'
import { MlPage } from '@/pages/MlPage'
import { RunAssessment } from '@/pages/RunAssessment'
import { Activity } from '@/pages/AnalystConsole'
import { ExperimentResult } from '@/pages/ExperimentResult'
import { SystemStatus } from '@/pages/SystemStatus'
import { ConfigurationIndex } from '@/pages/ConfigurationIndex'
import { ThreatMatrix } from '@/pages/ThreatMatrix'
import { NotAvailable } from '@/pages/NotAvailable'
import { NotFound } from '@/pages/NotFound'

// The canonical route table, mirrored from src/router.tsx.
const ROUTES: { path: string; element: ReactElement }[] = [
  { path: '/', element: createElement(LiveScreening) },
  { path: '/assessments', element: createElement(Assessments) },
  { path: '/assessments/some-real-id', element: createElement(AssessmentDetailRoute) },
  { path: '/findings', element: createElement(Findings) },
  { path: '/findings/assessment-a/RISK-EXAMPLE', element: createElement(FindingDetail) },
  { path: '/run', element: createElement(RunAssessment) },
  { path: '/experiments/job-1', element: createElement(ExperimentResult) },
  { path: '/overview', element: createElement(Activity) },
  { path: '/evidence', element: createElement(Evidence) },
  { path: '/explainability', element: createElement(XaiPage) },
  { path: '/analysis', element: createElement(MlPage) },
  { path: '/settings', element: createElement(SystemStatus) },
  { path: '/configuration', element: createElement(ConfigurationIndex) },
  { path: '/reports', element: createElement(NotAvailable, { kind: 'report documents' }) },
  { path: '/threat-matrix', element: createElement(ThreatMatrix) },
  { path: '/does-not-exist', element: createElement(NotFound) },
  // Legacy paths the router still redirects or serves.
  { path: '/xai', element: createElement(XaiPage) },
  { path: '/ml', element: createElement(MlPage) },
]

let failures = 0
for (const route of ROUTES) {
  try {
    const html = renderToString(
      createElement(
        StrictMode,
        null,
        createElement(
          MemoryRouter,
          { initialEntries: [route.path] },
          createElement(
            Routes,
            null,
            createElement(
              Route,
              { path: '/', element: createElement(AppLayout) },
              createElement(Route, { path: route.path.slice(1) || '/', element: route.element }),
            ),
          ),
        ),
      ),
    )
    // The shell titles every screen from the pathname. A routed page whose
    // title resolves to "Not Found" is the contradiction this guards: the body
    // rendered a real screen while the chrome claimed there wasn't one.
    const isCatchAll = route.path === '/does-not-exist'
    const titledNotFound = html.includes('>Not Found<')
    if (isCatchAll && !titledNotFound) {
      failures += 1
      console.error(`FAIL ${route.path}: catch-all route did not title itself "Not Found"`)
    } else if (!isCatchAll && titledNotFound) {
      failures += 1
      console.error(`FAIL ${route.path}: routed page is titled "Not Found"`)
    } else {
      console.log(`ok   ${route.path} (${html.length} bytes)`)
    }
  } catch (error) {
    failures += 1
    console.error(`FAIL ${route.path}: ${(error as Error).message}`)
  }
}
console.log(failures === 0 ? 'ALL ROUTES RENDERED' : `${failures} ROUTE(S) FAILED`)
if (failures > 0) process.exitCode = 1
