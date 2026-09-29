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
import { PacketWorkspace } from '@/pages/PacketWorkspace'
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
import { NotFound } from '@/pages/NotFound'

// The canonical route table, mirrored from src/router.tsx.
const ROUTES: { path: string; element: ReactElement }[] = [
  { path: '/', element: createElement(PacketWorkspace) },
  { path: '/assessments', element: createElement(Assessments) },
  { path: '/assessments/some-real-id', element: createElement(AssessmentDetailRoute) },
  { path: '/findings', element: createElement(Findings) },
  { path: '/findings/assessment-a/RISK-EXAMPLE', element: createElement(FindingDetail) },
  { path: '/run', element: createElement(RunAssessment) },
  { path: '/experiments/job-1', element: createElement(ExperimentResult) },
  { path: '/activity', element: createElement(Activity) },
  { path: '/evidence', element: createElement(Evidence) },
  { path: '/explainability', element: createElement(XaiPage) },
  { path: '/analysis', element: createElement(MlPage) },
  { path: '/system', element: createElement(SystemStatus) },
  { path: '/does-not-exist', element: createElement(NotFound) },
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
    console.log(`ok   ${route.path} (${html.length} bytes)`)
  } catch (error) {
    failures += 1
    console.error(`FAIL ${route.path}: ${(error as Error).message}`)
  }
}
console.log(failures === 0 ? 'ALL ROUTES RENDERED' : `${failures} ROUTE(S) FAILED`)
if (failures > 0) process.exitCode = 1
