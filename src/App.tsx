import { Suspense, lazy } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { AppLayout } from './components/layout/AppLayout.tsx'
import { Spinner } from './components/common/Spinner.tsx'
import { LEGACY_ROUTES } from './components/navigation/navData.ts'

/**
 * Route table.
 *
 * Every destination in the top navigation is a real page — there is no anchor
 * scrolling anywhere in the product. Pages are code-split so the initial bundle
 * only carries the shell and the command center; the analyzer workspace in
 * particular is large and rarely the first thing an operator opens.
 */
const HomePage = lazy(() => import('./features/home/HomePage.tsx').then((m) => ({ default: m.HomePage })))
const DashboardPage = lazy(() => import('./components/dashboard/DashboardPage.tsx').then((m) => ({ default: m.DashboardPage })))
const LiveMonitorPage = lazy(() => import('./components/live/LiveMonitorPage.tsx').then((m) => ({ default: m.LiveMonitorPage })))
const SessionsPage = lazy(() => import('./components/sessions/SessionsPage.tsx').then((m) => ({ default: m.SessionsPage })))
const SessionDetailPage = lazy(() => import('./components/sessions/SessionDetailPage.tsx').then((m) => ({ default: m.SessionDetailPage })))
const FindingsPage = lazy(() => import('./components/findings/FindingsPage.tsx').then((m) => ({ default: m.FindingsPage })))
const FindingDetailPage = lazy(() => import('./components/findings/FindingDetailPage.tsx').then((m) => ({ default: m.FindingDetailPage })))
const TrafficPage = lazy(() => import('./components/traffic/TrafficPage.tsx').then((m) => ({ default: m.TrafficPage })))
const ThreatMatrixPage = lazy(() => import('./components/threats/ThreatMatrixPage.tsx').then((m) => ({ default: m.ThreatMatrixPage })))
const ExperimentsPage = lazy(() => import('./components/experiments/ExperimentsPage.tsx').then((m) => ({ default: m.ExperimentsPage })))
const ExperimentDetailPage = lazy(() => import('./components/experiments/ExperimentDetailPage.tsx').then((m) => ({ default: m.ExperimentDetailPage })))
const ReportsPage = lazy(() => import('./components/reports/ReportsPage.tsx').then((m) => ({ default: m.ReportsPage })))
const NewReportPage = lazy(() => import('./components/reports/NewReportPage.tsx').then((m) => ({ default: m.NewReportPage })))
const DatasetPage = lazy(() => import('./components/dataset/DatasetPage.tsx').then((m) => ({ default: m.DatasetPage })))
const SystemHealthPage = lazy(() => import('./components/health/SystemHealthPage.tsx').then((m) => ({ default: m.SystemHealthPage })))
const DocumentationPage = lazy(() => import('./components/docs/DocumentationPage.tsx').then((m) => ({ default: m.DocumentationPage })))
const SettingsPage = lazy(() => import('./components/settings/SettingsPage.tsx').then((m) => ({ default: m.SettingsPage })))
const NotFoundPage = lazy(() => import('./components/landing/NotFoundPage.tsx').then((m) => ({ default: m.NotFoundPage })))

function RouteFallback() {
  return (
    <div className="flex h-full min-h-64 items-center justify-center" role="status" aria-live="polite">
      <span className="flex items-center gap-2 text-sm text-mist-faint">
        <Spinner />
        Loading page…
      </span>
    </div>
  )
}

export default function App() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<HomePage />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="live-monitor" element={<LiveMonitorPage />} />
          <Route path="vpn-sessions" element={<SessionsPage />} />
          <Route path="vpn-sessions/:sessionId" element={<SessionDetailPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/:findingId" element={<FindingDetailPage />} />
          <Route path="traffic" element={<TrafficPage />} />
          <Route path="threat-matrix" element={<ThreatMatrixPage />} />
          <Route path="experiments" element={<ExperimentsPage />} />
          <Route path="experiments/:experimentId" element={<ExperimentDetailPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="reports/new" element={<NewReportPage />} />
          <Route path="dataset" element={<DatasetPage />} />
          <Route path="system-health" element={<SystemHealthPage />} />
          <Route path="documentation" element={<DocumentationPage />} />
          <Route path="settings" element={<SettingsPage />} />
          {/* Legacy destinations from the pre-dashboard information architecture. */}
          {LEGACY_ROUTES.map(({ from, to }) => (
            <Route key={from} path={from} element={<Navigate to={to} replace />} />
          ))}
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </Suspense>
  )
}
