import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from '@tanstack/react-query'
import { useCallback } from 'react'
import { services } from '../services'
import { useSettings } from '../state/settings'
import type { DashboardQuery, DashboardSummary } from '../types/dashboard'
import type { SessionDetail, SessionPage, SessionQuery, SessionReference } from '../types/session'
import type { SessionFacets } from '../services/api/sessionService'
import type { FindingQuery, FindingSummary, SecurityFinding, ThreatMatrix } from '../types/analysis'
import type { FindingStatus } from '../types/analysis'
import type { TrafficClassification, TrafficOverview } from '../types/trafficIntelligence'
import type { Experiment, ExperimentDetail, ExperimentPage, ExperimentQuery } from '../types/experiment'
import type { ExperimentRequest } from '../services/api/experimentService'
import type { Report, ReportPreview, ReportRequest } from '../types/report'
import type { CaptureRecord, DatasetPage, DatasetQuery, DatasetStats } from '../types/dataset'
import type { CaptureMetadata } from '../types/dataset'
import type { CaptureUploadOptions } from '../services/api/datasetService'
import type { SystemHealth } from '../types/health'
import type { HomeSummary } from '../types/home'
import type { TunnelIdentity, TunnelSpineStep } from '../types/identity'

/**
 * Query layer.
 *
 * Pages never call a service directly: they use these hooks, so caching,
 * background refresh and error normalisation live in exactly one place.
 * The service behind each hook is swappable, which is why the UI does not need
 * to change when the backend arrives.
 */

export const queryKeys = {
  dashboard: (query: DashboardQuery) => ['dashboard', query] as const,
  sessions: (query: SessionQuery) => ['sessions', query] as const,
  session: (id: string) => ['session', id] as const,
  sessionFacets: ['session-facets'] as const,
  findings: (query: FindingQuery) => ['findings', query] as const,
  finding: (id: string) => ['finding', id] as const,
  findingSummary: (query: FindingQuery) => ['finding-summary', query] as const,
  threatMatrix: ['threat-matrix'] as const,
  traffic: ['traffic-overview'] as const,
  classifications: ['traffic-classifications'] as const,
  experiments: (query: ExperimentQuery) => ['experiments', query] as const,
  experiment: (id: string) => ['experiment', id] as const,
  experimentSelection: ['experiment-selection'] as const,
  reports: ['reports'] as const,
  report: (id: string) => ['report', id] as const,
  reportPreview: (id: string) => ['report-preview', id] as const,
  dataset: (query: DatasetQuery) => ['dataset', query] as const,
  datasetStats: ['dataset-stats'] as const,
  captureMetadata: (id: string) => ['capture-metadata', id] as const,
  health: ['system-health'] as const,
  home: ['home-summary'] as const,
  tunnels: (limit: number) => ['tunnels', limit] as const,
  tunnel: (id: string) => ['tunnel', id] as const,
  evidenceSpine: (id: string) => ['evidence-spine', id] as const,
} as const

/**
 * Poll cadence, taken from the user's preference so the refresh rate is a
 * setting rather than a constant buried in a hook.
 */
function useRefreshIntervalMs(): number {
  return useSettings().settings.refreshIntervalMs
}

/* ------------------------------------------------------------------ */
/* Dashboard                                                            */
/* ------------------------------------------------------------------ */

export function useDashboard(
  query: DashboardQuery = {},
  options?: { enabled?: boolean },
): UseQueryResult<DashboardSummary> {
  const REFRESH = useRefreshIntervalMs()
  return useQuery({
    queryKey: queryKeys.dashboard(query),
    queryFn: () => services.dashboard.getSummary(query),
    refetchInterval: REFRESH,
    staleTime: REFRESH / 2,
    enabled: options?.enabled,
  })
}

/* ------------------------------------------------------------------ */
/* Sessions                                                             */
/* ------------------------------------------------------------------ */

export function useSessions(
  query: SessionQuery = {},
  options?: { enabled?: boolean },
): UseQueryResult<SessionPage> {
  const REFRESH = useRefreshIntervalMs()
  return useQuery({
    queryKey: queryKeys.sessions(query),
    queryFn: () => services.sessions.query(query),
    refetchInterval: REFRESH,
    staleTime: REFRESH / 2,
    enabled: options?.enabled,
  })
}

export function useSessionDetail(id: string | undefined): UseQueryResult<SessionDetail> {
  return useQuery({
    queryKey: queryKeys.session(id ?? 'none'),
    queryFn: () => services.sessions.getDetail(id ?? ''),
    enabled: Boolean(id),
    retry: (count, error) => {
      const status = (error as { status?: number | null } | null)?.status
      // A 404 will not fix itself; retrying it just delays the empty state.
      return status !== 404 && count < 2
    },
  })
}

export function useSessionReferences(ids: string[]): UseQueryResult<SessionReference[]> {
  return useQuery({
    queryKey: ['session-references', ids],
    queryFn: () => services.sessions.getReferences(ids),
    enabled: ids.length > 0,
    staleTime: 5 * 60_000,
  })
}

export function useSessionFacets(): UseQueryResult<SessionFacets> {
  return useQuery({
    queryKey: queryKeys.sessionFacets,
    queryFn: () => services.sessions.getFacets(),
    staleTime: 10 * 60_000,
  })
}

/* ------------------------------------------------------------------ */
/* Findings                                                             */
/* ------------------------------------------------------------------ */

export function useFindings(
  query: FindingQuery = {},
  options?: { enabled?: boolean },
): UseQueryResult<SecurityFinding[]> {
  return useQuery({
    queryKey: queryKeys.findings(query),
    queryFn: () => services.findings.query(query),
    staleTime: 15_000,
    enabled: options?.enabled,
  })
}

export function useFinding(id: string | undefined): UseQueryResult<SecurityFinding> {
  return useQuery({
    queryKey: queryKeys.finding(id ?? 'none'),
    queryFn: () => services.findings.getById(id ?? ''),
    enabled: Boolean(id),
  })
}

export function useFindingSummary(query: FindingQuery = {}): UseQueryResult<FindingSummary> {
  return useQuery({
    queryKey: queryKeys.findingSummary(query),
    queryFn: () => services.findings.getSummary(query),
    staleTime: 15_000,
  })
}

export function useThreatMatrix(): UseQueryResult<ThreatMatrix> {
  return useQuery({
    queryKey: queryKeys.threatMatrix,
    queryFn: () => services.findings.getThreatMatrix(),
    staleTime: 30_000,
  })
}

export function useSetFindingStatus(): UseMutationResult<SecurityFinding, Error, {
  id: string
  status: FindingStatus
  note?: string
}> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, status, note }: { id: string; status: FindingStatus; note?: string }) =>
      services.findings.setStatus(id, status, note),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['findings'] })
      void client.invalidateQueries({ queryKey: ['finding-summary'] })
      void client.invalidateQueries({ queryKey: ['finding'] })
      void client.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
}

/* ------------------------------------------------------------------ */
/* Traffic                                                              */
/* ------------------------------------------------------------------ */

export function useTrafficOverview(): UseQueryResult<TrafficOverview> {
  const REFRESH = useRefreshIntervalMs()
  return useQuery({
    queryKey: queryKeys.traffic,
    queryFn: () => services.traffic.getOverview(),
    refetchInterval: REFRESH,
    staleTime: REFRESH / 2,
  })
}

export function useClassifications(): UseQueryResult<TrafficClassification[]> {
  const REFRESH = useRefreshIntervalMs()
  return useQuery({
    queryKey: queryKeys.classifications,
    queryFn: () => services.traffic.getClassifications(),
    refetchInterval: REFRESH,
    staleTime: REFRESH,
  })
}

/* ------------------------------------------------------------------ */
/* Experiments                                                          */
/* ------------------------------------------------------------------ */

export function useExperiments(
  query: ExperimentQuery = {},
  options?: { enabled?: boolean },
): UseQueryResult<ExperimentPage> {
  return useQuery({
    queryKey: queryKeys.experiments(query),
    queryFn: () => services.experiments.query(query),
    refetchInterval: 10_000,
    enabled: options?.enabled,
  })
}

export function useExperimentDetail(id: string | undefined): UseQueryResult<ExperimentDetail> {
  return useQuery({
    queryKey: queryKeys.experiment(id ?? 'none'),
    queryFn: () => services.experiments.getById(id ?? ''),
    enabled: Boolean(id),
    refetchInterval: 5_000,
  })
}

export function useCreateExperiment(): UseMutationResult<Experiment, Error, ExperimentRequest> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (request: ExperimentRequest) => services.experiments.create(request),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['experiments'] })
    },
  })
}

export function useCancelExperiment(): UseMutationResult<Experiment, Error, string> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => services.experiments.cancel(id),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['experiments'] })
      void client.invalidateQueries({ queryKey: ['experiment'] })
    },
  })
}

export function useDeleteExperiment(): UseMutationResult<void, Error, string> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => services.experiments.remove(id),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['experiments'] })
    },
  })
}

/** Pinned experiment ids for side-by-side comparison. */
export function useExperimentSelection(): {
  selection: string[]
  setSelection: (ids: string[]) => void
} {
  const client = useQueryClient()
  const query = useQuery({
    queryKey: queryKeys.experimentSelection,
    queryFn: () => services.experiments.getSelection(),
    staleTime: Infinity,
  })
  const setSelection = useCallback(
    (ids: string[]) => {
      // Optimistic: selection is a view preference, not analysis data.
      client.setQueryData(queryKeys.experimentSelection, ids)
      void services.experiments.setSelection(ids)
    },
    [client],
  )
  return { selection: query.data ?? [], setSelection }
}

/* ------------------------------------------------------------------ */
/* Reports                                                              */
/* ------------------------------------------------------------------ */

export function useReports(): UseQueryResult<Report[]> {
  return useQuery({
    queryKey: queryKeys.reports,
    queryFn: () => services.reports.list(),
    refetchInterval: 5_000,
  })
}

export function useReport(id: string | undefined): UseQueryResult<Report> {
  return useQuery({
    queryKey: queryKeys.report(id ?? 'none'),
    queryFn: () => services.reports.getById(id ?? ''),
    enabled: Boolean(id),
    refetchInterval: 5_000,
  })
}

export function useReportPreview(id: string | undefined): UseQueryResult<ReportPreview> {
  return useQuery({
    queryKey: queryKeys.reportPreview(id ?? 'none'),
    queryFn: () => services.reports.getPreview(id ?? ''),
    enabled: Boolean(id),
  })
}

export function useCreateReport(): UseMutationResult<Report, Error, ReportRequest> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (request: ReportRequest) => services.reports.create(request),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.reports })
    },
  })
}

export function useDeleteReport(): UseMutationResult<void, Error, string> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => services.reports.remove(id),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: queryKeys.reports })
    },
  })
}

/* ------------------------------------------------------------------ */
/* Dataset                                                              */
/* ------------------------------------------------------------------ */

export function useDataset(
  query: DatasetQuery = {},
  options?: { enabled?: boolean },
): UseQueryResult<DatasetPage> {
  return useQuery({
    queryKey: queryKeys.dataset(query),
    queryFn: () => services.dataset.query(query),
    staleTime: 15_000,
    enabled: options?.enabled,
  })
}

export function useDatasetStats(): UseQueryResult<DatasetStats> {
  return useQuery({
    queryKey: queryKeys.datasetStats,
    queryFn: () => services.dataset.getStats(),
    staleTime: 60_000,
  })
}

export function useCaptureMetadata(id: string | undefined): UseQueryResult<CaptureMetadata> {
  return useQuery({
    queryKey: queryKeys.captureMetadata(id ?? 'none'),
    queryFn: () => services.dataset.getMetadata(id ?? ''),
    enabled: Boolean(id),
  })
}

export function useUploadCapture(): UseMutationResult<
  CaptureRecord,
  Error,
  { file: File; options: CaptureUploadOptions }
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ file, options }: { file: File; options: CaptureUploadOptions }) =>
      services.dataset.upload(file, options),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['dataset'] })
      void client.invalidateQueries({ queryKey: queryKeys.datasetStats })
    },
  })
}

export function useDeleteCapture(): UseMutationResult<void, Error, string> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => services.dataset.remove(id),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['dataset'] })
      void client.invalidateQueries({ queryKey: queryKeys.datasetStats })
    },
  })
}

/* ------------------------------------------------------------------ */
/* System health                                                        */
/* ------------------------------------------------------------------ */

export function useSystemHealth(): UseQueryResult<SystemHealth> {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: () => services.health.getHealth(),
    refetchInterval: 15_000,
    staleTime: 10_000,
  })
}

/* ------------------------------------------------------------------ */
/* Tunnels                                                              */
/* ------------------------------------------------------------------ */

/** Recent tunnel investigations, newest activity first. */
export function useRecentTunnels(limit = 6): UseQueryResult<TunnelIdentity[]> {
  return useQuery({
    queryKey: queryKeys.tunnels(limit),
    queryFn: () => services.tunnel.listRecent(limit),
    staleTime: 20_000,
  })
}

/** One tunnel: identity plus its reconstructed lifecycle. */
export function useTunnel(sessionId: string | undefined): UseQueryResult<TunnelIdentity> {
  return useQuery({
    queryKey: queryKeys.tunnel(sessionId ?? ''),
    queryFn: () => services.tunnel.getIdentity(sessionId as string),
    enabled: Boolean(sessionId),
    staleTime: 20_000,
  })
}

/** The chain of reasoning behind a tunnel's conclusions. */
export function useEvidenceSpine(sessionId: string | undefined): UseQueryResult<TunnelSpineStep[]> {
  return useQuery({
    queryKey: queryKeys.evidenceSpine(sessionId ?? ''),
    queryFn: () => services.tunnel.getEvidenceSpine(sessionId as string),
    enabled: Boolean(sessionId),
    staleTime: 20_000,
  })
}

/* ------------------------------------------------------------------ */
/* Command center                                                       */
/* ------------------------------------------------------------------ */

export function useHomeSummary(): UseQueryResult<HomeSummary> {
  return useQuery({
    queryKey: queryKeys.home,
    queryFn: () => services.home.getSummary(),
    staleTime: 30_000,
  })
}
