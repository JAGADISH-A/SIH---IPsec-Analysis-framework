import { ErrorPanel, LoadingPanel } from '../../components/common/QueryState'
import { useHomeSummary } from '../../hooks/queries'
import { AnalyzerWelcome } from './AnalyzerWelcome'

/**
 * `/` — the analyzer welcome screen.
 *
 * One question, one screen: what do you want to analyze? It offers a live
 * capture, a PCAP file, the recent capture list and the analysis workspaces, and
 * explains nothing else — no hero, no marketing sections, no packet table, no
 * charts, because those belong to the analysis pages.
 *
 * The capture and file actions are not part of this data contract: they drive
 * the application-wide capture session and the `DatasetService` ingest path, so
 * they keep working when the composition root is pointed at a backend. The
 * summary read here — recent captures, capabilities, protocols — comes through
 * `useHomeSummary` → the service composition root, in one call.
 */
export function HomePage() {
  const summary = useHomeSummary()

  if (summary.isError) {
    return (
      <div className="flex h-full items-start justify-center overflow-y-auto p-4">
        <ErrorPanel
          className="w-full max-w-lg"
          error={summary.error}
          onRetry={() => void summary.refetch()}
          title="Could not load the welcome screen"
        />
      </div>
    )
  }

  if (!summary.data) {
    return (
      <div className="h-full overflow-hidden">
        <LoadingPanel label="Loading the analyzer welcome screen" rows={5} />
      </div>
    )
  }

  return <AnalyzerWelcome summary={summary.data} />
}
