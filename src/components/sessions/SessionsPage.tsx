import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Search } from 'lucide-react'
import { Badge } from '../../components/common/Badge.tsx'
import { ConfidenceTag } from '../../components/common/Evidence.tsx'
import { Field } from '../../components/common/Field.tsx'
import { Select } from '../../components/common/Select.tsx'
import { DataTable, type ColumnDef } from '../../components/common/Table.tsx'
import { Pagination, Toolbar } from '../../components/common/Data.tsx'
import { PageHeader, PageScroll } from '../../components/common/PageHeader.tsx'
import { QueryBoundary } from '../../components/common/QueryState.tsx'
import { useSessionFacets, useSessions } from '../../hooks/queries'
import { ENVIRONMENT_LABEL, SESSION_STATUS_LABEL, SESSION_STATUSES } from '../../types/session'
import type { SessionQuery, SessionSortKey, VpnSession } from '../../types/session'
import { RISK_TONE, RiskTag } from './sessionBits.tsx'

/**
 * VPN sessions register.
 *
 * Filters live in the URL so an operator can share a filtered view, and the
 * table is sortable on the columns that drive triage: risk, confidence and
 * recency.
 */
export function SessionsPage() {
  const [params, setParams] = useSearchParams()
  const [searchDraft, setSearchDraft] = useState(params.get('search') ?? '')

  const query = useMemo<SessionQuery>(() => {
    const list = (key: string): string[] => {
      const raw = params.get(key)
      return raw ? raw.split(',').filter(Boolean) : []
    }
    return {
      search: params.get('search') ?? undefined,
      statuses: list('status') as SessionQuery['statuses'],
      modes: list('mode') as SessionQuery['modes'],
      riskBands: list('risk') as SessionQuery['riskBands'],
      environments: list('environment') as SessionQuery['environments'],
      minConfidence: params.get('minConfidence') ? Number(params.get('minConfidence')) : undefined,
      sort: (params.get('sort') as SessionSortKey | null) ?? 'riskScore',
      direction: params.get('direction') === 'asc' ? 'asc' : 'desc',
      page: Number(params.get('page') ?? '1'),
      pageSize: Number(params.get('pageSize') ?? '25'),
    }
  }, [params])

  const sessions = useSessions(query)
  const facets = useSessionFacets()

  const setParam = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    if (value === null || value === '') next.delete(key)
    else next.set(key, value)
    if (key !== 'page') next.delete('page')
    setParams(next, { replace: true })
  }

  const applySearch = () => setParam('search', searchDraft.trim() || null)

  const rows = sessions.data?.items ?? []
  const total = sessions.data?.total ?? 0

  const columns = useMemo<ColumnDef<VpnSession>[]>(
    () => [
      {
        id: 'label',
        header: 'Session',
        render: (row) => (
          <div className="min-w-0">
            <Link to={`/vpn-sessions/${row.id}`} className="block truncate font-medium text-mist hover:text-accent-300">
              {row.label}
            </Link>
            <span className="font-mono text-[11px] text-mist-faint">
              {row.initiator.address} → {row.responder.address}
            </span>
          </div>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        width: '7rem',
        render: (row) => (
          <Badge
            tone={
              row.status === 'active'
                ? 'success'
                : row.status === 'rekeying'
                  ? 'info'
                  : row.status === 'failed'
                    ? 'danger'
                    : 'muted'
            }
            dot
          >
            {SESSION_STATUS_LABEL[row.status]}
          </Badge>
        ),
      },
      {
        id: 'ike',
        header: 'IKE',
        width: '6rem',
        render: (row) => <span className="font-mono text-xs text-mist-dim">{row.configuration.ikeVersion.value ?? '—'}</span>,
      },
      {
        id: 'mode',
        header: 'Mode',
        width: '6rem',
        render: (row) => <span className="font-mono text-xs text-mist-dim">{row.configuration.vpnMode.value ?? '—'}</span>,
      },
      {
        id: 'encryption',
        header: 'Encryption',
        width: '11rem',
        render: (row) => (
          <span className="font-mono text-xs text-mist-dim">{row.configuration.encryption.value ?? 'Unknown'}</span>
        ),
      },
      {
        id: 'risk',
        header: 'Risk',
        width: '6rem',
        render: (row) => <RiskTag band={row.riskBand} score={row.riskScore} />,
      },
      {
        id: 'findings',
        header: 'Findings',
        width: '10rem',
        render: (row) => <FindingCounts counts={row.findingCounts} />,
      },
      {
        id: 'confidence',
        header: 'Confidence',
        width: '7rem',
        render: (row) => <ConfidenceTag confidence={row.confidence} />,
      },
      {
        id: 'environment',
        header: 'Environment',
        width: '8rem',
        render: (row) => <span className="text-xs text-mist-dim">{ENVIRONMENT_LABEL[row.environment]}</span>,
      },
      {
        id: 'started',
        header: 'Started',
        width: '10rem',
        align: 'right',
        render: (row) => (
          <span className="font-mono text-[11px] text-mist-faint">{new Date(row.startedAt).toLocaleString()}</span>
        ),
      },
    ],
    [],
  )

  return (
    <PageScroll>
      <PageHeader
        title="VPN Sessions"
        description="Every analysed IPsec session with its negotiated configuration, risk band and finding counts."
        meta={
          <>
            <span className="font-mono">{total} session(s)</span>
            {sessions.dataUpdatedAt ? <span>Updated {new Date(sessions.dataUpdatedAt).toLocaleTimeString()}</span> : null}
          </>
        }
        actions={
          <Link to="/live-monitor?view=analyzer" className="btn">
            Open packet analyzer
          </Link>
        }
      />

      <Toolbar
        trailing={
          sessions.isFetching ? <span className="text-accent-300">Refreshing…</span> : undefined
        }
      >
        <form
          className="flex items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            applySearch()
          }}
        >
          <Field
            label="Search"
            placeholder="Label, address, testbed…"
            value={searchDraft}
            onChange={(event) => setSearchDraft(event.target.value)}
            leading={<Search className="size-3.5" aria-hidden />}
            className="w-56"
          />
          <button type="submit" className="btn h-[34px]">
            Search
          </button>
        </form>

        <Select
          label="Status"
          value={params.get('status') ?? ''}
          onChange={(event) => setParam('status', event.target.value || null)}
          className="w-36"
        >
          <option value="">All</option>
          {SESSION_STATUSES.map((status) => (
            <option key={status} value={status}>
              {SESSION_STATUS_LABEL[status]}
            </option>
          ))}
        </Select>

        <Select
          label="Risk band"
          value={params.get('risk') ?? ''}
          onChange={(event) => setParam('risk', event.target.value || null)}
          className="w-36"
        >
          <option value="">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </Select>

        <Select
          label="Environment"
          value={params.get('environment') ?? ''}
          onChange={(event) => setParam('environment', event.target.value || null)}
          className="w-40"
        >
          <option value="">All</option>
          {facets.data?.environments.map((environment) => (
            <option key={environment} value={environment}>
              {ENVIRONMENT_LABEL[environment as VpnSession['environment']] ?? environment}
            </option>
          ))}
        </Select>

        <Select
          label="Min confidence"
          value={params.get('minConfidence') ?? ''}
          onChange={(event) => setParam('minConfidence', event.target.value || null)}
          className="w-32"
        >
          <option value="">Any</option>
          <option value="0.9">90%+</option>
          <option value="0.75">75%+</option>
          <option value="0.5">50%+</option>
        </Select>

        <Select
          label="Sort"
          value={`${query.sort ?? 'riskScore'}:${query.direction ?? 'desc'}`}
          onChange={(event) => {
            const [sort, direction] = event.target.value.split(':')
            setParam('sort', sort ?? null)
            setParam('direction', direction ?? null)
          }}
          className="w-44"
        >
          <option value="riskScore:desc">Risk — high to low</option>
          <option value="riskScore:asc">Risk — low to high</option>
          <option value="confidence:desc">Confidence — high to low</option>
          <option value="createdAt:desc">Newest first</option>
          <option value="createdAt:asc">Oldest first</option>
          <option value="id:asc">Session ID</option>
        </Select>
      </Toolbar>

      <QueryBoundary
        isLoading={sessions.isLoading}
        isError={sessions.isError}
        error={sessions.error}
        onRetry={() => void sessions.refetch()}
        isEmpty={rows.length === 0}
        emptyTitle="No sessions match these filters"
        emptyDescription="Widen the filters, or clear the search box to see the full register."
      >
        <DataTable columns={columns} rows={rows} rowKey={(row) => row.id} />
      </QueryBoundary>

      {rows.length > 0 ? (
        <Pagination
          page={sessions.data?.page ?? 1}
          pageSize={sessions.data?.pageSize ?? 25}
          total={total}
          label="sessions"
          onPageChange={(page) => setParam('page', String(page))}
          onPageSizeChange={(pageSize) => setParam('pageSize', String(pageSize))}
        />
      ) : null}
    </PageScroll>
  )
}

function FindingCounts({ counts }: { counts: VpnSession['findingCounts'] }) {
  const entries = (Object.entries(counts) as [keyof VpnSession['findingCounts'], number][]).filter(
    ([, value]) => value > 0,
  )
  if (entries.length === 0) {
    return <span className="text-[11px] text-mist-faint">None</span>
  }
  return (
    <span className="flex flex-wrap gap-1">
      {entries.map(([severity, value]) => (
        <Badge key={severity} tone={RISK_TONE[severity] ?? 'muted'} className="font-mono">
          {value} {severity.slice(0, 3)}
        </Badge>
      ))}
    </span>
  )
}
