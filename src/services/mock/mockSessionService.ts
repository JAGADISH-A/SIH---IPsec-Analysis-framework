import type { SessionFacets, SessionService } from '../api/sessionService'
import type {
  SessionDetail,
  SessionPage,
  SessionQuery,
  SessionReference,
  SessionSortKey,
  VpnSession,
} from '../../types/session'
import { mockDataset } from './mockData'
import {
  atLeast,
  inFilter,
  latency,
  matchesSearch,
  notFound,
  paginate,
  withinRange,
} from './mockSupport'

function applyQuery(sessions: VpnSession[], query: SessionQuery): VpnSession[] {
  const filtered = sessions.filter((session) => {
    const config = session.configuration
    return (
      matchesSearch(
        query.search,
        session.id,
        session.label,
        session.initiator.address,
        session.responder.address,
        session.testbed,
        config.encryption.value,
        config.dhGroup.value,
      ) &&
      inFilter(session.status, query.statuses) &&
      inFilter(config.vpnMode.value, query.modes) &&
      inFilter(config.ikeVersion.value, query.ikeVersions) &&
      inFilter(config.ipVersion.value, query.ipVersions) &&
      inFilter(session.riskBand, query.riskBands) &&
      inFilter(session.environment, query.environments) &&
      inFilter(config.encryption.value, query.encryption) &&
      atLeast(session.confidence, query.minConfidence) &&
      withinRange(session.startedAt, query.from, query.to)
    )
  })

  return sortSessions(filtered, query.sort, query.direction)
}

function sortSessions(
  sessions: VpnSession[],
  sort: SessionSortKey = 'riskScore',
  direction: 'asc' | 'desc' = 'desc',
): VpnSession[] {
  const factor = direction === 'asc' ? 1 : -1
  const value = (session: VpnSession): number | string => {
    const config = session.configuration
    switch (sort) {
      case 'ikeVersion':
        return config.ikeVersion.value ?? ''
      case 'mode':
        return config.vpnMode.value ?? ''
      case 'encryption':
        return config.encryption.value ?? ''
      case 'riskScore':
        return session.riskScore
      case 'confidence':
        return session.confidence ?? -1
      case 'status':
        return session.status
      case 'createdAt':
        return session.startedAt
      case 'id':
      default:
        return session.id
    }
  }
  return [...sessions].sort((a, b) => {
    const left = value(a)
    const right = value(b)
    if (typeof left === 'string' || typeof right === 'string') {
      return String(left).localeCompare(String(right)) * factor
    }
    return (left - right) * factor
  })
}

export class MockSessionService implements SessionService {
  async query(query: SessionQuery = {}): Promise<SessionPage> {
    const matched = applyQuery(mockDataset.sessions, query)
    const page = paginate(matched, query.page, query.pageSize)
    return latency({ items: page.items, total: page.total, page: page.page, pageSize: page.pageSize }, 140)
  }

  async getDetail(id: string): Promise<SessionDetail> {
    const detail = mockDataset.sessionDetail(id)
    if (!detail) throw notFound('VPN session', id)
    return latency(detail, 150)
  }

  async getReferences(ids: string[]): Promise<SessionReference[]> {
    const wanted = new Set(ids)
    return latency(
      mockDataset.sessions
        .filter((session) => wanted.has(session.id))
        .map((session) => ({ id: session.id, label: session.label, riskBand: session.riskBand })),
      60,
    )
  }

  async getFacets(): Promise<SessionFacets> {
    const distinct = (values: (string | undefined)[]): string[] =>
      [...new Set(values.filter((value): value is string => Boolean(value)))].sort((a, b) =>
        a.localeCompare(b),
      )

    return latency(
      {
        encryption: distinct(
          mockDataset.sessions.map((session) => session.configuration.encryption.value ?? undefined),
        ),
        dhGroups: distinct(
          mockDataset.sessions.map((session) => session.configuration.dhGroup.value ?? undefined),
        ),
        environments: distinct(mockDataset.sessions.map((session) => session.environment)),
        testbeds: distinct(mockDataset.sessions.map((session) => session.testbed)),
      },
      60,
    )
  }
}
