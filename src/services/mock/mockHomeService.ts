import type { HomeCapability, HomeSummary } from '../../types/home'
import type { HomeService } from '../api/homeService'
import { latency } from './mockSupport'

/**
 * Welcome-screen data.
 *
 * Derived from the same mock dataset the rest of the platform reads, so the
 * launchpad can never disagree with the page that owns a number. The tunnel
 * list on this screen is served separately by the tunnel service, which is the
 * only place a tunnel is reconstructed.
 */

/** Protocols the dissector decodes, with the standard each is defined in. */
const PROTOCOLS: HomeSummary['protocols'] = [
  { label: 'IKEv2', rfc: 'RFC 7296', description: 'Key exchange and SA negotiation' },
  { label: 'ESP', rfc: 'RFC 4303', description: 'Encrypted payload with integrity' },
  { label: 'AH', rfc: 'RFC 4302', description: 'Authentication header, no encryption' },
]

/**
 * Availability of what this build can actually do.
 *
 * The backend is reported as not connected because it is not connected: there is
 * no REST or WebSocket endpoint wired into the composition root yet. Everything
 * else is genuinely usable in the browser, which is why it reads as ready rather
 * than as a feature promise.
 */
const CAPABILITIES: HomeCapability[] = [
  {
    id: 'frontend',
    label: 'Frontend',
    state: 'operational',
    detail: 'Static assets; no server state',
  },
  {
    id: 'mock-capture',
    label: 'Mock Capture',
    state: 'ready',
    detail: 'Simulated packet stream; no interface is touched',
  },
  {
    id: 'packet-analyzer',
    label: 'Packet Analyzer',
    state: 'ready',
    detail: 'In-browser IKEv2, ESP and AH dissection',
  },
  {
    id: 'ai-assistant',
    label: 'AI Assistant',
    state: 'ready',
    detail: 'Deterministic local responses; no model is called',
  },
  {
    id: 'backend',
    label: 'Backend',
    state: 'offline',
    detail: 'No REST or WebSocket endpoint is configured',
  },
]

export class MockHomeService implements HomeService {
  async getSummary(): Promise<HomeSummary> {
    return latency(
      {
        capabilities: CAPABILITIES,
        protocols: PROTOCOLS,
        generatedAt: new Date().toISOString(),
        mockMode: true,
      },
      90,
    )
  }
}
