import type { TunnelIdentity, TunnelSpineStep } from '../../types/identity'

/**
 * Tunnel investigation reads.
 *
 * The tunnel is the unit of investigation in IPsec Sentinel: captures hold
 * packets, packets belong to tunnels, and every finding, risk score and
 * confidence estimate is stated about a tunnel. This contract is deliberately
 * small — identity, reconstructed lifecycle, and the reasoning chain — because
 * a real backend will serve it as one aggregate read per tunnel and a short
 * index read for the list views.
 */
export interface TunnelService {
  /** Most recently active tunnels, newest activity first. */
  listRecent(limit?: number): Promise<TunnelIdentity[]>
  /** Full identity of one tunnel, including its reconstructed DNA. */
  getIdentity(sessionId: string): Promise<TunnelIdentity>
  /** The chain of reasoning behind a tunnel's conclusions. */
  getEvidenceSpine(sessionId: string): Promise<TunnelSpineStep[]>
}
