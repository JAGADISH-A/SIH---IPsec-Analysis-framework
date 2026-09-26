/**
 * Welcome-screen view model.
 *
 * One service call returns what `/` needs to know about itself: the
 * availability of each capability and the protocols the dissector speaks. The
 * tunnel list on the same screen is a separate read, because a tunnel is a
 * reconstructed investigation owned by the tunnel service rather than a
 * property of the welcome screen. Swapping the mock for a REST service changes
 * the implementation of one interface, never these shapes.
 */

/**
 * Availability of a welcome-screen capability.
 *
 * `offline` is a first-class state: the backend genuinely is not connected in
 * this build, and the welcome screen has to say so rather than imply readiness.
 */
export type HomeCapabilityState = 'operational' | 'ready' | 'offline'

export const HOME_STATE_LABEL: Record<HomeCapabilityState, string> = {
  operational: 'Operational',
  ready: 'Ready',
  offline: 'Not Connected',
}

export type HomeCapabilityId =
  | 'frontend'
  | 'mock-capture'
  | 'packet-analyzer'
  | 'ai-assistant'
  | 'backend'

export interface HomeCapability {
  id: HomeCapabilityId
  label: string
  state: HomeCapabilityState
  /** One short clause explaining what the state means for this dependency. */
  detail: string
}

/** A protocol the dissector decodes, with the standard it is defined in. */
export interface HomeProtocol {
  label: 'IKEv2' | 'ESP' | 'AH'
  rfc: string
  description: string
}

export interface HomeSummary {
  capabilities: HomeCapability[]
  protocols: HomeProtocol[]
  generatedAt: string
  /** True while every figure above comes from simulated services. */
  mockMode: boolean
}
