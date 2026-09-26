import type { RiskLevel } from '../../types/security'
import type { PacketProtocolName } from '../../types/packet'

/* ------------------------------------------------------------------ */
/* Presentation metadata for the analyzer workspace: how a protocol or */
/* a risk level is painted on the light analysis surface.               */
/* ------------------------------------------------------------------ */

/** Protocol tag colours. IPsec protocols get a distinct hue; the rest stay grey. */
const PROTO_STYLE: Record<string, { color: string; background: string }> = {
  IKEv2: { color: 'var(--color-ws-ike)', background: 'var(--color-ws-ike-dim)' },
  ESP: { color: 'var(--color-ws-esp)', background: 'var(--color-ws-esp-dim)' },
  AH: { color: 'var(--color-ws-ah)', background: 'var(--color-ws-ah-dim)' },
}

const PROTO_FALLBACK = { color: 'var(--color-ws-dim)', background: 'var(--color-ws-none-dim)' }

export function protocolStyle(protocol: PacketProtocolName | string) {
  return PROTO_STYLE[protocol] ?? PROTO_FALLBACK
}

/** Risk badge colours — restrained, no neon. */
const RISK_STYLE: Record<RiskLevel | 'none', { color: string; background: string; label: string }> = {
  critical: {
    color: 'var(--color-ws-critical)',
    background: 'var(--color-ws-critical-dim)',
    label: 'Critical',
  },
  high: { color: 'var(--color-ws-high)', background: 'var(--color-ws-high-dim)', label: 'High' },
  medium: { color: 'var(--color-ws-medium)', background: 'var(--color-ws-medium-dim)', label: 'Medium' },
  low: { color: 'var(--color-ws-low)', background: 'var(--color-ws-low-dim)', label: 'Low' },
  info: { color: 'var(--color-ws-dim)', background: 'var(--color-ws-none-dim)', label: 'Info' },
  none: { color: 'var(--color-ws-faint)', background: 'var(--color-ws-none-dim)', label: 'None' },
}

export function riskStyle(severity: RiskLevel | 'none') {
  return RISK_STYLE[severity]
}

/** Left accent colour for a finding card, keyed by severity. */
const FINDING_EDGE: Record<RiskLevel, string> = {
  critical: 'var(--color-ws-critical)',
  high: 'var(--color-ws-high)',
  medium: 'var(--color-ws-medium)',
  low: 'var(--color-ws-low)',
  info: 'var(--color-ws-faint)',
}

export function findingEdge(severity: RiskLevel): string {
  return FINDING_EDGE[severity]
}
