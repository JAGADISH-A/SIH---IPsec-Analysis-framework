import type { Packet } from '../../types/packet'
import type { RiskLevel } from '../../types/security'
import type { FilterService, FilterValidation } from '../api/filterService'

/* ------------------------------------------------------------------ */
/* Supported mini-grammar. Replaced by a backend filter engine later.  */
/* ------------------------------------------------------------------ */

/** Bare-token protocols (`esp`, `ikev2`, `ah`, ...). */
const KNOWN_PROTOCOLS = new Set(['ikev2', 'esp', 'ah', 'tcp', 'udp', 'icmp', 'dns', 'tls', 'http'])

/** Severity ordering: lower index = more severe. */
const RISK_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

const RISK_LEVELS = new Set(['critical', 'high', 'medium', 'low', 'info', 'none'])

/** Fields that compare with `==`/`!=` as strings. */
const STRING_FIELDS = new Set(['ip.src', 'ip.dst', 'ip.addr', 'protocol'])

/** `ip.addr` matches source OR destination; `!=` matches neither. */
const ADDR_FIELDS = new Set(['ip.addr'])

const FIELD_RE = /^(ip\.src|ip\.dst|ip\.addr|protocol|risk|len|length)\s*(==|!=|>=|<=|>|<)\s*(.+)$/i

function compareString(actual: string, op: string, expected: string): boolean {
  const a = actual.toLowerCase()
  const e = expected.toLowerCase()
  if (op === '==') return a === e
  if (op === '!=') return a !== e
  return false
}

function compareNumber(actual: number, op: string, expected: string): boolean {
  const e = Number(expected)
  switch (op) {
    case '==':
      return actual === e
    case '!=':
      return actual !== e
    case '>':
      return actual > e
    case '>=':
      return actual >= e
    case '<':
      return actual < e
    case '<=':
      return actual <= e
    default:
      return false
  }
}

function compareRisk(actual: RiskLevel | null, op: string, expected: string): boolean {
  const e = expected.toLowerCase()
  if (op === '==') return (actual ?? 'none').toLowerCase() === e
  if (op === '!=') return (actual ?? 'none').toLowerCase() !== e
  const expectedOrder = RISK_ORDER[e]
  if (expectedOrder === undefined || actual === null) return false
  const actualOrder = RISK_ORDER[actual]
  switch (op) {
    case '>':
      return actualOrder < expectedOrder
    case '>=':
      return actualOrder <= expectedOrder
    case '<':
      return actualOrder > expectedOrder
    case '<=':
      return actualOrder >= expectedOrder
    default:
      return false
  }
}

const COMPARABLE_NOTE =
  'Supported: esp, ikev2, ah (or other protocols); ip.src / ip.dst / ip.addr == <address>; protocol == <name>; risk == <critical|high|medium|low|info>; len > <bytes>.'

/**
 * Frontend-only filter engine evaluated against the mock packet dataset.
 * Deliberately small subset of the Wireshark display-filter syntax.
 */
export class MockFilterService implements FilterService {
  matches(packet: Packet, expression: string | null): boolean {
    if (expression == null) return true
    const expr = expression.trim()
    if (!expr) return true
    try {
      return expr
        .split(/\s*\|\|\s*/)
        .some((group) => group.split(/\s*&&\s*/).every((atom) => this.matchAtom(packet, atom.trim())))
    } catch {
      return false
    }
  }

  validate(expression: string): FilterValidation {
    const expr = expression.trim()
    if (!expr) return { ok: true }
    const atoms = expr.split(/\s*&&\s*|\s*\|\|\s*/)
    for (const atom of atoms) {
      if (!atom.trim()) continue
      const error = this.validateAtom(atom.trim())
      if (error) return { ok: false, error }
    }
    return { ok: true }
  }

  private validateAtom(atom: string): string | null {
    const match = atom.match(FIELD_RE)
    if (!match) {
      const token = atom.toLowerCase()
      if (token === 'ipsec' || KNOWN_PROTOCOLS.has(token)) return null
      return `Unsupported token "${atom}". ${COMPARABLE_NOTE}`
    }
    const [, rawField, op, rawValue] = match
    const field = rawField.toLowerCase()
    const value = rawValue.trim()
    if (!value) return `Missing value after "${op}".`
    if (STRING_FIELDS.has(field)) {
      if (op !== '==' && op !== '!=') return `Operator "${op}" is not supported for "${field}".`
      return null
    }
    if (field === 'risk') {
      if (!RISK_LEVELS.has(value.toLowerCase())) {
        return `Unknown risk level "${value}". Use critical, high, medium, low or info (or none).`
      }
      return null
    }
    // len / length
    if (Number.isNaN(Number(value))) return `"${field}" expects a byte count, got "${value}".`
    return null
  }

  private matchAtom(packet: Packet, atom: string): boolean {
    if (!atom) return true
    const match = atom.match(FIELD_RE)
    if (match) {
      const [, rawField, op, rawValue] = match
      return this.matchField(packet, rawField.toLowerCase(), op, rawValue.trim())
    }
    const token = atom.toLowerCase()
    if (token === 'ipsec') {
      return packet.protocol === 'IKEv2' || packet.protocol === 'ESP' || packet.protocol === 'AH'
    }
    return packet.protocol.toLowerCase() === token
  }

  private matchField(packet: Packet, field: string, op: string, value: string): boolean {
    if (ADDR_FIELDS.has(field)) {
      const left = packet.source.toLowerCase() === value.toLowerCase()
      const right = packet.destination.toLowerCase() === value.toLowerCase()
      if (op === '!=') return !left && !right
      return left || right
    }
    if (STRING_FIELDS.has(field)) {
      const actual =
        field === 'ip.src'
          ? packet.source
          : field === 'ip.dst'
            ? packet.destination
            : packet.protocol
      return compareString(actual, op, value)
    }
    if (field === 'risk') return compareRisk(packet.risk, op, value)
    if (field === 'len' || field === 'length') return compareNumber(packet.length, op, value)
    return false
  }
}