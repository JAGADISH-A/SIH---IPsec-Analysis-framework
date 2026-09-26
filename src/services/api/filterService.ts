import type { Packet } from '../../types/packet'

export interface FilterValidation {
  ok: boolean
  error?: string
}

/**
 * Evaluates packet-filter expressions.
 *
 * The frontend mock implementation understands a small Wireshark-inspired
 * subset today (ip.src / ip.dst / ip.addr / protocol / risk, bare protocol
 * tokens, `&&` and `||`). A real backend filter engine or a full Wireshark
 * parser can replace it behind this interface later without changing the UI.
 */
export interface FilterService {
  /** Whether `packet` satisfies `expression`. Empty/null → matches everything. */
  matches(packet: Packet, expression: string | null): boolean
  /** Static validation so the UI can surface inline errors before applying. */
  validate(expression: string): FilterValidation
}