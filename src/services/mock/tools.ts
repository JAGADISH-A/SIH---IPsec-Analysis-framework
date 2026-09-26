import type { Unsubscribe } from '../../types/common'

/** Deterministic PRNG so mock packet streams are reproducible per session. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export function pick<T>(rng: () => number, items: readonly T[]): T {
  return items[Math.floor(rng() * items.length)]
}

export function rangeInt(rng: () => number, min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1))
}

const HEX = '0123456789abcdef'

export function randomHex(rng: () => number, bytes: number): string {
  let out = ''
  for (let i = 0; i < bytes; i += 1) {
    out += HEX[Math.floor(rng() * 16)]
  }
  return out.toUpperCase()
}

export function generateId(prefix: string, nonce: number): string {
  return `${prefix}-${nonce.toString(36)}-${Math.abs(nonce * 2654435761).toString(36)}`
}

/** Minimal synchronous emitter used by every mock service. */
export class SimpleEmitter<T> {
  private listeners = new Set<(value: T) => void>()

  subscribe(listener: (value: T) => void): Unsubscribe {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  emit(value: T): void {
    for (const listener of [...this.listeners]) {
      listener(value)
    }
  }
}