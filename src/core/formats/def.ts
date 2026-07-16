import type { ParseResult } from '../region'

export interface FormatDef {
  id: string
  /** Human-readable name, e.g. "PNG image". */
  name: string
  mime?: string
  detect(bytes: Uint8Array): boolean
  parse(bytes: Uint8Array): ParseResult
}

/** True when `bytes` starts with `sig` at `offset`. */
export function startsWith(bytes: Uint8Array, sig: number[], offset = 0): boolean {
  if (bytes.length < offset + sig.length) return false
  for (let i = 0; i < sig.length; i++) {
    if (bytes[offset + i] !== sig[i]) return false
  }
  return true
}

export function sigOf(text: string): number[] {
  return [...text].map((c) => c.charCodeAt(0))
}
