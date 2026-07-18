/**
 * Cryptographically secure random digit strings — the kind that end up in
 * .env files as API keys and HMAC secrets. Pure logic, no DOM: the page hands
 * it window.crypto, the tests hand it a scripted byte source.
 */

/** Returns n fresh random bytes. Injectable so tests can script exact bytes. */
export type ByteSource = (n: number) => Uint8Array

const cryptoSource: ByteSource = (n) => crypto.getRandomValues(new Uint8Array(n))

/** Digit alphabets by radix (hex lowercase — display code can uppercase). */
export const ALPHABETS = {
  2: '01',
  10: '0123456789',
  16: '0123456789abcdef',
} as const

export type Radix = keyof typeof ALPHABETS

export const MAX_LENGTH = 65536

/**
 * Uniform random string of `length` characters drawn from `alphabet`.
 *
 * Uses rejection sampling: with k symbols, only byte values below
 * floor(256/k)*k are used and the rest are thrown away. Mapping every byte
 * through `% k` would be simpler but biased — for k=10, digits 0–5 would each
 * arrive 26/256 of the time and 6–9 only 25/256. Powers of two (k=2, 16)
 * divide 256 evenly, so nothing is ever rejected there.
 */
export function randomString(alphabet: string, length: number, source: ByteSource = cryptoSource): string {
  const k = alphabet.length
  if (k < 2 || k > 256) throw new Error('alphabet must have 2–256 symbols')
  if (!Number.isInteger(length) || length < 1 || length > MAX_LENGTH) {
    throw new Error(`length must be an integer between 1 and ${MAX_LENGTH}`)
  }
  const limit = 256 - (256 % k)
  const out: string[] = []
  while (out.length < length) {
    const batch = source(Math.max(32, length - out.length))
    if (batch.length === 0) throw new Error('byte source returned no bytes')
    for (const byte of batch) {
      if (byte >= limit) continue
      out.push(alphabet[byte % k])
      if (out.length === length) break
    }
  }
  return out.join('')
}

/** Bits of entropy in `length` characters drawn uniformly from `k` symbols. */
export function entropyBits(k: number, length: number): number {
  return length * Math.log2(k)
}

/** Characters from a k-symbol alphabet needed to reach at least `bits` of entropy. */
export function charsForBits(k: number, bits: number): number {
  return Math.ceil(bits / Math.log2(k))
}

/** Insert `sep` every `size` characters: group('deadbeef', 4) → 'dead beef'. */
export function group(s: string, size: number, sep = ' '): string {
  if (size <= 0 || s.length <= size) return s
  const parts: string[] = []
  for (let i = 0; i < s.length; i += size) parts.push(s.slice(i, i + size))
  return parts.join(sep)
}

const UNIVERSE_AGE_YEARS = 1.38e10

/**
 * How long a full sweep of a `bits`-entropy keyspace takes at a trillion
 * guesses per second, as a human phrase. Computed in log space — 2^256 has no
 * business inside a double as a plain number.
 */
export function sweepTime(bits: number): string {
  const log10Seconds = bits * Math.log10(2) - 12
  if (log10Seconds < 0) return 'under a second'
  const seconds = Math.pow(10, log10Seconds)
  if (seconds < 60) return `about ${Math.max(1, Math.round(seconds))} seconds`
  if (seconds < 3600) return `about ${Math.round(seconds / 60)} minutes`
  if (seconds < 86400) return `about ${Math.round(seconds / 3600)} hours`
  const years = seconds / 31557600
  if (years < 1) return `about ${Math.round(seconds / 86400)} days`
  if (years < 1e6) return `about ${Math.round(years).toLocaleString('en-US')} years`
  const log10Universes = log10Seconds - Math.log10(31557600) - Math.log10(UNIVERSE_AGE_YEARS)
  if (log10Universes < 1) return `about 10^${Math.round(log10Seconds - Math.log10(31557600))} years`
  return `about 10^${Math.round(log10Universes)} × the age of the universe`
}
