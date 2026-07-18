import { describe, expect, it } from 'vitest'
import { ALPHABETS, charsForBits, entropyBits, group, MAX_LENGTH, randomString, sweepTime, type ByteSource } from '../src/core/random'

/** Byte source that replays a fixed script, then loops back to the start. */
function scripted(bytes: number[]): ByteSource {
  let i = 0
  return (n) => Uint8Array.from({ length: n }, () => bytes[i++ % bytes.length])
}

describe('randomString', () => {
  it('maps bytes onto the alphabet in order', () => {
    const src = scripted([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    expect(randomString(ALPHABETS[16], 16, src)).toBe('0123456789abcdef')
  })

  it('wraps bytes beyond the alphabet with modulo (within the unbiased range)', () => {
    // 16 % 10 = 6, 249 % 10 = 9 — both below the base-10 rejection limit of 250
    expect(randomString(ALPHABETS[10], 2, scripted([16, 249]))).toBe('69')
  })

  it('rejects bytes in the biased tail for base 10', () => {
    // 250–255 must be discarded, not mapped to 0–5
    const src = scripted([250, 251, 252, 253, 254, 255, 7, 8])
    expect(randomString(ALPHABETS[10], 2, src)).toBe('78')
  })

  it('never rejects for power-of-two alphabets', () => {
    // 255 is a valid draw for k=2 and k=16
    expect(randomString(ALPHABETS[2], 1, scripted([255]))).toBe('1')
    expect(randomString(ALPHABETS[16], 1, scripted([255]))).toBe('f')
  })

  it('refills across batches until the length is reached', () => {
    let calls = 0
    const tiny: ByteSource = (n) => {
      calls++
      return new Uint8Array(Math.min(4, n)).fill(1)
    }
    expect(randomString(ALPHABETS[2], 10, tiny)).toBe('1111111111')
    expect(calls).toBeGreaterThan(1)
  })

  it('uses the real CSPRNG by default and stays inside the alphabet', () => {
    for (const alphabet of [ALPHABETS[2], ALPHABETS[10], ALPHABETS[16]]) {
      const s = randomString(alphabet, 512)
      expect(s).toHaveLength(512)
      expect([...s].every((c) => alphabet.includes(c))).toBe(true)
    }
  })

  it('produces every symbol over a large sample', () => {
    const s = randomString(ALPHABETS[10], 10000)
    for (const digit of ALPHABETS[10]) expect(s).toContain(digit)
  })

  it('validates length and alphabet', () => {
    expect(() => randomString(ALPHABETS[16], 0)).toThrow()
    expect(() => randomString(ALPHABETS[16], 1.5)).toThrow()
    expect(() => randomString(ALPHABETS[16], MAX_LENGTH + 1)).toThrow()
    expect(() => randomString('x', 8)).toThrow()
    expect(randomString(ALPHABETS[16], MAX_LENGTH).length).toBe(MAX_LENGTH)
  })

  it('throws instead of spinning on an empty byte source', () => {
    expect(() => randomString(ALPHABETS[16], 8, () => new Uint8Array(0))).toThrow()
  })
})

describe('entropy math', () => {
  it('computes bits per string', () => {
    expect(entropyBits(16, 32)).toBe(128)
    expect(entropyBits(16, 64)).toBe(256)
    expect(entropyBits(2, 128)).toBe(128)
    expect(entropyBits(10, 6)).toBeCloseTo(19.93, 2)
  })

  it('computes chars needed for a bit target', () => {
    expect(charsForBits(16, 128)).toBe(32)
    expect(charsForBits(16, 256)).toBe(64)
    expect(charsForBits(2, 128)).toBe(128)
    expect(charsForBits(10, 128)).toBe(39) // 128 / log2(10) = 38.5 → 39 digits
  })
})

describe('group', () => {
  it('inserts a separator every n chars', () => {
    expect(group('deadbeef', 4)).toBe('dead beef')
    expect(group('deadbeefc0', 4)).toBe('dead beef c0')
    expect(group('deadbeef', 4, '-')).toBe('dead-beef')
  })
  it('leaves short strings and size 0 alone', () => {
    expect(group('dead', 4)).toBe('dead')
    expect(group('deadbeef', 0)).toBe('deadbeef')
  })
})

describe('sweepTime', () => {
  it('scales from instant to cosmological', () => {
    expect(sweepTime(8)).toBe('under a second')
    expect(sweepTime(64)).toContain('days')
    expect(sweepTime(80)).toContain('years')
    expect(sweepTime(128)).toContain('age of the universe')
    expect(sweepTime(256)).toContain('age of the universe')
  })
})
