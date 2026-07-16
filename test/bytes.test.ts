import { describe, expect, it } from 'vitest'
import { crc32, entropy, extractStrings, parseHexInput } from '../src/core/bytes'

const ascii = (s: string) => new Uint8Array([...s].map((c) => c.charCodeAt(0)))

describe('parseHexInput', () => {
  it('parses raw hex', () => {
    expect([...parseHexInput('48656c6c6f')]).toEqual([0x48, 0x65, 0x6c, 0x6c, 0x6f])
  })
  it('parses spaced pairs and mixed case', () => {
    expect([...parseHexInput('DE ad BE ef')]).toEqual([0xde, 0xad, 0xbe, 0xef])
  })
  it('parses 0x and \\x styles with commas', () => {
    expect([...parseHexInput('0xDE, 0xAD')]).toEqual([0xde, 0xad])
    expect([...parseHexInput('\\xde\\xad\\xbe\\xef')]).toEqual([0xde, 0xad, 0xbe, 0xef])
  })
  it('parses colon-separated MAC style', () => {
    expect([...parseHexInput('08:00:27:8f:12:34')]).toEqual([8, 0, 0x27, 0x8f, 0x12, 0x34])
  })
  it('parses xxd dumps (offset + grouped pairs + ascii gutter)', () => {
    const dump = '00000000: 4865 6c6c 6f20 776f 726c 6421 0a         Hello world!.'
    expect([...parseHexInput(dump)]).toEqual([...ascii('Hello world!\n')])
  })
  it('parses hexdump -C dumps with |ascii| gutter', () => {
    const dump = '00000000  48 65 6c 6c 6f 20 77 6f  72 6c 64 21 0a          |Hello world!.|'
    expect([...parseHexInput(dump)]).toEqual([...ascii('Hello world!\n')])
  })
  it('parses Wireshark-style dumps and stops at the ascii column', () => {
    const dump = [
      '0000  08 00 27 8f 12 34 52 54  00 12 35 02 08 00 45 00   ..\'..4RT..5..E.',
      '0010  00 54 1c 46 40 00 40 01  a6 ec c0 a8 01 17 08 08   .T.F@.@.........',
    ].join('\n')
    const out = parseHexInput(dump)
    expect(out.length).toBe(32)
    expect(out[0]).toBe(0x08)
    expect(out[16]).toBe(0x00)
    expect(out[31]).toBe(0x08)
  })
  it('rejects odd digit counts and empty input', () => {
    expect(() => parseHexInput('abc')).toThrow(/odd number/)
    expect(() => parseHexInput('hello there')).toThrow(/no hex data/)
  })
})

describe('crc32', () => {
  it('matches the classic check value', () => {
    expect(crc32(ascii('123456789'))).toBe(0xcbf43926)
  })
  it('empty input is 0', () => {
    expect(crc32(new Uint8Array(0))).toBe(0)
  })
})

describe('strings + entropy', () => {
  it('extracts printable runs', () => {
    const data = new Uint8Array([0, 1, ...ascii('hello'), 0xff, ...ascii('ok'), 0, ...ascii('world!'), 2])
    const found = extractStrings(data, 4)
    expect(found.map((f) => f.text)).toEqual(['hello', 'world!'])
    expect(found[0].offset).toBe(2)
  })
  it('entropy of constant data is 0, of uniform data is 8', () => {
    expect(entropy(new Uint8Array(100).fill(7))).toBe(0)
    const uniform = new Uint8Array(256)
    for (let i = 0; i < 256; i++) uniform[i] = i
    expect(entropy(uniform)).toBeCloseTo(8, 5)
  })
})
