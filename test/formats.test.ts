import { describe, expect, it } from 'vitest'
import { crc32 } from '../src/core/bytes'
import { detectFormat } from '../src/core/formats/index'

const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))
const u32be = (v: number): number[] => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]
const u16le = (v: number): number[] => [v & 0xff, (v >> 8) & 0xff]
const u32le = (v: number): number[] => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]

function cat(...parts: (number[] | Uint8Array)[]): Uint8Array {
  const arrays = parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)))
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0))
  let off = 0
  for (const a of arrays) {
    out.set(a, off)
    off += a.length
  }
  return out
}

function pngChunk(type: string, data: number[]): Uint8Array {
  const td = cat(ascii(type), data)
  return cat(u32be(data.length), td, u32be(crc32(td)))
}

describe('PNG', () => {
  const png = cat(
    [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    pngChunk('IHDR', [...u32be(320), ...u32be(240), 8, 6, 0, 0, 0]),
    pngChunk('IDAT', [0x78, 0x9c, 1, 2, 3]),
    pngChunk('IEND', []),
  )
  it('detects and parses dimensions + color type', () => {
    const fmt = detectFormat(png)
    expect(fmt?.id).toBe('png')
    const out = fmt!.parse(png)
    expect(out.summary[0]).toContain('320 × 240')
    expect(out.summary[0]).toContain('truecolor + alpha')
    expect(out.warnings).toEqual([])
    const ihdr = out.regions.find((r) => r.name === 'IHDR')
    expect(ihdr?.children?.find((c) => c.name === 'CRC')?.flag).toBe('ok')
  })
  it('flags a corrupted CRC', () => {
    const bad = png.slice()
    bad[20] ^= 0xff // flip a bit inside IHDR data
    const out = detectFormat(bad)!.parse(bad)
    expect(out.warnings.join(' ')).toMatch(/bad CRC/)
  })
  it('reports trailing data after IEND', () => {
    const sneaky = cat(png, ascii('EXTRA'))
    const out = detectFormat(sneaky)!.parse(sneaky)
    expect(out.warnings.join(' ')).toMatch(/trailing data/)
  })
})

describe('ZIP', () => {
  function buildZip(): Uint8Array {
    const name = ascii('hello.txt')
    const data = ascii('hi')
    const crc = crc32(new Uint8Array(data))
    const lfh = cat([0x50, 0x4b, 0x03, 0x04], u16le(20), u16le(0), u16le(0), u16le(0), u16le(0x5321), u32le(crc), u32le(2), u32le(2), u16le(name.length), u16le(0), name, data)
    const cd = cat(
      [0x50, 0x4b, 0x01, 0x02],
      u16le(20), u16le(20), u16le(0), u16le(0), u16le(0), u16le(0x5321),
      u32le(crc), u32le(2), u32le(2),
      u16le(name.length), u16le(0), u16le(0), u16le(0), u16le(0), u32le(0), u32le(0),
      name,
    )
    const eocd = cat([0x50, 0x4b, 0x05, 0x06], u16le(0), u16le(0), u16le(1), u16le(1), u32le(cd.length), u32le(lfh.length), u16le(0))
    return cat(lfh, cd, eocd)
  }
  it('walks the central directory', () => {
    const zip = buildZip()
    const out = detectFormat(zip)!.parse(zip)
    expect(out.format).toBe('ZIP archive')
    expect(out.summary.join(' ')).toContain('1 entries')
    const cd = out.regions.find((r) => r.name === 'Central directory')
    expect(cd?.children?.[0].name).toBe('hello.txt')
    expect(cd?.children?.[0].note).toContain('stored')
    expect(out.warnings).toEqual([])
  })
})

describe('gzip', () => {
  it('reads flags, mtime, OS and original name', () => {
    const gz = cat(
      [0x1f, 0x8b, 8, 8],
      u32le(1700000000), // mtime
      [0, 3], // xfl, unix
      ascii('notes.txt'), [0],
      [1, 2, 3, 4], // fake deflate
      u32le(0xdeadbeef), u32le(12345),
    )
    const out = detectFormat(gz)!.parse(gz)
    expect(out.summary.join(' ')).toContain('notes.txt')
    expect(out.summary.join(' ')).toContain('Unix')
    expect(out.summary.join(' ')).toContain('12.1 KB')
  })
})

describe('SQLite', () => {
  it('decodes the 100-byte header', () => {
    const h = new Uint8Array(120)
    h.set(ascii('SQLite format 3\0'), 0)
    h.set([0x10, 0x00], 16) // page size 4096
    h[18] = 2 // WAL
    h[19] = 2
    h.set(u32be(1), 28) // 1 page
    h.set(u32be(1), 56) // utf-8
    h.set(u32be(3045001), 96) // 3.45.1
    const out = detectFormat(h)!.parse(h)
    expect(out.format).toBe('SQLite database')
    expect(out.summary[0]).toContain('SQLite 3.45.1')
    expect(out.summary.join(' ')).toContain('WAL')
  })
})

describe('ELF', () => {
  it('decodes a 64-bit little-endian header', () => {
    const h = new Uint8Array(64)
    h.set([0x7f, ...ascii('ELF'), 2, 1, 1, 0], 0)
    h[16] = 3 // DYN
    h[18] = 0x3e // x86-64
    h.set([1, 0, 0, 0], 20)
    h.set(u32le(0x1040), 24) // entry (low 4 of 8 bytes)
    h[52] = 64 // ehsize
    h[54] = 56 // phentsize
    const out = detectFormat(h)!.parse(h)
    expect(out.summary[0]).toContain('64-bit LSB DYN')
    expect(out.summary[0]).toContain('x86-64')
  })
})

describe('detect-only magics', () => {
  const cases: [string, number[]][] = [
    ['7z', [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 0]],
    ['zstd', [0x28, 0xb5, 0x2f, 0xfd, 0, 0]],
    ['xz', [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0]],
    ['pcap', [0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0]],
    ['flac', ascii('fLaC....')],
    ['wasm', [0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]],
  ]
  for (const [id, bytes] of cases) {
    it(`detects ${id}`, () => {
      expect(detectFormat(new Uint8Array(bytes))?.id).toBe(id)
    })
  }
  it('distinguishes Java class from fat Mach-O (shared CAFEBABE)', () => {
    const klass = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0, 30])
    expect(detectFormat(klass)?.id).toBe('class')
    const fat = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2, ...new Array(40).fill(0)])
    expect(detectFormat(fat)?.id).toBe('macho')
  })
})
