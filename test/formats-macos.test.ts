import { describe, expect, it } from 'vitest'
import { crc32 } from '../src/core/bytes'
import { detectFormat } from '../src/core/formats/index'
import type { Region } from '../src/core/region'

const ascii = (s: string): number[] => [...s].map((c) => c.charCodeAt(0))
const u16be = (v: number): number[] => [(v >> 8) & 0xff, v & 0xff]
const u32be = (v: number): number[] => [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]
const u64be = (v: number): number[] => [...u32be(Math.floor(v / 2 ** 32)), ...u32be(v >>> 0)]
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

const flatten = (regions: Region[]): Region[] => regions.flatMap((r) => [r, ...(r.children ? flatten(r.children) : [])])

describe('binary plist', () => {
  // {"a": 1, "s": "hi"} hand-assembled:
  // objects @8: dict(D2 01 02 03 04) @8, "a" @13, "s" @15, int 1 @17, "hi" @19
  // offset table @22, trailer @27
  const dictPlist = cat(
    ascii('bplist00'),
    [0xd2, 1, 2, 3, 4],
    [0x51, ...ascii('a')],
    [0x51, ...ascii('s')],
    [0x10, 1],
    [0x52, ...ascii('hi')],
    [8, 13, 15, 17, 19],
    [0, 0, 0, 0, 0, 0, 1, 1],
    u64be(5),
    u64be(0),
    u64be(22),
  )

  it('decodes a dict with string keys', () => {
    const fmt = detectFormat(dictPlist)
    expect(fmt?.id).toBe('bplist')
    const out = fmt!.parse(dictPlist)
    expect(out.warnings).toEqual([])
    expect(out.summary[0]).toContain('root: {2 pairs}')
    expect(out.summary[0]).toContain('5 objects')
    const all = flatten(out.regions)
    const a = all.find((r) => r.name === 'a')
    const s = all.find((r) => r.name === 's')
    expect(a?.value).toBe('1')
    expect(s?.value).toBe('"hi"')
  })

  it('decodes arrays, booleans and Cocoa dates', () => {
    // [true, date(0.0 = 2001-01-01)]
    const arrPlist = cat(
      ascii('bplist00'),
      [0xa2, 1, 2], // @8
      [0x09], // @11 true
      [0x33, ...u64be(0)], // @12 date, f64be 0.0
      [8, 11, 12], // offset table @21
      [0, 0, 0, 0, 0, 0, 1, 1],
      u64be(3),
      u64be(0),
      u64be(21),
    )
    const out = detectFormat(arrPlist)!.parse(arrPlist)
    expect(out.warnings).toEqual([])
    expect(out.summary[0]).toContain('root: [2 items]')
    const all = flatten(out.regions)
    expect(all.find((r) => r.name.includes('[0]'))?.value).toBe('true')
    expect(all.find((r) => r.name.includes('[1]'))?.value).toBe('2001-01-01T00:00:00Z')
  })

  it('rejects a corrupt trailer gracefully', () => {
    const bad = dictPlist.slice()
    bad[bad.length - 1] = 200 // offset table offset way past EOF
    const out = detectFormat(bad)!.parse(bad)
    expect(out.warnings.join(' ')).toMatch(/implausible|truncated/)
  })
})

describe('Apple disk image (koly trailer)', () => {
  function buildDmg(): Uint8Array {
    const xml = ascii('<plist><dict><key>Name</key><string>TestVol</string></dict></plist>')
    const body = cat(new Uint8Array(100), xml, new Uint8Array(10))
    const koly = new Uint8Array(512)
    const dv = new DataView(koly.buffer)
    koly.set(ascii('koly'), 0)
    dv.setUint32(4, 4) // version
    dv.setUint32(8, 512) // header size
    dv.setBigUint64(24, 0n) // data fork offset
    dv.setBigUint64(32, 100n) // data fork length
    dv.setUint32(56, 1) // segment number
    dv.setUint32(60, 1) // segment count
    dv.setBigUint64(216, 100n) // xml offset
    dv.setBigUint64(224, BigInt(xml.length)) // xml length
    dv.setBigUint64(492, 2048n) // sector count → 1 MiB
    return cat(body, koly)
  }

  it('identifies a dmg by its trailer and reads the plist name', () => {
    const dmg = buildDmg()
    const fmt = detectFormat(dmg)
    expect(fmt?.id).toBe('dmg')
    const out = fmt!.parse(dmg)
    expect(out.summary[0]).toContain('UDIF v4')
    expect(out.summary[0]).toContain('1.0 MB')
    const xmlRegion = out.regions.find((r) => r.name === 'XML property list')
    expect(xmlRegion?.value).toContain('TestVol')
    expect(out.warnings).toEqual([])
  })
})

describe('AppleSingle/AppleDouble', () => {
  function buildAppleDouble(): Uint8Array {
    const finder = cat(ascii('TEXT'), ascii('ttxt'), new Uint8Array(24))
    const rsrc = [1, 2, 3, 4]
    const header = cat(
      [0x00, 0x05, 0x16, 0x07],
      u32be(0x00020000),
      new Uint8Array(16),
      u16be(2),
      u32be(9), u32be(50), u32be(32), // Finder info @50
      u32be(2), u32be(82), u32be(4), // Resource fork @82
    )
    return cat(header, finder, rsrc)
  }

  it('walks entries and decodes Finder type/creator', () => {
    const ad = buildAppleDouble()
    const fmt = detectFormat(ad)
    expect(fmt?.id).toBe('applefork')
    const out = fmt!.parse(ad)
    expect(out.format).toContain('AppleDouble')
    expect(out.summary[0]).toContain('Finder info')
    expect(out.summary[0]).toContain('Resource fork')
    const all = flatten(out.regions)
    const finderData = all.find((r) => r.name === 'Data' && r.value?.includes('TEXT'))
    expect(finderData?.value).toContain('creator "ttxt"')
    expect(out.warnings).toEqual([])
  })
})

describe('icns', () => {
  it('lists icon entries and spots embedded PNG', () => {
    const png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]
    const entry = cat(ascii('ic07'), u32be(8 + png.length), png)
    const icns = cat(ascii('icns'), u32be(8 + entry.length), entry)
    const fmt = detectFormat(icns)
    expect(fmt?.id).toBe('icns')
    const out = fmt!.parse(icns)
    expect(out.warnings).toEqual([])
    const e = out.regions.find((r) => r.name === '"ic07"')
    expect(e?.value).toContain('128×128')
    expect(e?.value).toContain('PNG data')
  })
})

describe('xar', () => {
  it('reads the header and locates TOC + heap', () => {
    const toc = [0x78, 0x9c, 1, 2, 3, 4, 5, 6, 7, 8]
    // header is exactly 28 bytes: magic 4 + size 2 + version 2 + two u64 lengths + cksum alg 4
    const clean = cat(ascii('xar!'), u16be(28), u16be(1), u64be(toc.length), u64be(64), u32be(1), toc, [9, 9, 9, 9])
    const fmt = detectFormat(clean)
    expect(fmt?.id).toBe('xar')
    const out = fmt!.parse(clean)
    expect(out.summary[0]).toContain('xar v1')
    expect(out.summary[0]).toContain('SHA-1')
    expect(out.regions.some((r) => r.name.startsWith('Table of contents'))).toBe(true)
    expect(out.regions.some((r) => r.name.startsWith('Heap'))).toBe(true)
  })
})

describe('ipa detection inside zip', () => {
  function buildZip(name: string): Uint8Array {
    const nameBytes = ascii(name)
    const data = ascii('x')
    const crc = crc32(new Uint8Array(data))
    const lfh = cat([0x50, 0x4b, 0x03, 0x04], u16le(20), u16le(0), u16le(0), u16le(0), u16le(0), u32le(crc), u32le(1), u32le(1), u16le(nameBytes.length), u16le(0), nameBytes, data)
    const cd = cat(
      [0x50, 0x4b, 0x01, 0x02],
      u16le(20), u16le(20), u16le(0), u16le(0), u16le(0), u16le(0),
      u32le(crc), u32le(1), u32le(1),
      u16le(nameBytes.length), u16le(0), u16le(0), u16le(0), u16le(0), u32le(0), u32le(0),
      nameBytes,
    )
    const eocd = cat([0x50, 0x4b, 0x05, 0x06], u16le(0), u16le(0), u16le(1), u16le(1), u32le(cd.length), u32le(lfh.length), u16le(0))
    return cat(lfh, cd, eocd)
  }

  it('flags Payload/*.app zips as .ipa', () => {
    const out = detectFormat(buildZip('Payload/Hexbase.app/Info.plist'))!.parse(buildZip('Payload/Hexbase.app/Info.plist'))
    expect(out.format).toContain('.ipa')
  })
})

describe('macOS detect-only magics', () => {
  it('detects BOM and dyld shared cache', () => {
    expect(detectFormat(new Uint8Array(ascii('BOMStore....')))?.id).toBe('bom')
    expect(detectFormat(new Uint8Array(ascii('dyld_v1  arm64e.')))?.id).toBe('dyldcache')
  })
})
