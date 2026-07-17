import { describe, expect, it } from 'vitest'
import { decodePacket } from '../src/core/packet/decode'
import { frameTime, linkTypeName, looksLikePcap, parsePcapFile } from '../src/core/packet/pcap'
import { SAMPLE_PACKETS } from '../src/core/packet/samples'

const ethFrame = (id: string) => SAMPLE_PACKETS.find((s) => s.id === id)!.build()

// ---------------------------------------------------------------- builders

function u16(n: number, le: boolean): number[] {
  return le ? [n & 0xff, n >>> 8] : [n >>> 8, n & 0xff]
}

function u32(n: number, le: boolean): number[] {
  const b = [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]
  return le ? b.reverse() : b
}

function buildClassic(
  frames: { ts: number; frac: number; data: Uint8Array }[],
  opts: { le?: boolean; nanos?: boolean; linkType?: number; truncateLast?: number } = {},
): Uint8Array {
  const { le = true, nanos = false, linkType = 1 } = opts
  const out: number[] = []
  out.push(...u32(nanos ? 0xa1b23c4d : 0xa1b2c3d4, le))
  out.push(...u16(2, le), ...u16(4, le))
  out.push(...u32(0, le), ...u32(0, le), ...u32(65535, le), ...u32(linkType, le))
  for (const f of frames) {
    out.push(...u32(f.ts, le), ...u32(f.frac, le), ...u32(f.data.length, le), ...u32(f.data.length, le))
    out.push(...f.data)
  }
  const bytes = new Uint8Array(out)
  return opts.truncateLast ? bytes.subarray(0, bytes.length - opts.truncateLast) : bytes
}

function ngBlock(type: number, body: number[], le: boolean): number[] {
  const pad = (4 - (body.length % 4)) % 4
  const total = 12 + body.length + pad
  return [...u32(type, le), ...u32(total, le), ...body, ...new Array(pad).fill(0), ...u32(total, le)]
}

function ngOption(code: number, value: number[], le: boolean): number[] {
  const pad = (4 - (value.length % 4)) % 4
  return [...u16(code, le), ...u16(value.length, le), ...value, ...new Array(pad).fill(0)]
}

function buildPcapng(frames: { ifId: number; ts: number; data: Uint8Array }[], le = true): Uint8Array {
  const out: number[] = []
  // SHB: BOM, version 1.0, section length -1
  out.push(...ngBlock(0x0a0d0d0a, [...u32(0x1a2b3c4d, le), ...u16(1, le), ...u16(0, le), ...u32(0xffffffff, le), ...u32(0xffffffff, le)], le))
  // IDB: ethernet, snaplen 65535, with a name option and 10^-6 tsresol
  const name = [...'eth0'].map((c) => c.charCodeAt(0))
  out.push(
    ...ngBlock(
      0x00000001,
      [...u16(1, le), ...u16(0, le), ...u32(65535, le), ...ngOption(2, name, le), ...ngOption(9, [6], le), ...ngOption(0, [], le)],
      le,
    ),
  )
  for (const f of frames) {
    const usec = f.ts * 1e6
    const high = Math.floor(usec / 4294967296)
    const low = usec % 4294967296
    out.push(
      ...ngBlock(
        0x00000006,
        [...u32(f.ifId, le), ...u32(high, le), ...u32(low, le), ...u32(f.data.length, le), ...u32(f.data.length, le), ...f.data],
        le,
      ),
    )
  }
  return new Uint8Array(out)
}

// ---------------------------------------------------------------- tests

describe('classic pcap', () => {
  it('parses little-endian microsecond files and decodes frames end-to-end', () => {
    const dns = ethFrame('dns-query')
    const ping = ethFrame('ping')
    const file = buildClassic([
      { ts: 1700000000, frac: 250000, data: dns },
      { ts: 1700000001, frac: 500000, data: ping },
    ])
    expect(looksLikePcap(file)).toBe(true)
    const cap = parsePcapFile(file)
    expect(cap.kind).toBe('pcap')
    expect(cap.frames).toHaveLength(2)
    expect(cap.frames[0].firstLayer).toBe('eth')
    expect(cap.frames[0].tsSec).toBeCloseTo(1700000000.25, 6)
    expect(cap.frames[1].origLen).toBe(ping.length)
    expect(cap.meta.join('\n')).toContain('Ethernet')

    const decoded = decodePacket(cap.frames[0].bytes, cap.frames[0].firstLayer)
    expect(decoded.summary.join('\n')).toContain('DNS query: example.com A')
    expect(decoded.warnings).toEqual([])
  })

  it('parses big-endian and nanosecond variants', () => {
    const dns = ethFrame('dns-query')
    const be = parsePcapFile(buildClassic([{ ts: 1700000000, frac: 1, data: dns }], { le: false }))
    expect(be.meta[0]).toContain('big-endian')
    expect(be.frames[0].tsSec).toBeCloseTo(1700000000.000001, 9)

    const ns = parsePcapFile(buildClassic([{ ts: 1700000000, frac: 123456789, data: dns }], { nanos: true }))
    expect(ns.meta[0]).toContain('nanosecond')
    expect(ns.frames[0].tsSec).toBeCloseTo(1700000000.123456789, 6)
  })

  it('maps raw-IP link types by version nibble', () => {
    const dns = ethFrame('dns-query').subarray(14) // strip ethernet → starts at IPv4
    const cap = parsePcapFile(buildClassic([{ ts: 1, frac: 0, data: dns }], { linkType: 101 }))
    expect(cap.frames[0].firstLayer).toBe('ipv4')
    const decoded = decodePacket(cap.frames[0].bytes, cap.frames[0].firstLayer)
    expect(decoded.summary.join('\n')).toContain('DNS query')
  })

  it('strips Linux SLL headers and maps the EtherType', () => {
    const ip = ethFrame('dns-query').subarray(14)
    const sll = new Uint8Array(16 + ip.length)
    sll[15] = 0x00 // packet type / ARPHRD / addr fields left zero
    sll[14] = 0x08 // protocol 0x0800 (IPv4), big-endian at offset 14
    sll.set(ip, 16)
    const cap = parsePcapFile(buildClassic([{ ts: 1, frac: 0, data: sll }], { linkType: 113 }))
    expect(cap.frames[0].firstLayer).toBe('ipv4')
    expect(cap.frames[0].bytes.length).toBe(ip.length)
    expect(cap.warnings.join(' ')).toContain('SLL')
  })

  it('strips the loopback family header', () => {
    const ip = ethFrame('ping').subarray(14)
    const nullFrame = new Uint8Array(4 + ip.length)
    nullFrame[0] = 2 // AF_INET, writer byte order
    nullFrame.set(ip, 4)
    const cap = parsePcapFile(buildClassic([{ ts: 1, frac: 0, data: nullFrame }], { linkType: 0 }))
    expect(cap.frames[0].firstLayer).toBe('ipv4')
    expect(decodePacket(cap.frames[0].bytes, cap.frames[0].firstLayer).summary.join('\n')).toContain('Echo request')
  })

  it('drops a trailing truncated frame with a warning instead of throwing', () => {
    const dns = ethFrame('dns-query')
    const file = buildClassic(
      [
        { ts: 1, frac: 0, data: dns },
        { ts: 2, frac: 0, data: dns },
      ],
      { truncateLast: 10 },
    )
    const cap = parsePcapFile(file)
    expect(cap.frames).toHaveLength(1)
    expect(cap.warnings.join(' ')).toContain('truncated')
  })

  it('rejects non-capture files with a clear error', () => {
    expect(() => parsePcapFile(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0]))).toThrow(/not a pcap/)
    expect(looksLikePcap(new Uint8Array([0x89, 0x50, 0x4e, 0x47]))).toBe(false)
  })
})

describe('pcapng', () => {
  it('parses SHB/IDB/EPB with options and 64-bit timestamps', () => {
    const dns = ethFrame('dns-query')
    const file = buildPcapng([
      { ifId: 0, ts: 1700000000.25, data: dns },
      { ifId: 0, ts: 1700000001.5, data: ethFrame('ping') },
    ])
    expect(looksLikePcap(file)).toBe(true)
    const cap = parsePcapFile(file)
    expect(cap.kind).toBe('pcapng')
    expect(cap.frames).toHaveLength(2)
    expect(cap.meta.join('\n')).toContain('eth0')
    expect(cap.frames[0].tsSec).toBeCloseTo(1700000000.25, 5)
    expect(cap.frames[1].tsSec).toBeCloseTo(1700000001.5, 5)
    const decoded = decodePacket(cap.frames[1].bytes, cap.frames[1].firstLayer)
    expect(decoded.summary.join('\n')).toContain('Echo request')
  })

  it('skips packet blocks that reference unknown interfaces', () => {
    const file = buildPcapng([{ ifId: 7, ts: 1, data: ethFrame('ping') }])
    const cap = parsePcapFile(file)
    expect(cap.frames).toHaveLength(0)
    expect(cap.warnings.join(' ')).toContain('undeclared interface')
  })

  it('parses big-endian sections', () => {
    const cap = parsePcapFile(buildPcapng([{ ifId: 0, ts: 3, data: ethFrame('dns-query') }], false))
    expect(cap.meta[0]).toContain('big-endian')
    expect(cap.frames).toHaveLength(1)
    expect(cap.frames[0].firstLayer).toBe('eth')
  })
})

describe('helpers', () => {
  it('formats frame times with capture-relative deltas', () => {
    const t = frameTime({ index: 1, tsSec: 1700000000.5, bytes: new Uint8Array(), origLen: 0, linkType: 1, firstLayer: 'eth' }, 1700000000)
    expect(t).toContain('2023-11-14')
    expect(t).toContain('+0.500000s')
    expect(frameTime({ index: 1, tsSec: 0, bytes: new Uint8Array(), origLen: 0, linkType: 1, firstLayer: 'eth' }, 0)).toBe('—')
  })

  it('names link types', () => {
    expect(linkTypeName(1)).toBe('Ethernet')
    expect(linkTypeName(9999)).toContain('9999')
  })
})
