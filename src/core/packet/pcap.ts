import type { LayerId } from './net'

/**
 * pcap / pcapng capture-file parsing: turns a capture file into a list of
 * frames the packet decoder can walk one at a time. Link-layer pseudo-headers
 * that decodePacket doesn't model (NULL/LOOP family, Linux SLL) are stripped
 * here so every frame starts at a layer the decoder understands.
 */

export interface PcapFrame {
  /** 1-based frame number, as capture tools display it. */
  index: number
  /** Timestamp in seconds since the Unix epoch (fractional part preserved). */
  tsSec: number
  /** Captured bytes, starting at `firstLayer` (pseudo-headers pre-stripped). */
  bytes: Uint8Array
  /** Original length on the wire (may exceed bytes.length when truncated by snaplen). */
  origLen: number
  linkType: number
  firstLayer: LayerId
}

export interface PcapFile {
  kind: 'pcap' | 'pcapng'
  frames: PcapFrame[]
  /** Human-readable facts about the capture file itself. */
  meta: string[]
  warnings: string[]
}

const LINKTYPE_NAMES: Record<number, string> = {
  0: 'NULL (BSD loopback)',
  1: 'Ethernet',
  101: 'Raw IP',
  105: 'IEEE 802.11',
  108: 'OpenBSD loopback',
  113: 'Linux cooked capture (SLL)',
  127: '802.11 Radiotap',
  228: 'Raw IPv4',
  229: 'Raw IPv6',
  276: 'Linux cooked capture v2 (SLL2)',
}

export function linkTypeName(lt: number): string {
  return LINKTYPE_NAMES[lt] ?? `linktype ${lt}`
}

/** Quick magic check so callers can route dropped files (pcap vs plain hex dump). */
export function looksLikePcap(bytes: Uint8Array): boolean {
  if (bytes.length < 4) return false
  const m = readU32(bytes, 0, false)
  const ml = readU32(bytes, 0, true)
  if (m === 0xa1b2c3d4 || ml === 0xa1b2c3d4 || m === 0xa1b23c4d || ml === 0xa1b23c4d) return true
  return m === 0x0a0d0d0a // pcapng section header block type (endian-symmetric)
}

function readU16(b: Uint8Array, off: number, le: boolean): number {
  return le ? b[off] | (b[off + 1] << 8) : (b[off] << 8) | b[off + 1]
}

function readU32(b: Uint8Array, off: number, le: boolean): number {
  return le
    ? (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0
    : ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0
}

/** Map a link type to the decoder's first layer, stripping pseudo-headers we don't model. */
function mapLinkType(
  linkType: number,
  data: Uint8Array,
  le: boolean,
  warnOnce: (msg: string) => void,
): { bytes: Uint8Array; firstLayer: LayerId } {
  switch (linkType) {
    case 1: // Ethernet
      return { bytes: data, firstLayer: 'eth' }
    case 0: // NULL: 4-byte AF_* family in the *writer's* byte order
    case 108: {
      // OpenBSD loopback: family is big-endian
      if (data.length < 5) return { bytes: data, firstLayer: 'payload' }
      const payload = data.subarray(4)
      const v = payload[0] >>> 4
      warnOnce(`loopback frames: 4-byte family header stripped (${linkTypeName(linkType)})`)
      return { bytes: payload, firstLayer: v === 6 ? 'ipv6' : 'ipv4' }
    }
    case 101: // Raw IP: version nibble decides
    case 228:
    case 229: {
      const v = data.length > 0 ? data[0] >>> 4 : 0
      return { bytes: data, firstLayer: linkType === 229 || v === 6 ? 'ipv6' : 'ipv4' }
    }
    case 113: {
      // Linux SLL v1: 16-byte header, EtherType in the last 2 bytes (big-endian)
      if (data.length < 17) return { bytes: data, firstLayer: 'payload' }
      const proto = (data[14] << 8) | data[15]
      warnOnce('Linux cooked capture: 16-byte SLL header stripped from each frame')
      return { bytes: data.subarray(16), firstLayer: etherTypeLayer(proto) }
    }
    case 276: {
      // Linux SLL v2: 20-byte header, EtherType in the first 2 bytes (big-endian)
      if (data.length < 21) return { bytes: data, firstLayer: 'payload' }
      const proto = (data[0] << 8) | data[1]
      warnOnce('Linux cooked capture v2: 20-byte SLL2 header stripped from each frame')
      return { bytes: data.subarray(20), firstLayer: etherTypeLayer(proto) }
    }
    default:
      warnOnce(`${linkTypeName(linkType)} is not decoded layer-by-layer — frames shown as raw payload`)
      return { bytes: data, firstLayer: 'payload' }
  }
}

function etherTypeLayer(proto: number): LayerId {
  if (proto === 0x0800) return 'ipv4'
  if (proto === 0x86dd) return 'ipv6'
  if (proto === 0x0806) return 'arp'
  return 'payload'
}

/** Parse a capture file. Throws with a helpful message when it isn't pcap/pcapng. */
export function parsePcapFile(bytes: Uint8Array): PcapFile {
  if (bytes.length < 4) throw new Error('file is too short to be a capture file')
  const magicBE = readU32(bytes, 0, false)
  if (magicBE === 0x0a0d0d0a) return parsePcapng(bytes)
  const magicLE = readU32(bytes, 0, true)
  for (const [magic, le, ns] of [
    [0xa1b2c3d4, false, false],
    [0xa1b23c4d, false, true],
  ] as const) {
    if (magicBE === magic) return parseClassic(bytes, le, ns)
  }
  for (const [magic, le, ns] of [
    [0xa1b2c3d4, true, false],
    [0xa1b23c4d, true, true],
  ] as const) {
    if (magicLE === magic) return parseClassic(bytes, le, ns)
  }
  throw new Error('not a pcap or pcapng file (no capture magic in the first 4 bytes)')
}

function parseClassic(bytes: Uint8Array, le: boolean, nanos: boolean): PcapFile {
  if (bytes.length < 24) throw new Error('pcap global header is truncated (need 24 bytes)')
  const warnings: string[] = []
  const seen = new Set<string>()
  const warnOnce = (m: string) => {
    if (!seen.has(m)) {
      seen.add(m)
      warnings.push(m)
    }
  }
  const vMaj = readU16(bytes, 4, le)
  const vMin = readU16(bytes, 6, le)
  const snaplen = readU32(bytes, 16, le)
  const linkType = readU32(bytes, 20, le)

  const frames: PcapFrame[] = []
  let off = 24
  while (off + 16 <= bytes.length) {
    const tsSec = readU32(bytes, off, le)
    const tsFrac = readU32(bytes, off + 4, le)
    const inclLen = readU32(bytes, off + 8, le)
    const origLen = readU32(bytes, off + 12, le)
    off += 16
    if (inclLen > 256 * 1024 * 1024) throw new Error(`frame ${frames.length + 1} claims ${inclLen} bytes — corrupt record header`)
    if (off + inclLen > bytes.length) {
      warnings.push(`file ends mid-frame: frame ${frames.length + 1} is truncated and was dropped`)
      break
    }
    const data = bytes.subarray(off, off + inclLen)
    off += inclLen
    const mapped = mapLinkType(linkType, data, le, warnOnce)
    frames.push({
      index: frames.length + 1,
      tsSec: tsSec + tsFrac / (nanos ? 1e9 : 1e6),
      bytes: mapped.bytes,
      origLen,
      linkType,
      firstLayer: mapped.firstLayer,
    })
  }

  return {
    kind: 'pcap',
    frames,
    meta: [
      `pcap ${vMaj}.${vMin} (${le ? 'little' : 'big'}-endian, ${nanos ? 'nanosecond' : 'microsecond'} timestamps)`,
      `link type: ${linkTypeName(linkType)} · snaplen ${snaplen}`,
      `${frames.length} frame${frames.length === 1 ? '' : 's'}`,
    ],
    warnings,
  }
}

interface NgInterface {
  linkType: number
  tsDivisor: number
  name: string | null
}

function parsePcapng(bytes: Uint8Array): PcapFile {
  const warnings: string[] = []
  const seen = new Set<string>()
  const warnOnce = (m: string) => {
    if (!seen.has(m)) {
      seen.add(m)
      warnings.push(m)
    }
  }
  const frames: PcapFrame[] = []
  const meta: string[] = []
  let interfaces: NgInterface[] = []
  let le = true
  let sections = 0
  let off = 0

  while (off + 12 <= bytes.length) {
    // Block type is endian-sensitive except the SHB, whose type is a palindrome.
    const rawType = readU32(bytes, off, le)
    if (rawType === 0x0a0d0d0a) {
      // New section: byte order magic sits at body offset 0 (block offset 8).
      const bomBE = readU32(bytes, off + 8, false)
      le = bomBE !== 0x1a2b3c4d
      sections++
      interfaces = []
      const vMaj = readU16(bytes, off + 12, le)
      const vMin = readU16(bytes, off + 14, le)
      if (sections === 1) meta.push(`pcapng ${vMaj}.${vMin} (${le ? 'little' : 'big'}-endian)`)
    }
    const type = rawType === 0x0a0d0d0a ? rawType : readU32(bytes, off, le)
    const totalLen = readU32(bytes, off + 4, le)
    if (totalLen < 12 || totalLen % 4 !== 0 || off + totalLen > bytes.length) {
      warnings.push(`corrupt block at offset ${off} (declared length ${totalLen}) — stopped there`)
      break
    }
    const body = bytes.subarray(off + 8, off + totalLen - 4)

    if (type === 0x00000001 && body.length >= 8) {
      // Interface Description Block
      const linkType = readU16(body, 0, le)
      const iface: NgInterface = { linkType, tsDivisor: 1e6, name: null }
      // options: code u16, len u16, value padded to 4
      let o = 8
      while (o + 4 <= body.length) {
        const code = readU16(body, o, le)
        const len = readU16(body, o + 2, le)
        if (code === 0) break
        const val = body.subarray(o + 4, o + 4 + len)
        if (code === 2) iface.name = new TextDecoder().decode(val)
        if (code === 9 && len >= 1) {
          const v = val[0]
          iface.tsDivisor = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** v
        }
        o += 4 + (len + 3 & ~3)
      }
      interfaces.push(iface)
      meta.push(`interface ${interfaces.length - 1}: ${linkTypeName(linkType)}${iface.name ? ` (${iface.name})` : ''}`)
    } else if (type === 0x00000006 && body.length >= 20) {
      // Enhanced Packet Block
      const ifId = readU32(body, 0, le)
      const tsHigh = readU32(body, 4, le)
      const tsLow = readU32(body, 8, le)
      const capLen = readU32(body, 12, le)
      const origLen = readU32(body, 16, le)
      const iface = interfaces[ifId]
      if (!iface) {
        warnOnce(`packet block references undeclared interface ${ifId} — skipped`)
      } else if (20 + capLen <= body.length + 1) {
        const data = body.subarray(20, 20 + capLen)
        const mapped = mapLinkType(iface.linkType, data, le, warnOnce)
        frames.push({
          index: frames.length + 1,
          tsSec: (tsHigh * 4294967296 + tsLow) / iface.tsDivisor,
          bytes: mapped.bytes,
          origLen,
          linkType: iface.linkType,
          firstLayer: mapped.firstLayer,
        })
      }
    } else if (type === 0x00000003 && body.length >= 4) {
      // Simple Packet Block: no timestamp, first interface's link type
      const origLen = readU32(body, 0, le)
      const iface = interfaces[0]
      if (iface) {
        const capLen = Math.min(origLen, body.length - 4)
        const data = body.subarray(4, 4 + capLen)
        const mapped = mapLinkType(iface.linkType, data, le, warnOnce)
        frames.push({
          index: frames.length + 1,
          tsSec: 0,
          bytes: mapped.bytes,
          origLen,
          linkType: iface.linkType,
          firstLayer: mapped.firstLayer,
        })
      }
    }
    off += totalLen
  }

  if (sections > 1) meta.push(`${sections} sections`)
  meta.push(`${frames.length} frame${frames.length === 1 ? '' : 's'}`)
  return { kind: 'pcapng', frames, meta, warnings }
}

/** Format a frame timestamp: absolute UTC plus the delta from the capture start. */
export function frameTime(frame: PcapFrame, firstTs: number): string {
  if (frame.tsSec === 0) return '—'
  const abs = new Date(frame.tsSec * 1000).toISOString().replace('T', ' ').replace('Z', '')
  const delta = frame.tsSec - firstTs
  return `${abs}  (+${delta.toFixed(6)}s)`
}
