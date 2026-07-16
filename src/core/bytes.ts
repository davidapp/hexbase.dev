/** Byte-level helpers shared by the hex inspector, packet decoder, and format parsers. */

export function hex(n: number | bigint, width = 2): string {
  return n.toString(16).toUpperCase().padStart(width, '0')
}

export function hexPrefix(n: number | bigint, width = 2): string {
  return '0x' + hex(n, width)
}

export function bytesToHex(b: Uint8Array, sep = ' '): string {
  const out: string[] = []
  for (let i = 0; i < b.length; i++) out.push(hex(b[i]))
  return out.join(sep)
}

export function formatSize(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n
  let u = -1
  do {
    v /= 1024
    u++
  } while (v >= 1024 && u < units.length - 1)
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[u]}`
}

/** Printable ASCII for hex-dump gutters; everything else becomes a middle dot. */
export function printable(byte: number): string {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '·'
}

/** Latin-1 string from bytes (each byte one char) — for magic strings and tags. */
export function latin1(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
  return s
}

/** Sequential reader over a Uint8Array with bounds checking. */
export class ByteReader {
  readonly bytes: Uint8Array
  readonly view: DataView
  pos: number

  constructor(bytes: Uint8Array, pos = 0) {
    this.bytes = bytes
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    this.pos = pos
  }

  get length(): number {
    return this.bytes.length
  }
  remaining(): number {
    return this.bytes.length - this.pos
  }
  eof(): boolean {
    return this.pos >= this.bytes.length
  }
  need(n: number): void {
    if (this.pos + n > this.bytes.length) {
      throw new RangeError(`unexpected end of data at offset ${hexPrefix(this.pos, 4)} (need ${n} more byte${n === 1 ? '' : 's'})`)
    }
  }
  u8(): number {
    this.need(1)
    return this.view.getUint8(this.pos++)
  }
  u16be(): number {
    this.need(2)
    const v = this.view.getUint16(this.pos)
    this.pos += 2
    return v
  }
  u16le(): number {
    this.need(2)
    const v = this.view.getUint16(this.pos, true)
    this.pos += 2
    return v
  }
  u32be(): number {
    this.need(4)
    const v = this.view.getUint32(this.pos)
    this.pos += 4
    return v
  }
  u32le(): number {
    this.need(4)
    const v = this.view.getUint32(this.pos, true)
    this.pos += 4
    return v
  }
  u64be(): bigint {
    this.need(8)
    const v = this.view.getBigUint64(this.pos)
    this.pos += 8
    return v
  }
  u64le(): bigint {
    this.need(8)
    const v = this.view.getBigUint64(this.pos, true)
    this.pos += 8
    return v
  }
  slice(n: number): Uint8Array {
    this.need(n)
    const v = this.bytes.subarray(this.pos, this.pos + n)
    this.pos += n
    return v
  }
  ascii(n: number): string {
    return latin1(this.slice(n))
  }
  skip(n: number): void {
    this.need(n)
    this.pos += n
  }
  seek(pos: number): void {
    this.pos = pos
  }
}

/**
 * Parse loosely formatted hex input into bytes.
 *
 * Accepts raw hex ("48656c6c6f"), spaced pairs, "0x.." / "\x.." prefixes,
 * comma/colon/dash separated values, and offset-prefixed dumps produced by
 * xxd, hexdump -C, od, or Wireshark (offset column and trailing ASCII column
 * are stripped automatically).
 */
export function parseHexInput(text: string): Uint8Array {
  let digits = ''
  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine
    // hexdump -C style ASCII gutter: |ascii here|
    const pipe = line.indexOf('|')
    if (pipe !== -1) line = line.slice(0, pipe)
    line = line.trim()
    if (!line) continue

    // Offset prefix: 4-16 hex digits followed by ":" or whitespace, with more data after.
    const off = /^(?:0x)?[0-9a-fA-F]{4,16}:?\s+(.+)$/.exec(line)
    if (off && /^[0-9a-fA-F\\0]/.test(off[1])) line = off[1]

    // Walk whitespace-separated tokens; the first non-hex token starts the
    // ASCII gutter (Wireshark style), so we stop there.
    for (const token of line.split(/\s+/)) {
      const cleaned = token
        .replace(/\\x/gi, '')
        .replace(/0x/gi, '')
        .replace(/[,;:\-.]/g, '')
      if (cleaned === '') continue
      if (!/^[0-9a-fA-F]+$/.test(cleaned)) break
      digits += cleaned
    }
  }
  if (digits.length === 0) throw new Error('no hex data found in input')
  if (digits.length % 2 !== 0) throw new Error(`odd number of hex digits (${digits.length}) — one nibble is missing somewhere`)
  const out = new Uint8Array(digits.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(digits.slice(i * 2, i * 2 + 2), 16)
  return out
}

let CRC_TABLE: Uint32Array | null = null

/** CRC-32 (IEEE 802.3, the one PNG/ZIP/gzip use). */
export function crc32(bytes: Uint8Array, start = 0, end = bytes.length): number {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256)
    for (let n = 0; n < 256; n++) {
      let c = n
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
      CRC_TABLE[n] = c >>> 0
    }
  }
  let c = 0xffffffff
  for (let i = start; i < end; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

/** Extract printable ASCII runs of at least `minLen` chars, like the Unix `strings` tool. */
export function extractStrings(bytes: Uint8Array, minLen = 4, maxResults = 500): { offset: number; text: string }[] {
  const out: { offset: number; text: string }[] = []
  let start = -1
  for (let i = 0; i <= bytes.length; i++) {
    const b = i < bytes.length ? bytes[i] : 0
    const isPrintable = (b >= 0x20 && b <= 0x7e) || b === 0x09
    if (isPrintable) {
      if (start === -1) start = i
    } else if (start !== -1) {
      if (i - start >= minLen) {
        out.push({ offset: start, text: latin1(bytes.subarray(start, i)) })
        if (out.length >= maxResults) return out
      }
      start = -1
    }
  }
  return out
}

/** Shannon entropy in bits/byte (0 = constant, 8 = uniformly random). */
export function entropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0
  const counts = new Uint32Array(256)
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++
  let h = 0
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue
    const p = counts[i] / bytes.length
    h -= p * Math.log2(p)
  }
  return h
}
