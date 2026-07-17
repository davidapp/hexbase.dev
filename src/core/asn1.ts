import { bytesToHex, hex } from './bytes'
import { region, type Region } from './region'

/**
 * DER (Distinguished Encoding Rules) parser — the encoding under X.509
 * certificates, and the substrate the cert tool's byte-level tree is built on.
 * Parses any DER blob into a tag/length/value tree with exact offsets.
 */

export interface Asn1Node {
  /** 0 universal · 1 application · 2 context-specific · 3 private */
  tagClass: 0 | 1 | 2 | 3
  tag: number
  constructed: boolean
  /** Offset of the first tag byte. */
  offset: number
  /** Tag + length bytes before the content starts. */
  headerLen: number
  /** Content length in bytes. */
  length: number
  children?: Asn1Node[]
}

const UNIVERSAL_NAMES: Record<number, string> = {
  1: 'BOOLEAN',
  2: 'INTEGER',
  3: 'BIT STRING',
  4: 'OCTET STRING',
  5: 'NULL',
  6: 'OBJECT IDENTIFIER',
  10: 'ENUMERATED',
  12: 'UTF8String',
  16: 'SEQUENCE',
  17: 'SET',
  18: 'NumericString',
  19: 'PrintableString',
  20: 'T61String',
  22: 'IA5String',
  23: 'UTCTime',
  24: 'GeneralizedTime',
  30: 'BMPString',
}

export function tagName(node: Asn1Node): string {
  if (node.tagClass === 0) return UNIVERSAL_NAMES[node.tag] ?? `UNIVERSAL ${node.tag}`
  const prefix = node.tagClass === 2 ? '' : node.tagClass === 1 ? 'APPLICATION ' : 'PRIVATE '
  return `[${prefix}${node.tag}]`
}

/** Parse consecutive TLVs between offset and end. Throws on malformed DER. */
export function parseDer(bytes: Uint8Array, offset = 0, end = bytes.length, depth = 0): Asn1Node[] {
  if (depth > 48) throw new Error('ASN.1 nesting deeper than 48 levels — refusing (corrupt or adversarial input)')
  const nodes: Asn1Node[] = []
  let off = offset
  while (off < end) {
    const start = off
    if (off >= end) break
    const first = bytes[off++]
    const tagClass = ((first >> 6) & 3) as Asn1Node['tagClass']
    const constructed = (first & 0x20) !== 0
    let tag = first & 0x1f
    if (tag === 0x1f) {
      // high tag number form
      tag = 0
      let more = true
      let count = 0
      while (more) {
        if (off >= end || ++count > 4) throw new Error(`unterminated high tag number at offset ${start}`)
        const b = bytes[off++]
        tag = (tag << 7) | (b & 0x7f)
        more = (b & 0x80) !== 0
      }
    }
    if (off >= end) throw new Error(`missing length byte at offset ${off}`)
    let length = bytes[off++]
    if (length === 0x80) throw new Error(`indefinite length at offset ${start} — BER, not DER (certificates must be DER)`)
    if (length > 0x80) {
      const numBytes = length & 0x7f
      if (numBytes > 4) throw new Error(`length of ${numBytes} bytes at offset ${start} is beyond sane limits`)
      length = 0
      for (let i = 0; i < numBytes; i++) {
        if (off >= end) throw new Error(`truncated long-form length at offset ${start}`)
        length = length * 256 + bytes[off++]
      }
    }
    const headerLen = off - start
    if (off + length > end) {
      throw new Error(`element at offset ${start} declares ${length} content bytes but only ${end - off} remain`)
    }
    const node: Asn1Node = { tagClass, tag, constructed, offset: start, headerLen, length }
    if (constructed) node.children = parseDer(bytes, off, off + length, depth + 1)
    nodes.push(node)
    off += length
  }
  return nodes
}

export function content(bytes: Uint8Array, node: Asn1Node): Uint8Array {
  return bytes.subarray(node.offset + node.headerLen, node.offset + node.headerLen + node.length)
}

export function decodeOid(bytes: Uint8Array, node: Asn1Node): string {
  const c = content(bytes, node)
  if (c.length === 0) return '(empty OID)'
  // Each subidentifier is a base-128 varint; the first one packs the top two arcs.
  const subids: bigint[] = []
  let acc = 0n
  for (let i = 0; i < c.length; i++) {
    acc = (acc << 7n) | BigInt(c[i] & 0x7f)
    if ((c[i] & 0x80) === 0) {
      subids.push(acc)
      acc = 0n
    }
  }
  if (subids.length === 0) return '(malformed OID)'
  const first = subids[0]
  const arc1 = first < 40n ? 0n : first < 80n ? 1n : 2n
  const arc2 = first - arc1 * 40n
  return [arc1, arc2, ...subids.slice(1)].join('.')
}

export function decodeInteger(bytes: Uint8Array, node: Asn1Node): { value: bigint; hex: string } {
  const c = content(bytes, node)
  if (c.length === 0) return { value: 0n, hex: '00' }
  let v = 0n
  for (const b of c) v = (v << 8n) | BigInt(b)
  if (c[0] & 0x80) v -= 1n << BigInt(c.length * 8) // two's complement
  return { value: v, hex: bytesToHex(c, '') }
}

export function decodeBoolean(bytes: Uint8Array, node: Asn1Node): boolean {
  const c = content(bytes, node)
  return c.length > 0 && c[0] !== 0
}

export function decodeString(bytes: Uint8Array, node: Asn1Node): string {
  const c = content(bytes, node)
  if (node.tag === 30) {
    // BMPString: UCS-2 big-endian
    let s = ''
    for (let i = 0; i + 1 < c.length; i += 2) s += String.fromCharCode((c[i] << 8) | c[i + 1])
    return s
  }
  return new TextDecoder().decode(c) // utf-8, replacement chars on invalid bytes
}

/** UTCTime (YYMMDDHHMMSSZ, RFC 5280 50-year window) and GeneralizedTime (YYYY…). */
export function decodeTime(bytes: Uint8Array, node: Asn1Node): Date | null {
  const s = decodeString(bytes, node)
  let m: RegExpMatchArray | null
  if (node.tag === 23) {
    m = s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/)
    if (!m) return null
    const yy = parseInt(m[1], 10)
    const year = yy >= 50 ? 1900 + yy : 2000 + yy
    return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], m[6] ? +m[6] : 0))
  }
  m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$/)
  if (!m) return null
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], m[6] ? +m[6] : 0))
}

export function decodeBitString(bytes: Uint8Array, node: Asn1Node): { unused: number; bits: Uint8Array } {
  const c = content(bytes, node)
  if (c.length === 0) return { unused: 0, bits: new Uint8Array(0) }
  return { unused: c[0], bits: c.subarray(1) }
}

/** Preview a node's value for tree display; oidLabel lets callers name known OIDs. */
export function nodeValue(bytes: Uint8Array, node: Asn1Node, oidLabel?: (oid: string) => string | null): string {
  if (node.constructed) return `${node.children?.length ?? 0} element${node.children?.length === 1 ? '' : 's'}`
  switch (node.tagClass === 0 ? node.tag : -1) {
    case 1:
      return decodeBoolean(bytes, node) ? 'TRUE' : 'FALSE'
    case 2: {
      const { value, hex: h } = decodeInteger(bytes, node)
      return node.length <= 8 ? String(value) : `${node.length * 8}-bit: ${h.slice(0, 24)}${h.length > 24 ? '…' : ''}`
    }
    case 3: {
      const { unused, bits } = decodeBitString(bytes, node)
      const preview = bytesToHex(bits.subarray(0, 12))
      return `${bits.length * 8 - unused} bits: ${preview}${bits.length > 12 ? ' …' : ''}`
    }
    case 4: {
      const c = content(bytes, node)
      return `${c.length} bytes: ${bytesToHex(c.subarray(0, 12))}${c.length > 12 ? ' …' : ''}`
    }
    case 5:
      return ''
    case 6: {
      const oid = decodeOid(bytes, node)
      const label = oidLabel?.(oid)
      return label ? `${oid} (${label})` : oid
    }
    case 12:
    case 18:
    case 19:
    case 20:
    case 22:
    case 30:
      return JSON.stringify(decodeString(bytes, node))
    case 23:
    case 24: {
      const d = decodeTime(bytes, node)
      return d ? d.toISOString().replace('.000', '') : decodeString(bytes, node)
    }
    default: {
      const c = content(bytes, node)
      return c.length === 0 ? '' : `${c.length} bytes: ${bytesToHex(c.subarray(0, 12))}${c.length > 12 ? ' …' : ''}`
    }
  }
}

/** Generic ASN.1 → Region tree, for byte-level display of any DER blob. */
export function toRegionTree(bytes: Uint8Array, nodes: Asn1Node[], oidLabel?: (oid: string) => string | null): Region[] {
  return nodes.map((n) => {
    const r = region(tagName(n), n.offset, n.headerLen + n.length, {
      value: nodeValue(bytes, n, oidLabel),
      note: `tag 0x${hex(bytes[n.offset])} · ${n.headerLen}-byte header + ${n.length}-byte content`,
    })
    if (n.children?.length) r.children = toRegionTree(bytes, n.children, oidLabel)
    return r
  })
}
