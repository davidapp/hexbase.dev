import { bytesToHex, hex, parseHexInput } from './bytes'

// ---------------------------------------------------------------- Base64

export function bytesToBase64(bytes: Uint8Array, urlSafe = false): string {
  let bin = ''
  const CHUNK = 0x8000
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, Math.min(i + CHUNK, bytes.length)))
  }
  let b64 = btoa(bin)
  if (urlSafe) b64 = b64.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
  return b64
}

export function base64ToBytes(b64: string): Uint8Array {
  let s = b64.replace(/\s+/g, '').replaceAll('-', '+').replaceAll('_', '/')
  if (s.length % 4 === 1) throw new Error('invalid base64: length mod 4 is 1')
  while (s.length % 4 !== 0) s += '='
  let bin: string
  try {
    bin = atob(s)
  } catch {
    throw new Error('invalid base64: contains characters outside the base64 alphabet')
  }
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function textToBase64(text: string, urlSafe = false): string {
  return bytesToBase64(new TextEncoder().encode(text), urlSafe)
}

/** Throws if the decoded bytes are not valid UTF-8. */
export function base64ToText(b64: string): string {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(base64ToBytes(b64))
}

// ---------------------------------------------------------------- URL

export function urlEncode(text: string, full = false): string {
  return full ? encodeURI(text) : encodeURIComponent(text)
}

export function urlDecode(text: string, plusAsSpace = false): string {
  const src = plusAsSpace ? text.replaceAll('+', ' ') : text
  return decodeURIComponent(src)
}

// ---------------------------------------------------------------- HTML entities

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  copy: '©', reg: '®', trade: '™', hellip: '…',
  mdash: '—', ndash: '–', lsquo: '‘', rsquo: '’',
  ldquo: '“', rdquo: '”', bull: '•', middot: '·',
  sect: '§', para: '¶', deg: '°', plusmn: '±',
  times: '×', divide: '÷', frac12: '½', frac14: '¼',
  sup2: '²', sup3: '³', micro: 'µ', laquo: '«',
  raquo: '»', euro: '€', pound: '£', yen: '¥',
  cent: '¢', infin: '∞', ne: '≠', le: '≤', ge: '≥',
  larr: '←', uarr: '↑', rarr: '→', darr: '↓',
  alpha: 'α', beta: 'β', gamma: 'γ', delta: 'δ',
  pi: 'π', sigma: 'σ', omega: 'ω', lambda: 'λ', mu: 'μ',
}

/** minimal = only the five XML-significant chars; full = also numeric-escape all non-ASCII. */
export function escapeHtml(text: string, mode: 'minimal' | 'full' = 'minimal'): string {
  const map: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
  let out = text.replace(/[&<>"']/g, (c) => map[c])
  if (mode === 'full') {
    out = out.replace(/[\u0080-\u{10FFFF}]/gu, (c) => `&#${c.codePointAt(0)};`)
  }
  return out
}

export function unescapeHtml(text: string): string {
  return text.replace(/&(#[xX]?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);/g, (m, ent: string) => {
    if (ent[0] === '#') {
      const isHex = ent[1] === 'x' || ent[1] === 'X'
      const cp = parseInt(ent.slice(isHex ? 2 : 1), isHex ? 16 : 10)
      if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return m
      return String.fromCodePoint(cp)
    }
    return NAMED_ENTITIES[ent] ?? NAMED_ENTITIES[ent.toLowerCase()] ?? m
  })
}

// ---------------------------------------------------------------- Hex / binary text

export function textToHexBytes(text: string, sep = ' '): string {
  return bytesToHex(new TextEncoder().encode(text), sep)
}

/** Throws if input is not valid hex or the bytes are not valid UTF-8. */
export function hexToText(hexStr: string): string {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(parseHexInput(hexStr))
}

export function textToBinary(text: string, sep = ' '): string {
  const bytes = new TextEncoder().encode(text)
  const out: string[] = []
  for (let i = 0; i < bytes.length; i++) out.push(bytes[i].toString(2).padStart(8, '0'))
  return out.join(sep)
}

export function binaryToText(bin: string): string {
  const digits = bin.replace(/[^01]/g, '')
  if (digits.length === 0) throw new Error('no binary digits found')
  if (digits.length % 8 !== 0) throw new Error(`bit count (${digits.length}) is not a multiple of 8`)
  const bytes = new Uint8Array(digits.length / 8)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(digits.slice(i * 8, i * 8 + 8), 2)
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes)
}

// ---------------------------------------------------------------- Unicode escapes

export function toUnicodeEscapes(text: string, es6 = false): string {
  let out = ''
  for (const ch of text) {
    const cp = ch.codePointAt(0)!
    if (cp >= 0x20 && cp < 0x7f && ch !== '\\') {
      out += ch
    } else if (es6) {
      out += `\\u{${cp.toString(16).toUpperCase()}}`
    } else if (cp > 0xffff) {
      // encode as a UTF-16 surrogate pair
      for (let i = 0; i < ch.length; i++) out += `\\u${hex(ch.charCodeAt(i), 4)}`
    } else {
      out += `\\u${hex(cp, 4)}`
    }
  }
  return out
}

export function fromUnicodeEscapes(text: string): string {
  return text
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_m, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_m, h: string) => String.fromCharCode(parseInt(h, 16)))
}

export interface CharInfo {
  char: string
  codePoint: number
  /** "U+0041" style label. */
  label: string
  utf8: string
  utf16: string
}

/** Per-code-point breakdown of a string: code point, UTF-8 bytes, UTF-16 units. */
export function inspectString(text: string, limit = 500): CharInfo[] {
  const enc = new TextEncoder()
  const out: CharInfo[] = []
  for (const ch of text) {
    if (out.length >= limit) break
    const cp = ch.codePointAt(0)!
    const units: string[] = []
    for (let i = 0; i < ch.length; i++) units.push(hex(ch.charCodeAt(i), 4))
    out.push({
      char: ch,
      codePoint: cp,
      label: 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'),
      utf8: bytesToHex(enc.encode(ch)),
      utf16: units.join(' '),
    })
  }
  return out
}

// ---------------------------------------------------------------- ROT13

export function rot13(text: string): string {
  return text.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base)
  })
}

// ---------------------------------------------------------------- MD5 (for the hash tab; SHA-* comes from WebCrypto)

export function md5(bytes: Uint8Array): string {
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21]
  const K = new Uint32Array(64)
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32)

  const len = bytes.length
  const padded = (((len + 8) >> 6) + 1) << 6
  const buf = new Uint8Array(padded)
  buf.set(bytes)
  buf[len] = 0x80
  const dv = new DataView(buf.buffer)
  const bitLen = len * 8
  dv.setUint32(padded - 8, bitLen >>> 0, true)
  dv.setUint32(padded - 4, Math.floor(bitLen / 2 ** 32), true)

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476
  const M = new Uint32Array(16)
  for (let off = 0; off < padded; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true)
    let A = a0, B = b0, C = c0, D = d0
    for (let i = 0; i < 64; i++) {
      let F: number, g: number
      if (i < 16) { F = (B & C) | (~B & D); g = i }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16 }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16 }
      else { F = C ^ (B | ~D); g = (7 * i) % 16 }
      F = (F + A + K[i] + M[g]) | 0
      A = D; D = C; C = B
      const s = S[(i >> 4) * 4 + (i & 3)]
      B = (B + ((F << s) | (F >>> (32 - s)))) | 0
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0
  }
  const out = new Uint8Array(16)
  const ov = new DataView(out.buffer)
  ov.setUint32(0, a0 >>> 0, true)
  ov.setUint32(4, b0 >>> 0, true)
  ov.setUint32(8, c0 >>> 0, true)
  ov.setUint32(12, d0 >>> 0, true)
  let hexStr = ''
  for (let i = 0; i < 16; i++) hexStr += out[i].toString(16).padStart(2, '0')
  return hexStr
}
