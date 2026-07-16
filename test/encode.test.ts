import { describe, expect, it } from 'vitest'
import {
  base64ToText,
  binaryToText,
  escapeHtml,
  fromUnicodeEscapes,
  hexToText,
  inspectString,
  md5,
  rot13,
  textToBase64,
  textToBinary,
  textToHexBytes,
  toUnicodeEscapes,
  unescapeHtml,
} from '../src/core/encode'
import { decodeJwt } from '../src/core/jwt'

describe('base64', () => {
  it('round-trips UTF-8 text', () => {
    expect(textToBase64('Hello, 世界!')).toBe('SGVsbG8sIOS4lueVjCE=')
    expect(base64ToText('SGVsbG8sIOS4lueVjCE=')).toBe('Hello, 世界!')
  })
  it('url-safe variant', () => {
    const b64 = textToBase64('\xff\xfe?>', true)
    expect(b64).not.toMatch(/[+/=]/)
  })
  it('decodes unpadded and url-safe input', () => {
    expect(base64ToText('aGV4YmFzZQ')).toBe('hexbase')
  })
  it('rejects invalid input', () => {
    expect(() => base64ToText('a')).toThrow()
    expect(() => base64ToText('$$$$')).toThrow()
  })
})

describe('html entities', () => {
  it('escapes the five significant chars', () => {
    expect(escapeHtml(`<a href="x">'&'</a>`)).toBe('&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;')
  })
  it('full mode escapes non-ascii numerically', () => {
    expect(escapeHtml('café', 'full')).toBe('caf&#233;')
  })
  it('unescapes named, decimal and hex entities', () => {
    expect(unescapeHtml('&lt;b&gt; &amp; &#65; &#x42; &copy; &euro;')).toBe('<b> & A B © €')
  })
  it('leaves unknown entities alone', () => {
    expect(unescapeHtml('&nosuchthing;')).toBe('&nosuchthing;')
  })
})

describe('hex / binary text', () => {
  it('round-trips hex', () => {
    expect(textToHexBytes('Hi')).toBe('48 69')
    expect(hexToText('48 69')).toBe('Hi')
  })
  it('round-trips binary', () => {
    expect(textToBinary('A')).toBe('01000001')
    expect(binaryToText('01000001 01000010')).toBe('AB')
  })
})

describe('unicode escapes', () => {
  it('escapes non-ascii as \\u sequences with surrogate pairs', () => {
    expect(toUnicodeEscapes('A→𝕏')).toBe('A\\u2192\\uD835\\uDD4F')
  })
  it('es6 style uses code points', () => {
    expect(toUnicodeEscapes('𝕏', true)).toBe('\\u{1D54F}')
  })
  it('unescapes all three styles', () => {
    expect(fromUnicodeEscapes('\\u2192 \\u{1D54F} \\x41')).toBe('→ 𝕏 A')
  })
  it('inspectString reports code points and utf-8 bytes', () => {
    const info = inspectString('€')
    expect(info[0].label).toBe('U+20AC')
    expect(info[0].utf8).toBe('E2 82 AC')
    expect(info[0].utf16).toBe('20AC')
  })
})

describe('md5', () => {
  const enc = (s: string) => new TextEncoder().encode(s)
  it('matches RFC 1321 test vectors', () => {
    expect(md5(new Uint8Array(0))).toBe('d41d8cd98f00b204e9800998ecf8427e')
    expect(md5(enc('abc'))).toBe('900150983cd24fb0d6963f7d28e17f72')
    expect(md5(enc('message digest'))).toBe('f96b697d7cb7938d525a2f31aaf161d0')
    expect(md5(enc('abcdefghijklmnopqrstuvwxyz'))).toBe('c3fcd3d76192e4007dfb496cca67e13b')
  })
  it('handles inputs spanning block boundaries', () => {
    expect(md5(enc('a'.repeat(64)))).toBe('014842d480b571495a4a0363793f7367')
  })
})

describe('rot13', () => {
  it('is its own inverse', () => {
    expect(rot13('Why did the chicken?')).toBe('Jul qvq gur puvpxra?')
    expect(rot13(rot13('Attack at dawn'))).toBe('Attack at dawn')
  })
})

describe('jwt', () => {
  // header {"alg":"HS256","typ":"JWT"} payload {"sub":"1234567890","name":"John Doe","iat":1516239022}
  const token =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
  it('decodes header and payload', () => {
    const parts = decodeJwt(token)
    expect(parts.header.alg).toBe('HS256')
    expect(parts.payload.name).toBe('John Doe')
    expect(parts.payload.iat).toBe(1516239022)
  })
  it('rejects malformed tokens', () => {
    expect(() => decodeJwt('a.b')).toThrow(/3 dot-separated/)
    expect(() => decodeJwt('!!!.???.###')).toThrow(/base64url/)
  })
})
