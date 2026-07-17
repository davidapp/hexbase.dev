import { describe, expect, it } from 'vitest'
import { decodeOid, decodeTime, parseDer, tagName, toRegionTree } from '../src/core/asn1'
import { describeValidity, parseAnyDer, parseCertificate, toDer } from '../src/core/x509'

// ---------------------------------------------------------------- DER builders

function len(n: number): number[] {
  if (n < 0x80) return [n]
  const out: number[] = []
  let v = n
  while (v > 0) {
    out.unshift(v & 0xff)
    v >>= 8
  }
  return [0x80 | out.length, ...out]
}

const tlv = (tag: number, body: number[]): number[] => [tag, ...len(body.length), ...body]
const seq = (...parts: number[][]): number[] => tlv(0x30, parts.flat())
const set = (...parts: number[][]): number[] => tlv(0x31, parts.flat())
const int = (bytes: number[]): number[] => tlv(0x02, bytes)
const bool = (v: boolean): number[] => tlv(0x01, [v ? 0xff : 0x00])
const octet = (body: number[]): number[] => tlv(0x04, body)
const bitstr = (body: number[], unused = 0): number[] => tlv(0x03, [unused, ...body])
const utf8 = (s: string): number[] => tlv(0x0c, [...s].map((c) => c.charCodeAt(0)))
const printable = (s: string): number[] => tlv(0x13, [...s].map((c) => c.charCodeAt(0)))
const ia5 = (s: string): number[] => tlv(0x16, [...s].map((c) => c.charCodeAt(0)))
const utc = (s: string): number[] => tlv(0x17, [...s].map((c) => c.charCodeAt(0)))
const ctx = (tag: number, body: number[], constructed = true): number[] => tlv((constructed ? 0xa0 : 0x80) | tag, body)

function oid(dotted: string): number[] {
  const arcs = dotted.split('.').map(Number)
  const body: number[] = []
  const first = arcs[0] * 40 + arcs[1]
  const enc = (v: number) => {
    const chunk: number[] = [v & 0x7f]
    v >>= 7
    while (v > 0) {
      chunk.unshift(0x80 | (v & 0x7f))
      v >>= 7
    }
    body.push(...chunk)
  }
  enc(first)
  for (const arc of arcs.slice(2)) enc(arc)
  return tlv(0x06, body)
}

const rdn = (attrOid: string, value: number[]): number[] => set(seq(oid(attrOid), value))

function buildCert(): Uint8Array {
  // 2048-bit RSA modulus stand-in: leading 0x00 + 256 bytes
  const modulus = int([0x00, ...Array.from({ length: 256 }, (_, i) => (i === 0 ? 0xb1 : (i * 7) % 256))])
  const spki = seq(seq(oid('1.2.840.113549.1.1.1'), tlv(0x05, [])), bitstr(seq(modulus, int([0x01, 0x00, 0x01]))))
  const dns = (name: string) => ctx(2, [...name].map((c) => c.charCodeAt(0)), false)
  const extensions = ctx(
    3,
    seq(
      seq(oid('2.5.29.19'), bool(true), octet(seq(bool(true), int([0x00])))), // basicConstraints, critical: CA:TRUE pathlen 0
      seq(oid('2.5.29.15'), octet(bitstr([0b10000110], 1))), // keyUsage: digitalSignature, keyCertSign, cRLSign
      seq(oid('2.5.29.37'), octet(seq(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.2')))), // EKU
      seq(oid('2.5.29.17'), octet(seq(dns('example.com'), dns('*.example.com'), ctx(7, [93, 184, 216, 34], false)))), // SANs
    ),
  )
  const tbs = seq(
    ctx(0, int([0x02])),                                    // version v3
    int([0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),                    // serial
    seq(oid('1.2.840.113549.1.1.11'), tlv(0x05, [])),       // sig alg
    seq(rdn('2.5.4.6', printable('US')), rdn('2.5.4.10', utf8('Test CA Org')), rdn('2.5.4.3', utf8('Test Root CA'))), // issuer
    seq(utc('240101000000Z'), utc('340101000000Z')),        // validity
    seq(rdn('2.5.4.3', utf8('example.com'))),               // subject
    spki,
    extensions,
  )
  const cert = seq(tbs, seq(oid('1.2.840.113549.1.1.11'), tlv(0x05, [])), bitstr(Array.from({ length: 256 }, (_, i) => i % 251)))
  return new Uint8Array(cert)
}

const node = (bytes: Uint8Array) => parseDer(bytes)[0]

// ---------------------------------------------------------------- ASN.1 core

describe('DER parser', () => {
  it('parses long-form lengths', () => {
    const big = new Uint8Array(tlv(0x04, new Array(300).fill(0xaa)))
    const n = node(big)
    expect(n.length).toBe(300)
    expect(n.headerLen).toBe(4) // tag + 0x82 + 2 length bytes
  })

  it('rejects indefinite length (BER)', () => {
    expect(() => parseDer(new Uint8Array([0x30, 0x80, 0x00, 0x00]))).toThrow(/BER, not DER/)
  })

  it('rejects truncated content', () => {
    expect(() => parseDer(new Uint8Array([0x04, 0x05, 0x01]))).toThrow(/declares 5/)
  })

  it('decodes multi-byte OID arcs both ways', () => {
    const bytes = new Uint8Array(oid('1.2.840.113549.1.1.11'))
    expect(decodeOid(bytes, node(bytes))).toBe('1.2.840.113549.1.1.11')
    const b2 = new Uint8Array(oid('2.5.29.17'))
    expect(decodeOid(b2, node(b2))).toBe('2.5.29.17')
  })

  it('decodes UTCTime with the RFC 5280 century window', () => {
    const b = new Uint8Array(utc('490101120000Z'))
    expect(decodeTime(b, node(b))?.getUTCFullYear()).toBe(2049)
    const b2 = new Uint8Array(utc('500101120000Z'))
    expect(decodeTime(b2, node(b2))?.getUTCFullYear()).toBe(1950)
  })

  it('names tags and context classes', () => {
    const b = new Uint8Array(seq(int([1])))
    const n = node(b)
    expect(tagName(n)).toBe('SEQUENCE')
    expect(tagName(n.children![0])).toBe('INTEGER')
    const c = new Uint8Array(ctx(3, int([1])))
    expect(tagName(node(c))).toBe('[3]')
  })

  it('builds a region tree with exact offsets', () => {
    const b = new Uint8Array(seq(int([0x05]), utf8('hi')))
    const regions = toRegionTree(b, parseDer(b))
    expect(regions[0].offset).toBe(0)
    expect(regions[0].length).toBe(b.length)
    expect(regions[0].children).toHaveLength(2)
    expect(regions[0].children![1].value).toBe('"hi"')
  })
})

// ---------------------------------------------------------------- X.509

describe('X.509 certificate parsing', () => {
  const der = buildCert()

  it('extracts subject, issuer, serial and version', () => {
    const { facts } = parseCertificate(der)
    expect(facts.subject).toBe('CN=example.com')
    expect(facts.issuer).toContain('C=US')
    expect(facts.issuer).toContain('O=Test CA Org')
    expect(facts.issuer).toContain('CN=Test Root CA')
    expect(facts.version).toBe(3)
    expect(facts.serialHex).toBe('1A2B3C4D5E')
    expect(facts.selfSigned).toBe(false)
  })

  it('parses validity and computes status', () => {
    const { facts } = parseCertificate(der)
    expect(facts.notBefore?.toISOString()).toBe('2024-01-01T00:00:00.000Z')
    expect(facts.notAfter?.toISOString()).toBe('2034-01-01T00:00:00.000Z')
    expect(describeValidity(facts, new Date('2030-01-01'))).toContain('valid, ')
    expect(describeValidity(facts, new Date('2035-01-01'))).toContain('EXPIRED')
    expect(describeValidity(facts, new Date('2020-01-01'))).toContain('NOT YET VALID')
  })

  it('reads the RSA key size and exponent', () => {
    const { facts } = parseCertificate(der)
    expect(facts.keyDetail).toBe('RSA-2048, e=65537')
    expect(facts.keyAlg).toBe('rsaEncryption')
  })

  it('parses the extensions people care about', () => {
    const { facts } = parseCertificate(der)
    expect(facts.isCA).toBe(true)
    expect(facts.keyUsage).toEqual(['digitalSignature', 'keyCertSign', 'cRLSign'])
    expect(facts.extKeyUsage).toEqual(['serverAuth', 'clientAuth'])
    expect(facts.sans).toEqual(['DNS:example.com', 'DNS:*.example.com', 'IP:93.184.216.34'])
  })

  it('produces a byte-accurate region tree', () => {
    const { result } = parseCertificate(der)
    expect(result.format).toContain('X.509')
    const root = result.regions[0]
    expect(root.offset).toBe(0)
    expect(root.length).toBe(der.length)
    const tbs = root.children![0]
    expect(tbs.name).toBe('tbsCertificate')
    const ext = tbs.children!.find((r) => r.name === 'Extensions')
    expect(ext?.children?.map((c) => c.name)).toContain('subjectAltName')
    expect(ext?.children?.find((c) => c.name === 'basicConstraints')?.value).toContain('CA:TRUE')
    expect(ext?.children?.find((c) => c.name === 'basicConstraints')?.value).toContain('critical')
  })

  it('summarizes for the result header', () => {
    const { result } = parseCertificate(der)
    const text = result.summary.join('\n')
    expect(text).toContain('subject: CN=example.com')
    expect(text).toContain('sha256WithRSAEncryption')
    expect(text).toContain('DNS:example.com')
  })
})

// ---------------------------------------------------------------- input handling

describe('input decoding', () => {
  const der = buildCert()

  it('accepts raw DER', () => {
    expect(toDer(der)).toBe(der)
  })

  it('accepts PEM armor with whitespace and line wraps', () => {
    let b64 = ''
    const bin = String.fromCharCode(...der)
    b64 = btoa(bin)
    const wrapped = b64.match(/.{1,64}/g)!.join('\n')
    const pem = `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`
    const round = toDer(pem)
    expect([...round]).toEqual([...der])
    // also as bytes (e.g. a dropped .pem file)
    expect([...toDer(new TextEncoder().encode(pem))]).toEqual([...der])
  })

  it('refuses private-key PEM blocks', () => {
    expect(() => toDer('-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----')).toThrow(/private keys/i)
  })

  it('rejects garbage with a clear error', () => {
    expect(() => toDer('this is not base64 at all!!')).toThrow(/not a certificate/)
  })

  it('parses a real ECDSA leaf certificate (example.com)', () => {
    const pem = `-----BEGIN CERTIFICATE-----
MIID5zCCA42gAwIBAgIQGqc/6iV74zNLmilVLm+HjjAKBggqhkjOPQQDAjBRMQsw
CQYDVQQGEwJVUzEYMBYGA1UECgwPU1NMIENvcnBvcmF0aW9uMSgwJgYDVQQDDB9D
bG91ZGZsYXJlIFRMUyBJc3N1aW5nIEVDQyBDQSAzMB4XDTI2MDUzMTIxMzkxMloX
DTI2MDgyOTIxNDEyNlowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAAR3K9vg9mgByiZluphXApVAUpQtIO9MPLbbdVxu2SDI
KEYKZhTqszaA9lNa6oAGtsi++/m+uwI35sAG+zkIpAeOo4ICgDCCAnwwDAYDVR0T
AQH/BAIwADAfBgNVHSMEGDAWgBSDA/3n9vVKTRVB9O0iFtMyCj7KZjBsBggrBgEF
BQcBAQRgMF4wOQYIKwYBBQUHMAKGLWh0dHA6Ly9pLmNmLWkuc3NsLmNvbS9DbG91
ZGZsYXJlLVRMUy1JLUUzLmNlcjAhBggrBgEFBQcwAYYVaHR0cDovL28uY2YtaS5z
c2wuY29tMCUGA1UdEQQeMByCC2V4YW1wbGUuY29tgg0qLmV4YW1wbGUuY29tMCMG
A1UdIAQcMBowCAYGZ4EMAQIBMA4GDCsGAQQBgqkwAQMBATATBgNVHSUEDDAKBggr
BgEFBQcDATBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vYy5jZi1pLnNzbC5jb20v
YWU4MDFlZDFjNTViYjU3OWQ3OTIwOGIwZDc3MmFjZmI4Y2MzYTIwOC5jcmwwDgYD
VR0PAQH/BAQDAgeAMA8GCSsGAQQBgtpLLAQCBQAwggEEBgorBgEEAdZ5AgQCBIH1
BIHyAPAAdgCUTkOH+uzB74HzGSQmqBhlAcfTXzgCAT9yZ31VNy4Z2AAAAZ6AAzGJ
AAAEAwBHMEUCIQCBv0JM0mXaiiQ9efuArkk3O2t/RQ39q7O3oKtYCvOUhQIgdn2u
t5rn+AWzBqZ9m1VOlMLpT/jy2M92Is6itMy9rR8AdgDIo8R/x7OtuTVrAT9qehJt
4zpOQ6XGRvmXrTl1mR3PmgAAAZ6AAzGgAAAEAwBHMEUCIQCoc8r0LVigaz6pvG8s
v0+uBqzf+LPNPxwYxtgkuVdNMwIgAbK/qRNJIWljIVp30PFWjmM+SnoT80ShaPJM
GdbtNLMwCgYIKoZIzj0EAwIDSAAwRQIhALDciGbviRHUIMPez2CVH+Vc0NiaT8Br
FrUGD7dej3D4AiAfs90UtVHGYKTXYYPIJlVqUK1amlBBby7M2KI7pSMjxA==
-----END CERTIFICATE-----`
    const { facts, result } = parseCertificate(toDer(pem))
    expect(facts.subject).toBe('CN=example.com')
    expect(facts.issuer).toContain('Cloudflare TLS Issuing ECC CA 3')
    expect(facts.keyDetail).toBe('ECDSA on P-256 (secp256r1)')
    expect(facts.sigAlg).toBe('ecdsa-with-SHA256')
    expect(facts.sans).toEqual(['DNS:example.com', 'DNS:*.example.com'])
    expect(facts.isCA).toBe(false)
    expect(facts.keyUsage).toEqual(['digitalSignature'])
    expect(facts.extKeyUsage).toEqual(['serverAuth'])
    expect(facts.notAfter?.toISOString().slice(0, 10)).toBe('2026-08-29')
    const ext = result.regions[0].children![0].children!.find((r) => r.name === 'Extensions')
    expect(ext?.children?.map((c) => c.name)).toContain('SCT list (Certificate Transparency)')
    expect(ext?.children?.map((c) => c.name)).toContain('authorityInfoAccess')
    expect(result.warnings).toEqual([])
  })

  it('falls back to a generic ASN.1 view for non-certificate DER', () => {
    const blob = new Uint8Array(seq(oid('1.2.840.113549.1.1.11'), utf8('hello')))
    const out = parseAnyDer(blob)
    expect(out.format).toContain('ASN.1')
    expect(out.regions[0].children).toHaveLength(2)
    expect(out.regions[0].children![0].value).toContain('sha256WithRSAEncryption')
  })
})
